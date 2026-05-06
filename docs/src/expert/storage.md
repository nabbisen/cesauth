# Storage responsibilities

cesauth uses four storage backends, each with a distinct job:

| Store           | Purpose                                                         | Guarantee                           |
|-----------------|-----------------------------------------------------------------|-------------------------------------|
| Durable Objects | Auth challenges, refresh families, active sessions, rate limits | Per-key serialized / strong consistency |
| D1              | `users`, `authenticators`, `oidc_clients`, `consent`, `grants`  | Relational, eventually consistent   |
| KV              | Cache only — JWKS, discovery doc, public metadata               | Best-effort, stale-okay             |
| R2              | Audit logs, event logs, static assets                           | Append-only, date-partitioned       |

The mapping from domain state to backend is deliberate:

| State                                    | Lives in                 |
|------------------------------------------|--------------------------|
| Auth codes, WebAuthn nonces, OTP hashes  | `AuthChallenge` DO       |
| Refresh-token family state               | `RefreshTokenFamily` DO  |
| Session (for revocation check)           | `ActiveSession` DO       |
| Rate-limit counters                      | `RateLimit` DO           |
| Users, clients, authenticators, grants   | D1                       |
| Discovery doc, JWKS                      | KV (cache only)          |
| Audit events                             | R2                       |

## The one rule

> **KV is never authoritative for anything that can be forged or
> double-spent.**

If losing a KV entry could let an attacker replay a code or an OTP,
the state belongs in a Durable Object instead. This is why auth
codes do not live in KV, why refresh-token families do not live in
D1, and why cesauth deliberately has no generic `KeyValueStore`
trait — a single trait would smuggle the weaker guarantee across the
port boundary.

## Why D1 + Durable Objects, not just D1

Both are "databases" in a loose sense. The split is between the two
consistency stories Cloudflare actually offers:

- **D1 is eventually consistent** across the edge. It is the right
  home for slow-changing relational state where a second of lag is
  fine — account profiles, registered clients, WebAuthn credential
  metadata, grant history.

- **Durable Objects give per-key strong consistency.** Each DO
  instance is pinned to a single region and serializes requests
  against its storage. That is the right home for state that must
  not double-spend: auth code consumption, refresh-token rotation,
  rate-limit windows, session revocation status.

Mixing them in the same trait would let a future contributor
accidentally put `consume_auth_code` on a store that D1 can't
guarantee, and the bug would be a race condition in the wild.

## Audit lives in D1 with a hash chain

Audit events live in the `audit_events` D1 table (v0.32.0+,
ADR-010). Each row carries a SHA-256 hash chain over its
predecessor, making the log tamper-evident: modifying any past
row invalidates every subsequent `chain_hash`.

The chain ledger is the source of truth. v0.31.x and earlier
wrote audit events to the R2 `AUDIT` bucket as
one-NDJSON-object-per-event; that path was retired entirely in
v0.32.0 alongside the `[[r2_buckets]] AUDIT` binding. Operators
upgrading retain any historical R2 data on their account, but
cesauth no longer reads or writes it. See the
[Audit log hash chain](./audit-log-hash-chain.md) chapter for
operator perspective and ADR-010 for the design rationale.

The audit retrieval dev endpoint at `/__dev/audit` (gated on
`WRANGLER_LOCAL="1"`) was rewritten to query the D1 table; it
remains the local-development inspection surface. The admin
search at `/admin/console/audit` queries the same table.

## KV is a cache

The two things that live in KV — the OIDC discovery doc and the
JWKS — are both reconstructible from D1 + secrets at any time. KV
holds them to spare the Worker a D1 round-trip on every
`/.well-known/openid-configuration` or `/jwks.json` hit. If a KV
entry disappears, the next hit populates it again.

No code path depends on KV durability. The [ports &
adapters](./ports-adapters.md) chapter explains how this intent is
encoded in the trait boundary (`CacheStore` is a different port from
`UserRepository`).
