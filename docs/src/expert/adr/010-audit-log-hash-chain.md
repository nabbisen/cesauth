# ADR-010: Audit log hash chain

**Status**: **Draft (v0.32.0)**. The chain mechanism, schema,
and write path arrive in v0.32.0 (Phase 1). The verify cron and
admin verification UI arrive in v0.33.0 (Phase 2). The ADR
graduates to Accepted when both phases are deployed and the
chain has been validated end-to-end against tampering scenarios.

**Context**: cesauth writes audit events to record authentication
attempts, admin actions, token lifecycle events, and tenancy
mutations (see `crates/worker/src/audit.rs` for the `EventKind`
enum). These records exist to answer "what happened, and when,
and to which subject" after the fact — for incident response,
for compliance, and for the user themselves when shown a
self-service audit view.

For an audit log to fulfil that role, it must be **tamper-evident**.
A storage-layer compromise that lets an attacker silently
modify or delete past events would let them rewrite the record
of their intrusion. Cesauth's audit log up to v0.31.0 had no
such defense: events were one-NDJSON-object-per-event in R2,
with no ordering, no integrity proof, and no cross-record
binding.

**Decision**: Move audit events from R2 to a D1 table
`audit_events` and introduce a SHA-256 hash chain over the rows.
Each row carries:

- `payload_hash` — SHA-256 of the event's serialized payload.
- `previous_hash` — the `chain_hash` of the previous row.
- `chain_hash` — SHA-256 over the previous_hash, payload_hash,
  sequence number, timestamp, kind, and event id.

Modifying any past row would force its `chain_hash` to change,
which would break the `previous_hash` of the next row, which
would force its `chain_hash` to change, and so on. To "fix"
the chain after a tamper, an attacker would need to rewrite
every row from the tampered point to the head — a workload
that grows linearly with the number of intervening events.

The single source of truth for audit becomes D1. R2 is no
longer written to and the bucket binding is removed.

## Why D1, not R2 + chain

A first cut of this design kept events in R2 and added a
parallel D1 chain ledger ("D1 stores the chain only, R2 stores
payload"). That design was rejected because:

- **Concurrent writes** would race. R2 has no read-your-writes
  guarantee on `list()`; two writers reading "the latest row"
  could both see the same predecessor and both write a new
  row claiming it as their `previous_hash`. The result is a
  fork the chain has no way to express.
- **Cross-store consistency** would be a permanent operational
  hazard. Either store can fail independently. R2-success +
  D1-failure leaves an event without a chain row; the next
  event's chain would skip it. R2-failure + D1-success leaves
  a chain row that points at a non-existent payload.
- **Verification cost** would be N+1: a sweep of M events would
  require M D1 rows + M R2 fetches.
- **Future features** (`/me/security/audit`, admin filtering by
  subject, retention sweeps) would all be N+1 or require
  building a denormalized D1 index anyway.

D1 is a serializable transactional store. INSERT against it
either succeeds or fails atomically; concurrent INSERTs are
ordered by SQLite's lock manager. SHA-256 calculation is cheap
(microseconds). The Cloudflare D1 row count budget — 5 GB on
the paid plan, several years of audit at any reasonable
deployment scale — is comfortably within reach.

## Why SHA-256, not Merkle tree or signatures

A flat hash chain is the simplest mechanism that delivers the
tamper-evidence property. Adding a Merkle tree would let
verifiers check a single inclusion proof against an external
anchor (signed checkpoint, public ledger), but cesauth has no
such anchor today. Adding signatures (Ed25519 over the chain
head) would protect against an attacker with write access to
D1 — but such an attacker can also rewrite the signing key
location, so the protection is illusory absent a trusted
out-of-band anchor.

SHA-256 over a flat chain protects against a tamper that
modifies past rows but leaves the chain head unchanged. That
is the realistic threat model: an attacker who reaches D1
read/write access tries to delete or alter their own activity,
but doesn't realize the chain head has been recorded
elsewhere (via observation, snapshot, replication). The Phase 2
verification cron records chain heads to a separate location
periodically; that becomes the practical anchor.

Stronger mechanisms (Merkle, signatures, third-party anchors)
remain a future option built on top of this foundation. They
are not Phase 1 work.

## Schema

```sql
CREATE TABLE audit_events (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    id            TEXT    NOT NULL UNIQUE,
    ts            INTEGER NOT NULL,
    kind          TEXT    NOT NULL,
    subject       TEXT,
    client_id     TEXT,
    ip            TEXT,
    user_agent    TEXT,
    reason        TEXT,
    payload       TEXT    NOT NULL,
    payload_hash  TEXT    NOT NULL,
    previous_hash TEXT    NOT NULL,
    chain_hash    TEXT    NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE INDEX idx_audit_events_ts       ON audit_events(ts);
CREATE INDEX idx_audit_events_kind_ts  ON audit_events(kind, ts);
CREATE INDEX idx_audit_events_subject  ON audit_events(subject)
    WHERE subject IS NOT NULL;
```

`payload` is the JSON blob written to R2 in v0.31.0 and earlier
(structurally identical to `worker::audit::Event` serialized
via serde_json). Keeping it as a single TEXT column means a
future schema change to add a new field doesn't require a
migration of existing rows. Per-field columns (`subject`,
`client_id`, `ip`, `user_agent`, `reason`) duplicate top-level
fields for query efficiency — they're indexed and used by
admin search, while the JSON `payload` is the canonical record
that participates in the hash chain.

## Hash calculation

```text
payload_hash  = SHA-256(payload_bytes)
chain_input   = previous_hash || ":" || payload_hash || ":" ||
                seq || ":" || ts || ":" || kind || ":" || id
chain_hash    = SHA-256(chain_input)
```

The `:` separators prevent canonicalization ambiguity (e.g., a
kind value that happens to start with the digits of a sequence
number cannot be confused with a different (kind, seq) pair).

The genesis row uses the all-zeros 64-character hex string
`"0...0"` for both `previous_hash` and `chain_hash` and stores
an empty `payload` `{}`. The first real event chains from the
genesis.

The exact byte layout of `chain_input` is pinned by tests in
`cesauth_core::audit::chain` and must not change between
releases without a chain version bump.

## Concurrency

D1 is serializable for single-statement transactions. The
write path:

```text
BEGIN
SELECT seq, chain_hash FROM audit_events ORDER BY seq DESC LIMIT 1
-- compute new row's chain_hash from the SELECT result
INSERT INTO audit_events (...) VALUES (...)
COMMIT
```

requires that the SELECT and INSERT see the same view of the
table. cesauth runs this as a D1 batch (`db.batch([prepare, ...])`)
which gives transactional semantics. If two workers race and
both pick the same predecessor, the second INSERT will see a
UNIQUE constraint violation on `seq` (since the first INSERT
already incremented the autoincrement counter inside its
transaction); the worker retries with the new tail.

The retry budget is small (3 attempts) — sustained concurrent
writes against a single D1 are not the deployment shape
cesauth targets, and a small handful of retries covers normal
contention. After the budget the write fails best-effort, like
the v0.31.0 behavior.

## Genesis row

The migration that creates `audit_events` also INSERTs a single
row with `seq=1`, `kind='ChainGenesis'`, all-zero
`previous_hash` and `chain_hash`. This makes the chain
verification logic uniform — every real event has a non-trivial
predecessor, and the verifier can stop at `seq=1` knowing it's
reached the start.

## R2 deprecation

The R2 `AUDIT` bucket is no longer written to. The bucket
binding is removed from `wrangler.toml`. The
`worker::audit::write` function is rewritten to insert into D1
via the new repository.

This is a breaking deployment change: any operator with the
v0.31.x `AUDIT` R2 binding configured must accept that
historical R2 data will not be migrated by cesauth itself.
Operators who want continuity over the cutover may export the
R2 audit data with their own tooling before deploying v0.32.0.
The CHANGELOG and the audit chapter both call this out.

## Phasing

- **Phase 1 (v0.32.0)** — this ADR's foundation. Migration
  0008 adds `audit_events`. New `cesauth_core::audit::chain`
  module with pure hash calculation. New
  `AuditEventRepository` port + in-memory + D1 adapters.
  Worker `audit::write` rewritten to insert into D1.
  `CloudflareAuditQuerySource` rewritten to SELECT from D1.
  `r2_metrics` for admin cost dashboard switched from R2 list
  to D1 row count. R2 `AUDIT` binding removed from
  `wrangler.toml`. Documentation chapter
  (`docs/src/expert/audit-log-hash-chain.md`) covers operator
  perspective: what's chained, how to read the chain, what
  the genesis row means, what to do with old R2 data. **No
  automated verification yet.**

- **Phase 2 (v0.33.0)** — verification. Daily cron walks the
  chain, recomputes `chain_hash` for every row, fails the
  sweep on the first mismatch (records the offending `seq` and
  `event_id`). Admin verification UI shows "chain valid through
  row N" plus any reported gaps. Periodic chain-head
  checkpoints — a row is recorded to a separate D1 table or
  external store (TBD) so a compromised D1 can't quietly roll
  back the head. Failure semantics: a tamper detection raises
  a critical alert in the admin console; cesauth does not
  refuse to start (the chain is for forensic value, not
  runtime gating).

After Phase 2 ships and is exercised against deliberately
tampered test data, this ADR graduates to Accepted.

## Open questions

These are deferred to Phase 2 or beyond:

- **Q1**: Where does the chain-head checkpoint live? Candidates:
  separate D1 table, KV with TTL, R2 (paradoxically, after we
  removed the audit bucket — but a separate `cesauth-anchor`
  bucket would be small and rarely written), Workers Analytics
  Engine. Tracking in Phase 2.
- **Q2**: How is the chain rotated if the SHA-256 input format
  needs to change? Possible answer: a `chain_version` column
  defaulted to 1; bump when the input layout changes; the
  verifier consults the column. Not Phase 1.
- **Q3**: When a chain mismatch is detected, what happens to
  audit writing in flight? Phase 2 must answer; Phase 1 doesn't
  detect, so the question doesn't bite yet.
- **Q4**: Per-tenant audit retention policy. v0.33.0 might add a
  retention sweep that physically deletes rows older than N
  days. The chain would need a "tombstone" record to preserve
  integrity across retained gaps. This is post-Phase-2 work.
- **Q5**: User-facing self-service audit view (`/me/security/audit`).
  This is the user-side counterpart to the admin verification
  UI. Useful, but separate from the integrity track — schedule
  with a future UI/UX iteration.

## Considered alternatives (rejected)

- **R2 with `previous_hash` field embedded in each NDJSON
  object**. Rejected: no atomic list-then-write in R2; the
  chain would fork under concurrency.
- **Durable Object holding the chain head**. The DO would
  serialize all audit writes, which is the right concurrency
  model but costs an extra round trip per audit event on the
  hot path of authentication. The D1 batch achieves the same
  atomicity at lower latency.
- **Append a Merkle tree leaf per event, sign the root**. Adds
  a key management problem (where does the signing key live,
  how is it rotated) without commensurate benefit when no
  third-party verifier exists yet. Schedule for after Phase 2
  if external anchoring becomes a requirement.

## See also

- `docs/src/expert/audit-log-hash-chain.md` — operator chapter.
- `migrations/0008_audit_chain.sql` — schema.
- `crates/core/src/audit/chain.rs` — pure hash calc.
- `crates/core/src/ports/audit.rs` — port traits.
