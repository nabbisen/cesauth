# ADR-004: Anonymous trial → human user promotion

**Status**: Draft (v0.16.0)
**Decision**: Anonymous trials are server-issued, single-session,
non-recoverable principals with a 7-day retention window. Promotion
to `human_user` preserves the `User.id` and reuses the standard
Magic Link verification — same email-claim ceremony as fresh
self-registration, but with the existing anonymous row updated in
place rather than a new row created.
**Rejected**:
- Storing anonymous principals in a separate table.
- Permanent (non-expiring) anonymous accounts.
- Promotion via in-session "claim email" without re-verifying.

## Context

Spec §3.3 introduces `AccountType::Anonymous` as a first-class
account type alongside `HumanUser`, `ServiceAccount`,
`SystemOperator`, and `ExternalFederatedUser`. §11 priority 5 then
asks for a promotion flow — anonymous → human_user — without
specifying how it works. The current state (post v0.15.1) is that
the enum variant exists in `crates/core/src/tenancy/types.rs` but
no code path constructs an `Anonymous` principal, no token issuer
recognizes one, and no UI surface mentions one. The v0.11.0 ADR
note said this would land at "0.14.0 or later"; it has now slid
across three releases. The reason for the slide is genuine: every
slot needed a different design pass first (read pages → mutations
→ token-mint → membership × 3 → security fix), and Anonymous
without a thought-out lifecycle is a security regression waiting
to happen.

The use case is the standard one: a visitor wants to try the
product without creating an account. The product wants to keep
the data they generate so that **if** they later sign up, their
work isn't lost. The threat model is also standard: an attacker
should not be able to (a) hijack someone else's anonymous trial
to claim their data, (b) bypass real account creation by laundering
through the anonymous path, or (c) accumulate anonymous principals
indefinitely as a vector for abuse or storage exhaustion.

Five design questions cluster around this:

1. **Provenance** — who or what creates the anonymous user, and
   how is the request authenticated?
2. **Token issuance** — what token does the anonymous principal
   receive, and what does it look like to RPs and to the audit
   layer?
3. **Retention** — when and how does an unclaimed anonymous user
   stop existing?
4. **Conversion ceremony** — when the anonymous user supplies an
   email, how does the system verify ownership of that email and
   what happens to the existing user row?
5. **Audit trail** — what records survive the promotion, and what
   does the audit log say about the transition?

The design space is large enough that "just do the obvious thing"
isn't well-defined. This ADR picks one coherent point in the
space and explains the rejected alternatives so a future
maintainer asking "why doesn't anonymous trial do X" finds an
answer.

## Decision

### Q1: Provenance — server-issued, single-shot

A new endpoint `POST /api/v1/anonymous/begin` creates an
anonymous user and returns its bearer token in the response body.
No request body is required; the endpoint is **not** authenticated.
The server enforces a per-IP rate limit (existing `RateLimit` DO,
new bucket key `anonymous_begin_per_ip`) to prevent farming.

**Rejected**: `POST /api/v1/users` with `account_type=anonymous`.
Reusing the existing user-creation route would conflate two very
different lifecycles (admin-created users vs visitor-self-created
trials) on one route, with one set of permissions checks gating
both. Splitting the route makes the trust boundary explicit:
`/anonymous/begin` is unauthenticated by design and is the only
unauthenticated user-creating route in cesauth.

The anonymous user's row in `users`:

- `id`: fresh ULID, same generator as other users.
- `tenant_id`: the deployment's `DEFAULT_TENANT_ID`. Spec §3.3
  permits a per-deployment override via `ANONYMOUS_TENANT_ID`
  env var; we default to `tenant-default` so single-tenant
  deployments don't have to think about it.
- `email`: `None`. This is the field that distinguishes a
  trial from a registered user.
- `email_verified`: `false`.
- `display_name`: a short randomly-generated tag like
  `Anon-7K9F2`. RPs that need a non-blank label can use this.
- `account_type`: `Anonymous`.
- `status`: `Active`.

### Q2: Token issuance — short-lived bearer, not OIDC

The anonymous principal does **not** go through the OIDC
ceremony. It receives a single opaque bearer token from
`/anonymous/begin`. The token is recognized by cesauth's
existing user-token plumbing the same way an OIDC access token
is — `Authorization: Bearer ...` — but it carries no `id_token`
and is not refreshable.

- Token format: same `cesauth-anon-...` prefix scheme used for
  admin tokens, but in a separate table `anonymous_sessions`
  (new in migration `0006`) to keep the auth surface narrow.
  The token's hash is stored; the plaintext is shown once in
  the response and never recoverable.
- TTL: **24 hours** from creation. After 24h the token stops
  working but the user row survives (subject to Q3 retention).
- Refresh: not supported. If the visitor's session expires they
  call `/anonymous/begin` again and get a new token + new
  anonymous user. The old user row is orphaned and will be
  garbage-collected by the retention sweep.

**Rejected**: full OIDC tokens (id_token + access_token + refresh)
for anonymous principals. The OIDC tokens carry an `email` claim
that's required for most RPs to consume them; an anonymous user
has no verified email. We could synthesize a placeholder
(`anon-7K9F2@anonymous.local`) but that pretends to a level of
identity verification we don't have.

**Rejected**: signed JWT bearer (instead of opaque). JWTs would
let RPs validate the principal stateless-ly, but anonymous
principals are exactly the case where stateful validation
matters — the server needs to be able to revoke them on
promotion (see Q4) without waiting for the JWT to expire.

### Q3: Retention — 7 days, sweep daily

An anonymous user's row is **kept for 7 days** from creation
unless promoted. After 7 days a scheduled sweep (Cloudflare
Workers Cron Trigger, daily at 04:00 UTC) deletes the row and
all its memberships, role assignments, and authenticator rows
(if any — see Q4 for why these can exist before promotion).

- 7 days is enough to cover "I tried it Friday, came back
  Monday" but short enough that abandoned trials don't
  accumulate.
- Tokens already expire at 24h (Q2) so a row in days 2-7 is
  technically reachable only if the visitor rotates back through
  `/anonymous/begin` — not the same row, a new one.
- The sweep is deterministic and idempotent: it deletes any row
  with `account_type='anonymous' AND created_at < now - 7d AND
  email IS NULL`. Promoted rows have `email IS NOT NULL` and
  survive.

**Rejected**: hard delete on token expiry (24h). Too aggressive
for the "came back Monday" case.

**Rejected**: indefinite retention with `Disabled` status after
24h. Risks unbounded growth of stale rows.

**Rejected**: per-tenant retention overrides. Adding a tenant-
level config knob is premature — every deployment should pick
the same number first. If a real customer needs longer, we
revisit.

### Q4: Conversion ceremony — Magic Link verifies email, then UPDATE in place

To promote, the visitor visits a `/promote` flow that:

1. Asks for an email address.
2. Sends a Magic Link to that address.
3. On link click, **updates** the existing anonymous row:
   - `email` ← submitted address.
   - `email_verified` ← `true`.
   - `account_type` ← `HumanUser`.
   - The `User.id` is **preserved**.

The promotion is gated on the same `MagicLinkChallenge` issuance
+ verification ceremony as fresh self-registration. The
difference is that fresh registration does INSERT into `users`;
promotion does UPDATE on the existing row. From the database's
perspective, the row's `id` doesn't change, so all foreign keys
pointing at the user (memberships, role assignments,
authenticator credentials, audit subject ids) survive without
remapping.

**Edge case — email already exists in the same tenant**: the
`users.email` unique constraint per tenant fails the UPDATE.
The promotion endpoint catches this case and returns an error
distinguishing "this email is already registered, log in
normally instead" from "this email failed to verify". The
anonymous row stays anonymous; the visitor can either log in
to the existing account (losing the anonymous-session data) or
choose a different email.

**Authentication required for the promotion request**: the
`Authorization: Bearer <anon-token>` header. This proves the
caller is the anonymous principal whose row is about to be
promoted. Without this, anyone could submit a `/promote` request
naming any anonymous user id.

**Rejected**: separate `anonymous_users` table with a "copy
fields, delete row" promotion. Forces every dependent table
(memberships, assignments, auth challenges, ...) to handle the
id remap. The bug surface is large; the implementation cost is
larger; the only upside is a slightly cleaner model boundary.

**Rejected**: in-session "claim this email" without Magic Link.
Trivially exploitable: an attacker who hijacks the anonymous
bearer token could claim any victim's email and the system
would take them at their word.

**Rejected**: invitation-style promotion (system-admin promotes).
Out of band of the visitor's own intent. If we ever need this
case, it's a separate flow.

### Q5: Audit trail — three events, principal survives

Three audit events:

- `AnonymousCreated` — new event kind. Subject is the freshly
  created anonymous user id. Reason carries `via=anonymous-begin,ip=<masked>`.
- `AnonymousExpired` — emitted by the daily sweep for each row
  it deletes. Subject is the deleted user id.
- `AnonymousPromoted` — new event kind. Subject is the user id
  (unchanged). Reason carries
  `via=anonymous-promote,from=anonymous,to=human_user`.

Because the user id is preserved across promotion (Q4), all
audit events emitted *during* the anonymous phase remain
queryable by subject id after promotion. An auditor reviewing
"what did user `u-7K9F` do" sees the full timeline including
the promotion ceremony.

**Rejected**: separate-account-per-phase audit. Would require
mapping anonymous-phase events to the post-promotion id, which
needs a side table — extra storage, extra fail mode.

## Consequences

- **New**: migration `0006_anonymous.sql` adds the
  `anonymous_sessions` table. Two columns on `users` may need
  to track promotion lineage (`promoted_at`, `promoted_from`)
  but I want to defer that until we have a concrete reason.
  Promotions are observable from audit alone today.
- **New**: `POST /api/v1/anonymous/begin` route, unauthenticated
  except for IP rate limiting.
- **New**: `POST /api/v1/anonymous/promote` route, gated on the
  anonymous bearer + the Magic Link verification flow.
- **New**: `EventKind::AnonymousCreated`, `AnonymousExpired`,
  `AnonymousPromoted` audit variants.
- **New**: `AnonymousSessionRepository` port in `cesauth-core`
  with D1 + in-memory implementations, mirroring the existing
  `AdminTokenRepository` shape.
- **New**: Cloudflare Cron Trigger for the daily retention
  sweep. cesauth doesn't currently use cron triggers; the
  `audit.yml` workflow is the closest parallel and runs in
  GitHub Actions, not Workers. The Workers cron is configured
  in `wrangler.toml`.
- **Changed**: nothing in existing routes or schemas.
  Anonymous flows land additively.
- **Documented**: `docs/src/expert/tenancy.md` gains an
  "Anonymous trial lifecycle" section; the operator runbook
  gains "Verifying the retention sweep ran".

## Implementation phases

The ADR settles the design; the foundation work in 0.16.0
ships the schema and types. Form/UI surface follows in
later releases on the v0.11.0 → v0.13.0 → v0.14.0 model:

1. **0.16.0 (this ADR + foundation)**: ADR-004 written,
   migration `0006_anonymous.sql`, `AnonymousSessionRepository`
   port, D1 adapter, in-memory adapter, type-level surface.
   No HTTP routes yet. Tests cover the type surface.
2. **0.17.0 (begin + promote routes)**: `POST
   /api/v1/anonymous/begin`, `POST /api/v1/anonymous/promote`.
   Magic Link integration for the promote step.
3. **0.6.05 (retention sweep)**: Cloudflare Cron Trigger and
   sweep handler. Operator runbook section for verifying it
   ran.

This staging mirrors v0.11.0 → v0.13.0 → v0.14.0 — the design
+ foundation comes first as a small release; the surface
follows in subsequent releases. Each phase is independently
shippable and reverts to the previous if a problem surfaces.
