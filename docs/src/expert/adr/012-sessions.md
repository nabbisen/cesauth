# ADR-012: Session hardening + user-facing session list

**Status**: **Accepted (v0.35.0)**.

**Context**: cesauth's session layer in v0.4 — v0.34.0 had three
properties already in place:

- A signed `__Host-cesauth_session` cookie carrying
  `(session_id, user_id, auth_method, issued_at, expires_at)`.
- A per-session `ActiveSession` Durable Object holding
  authoritative liveness state. Revocation goes through the DO
  and is atomic.
- An absolute-lifetime hard cap via `expires_at` on the cookie.

What was missing relative to current OWASP / NIST 800-63B
session-management guidance and relative to operator UX
expectations:

1. **No idle timeout.** A session active once would remain
   live for the full 7-day default lifetime even if the user
   walked away. NIST 800-63B §4.1.3 and OWASP ASVS V3.3.4
   both expect an idle limit; a typical web AAL2 deployment
   uses 30 minutes or shorter.
2. **No way for a user to see their own sessions.** If a
   user signed in on a public laptop and forgot to log out,
   the only recovery path was admin intervention or waiting
   for the absolute lifetime (7 days).
3. **No way for a user to revoke a session from another
   device.** Same scenario as above. The admin console had a
   revoke button (v0.30.x), but expecting users to file
   support tickets for "I think I left a session open" is
   poor UX and creates an attack window.
4. **`touch()` was never called from production.** Reviewing
   the code path showed `me::auth::resolve_or_redirect`
   calling `status()` instead of `touch()`. `last_seen_at` was
   never updated on authenticated requests. This was a
   structural bug — even if the v0.34.0 code had carried an
   idle timeout config, the gate would never have fired
   because the data backing it was dormant.
5. **Audit events collapsed all session terminations.** A
   single `session_revoked` event covered admin revoke, user
   logout, idle timeout, absolute timeout, and external
   admin-API revoke. Operators monitoring for "someone is
   forcibly logging users out of the system" had no signal
   distinct from "user clicked logout".

This ADR documents the v0.35.0 changes that close these gaps.

## Audit findings

What's already correct in v0.34.0 and stays unchanged:

- **Cookie integrity.** `SessionCookie::sign/verify` with
  HMAC-SHA256. The cookie name uses the `__Host-` prefix so
  the browser refuses to set it without `Secure` and `Path=/`,
  and won't accept it across subdomains.
- **DO atomicity.** The DO is a single-writer state machine;
  start/touch/revoke/status are individually atomic.
- **Session-id rotation on login.** Every login mints a fresh
  `Uuid::new_v4()` in `complete_auth_post_gate`. There's no
  reuse-an-existing-session-on-login path.
- **Revocation is server-side first.** A revoked session is
  rejected even if the cookie's signature checks out. The
  worker consults the DO before treating the session as
  authoritative.

The remaining out-of-scope items from the original v0.35.0
ROADMAP entry, deferred for the reasons documented:

- **"New device" notification.** Needs a transactional-email
  pipeline that doesn't yet exist (cesauth has Magic Link
  email but no general-purpose templated-message channel).
  Adding one is a release of its own; defer.
- **Device fingerprinting** (User-Agent + IP capture into
  SessionState). Useful for the user-facing list ("Chrome on
  macOS, Tokyo, signed in 3 days ago") but separable from
  the BCP-direct items. Schedule alongside the i18n track or
  the next UI/UX iteration.
- **Session-id rotation on existing-session step-up.** Already
  happens — `complete_auth_post_gate` mints a fresh id on
  every successful TOTP step-up. No bug; nothing to fix.

## Decision

### Idle timeout

Add `Config::session_idle_timeout_secs` (default 30 minutes,
env `SESSION_IDLE_TIMEOUT_SECS`). Setting to 0 disables the
gate (operators with a "trusted device" policy may want
this). The absolute `session_ttl_secs` continues to apply
independently.

The check happens **inside the DO `Touch` command**, atomic
with the touch update. Doing the check in the worker
(peek-then-decide) would open a small race window between
the peek and a follow-up revoke; the in-DO check is one
transaction.

### `SessionStatus` variants

```rust
pub enum SessionStatus {
    NotStarted,
    Active(SessionState),
    Revoked(SessionState),
    /// v0.35.0
    IdleExpired(SessionState),
    AbsoluteExpired(SessionState),
}
```

Distinct variants per termination cause. The HTTP-visible
behavior is the same for all three (redirect to /login), but
the audit dispatch differentiates so operators can monitor
each independently.

### `ActiveSessionStore::touch` signature

```rust
async fn touch(
    &self,
    session_id:        &str,
    now_unix:          i64,
    idle_timeout_secs: i64,
    absolute_ttl_secs: i64,
) -> PortResult<SessionStatus>;
```

Timeout config is passed in by the caller rather than read
from a Config inside the store — keeps the store
transport-agnostic (the in-memory adapter doesn't have a
Config).

Order of checks: **absolute first, then idle**. A session
past both gates reports `AbsoluteExpired` because that's
the deeper cause; if the absolute gate hadn't fired, the
session would still be revoked, just later. This ordering
is pinned by `session_touch_absolute_takes_priority_over_idle`.

### `me::auth::resolve_or_redirect` switches `status()` → `touch()`

The structural bug fix from finding (4). Without this,
v0.35.0's idle-timeout config would be dead code. The
resolver also dispatches the new audit kinds:

- `Active` → resolve to live state.
- `IdleExpired` → emit `session_idle_timeout` audit event +
  redirect to /login.
- `AbsoluteExpired` → emit `session_absolute_timeout` +
  redirect.
- `Revoked` / `NotStarted` → redirect (already audited
  somewhere else).

Audit writes are best-effort: an audit-store outage must
not leave the user on an error page when redirecting them
to /login is the safer outcome.

### Per-user session enumeration: DO + D1 hybrid

This is the load-bearing design choice for the user-facing
list page. The structural problem: `ActiveSession` DOs are
keyed one-per-session. There's no "iterate the namespace"
operation in Cloudflare's DO surface; cross-DO iteration
isn't a thing.

Three alternatives considered:

1. **Add a second `UserSessionIndex` DO** keyed by user_id,
   holding a list of session_ids. *Rejected*: doubles DO
   classes, every session start has to write to two DOs
   (multiplying failure modes), and the index-DO would be a
   single bottleneck per user.
2. **Iterate at the namespace level.** *Rejected* — the
   capability doesn't exist.
3. **D1 secondary index** (`user_sessions` table). *Chosen*.
   The DO remains source of truth for individual session
   state; the D1 row is a denormalized per-user index whose
   job is "given a user_id, what session_ids exist". Already
   established as a pattern by the v0.32.0 audit_events
   table (D1 as secondary store for DO data).

The D1 schema is added in migration 0009:

```sql
CREATE TABLE user_sessions (
  session_id   TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  revoked_at   INTEGER,
  auth_method  TEXT NOT NULL,
  client_id    TEXT NOT NULL
);
CREATE INDEX user_sessions_user_idx
  ON user_sessions (user_id, created_at DESC);
```

`last_seen_at` is **NOT mirrored** into D1. It's hot-path
mutable in the DO (updates on every authenticated request);
mirroring it would multiply D1 write load by request
volume. The user-facing list shows `created_at` instead and
documents "last activity" as approximate. This is a
deliberate trade-off; if a future UI iteration needs precise
last-active rendering, it can peek the DO per-row.

The two stores are eventually consistent for the index
columns. The DO is always the "newer" of the two:

- `start`: DO write succeeds → D1 INSERT (best-effort).
- `revoke`: DO Revoke succeeds → D1 UPDATE (best-effort).
- `touch` reaching `IdleExpired` / `AbsoluteExpired`: DO
  state mutated → D1 UPDATE (best-effort).

A D1 hiccup must not unwind a successful DO operation. The
worst outcome is an index row that says "active" when the
DO knows the session is revoked; the next DO read corrects
it, and the user-facing list re-fetches fresh. Operators
who want strong consistency between the two stores can
trigger the index reconciliation manually (planned but not
shipped in v0.35.0; see Open Questions).

### Audit event split

```
SessionStarted            (existing)
SessionRevoked            (legacy, retained for backward compat)
SessionRevokedByUser      (v0.35.0, new) — user clicked revoke
SessionRevokedByAdmin     (v0.35.0, new) — admin console action
SessionIdleTimeout        (v0.35.0, new) — auto on touch
SessionAbsoluteTimeout    (v0.35.0, new) — auto on touch
```

`SessionRevoked` (the legacy generic kind) stays in the
catalog so pre-v0.35.0 audit rows still parse; new code
paths emit the split kinds. Operator-facing dashboards
should migrate to the split kinds.

### `/me/security/sessions` page

Renders the user's active sessions newest-first. Each row
shows:

- Auth method (passkey / magic link / admin)
- Client id
- Sign-in time (created_at)
- Last activity (approximate, from D1 mirror)
- Shortened session id (first 8 chars)
- Revoke button (POST form, CSRF-guarded) — disabled and
  labeled "current device" for the row representing the
  session rendering the page.

POST `/me/security/sessions/:session_id/revoke` performs:

1. CSRF check.
2. Refuse if `session_id` matches the requesting session
   (this would be a self-log-out; users should use the
   logout flow instead, which has clearer UX).
3. Ownership check via `store.status(target_id)` — if the
   target's `user_id` doesn't match the requester's, return
   403. The page only renders the user's own sessions, so
   this branch is defensive (UUIDv4 forging is
   cryptographically unlikely), but the depth-of-defense
   matters in case of future bugs that expose `session_id`
   in URLs.
4. Already-revoked / never-started: silent success, no leak
   of which existed (don't enable session-id probing).
5. Revoke + audit `session_revoked_by_user`.
6. Redirect back with `SessionRevoked` flash.

## Wire compatibility

No client-visible changes for the OAuth / OIDC layer. Refresh
tokens, access tokens, the `/token` endpoint — none are
affected.

End-user behavior change: a user idle for `>=
session_idle_timeout_secs` (default 30 min) on the next
request is redirected to /login instead of seeing their
content. This is the intended security improvement; operators
who want the v0.34.0 behavior can set
`SESSION_IDLE_TIMEOUT_SECS=0`.

## Operator-visible changes

- **One D1 migration.** `wrangler d1 migrations apply
  cesauth-prod --remote` after deploy. Schema version 8 → 9.
- **Existing sessions don't appear in `user_sessions`.** The
  index is populated on `start`; sessions started before the
  v0.35.0 deploy aren't backfilled. Effect: users who were
  signed in across the upgrade see only sessions started
  after the upgrade in their `/me/security/sessions` page,
  and old sessions remain authoritative-but-invisible until
  they expire (idle or absolute) or the user signs in again.
  This is a deliberate trade-off — backfilling would require
  iterating the DO namespace which isn't possible. Documented
  in the upgrade notes.
- **Audit dashboards may want updates.** Add panels for the
  new kinds (`session_idle_timeout`, `session_absolute_timeout`,
  `session_revoked_by_user`); the legacy `session_revoked` kind
  no longer fires for these cases.
- **Idle timeout default 30 min.** Operators may tighten
  (e.g., 10 min for high-security tenants) or set to 0 to
  disable.

## Tests

777 → 808 (+25). New coverage:

- 11 new tests in `cesauth-adapter-test::store::tests` for the
  in-memory `ActiveSessionStore`'s timeout + list_for_user
  semantics. Cases include touch-bumps-last-seen,
  idle-fires-when-stale, idle-disabled-with-zero, absolute-
  fires, absolute-priority-over-idle, idempotent-on-revoked,
  unknown-id-NotStarted, list-returns-only-user-newest-first,
  list-excludes-revoked-by-default, list-includes-revoked-with-
  flag, list-respects-limit, list-empty-on-unknown-user.
- 7 new UI rendering tests in `cesauth_ui::templates::tests`
  for `sessions_page` covering empty state, listing, current-
  device disable, revoke-form rendering, CSRF escaping,
  flash splice, back-link.

## Open questions

- **Q1**: D1-DO reconciliation tool. Operators who notice
  index drift (e.g., from a D1 outage during a revoke
  cascade) need a way to repair it. v0.35.0 ships with the
  drift documented; the reconciliation tool is post-Phase
  work. Likely a `cesauth-migrate sessions reconcile` admin
  subcommand.
- **Q2**: User notification on idle / absolute timeout. The
  current behavior is silent (the user just gets redirected
  to /login on the next request). A notification "your
  session ended due to inactivity" before the redirect
  would be friendlier UX. Defer with the email-pipeline work.
- **Q3**: Geographic / device-fingerprint columns on
  user_sessions. Useful for the user-facing list but
  separable; defer.
- **Q4**: Bulk "revoke all other sessions" button on the
  list page. The page has 50 rows max; for users with
  multiple sessions a bulk option would be friendlier than
  clicking each row. Defer, low priority.

## Considered alternatives (rejected)

- **Idle timeout as cookie expiry only.** Rejected — cookies
  are client-side state; an attacker with a stolen cookie
  doesn't honor the expiry attribute. The check has to be
  server-side.
- **Sliding-window absolute timeout.** RFC 9700 §4.13 and
  NIST 800-63B both treat absolute timeouts as hard caps
  precisely because they're not subject to user-side
  manipulation. cesauth keeps the hard-cap.
- **Single DO per user holding all sessions.** Same problems
  as a UserSessionIndex DO plus the additional concern that
  every session-start would serialize through one DO per
  user, creating a per-user bottleneck.

## See also

- [ADR-011: Refresh token reuse hardening](011-refresh-token-reuse-hardening.md)
  — the previous security-track release; same pattern of
  closing observability gaps.
- [ADR-010: Audit log hash chain](010-audit-log-hash-chain.md)
  — the audit events emitted on idle/absolute timeout flow
  through this chain.
- NIST 800-63B §4.1.3 (idle timeout requirements for AAL1
  reauth).
- OWASP ASVS V3.3.4 (idle timeout requirements).
- RFC 9700 §4.14.2 (refresh-token-related session
  considerations; this ADR doesn't change refresh behavior
  but the cousin doc is useful background).
