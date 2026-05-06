# ADR-012: Session hardening + user-facing session list

**Status**: **Accepted (v0.35.0)**.

**Context**: cesauth has carried a session subsystem since
v0.4 — `SessionState` + `ActiveSessionStore` (`crates/core/src/
ports/store.rs`), backed by a per-session Cloudflare Durable
Object (`crates/adapter-cloudflare/src/active_session.rs`).
Each authenticated request resolves the `__Host-cesauth_session`
cookie, signature-verifies it, and consults the DO for
revocation status. Logout, admin revocation, and TOTP step-up
all go through the same DO `revoke()` operation.

What that v0.34.x baseline did NOT have:

1. **No idle timeout.** The session cookie carries an
   `expires_at` (absolute lifetime), but a session that's been
   idle for hours within that window kept working. RFC 9700 +
   common BCP guidance treat an absolute lifetime as
   insufficient on its own.
2. **No active-touch wiring.** The auth resolver consulted
   `status()` on each request, not `touch()`. `last_seen_at`
   never advanced past `created_at` in production. This was a
   structural bug rather than a deliberate choice — the touch
   was just never called.
3. **No per-user session enumeration.** `ActiveSession` is one
   DO per session_id; cross-DO iteration is not a thing in the
   Workers runtime. There was no answer to "show me all
   sessions for user X" — which is exactly what a user-facing
   "active devices" page needs.
4. **No user-facing revoke.** The Security Center index
   (`/me/security`) showed login + TOTP state but had no
   surface for a user to forcibly log out other devices. Admin
   could revoke sessions; users couldn't.
5. **No audit signal differentiation.** Every revocation
   emitted `EventKind::SessionRevoked` regardless of cause.
   Operators couldn't distinguish "user clicked revoke" from
   "admin kicked the session" from "auto-expiry".

This ADR documents the v0.35.0 changes that close those gaps.

## Audit findings (v0.34.x baseline)

What v0.34.x got right and we didn't change:

- **Session cookie is HMAC-signed.** Wire-tampering catches.
  `SessionCookie::sign/verify` (`crates/core/src/session.rs`).
- **Cookie carries `expires_at`.** Absolute lifetime hard limit
  enforced by the cookie itself; even a misbehaving server-side
  store can't revive an expired cookie.
- **Per-session DO.** Revocation is atomic: one DO write
  decides the session's state at request resolution time. No
  cache window where a revoked session can be used.
- **`__Host-` cookie prefix.** Forces `Secure`, `Path=/`,
  disallows `Domain` attribute. Matches the cross-origin-
  unsafe first-party shape we want.
- **Session-id rotation on login.** Every successful TOTP /
  Magic Link / Passkey verification mints a fresh `Uuid::new_v4`
  inside `complete_auth_post_gate` (`crates/worker/src/
  post_auth.rs`). Step-up doesn't reuse the pre-step-up
  session_id. This behavior was already present and is
  preserved unchanged.

What was missing — five gaps — gets addressed by v0.35.0.

## Decision

### Gap 1: idle timeout

Add `Config::session_idle_timeout_secs` (default 30 minutes).
Extend `ActiveSessionStore::touch` to consult both `idle_timeout_secs`
AND `absolute_ttl_secs` atomically with the touch update —
INSIDE the DO, so the check and the state mutation are one
transaction.

```rust
async fn touch(
    &self,
    session_id:        &str,
    now_unix:          i64,
    idle_timeout_secs: i64,
    absolute_ttl_secs: i64,
) -> PortResult<SessionStatus>;
```

Two new `SessionStatus` variants make the cause observable:

- `SessionStatus::IdleExpired(state)` — `last_seen_at +
  idle_timeout_secs <= now`. State is mutated (revoked_at
  populated) before the DO returns.
- `SessionStatus::AbsoluteExpired(state)` — `created_at +
  absolute_ttl_secs <= now`. Same atomic-mutation contract.

Order matters: the absolute gate is consulted FIRST. A session
past both gates reports `AbsoluteExpired` (the deeper-cause
attribution). Pinned by test
`session_touch_absolute_takes_priority_over_idle`.

`idle_timeout_secs = 0` disables the idle gate (operator
escape hatch, e.g., for kiosk-style deployments where idleness
isn't meaningful). `absolute_ttl_secs = 0` likewise disables
the absolute gate, but operators shouldn't use that — the
absolute lifetime is a hard cap that the BCP guidance
explicitly recommends keeping.

### Gap 2: wire `touch()` into the auth resolver

`me::auth::resolve_or_redirect` switches from `status()` to
`touch()`. This is the load-bearing v0.35.0 change — without
it, the new timeouts are dormant. Resolution path on each
authenticated request:

1. Cookie present? signature valid?
2. `touch(session_id, now, idle, absolute)` → consult both
   gates atomically with the state write.
3. Active → return state to caller.
4. IdleExpired / AbsoluteExpired → emit the corresponding
   audit event, redirect to `/login`.
5. Revoked / NotStarted / Err → redirect to `/login`.

The audit dispatch in step 4 is what the gap-5 fix needs —
operators can monitor `session_idle_timeout` and
`session_absolute_timeout` separately.

### Gap 3: per-user session enumeration

`ActiveSessionStore` gains `list_for_user(user_id,
include_revoked, limit)`. Implementation by adapter:

- **In-memory (tests):** O(n) scan over the map.
- **Cloudflare (production):** D1 `user_sessions` index table,
  written alongside the DO at `start()` and mirrored on
  `revoke()`. The DO remains the source of truth for
  individual session state; the D1 row is a denormalized
  index whose only job is "given a user_id, what session_ids
  exist".

Three alternatives were considered for the production index:

1. **Second `UserSessionIndex` DO keyed by user_id.** Pros:
   same single-store shape as the existing session DO.
   Cons: doubles the number of DO classes (currently three);
   each new session has to write to TWO DOs at start time,
   multiplying failure modes; cleanup of stale list entries
   becomes its own concern.
2. **Iterate the DO storage at the namespace level.**
   Cloudflare DOs don't support cross-DO iteration. Rejected
   outright.
3. **D1 secondary index.** session_id PRIMARY KEY, user_id
   indexed. Eventually-consistent updates from the DO are
   fine — at most the user-facing list shows a session_id
   whose state has changed since the index was written, and
   the per-row DO peek catches that on user click-through.

We chose **option 3** because it adds a small DDL change
rather than doubling the DO count, and the v0.32.0
`audit_events` table already established the precedent of
"D1 as secondary store for DO-derived data".

The D1 row mirrors only what the user-facing list page renders:

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

Notably absent: `last_seen_at` and `scopes`. `last_seen_at` is
hot-path mutable in the DO — mirroring it on every touch
would put significant write pressure on D1 just to surface a
column the page doesn't render in real time. The user-facing
list shows a "signed in: <created_at>" timestamp instead; the
"last access" column is omitted from the v0.35.0 page. If
operators want it back later, the layered work is:
(a) decide on a sampling cadence (e.g., persist
last_seen_at to D1 at most once per N minutes), (b) extend
the SessionListItem.

### Gap 4: user-facing list + revoke

New page at `GET /me/security/sessions`. Renders the
authenticated user's sessions with:

- Session card per active row: auth method (パスキー / Magic
  Link / 管理者ログイン), client_id, created_at timestamp,
  shortened session_id.
- "この端末" badge on the row that matches the requesting
  cookie's session_id. That row's revoke button is
  disabled — see "current session" rationale below.
- Revoke button (取り消す) on every other row; each row's
  form POSTs to `/me/security/sessions/:session_id/revoke`
  with a CSRF token.

POST handler at `POST /me/security/sessions/:session_id/
revoke`:

1. CSRF.
2. Path param session_id.
3. **Refuse revoking the current session** via this endpoint.
   Doing so would cause the next request to bounce to
   /login — surprising UX. The user should use the explicit
   logout flow. Defensive check, since the UI's button is
   already disabled for the current row.
4. **Ownership check**: peek the target session, refuse if
   `target.user_id != caller.user_id`. The page only renders
   the caller's sessions, so this branch shouldn't fire in
   practice; defense in depth in case a forged URL is
   submitted.
5. `revoke()` on the store (DO + D1 mirror).
6. Audit: `EventKind::SessionRevokedByUser` with payload
   `{session_id, revoked_by: "user", actor_user_id}`.
7. Redirect back to `/me/security/sessions`.

### Gap 5: audit event split

`EventKind` gains:

- `SessionRevokedByUser` — user-initiated revoke.
- `SessionRevokedByAdmin` — admin-initiated revoke.
- `SessionIdleTimeout` — auto-revoked by the idle gate.
- `SessionAbsoluteTimeout` — auto-revoked by the absolute
  gate.

The legacy `SessionRevoked` kind stays in the catalog for
backward compatibility with v0.4–v0.34.x audit chain rows.
New code paths use the split kinds.

`me::auth::resolve_or_redirect` emits the timeout kinds
when `touch()` returns IdleExpired/AbsoluteExpired. The
revoke handlers emit the by-user/by-admin kinds. Operators
monitoring for compromise can now alert on the split
signals separately.

## Wire compatibility

No client-visible changes for OAuth clients. The session
cookie format is unchanged. Existing v0.34.x clients
continue working.

The auth resolver's `touch()` switch IS visible to existing
sessions:

- Sessions created at v0.34.x with `last_seen_at = created_at`
  are now subject to the new idle gate. A session that was
  idle for >30 minutes when v0.35.0 deploys will be revoked
  on its next request. This is the BCP-correct behavior;
  operators should communicate the change to users if they
  expect long-idle sessions.

## Schema changes

- Migration `0009_user_session_index.sql` adds the
  `user_sessions` table + index.
- `SCHEMA_VERSION` bumps from 8 to 9.
- Operators must run `wrangler d1 migrations apply` before
  the v0.35.0 build can serve traffic. Without the migration,
  `start()` will fail on the D1 INSERT and new sessions
  cannot be created.

## Operator-visible changes

- `SESSION_IDLE_TIMEOUT_SECS` env var (default 1800 = 30 min).
- New audit kinds; operator dashboards may need a panel update.
- Per-row write amplification: each session start now writes
  one DO record + one D1 row (was: DO only). Each revoke
  writes one DO record + one D1 update (was: DO only). Hot
  path (touch on every authenticated request) is unchanged
  — D1 is not in the touch path.

## Considered alternatives (rejected)

- **Per-family rate limit on `/token`.** Out of scope; this
  is ADR-011 §Q1 territory. v0.35.0 stays focused on the
  session subsystem.
- **Device fingerprinting in `SessionState`.** Capturing
  IP + User-Agent at session start would let the user's
  list page show "Chrome on macOS, 192.0.2.1". Useful but
  separable; the `SessionState` shape already has plenty of
  rationale to evolve and we didn't want to entangle two
  changes. Defer.
- **"New device" notification.** Email the user when a new
  session starts on an unrecognized device. cesauth has the
  Magic Link email plumbing but no general transactional
  email infrastructure for arbitrary "new login from X"
  notices, and adding one is its own project. Defer.
- **last_seen_at mirroring to D1.** Discussed above; rejected
  because the write amplification on the hot path is not
  worth the user-facing benefit (the list page renders
  created_at well enough).

## Open questions

- **Q1**: Per-tenant override of `session_idle_timeout_secs`.
  Currently a global env var. A future tenancy-aware setting
  could let high-security tenants tighten idle to 5 min.
  Defer to ROADMAP feature track.
- **Q2**: Revoke-all-other-sessions button on the user
  page. v0.35.0 ships per-row revoke; a "log out everywhere
  except here" button is a natural follow-up. Defer.
- **Q3**: User notification on auto-revoke (idle / absolute).
  When a user comes back to a tab and gets bounced to /login,
  it'd help to surface a flash explaining why ("session
  expired due to inactivity"). The redirect is currently
  silent. Defer to an i18n-aware flash key.
- **Q4**: D1 `user_sessions` retention. Rows accumulate
  indefinitely. A daily sweep that deletes rows where
  `revoked_at < now - retention_days` would bound the table
  size. Defer; daily cron is already wired (audit chain
  verifier + sweep) so this is a small extension when needed.

## See also

- [ADR-011: Refresh token reuse hardening](
  011-refresh-token-reuse-hardening.md) — sibling
  security-track release; same Approach 2 pattern (DO is
  authoritative; observability work happens around it).
- [Audit log hash chain](../audit-log-hash-chain.md) — the
  audit chain that captures `session_idle_timeout` and
  related events.
- RFC 9700 — OAuth 2.0 Security Best Current Practice;
  §4.13 idle vs. absolute timeout discussion.
