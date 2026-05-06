# Session cookies

cesauth issues a signed session cookie on every successful
authentication. This chapter covers the format, signing, and
revocation model.

## Cookie

```
__Host-cesauth_session = <b64url(json-payload)>.<b64url(hmac-sha256)>

Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000
```

The `__Host-` prefix requires (per CHIPS-adjacent rules):

- `Secure` attribute set
- `Path=/`
- No `Domain` attribute

All three are enforced by the issuing code.

## Payload

```json
{
  "sid":              "<session_id, uuid>",
  "uid":              "<user_id>",
  "iat":              1715712445,
  "exp":              1718304445,
  "authenticated_at": 1715712400,
  "auth_method":      "magic_link" | "webauthn"
}
```

`iat` / `exp` are cookie-level. `authenticated_at` is the moment the
user last proved identity (updated on each `post_auth::complete_auth`
call), used by the `max_age` check in `/authorize`.

## Why HMAC-SHA256, not JWT

A session cookie does not need to be readable by a third party,
round-trippable through other systems, or support algorithm
negotiation. It needs:

1. Integrity against forgery.
2. A small, fixed wire format.
3. A straightforward rotation story.

HMAC-SHA256 with a dedicated secret (`SESSION_COOKIE_KEY`) covers
all three in a fraction of the complexity of JWT. If you rotate the
signing key, old sessions become invalid on the next `/authorize`
hit — which also happens to be the intended behavior of a key
rotation.

The `SESSION_COOKIE_KEY` is a distinct secret from
`JWT_SIGNING_KEY`. Leaking one does not compromise the other; the
two blast radii are disjoint.

## Verification

Every route that reads the session does:

```rust
let cookie   = extract_cookie("__Host-cesauth_session")?;
let (payload, sig) = split_at_dot(cookie)?;
let expected_sig = hmac_sha256(&SESSION_COOKIE_KEY, payload);
if !constant_time_eq(sig, &expected_sig) {
    return Err(SessionInvalid);
}
let s: SessionPayload = serde_json::from_slice(&b64_decode(payload))?;
if s.exp < now { return Err(SessionExpired); }
```

Signature first, then body parsing. A forged body never reaches
serde.

## Revocation

The cookie carries `sid`. The authoritative revocation check is
`ActiveSessionStore::status(sid)`, which returns one of:

- `Active(state)` — ok to proceed
- `Revoked(state)` — session was revoked; the cookie is dead
- `NotStarted` — `sid` never existed; treat as forgery

`/authorize` calls `status(sid)` on every hit. A revoked session
means `/authorize` goes to the cold path (login page), regardless
of cookie presence.

`POST /logout` calls `ActiveSessionStore::revoke(sid)` and clears the
cookie by setting `Max-Age=0`. The admin surface has `DELETE
/admin/sessions/:id` for operator-initiated revocation (phone
stolen).

## Why an unsigned pending cookie is OK

`__Host-cesauth_pending` carries a single UUID — a handle into the
`AuthChallenge` DO. No identity claims. Forging the cookie at worst
points to a handle that does not exist (or belongs to another user),
and the DO rejects the `take` because the bound IP + UA hash does
not match. Signing it would be belt-and-suspenders.

## Cookie lifecycle

| Event                              | Session cookie              | Pending cookie       |
|------------------------------------|-----------------------------|----------------------|
| Fresh browser hits `/authorize`    | —                           | Set (pending handle) |
| User authenticates                 | Set (signed, Max-Age=30d)   | Cleared              |
| Return visit, valid session        | Untouched                   | —                    |
| Return visit, revoked session      | Ignored, pending set        | Set                  |
| `POST /logout`                     | Cleared                     | Cleared              |
| Admin revokes session              | Still in browser, but `/authorize` treats as invalid | — |

## Idle timeout (v0.35.0)

In addition to the absolute lifetime above (the `expires_at`
field on the cookie), v0.35.0 adds an **idle timeout** —
configurable, default 30 minutes, env
`SESSION_IDLE_TIMEOUT_SECS`. Set to 0 to disable.

The idle gate is consulted **inside the `ActiveSession` DO's
`Touch` command**, atomic with the touch update. When
`now - last_seen_at >= idle_timeout_secs`, the DO sets
`revoked_at` and returns the new `IdleExpired` outcome rather
than `Active`. The `me::auth::resolve_or_redirect` path then
emits a `session_idle_timeout` audit event and redirects the
user to `/login`.

### Why in the DO, not the worker

A worker-side peek-then-decide opens a small race window: a
concurrent request between the peek and a follow-up revoke
could touch the session successfully against the operator's
intent. Doing the check inside the DO closes the window.

### Order of timeout gates

If a session is past **both** the idle and absolute windows
on the same `Touch`, the DO reports **`AbsoluteExpired`**
rather than `IdleExpired`. The absolute case is the deeper
cause; the audit event reflects that. Pinned by
`session_touch_absolute_takes_priority_over_idle` in
`cesauth-adapter-test::store::tests`.

### When operators tune this

- Default 30 min suits a typical AAL2 web deployment per
  NIST 800-63B §4.1.3.
- 10 min for high-security tenants.
- 0 for "trusted device" deployments where the absolute
  TTL is the only gate. Note this departs from NIST 800-63B
  guidance — document the deviation in your tenant's
  threat model.

## User-facing session list (v0.35.0)

`/me/security/sessions` renders the signed-in user's active
sessions newest-first, one card per session, with a
revoke button per non-current row.

The page is backed by a hybrid storage layout:

- The per-session `ActiveSession` DO remains source of truth
  for individual session state (touch / revoke / status).
- A D1 `user_sessions` table provides the per-user index
  the DO layout structurally can't (DOs are single-keyed;
  cross-DO iteration isn't a thing).

ADR-012 documents the design rationale.

### What gets mirrored

D1 carries: `session_id`, `user_id`, `created_at`,
`revoked_at`, `auth_method`, `client_id`. The `last_seen_at`
column is **deliberately not mirrored** — it's hot-path
mutable in the DO, and mirroring would multiply D1 write
load by request volume. The user-facing list shows
`created_at` as approximate "last activity"; if you need
precise rendering, peek the DO per-row.

### The current-session button is disabled

The session that's currently rendering the page shows a
"この端末" badge with a disabled button. Revoking the
session you're using would just self-log-the-user-out,
which is what the regular logout flow is for — making this
button live would surprise users.

### Revoke endpoint

`POST /me/security/sessions/:session_id/revoke` is
CSRF-guarded. Defenses applied:

- **CSRF check** against the session-cookie-derived MAC.
- **Self-revoke refused** with HTTP 400 ("use the logout
  flow"). The form's button is disabled for the current
  row, so this branch is defensive; submitting via curl
  hits it.
- **Ownership check** via `store.status(target_id)` —
  refuses with HTTP 403 if the target's `user_id` doesn't
  match the requester's. The page only renders the user's
  own sessions, so reaching this branch implies a UUIDv4
  forge attempt; depth-of-defense.
- **Already-revoked / never-started** returns silent
  success (302 + flash) rather than a distinct error,
  so an attacker can't probe session-id existence.

On success: revoke + `session_revoked_by_user` audit event
+ flash + redirect to `/me/security/sessions`.

## Audit events (v0.35.0)

The session lifecycle events split into:

| Event                       | Cause                                   |
|-----------------------------|-----------------------------------------|
| `session_started`           | Successful authentication               |
| `session_revoked_by_user`   | User clicked revoke on the list page    |
| `session_revoked_by_admin`  | Admin console action                    |
| `session_idle_timeout`      | Auto on touch (idle gate fired)         |
| `session_absolute_timeout`  | Auto on touch (absolute gate fired)     |
| `session_revoked` (legacy)  | Pre-v0.35.0 generic kind, retained for backward-compat with rows in the audit chain from v0.4-v0.34.x |

Operator dashboards monitoring for compromise should alert
on `session_revoked_by_admin` specifically (someone is
forcibly logging users out of the system) and on a sustained
spike in `session_idle_timeout` at unusual hours (sign of an
attacker session-walking through users' devices). The legacy
`session_revoked` kind no longer fires for these cases in
v0.35.0+ deployments.

## Caveats and operator notes

- **Existing sessions don't appear in `user_sessions`.** The
  D1 index is populated on `start`; sessions started before
  the v0.35.0 deploy aren't backfilled. Backfilling would
  require iterating the DO namespace, which Cloudflare
  doesn't support. Effect: users signed in across the
  upgrade see only post-upgrade sessions in their list page;
  pre-existing sessions remain authoritative-but-invisible
  until they expire (idle, absolute) or the user signs in
  again.
- **D1-DO eventual consistency.** A D1 hiccup during a
  revoke-mirror leaves the index out of sync with the DO.
  The user-facing list might show "active" for a session
  the DO knows is revoked. The next authenticated request
  through that session corrects it (touch returns Revoked).
  Per ADR-012 §Q1, a future release will ship a
  reconciliation tool.

## See also

- [ADR-012: Session hardening](./adr/012-sessions.md) —
  design rationale, alternatives, open questions.
- [Audit log hash chain](./audit-log-hash-chain.md) —
  the audit chain that session events flow through.
- NIST 800-63B §4.1.3 (idle timeout requirements).
- OWASP ASVS V3.3.4 (idle timeout requirements).
