# Authorization Code + PKCE

## Endpoint

```
GET /authorize
```

## Parameters

| Name                     | Required       | Notes                                    |
|--------------------------|----------------|------------------------------------------|
| `response_type`          | yes            | Must be `code`                           |
| `client_id`              | yes            | Must exist in `oidc_clients`             |
| `redirect_uri`           | yes            | Must be in `oidc_clients.redirect_uris`  |
| `scope`                  | yes            | Subset of `oidc_clients.allowed_scopes`  |
| `state`                  | recommended    | Echoed back on the callback              |
| `nonce`                  | required for OIDC | Embedded in the ID token              |
| `code_challenge`         | yes (PKCE)     | Base64url, 43–128 chars                  |
| `code_challenge_method`  | yes (PKCE)     | `S256` only (`plain` rejected)           |
| `prompt`                 | no             | `none` or `login`. `consent` / `select_account` are rejected. |
| `max_age`                | no             | Force reauth if session is older         |

## Flow

```
/authorize hit
    │
    ├── validate AR (client exists, redirect_uri whitelisted, scope allowed,
    │                PKCE present, prompt/max_age understood)
    │
    ├── read __Host-cesauth_session cookie → check ActiveSessionStore.status
    │
    ├─ if session is Active AND satisfies max_age AND prompt ≠ login:
    │    ├── mint AuthCode, put into AuthChallenge DO
    │    ├── 302 to redirect_uri?code=...&state=...
    │    └── DONE
    │
    └─ else (cold path):
         ├── create Challenge::PendingAuthorize, put into AuthChallenge DO
         ├── set __Host-cesauth_pending=<handle> cookie
         ├── render the login page (200 OK)
         └── (user authenticates via magic link or passkey;
              `post_auth::complete_auth` takes the parked AR,
              mints the code, and 302s to redirect_uri)
```

## Validation outcomes

Errors observable before `redirect_uri` is validated return an
HTML error page (not a redirect — RFC 6749 §3.1.2.6). Errors
observable after validation are returned as
`redirect_uri?error=<code>&state=<state>`.

| Observable error                 | Mapping                                   |
|----------------------------------|-------------------------------------------|
| Missing / unknown `client_id`    | HTML error, status 400                    |
| `redirect_uri` not whitelisted   | HTML error, status 400                    |
| `response_type` ≠ `code`         | 302 to error redirect with `unsupported_response_type` |
| Missing / unsupported PKCE       | 302 error redirect with `invalid_request` |
| Scope outside whitelist          | 302 error redirect with `invalid_scope`   |
| `prompt=none` + session stale    | 302 error redirect with `login_required`  |
| `prompt=consent`/`select_account`| 302 error redirect with `invalid_request` |

## Session short-circuit

When a logged-in user bounces back to `/authorize` from a new client,
cesauth skips the login page entirely if three conditions hold:

1. The `__Host-cesauth_session` cookie verifies against
   `SESSION_COOKIE_KEY`.
2. `ActiveSessionStore::status(session_id)` returns `Active`.
3. `session.authenticated_at + max_age >= now`, if `max_age` is
   given.

If so, `post_auth::complete_auth` runs on the parked AR directly,
mints a code, and returns a 302. The user sees an instant redirect.

When `prompt=login` is specified the short-circuit is skipped on
purpose: the client is telling cesauth to force fresh
authentication.

## Why `__Host-cesauth_pending` is unsigned

The pending cookie carries a single UUID — a handle into the
`AuthChallenge` DO. The DO entry is what actually carries the AR.
Even if an attacker forges or substitutes the cookie, the worst case
is they point at a handle that does not exist (or belongs to
someone else) — and the DO rejects `take` on a handle whose bound
IP / user-agent hash does not match. Signing the handle itself
would add a second layer of verification for a value that is
already bound server-side.

The session cookie, by contrast, is signed: it carries user identity
claims directly, so forgery there would let an attacker assume a
session. See [Session cookies](./sessions.md).
