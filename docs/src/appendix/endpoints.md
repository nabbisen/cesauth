# Endpoint reference

## OIDC

| Method | Path                                   | Purpose                             |
|--------|----------------------------------------|-------------------------------------|
| GET    | `/.well-known/openid-configuration`    | Discovery document                  |
| GET    | `/jwks.json`                           | Public keys (EdDSA)                 |
| GET    | `/authorize`                           | Authorization Code + PKCE start     |
| POST   | `/token`                               | Code exchange + refresh rotation    |
| POST   | `/revoke`                              | Token revocation (RFC 7009)         |

## Authentication

| Method | Path                                   | Purpose                             |
|--------|----------------------------------------|-------------------------------------|
| POST   | `/webauthn/register/start`             | Begin registration ceremony         |
| POST   | `/webauthn/register/finish`            | Complete registration               |
| POST   | `/webauthn/authenticate/start`         | Begin authentication ceremony       |
| POST   | `/webauthn/authenticate/finish`        | Complete authentication             |
| POST   | `/magic-link/request`                  | Request email OTP                   |
| POST   | `/magic-link/verify`                   | Verify OTP                          |

## Session

| Method | Path                                   | Purpose                             |
|--------|----------------------------------------|-------------------------------------|
| GET    | `/login`                               | Login page (renders HTML form)      |
| POST   | `/logout`                              | Revoke current session, clear cookies|

## Admin (bearer auth)

| Method | Path                                   | Purpose                             |
|--------|----------------------------------------|-------------------------------------|
| POST   | `/admin/users`                         | Create a user                       |
| DELETE | `/admin/sessions/:id`                  | Revoke a session                    |

## Dev only (WRANGLER_LOCAL="1")

| Method | Path                                   | Purpose                             |
|--------|----------------------------------------|-------------------------------------|
| GET    | `/__dev/audit`                         | List audit R2 objects               |
| POST   | `/__dev/stage-auth-code/:handle`       | Stage a raw `AuthCode` challenge    |

Both return 404 unless `WRANGLER_LOCAL` is exactly `"1"`. Production
deploys MUST NOT set this.
