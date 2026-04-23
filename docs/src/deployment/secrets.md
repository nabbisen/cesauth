# Secrets & environment variables

cesauth has two parallel secret stores:

| Where           | When                    | Tooling               |
|-----------------|-------------------------|-----------------------|
| `.dev.vars`     | Local development       | text file, git-ignored |
| Cloudflare side | `wrangler deploy` target | `wrangler secret put` |

Both are read via the same `env.secret("NAME")` call in the Worker.
Neither file nor API distinguishes which backed the value.

## `.dev.vars` (local)

Lives at the repo root. Dotenv syntax:

```
# Comments are fine
JWT_SIGNING_KEY="-----BEGIN PRIVATE KEY-----
MC4CAQ...==
-----END PRIVATE KEY-----
"

SESSION_COOKIE_KEY="<base64 random>"

ADMIN_API_KEY="dev-admin-secret-change-me"

WRANGLER_LOCAL="1"
LOG_LEVEL="debug"
LOG_EMIT_SENSITIVE="1"
```

Wrangler/Miniflare uses `dotenv` v15+, which supports real newlines
inside double quotes. An older shell write-path that produces `\n`
escapes also works because `load_signing_key` in
`crates/worker/src/config.rs` normalizes both forms.

`.dev.vars` is listed in `.gitignore`. Never commit it.

## `wrangler secret put` (production)

```sh
openssl genpkey -algorithm ed25519 | wrangler secret put JWT_SIGNING_KEY
openssl rand -base64 48 | tr -d '\n' | wrangler secret put SESSION_COOKIE_KEY
openssl rand -hex 24 | wrangler secret put ADMIN_API_KEY
```

For multi-environment deploys, target explicitly:

```sh
wrangler secret put JWT_SIGNING_KEY --env production
wrangler secret put JWT_SIGNING_KEY --env staging
```

Secrets are stored encrypted on Cloudflare's side and are not
readable back. To rotate, put a new value; the old one is
overwritten atomically.

## The full secret inventory

| Name                      | Required | Used for                                          |
|---------------------------|----------|---------------------------------------------------|
| `JWT_SIGNING_KEY`         | yes      | Signing access + ID tokens                        |
| `SESSION_COOKIE_KEY`      | yes      | HMAC-signing session cookies                      |
| `ADMIN_API_KEY`           | yes      | Bearer for `/admin/*` (set empty string to disable admin surface) |
| `TURNSTILE_SECRET`        | no       | Siteverify call                                   |
| `MAGIC_LINK_MAIL_API_KEY` | no*      | Mail provider API key (real delivery, still TODO)|

*`MAGIC_LINK_MAIL_API_KEY` is not yet consumed in this build. See
[Security → Pre-production release gates](../expert/security.md).

## The full `[vars]` inventory

| Name                         | Default             | Meaning                                   |
|------------------------------|---------------------|-------------------------------------------|
| `ISSUER`                     | `https://auth.example.com` | Must match the discovery doc's `issuer` |
| `JWT_KID`                    | `cesauth-2026-01`   | Stamped on every issued JWT               |
| `ACCESS_TOKEN_TTL_SECS`      | `600`               | JWT `exp` offset                          |
| `REFRESH_TOKEN_TTL_SECS`     | `2592000`           | Refresh family lifetime                   |
| `MAGIC_LINK_TTL_SECS`        | `600`               | OTP validity                              |
| `SESSION_TTL_SECS`           | `2592000`           | Session cookie lifetime                   |
| `PENDING_AUTHORIZE_TTL_SECS` | `300`               | `/authorize` cold-path park               |
| `AUTH_CODE_TTL_SECS`         | `300`               | Auth-code validity                        |
| `RP_ID`                      | `auth.example.com`  | WebAuthn RP ID                            |
| `RP_NAME`                    | `cesauth demo`      | Displayed during passkey registration     |
| `RP_ORIGIN`                  | `https://auth.example.com` | WebAuthn origin check             |
| `TURNSTILE_SITEKEY`          | (empty)             | Public sitekey for the widget             |
| `LOG_LEVEL`                  | `info`              | `trace` / `debug` / `info` / `warn` / `error` |
| `LOG_EMIT_SENSITIVE`         | `0`                 | Gates Auth/Session/Crypto log categories  |
| `WRANGLER_LOCAL`             | `0`                 | MUST be `0` in any deployed environment   |

## Rotation

**JWT signing key** rotation is the most operationally complex:

1. Generate the new key locally; compute its base64url public form.
2. Insert the new row in `jwt_signing_keys` (with `retired_at NULL`).
3. `wrangler secret put JWT_SIGNING_KEY` with the new PEM.
4. Update `JWT_KID` in `wrangler.toml` `[vars]` to the new kid.
5. `wrangler deploy`.
6. After the grace window (at least one `REFRESH_TOKEN_TTL_SECS`),
   mark the old kid retired:
   ```sh
   wrangler d1 execute cesauth --command \
     "UPDATE jwt_signing_keys SET retired_at=strftime('%s','now') WHERE kid='<old>';"
   ```
   JWKS will continue to serve the retired key until clients have
   rotated through it.

**Session key** rotation is simpler: `wrangler secret put
SESSION_COOKIE_KEY` invalidates all sessions on the next
`/authorize` hit. Do it intentionally; it is a global sign-out.

**Admin key** rotation: `wrangler secret put ADMIN_API_KEY`. Any
in-flight admin API clients must be updated simultaneously.
