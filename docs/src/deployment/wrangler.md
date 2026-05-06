# Wrangler configuration

The shipped `wrangler.toml` is production-shaped: every binding it
declares is a placeholder that you substitute with real IDs on your
first production deploy. For local dev, Miniflare ignores the IDs
entirely (see [First local run](../beginner/first-local-run.md)).

## Bindings

| Binding       | Type          | `wrangler.toml` key                 |
|---------------|---------------|-------------------------------------|
| `DB`          | D1            | `[[d1_databases]]`                  |
| `CACHE`       | KV            | `[[kv_namespaces]]`                 |
| `ASSETS`      | R2 bucket     | `[[r2_buckets]]`                    |
| `AUTH_CHALLENGE` | Durable Object | `[[durable_objects.bindings]]`   |
| `REFRESH_TOKEN_FAMILY` | DO      | `[[durable_objects.bindings]]`      |
| `ACTIVE_SESSION` | DO          | `[[durable_objects.bindings]]`      |
| `RATE_LIMIT`  | DO            | `[[durable_objects.bindings]]`      |

(v0.32.0+: the v0.31.x `AUDIT` R2 binding was removed when audit
moved to D1 with a hash chain — see ADR-010.)

Binding **names** are the contract between `wrangler.toml` and the
Rust code (`crates/adapter-cloudflare/src/ports/repo.rs` calls
`env.d1("DB")`, `env.bucket("ASSETS")`, etc.). Binding **IDs** are
the contract between Wrangler and Cloudflare's control plane — you
fill them in with `wrangler d1 create`, `wrangler kv namespace
create`, etc. output.

## Secrets in `wrangler.toml`

The secrets comment block near the top of the file is authoritative.
The set cesauth needs:

```
JWT_SIGNING_KEY           : Ed25519 PKCS#8 PEM for JWT signing.
                            openssl genpkey -algorithm ed25519 |
                              wrangler secret put JWT_SIGNING_KEY

SESSION_COOKIE_KEY        : HMAC-SHA256 key for session cookies.
                            openssl rand -base64 48 | tr -d '\n' |
                              wrangler secret put SESSION_COOKIE_KEY

ADMIN_API_KEY             : Bearer token for /admin/*.
                            openssl rand -hex 24 |
                              wrangler secret put ADMIN_API_KEY

TURNSTILE_SECRET          : Optional; server-side Turnstile secret.

MAGIC_LINK_MAIL_API_KEY   : Currently unused; read this chapter's
                            "Release gates" before deploying.
```

See [Secrets & environment variables](./secrets.md) for the
local-dev equivalent via `.dev.vars`.

## `[vars]`

`[vars]` holds non-secret config. The shipped values include:

- `ISSUER` — the `iss` claim in issued JWTs; must exactly match the
  `issuer` field in the discovery doc that clients validate against.
- `JWT_KID` — the `kid` header cesauth stamps on JWTs; must exist as
  a row in `jwt_signing_keys`.
- `ACCESS_TOKEN_TTL_SECS`, `REFRESH_TOKEN_TTL_SECS`,
  `MAGIC_LINK_TTL_SECS`, `SESSION_TTL_SECS`,
  `PENDING_AUTHORIZE_TTL_SECS`, `AUTH_CODE_TTL_SECS`.
- `LOG_LEVEL` — `trace` | `debug` | `info` | `warn` | `error`.
- `LOG_EMIT_SENSITIVE` — `"0"` or `"1"`. Default `"0"`.
- `WRANGLER_LOCAL` — `"0"` in production. MUST NOT be `"1"` on any
  deployed worker.

## Environments

Wrangler supports `[env.production]`, `[env.staging]`, etc. Each
environment overrides the top-level config. When deploying to
multiple environments:

```toml
[env.production.vars]
ISSUER             = "https://auth.example.com"
WRANGLER_LOCAL     = "0"

[[env.production.d1_databases]]
binding         = "DB"
database_name   = "cesauth-prod"
database_id     = "…real UUID…"
```

`WRANGLER_LOCAL` in particular should be explicitly set in every
deployed env, not inherited — the `inheritance=fallthrough` behavior
is subtle across Wrangler versions and explicit is safer.

## Build command

cesauth's `wrangler.toml` uses:

```toml
main = "crates/worker/build/worker/shim.mjs"

[build]
command = "cargo install -q worker-build && worker-build --release crates/worker"
```

The `crates/worker` positional argument is `worker-build`'s "crate
path" — it targets the cdylib crate. The output lands at
`<crate>/build/worker/shim.mjs` (hence the nested path in `main`).

`build/` is `.gitignore`'d unanchored, so the nested path is
covered.
