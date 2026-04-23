# First local run

By the end of this chapter `wrangler dev` will be serving cesauth on
`http://localhost:8787` against Miniflare's in-process simulation of
D1, KV, R2, and Durable Objects.

## Why no `wrangler d1 create`?

Wrangler v3 runs locally by default. `wrangler dev` boots Miniflare,
which simulates the Cloudflare stack on disk under
`.wrangler/state/`. **Local development does not need `wrangler d1
create`, `wrangler kv namespace create`, or `wrangler r2 bucket
create`** — those commands call the Cloudflare REST API to provision
real production resources.

For local dev, all you need is a `wrangler.toml` whose bindings name
the resources. Miniflare creates each local instance the first time
it sees the binding. The shipped `wrangler.toml` already declares
all four storage bindings (`DB`, `CACHE`, `AUDIT`, `ASSETS`) plus
the four Durable Object classes.

The `database_id` and `id` placeholders in `wrangler.toml` (e.g.
`REPLACE_WITH_D1_DATABASE_ID`) are required by Wrangler's schema
even for local dev, but their values are ignored — Miniflare matches
by binding name. Leave the placeholders as-is for local-only work.
Real UUIDs only matter at `wrangler deploy` time.

## Step 1 — Apply the D1 migrations

```sh
wrangler d1 migrations apply cesauth --local
```

This creates the local D1 instance on first run and applies
`migrations/0001_initial.sql`. You should see:

```
Migrations to be applied:
┌─────────────────────┐
│ name                │
├─────────────────────┤
│ 0001_initial.sql    │
└─────────────────────┘
✔ Applied 1 migration(s)
```

> **`--local` is load-bearing.** Without it, the command defaults to
> applying against your **remote production** database (which, for a
> local-only setup, does not exist and triggers an OAuth flow). The
> same applies to every `wrangler d1 execute`, `kv key put`, and
> `r2 object get/put/delete` command for the rest of this guide.

## Step 2 — Generate secrets

cesauth needs three secrets:

| Secret               | Used for                                           |
|----------------------|----------------------------------------------------|
| `JWT_SIGNING_KEY`    | Signing access + ID tokens (Ed25519 PKCS#8 PEM)    |
| `SESSION_COOKIE_KEY` | HMAC-signing session cookies on successful auth    |
| `ADMIN_API_KEY`      | Bearer token for `/admin/*`                        |

Locally they all live in `.dev.vars`, which `wrangler dev` reads at
boot. Production uses `wrangler secret put`.

```sh
# JWT signing key (Ed25519).
openssl genpkey -algorithm ed25519 -out /tmp/cesauth-jwt.pem

# Write the PEM as a multi-line double-quoted value. dotenv v15+
# (what wrangler/miniflare uses) supports real newlines inside
# double quotes, so no escaping needed.
{
  printf 'JWT_SIGNING_KEY="'
  cat /tmp/cesauth-jwt.pem
  printf '"\n'
} >> .dev.vars

# Session cookie HMAC key. 32+ bytes recommended; the worker rejects
# anything shorter than 16.
echo "SESSION_COOKIE_KEY=\"$(openssl rand -base64 48 | tr -d '\n')\"" >> .dev.vars

# Admin API key (the OIDC flow chapter uses it).
echo 'ADMIN_API_KEY="dev-admin-secret-change-me"' >> .dev.vars
```

> **Why `.dev.vars` and not `wrangler secret put`?** `wrangler secret
> put` stores secrets on the Cloudflare side — it is the production
> path. For local dev, `.dev.vars` is read once at boot and never
> leaves your machine. `.gitignore` already excludes it.

## Step 3 — Register the public half of the signing key

cesauth's `/jwks.json` endpoint reads the public keys from D1's
`jwt_signing_keys` table. Extract and register:

```sh
PUBKEY_B64URL=$(
  openssl pkey -in /tmp/cesauth-jwt.pem -pubout -outform DER |
  tail -c 32 |
  base64 | tr '+/' '-_' | tr -d '=\n'
)

wrangler d1 execute cesauth --local --command "
  INSERT INTO jwt_signing_keys (kid, public_key, alg, created_at, retired_at)
  VALUES ('cesauth-2026-01', '$PUBKEY_B64URL', 'EdDSA', strftime('%s','now'), NULL);
"
```

The `kid` value must match the `JWT_KID` var in `wrangler.toml`.

## Step 4 — Seed an OIDC client

`/authorize` and `/token` both consult `oidc_clients`. Insert a
public PKCE-only client for the tutorial:

```sh
wrangler d1 execute cesauth --local --command "
  INSERT INTO oidc_clients (
    id, name, client_type, client_secret_hash,
    redirect_uris, allowed_scopes, token_auth_method,
    require_pkce, created_at, updated_at
  ) VALUES (
    'demo-cli',
    'Demo CLI client',
    'public',
    NULL,
    '[\"http://localhost:8787/callback\"]',
    '[\"openid\",\"profile\",\"email\"]',
    'none',
    1,
    strftime('%s','now'),
    strftime('%s','now')
  );
"
```

## Step 5 — Enable the dev-only routes

The next chapter uses two helper endpoints that exist only in dev mode
and return 404 in production:

- `GET /__dev/audit` — lists audit-log objects (an in-worker
  replacement for the non-existent `wrangler r2 object list`).
- `POST /__dev/stage-auth-code/:handle` — stages a raw auth-code
  challenge so `/token` can be exercised without a browser cookie jar.

Both are gated behind `WRANGLER_LOCAL="1"`:

```sh
grep -q WRANGLER_LOCAL .dev.vars 2>/dev/null \
  || echo 'WRANGLER_LOCAL="1"' >> .dev.vars
```

> **Production deploys MUST NOT set `WRANGLER_LOCAL`.** `.dev.vars` is
> local-only. Production config lives in `wrangler.toml` `[vars]`
> (shipped with `WRANGLER_LOCAL = "0"`) and `wrangler secret put`.

## Step 6 — Start the Worker

```sh
wrangler dev
```

Wrangler compiles the Rust code via `worker-build`, boots Miniflare,
and binds the Worker to `http://localhost:8787`. Leave this running;
open a second terminal for everything else.

> **After editing `.dev.vars`, restart `wrangler dev`.** The file is
> read once at boot. A stale value for `WRANGLER_LOCAL` is the usual
> cause of surprise 404s from the dev routes.

## Step 7 — Sanity checks

```sh
curl -s http://localhost:8787/.well-known/openid-configuration | jq .
```

Expected (trimmed):

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "jwks_uri": "https://auth.example.com/jwks.json",
  "response_types_supported": ["code"],
  "id_token_signing_alg_values_supported": ["EdDSA"],
  "code_challenge_methods_supported": ["S256"]
}
```

The `issuer` value is whatever you put in `wrangler.toml`; the
`host` in your curl does not need to match.

Confirm the dev surface is on:

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8787/__dev/audit
# 200   -> good
# 404   -> WRANGLER_LOCAL is unset or not exactly "1"; check .dev.vars
#          and restart wrangler dev.
```

When both return what you expect, continue to the [next
chapter](./first-oidc-flow.md) — a curl walkthrough of a complete
OIDC flow.
