# Multi-environment workflow

Most cesauth deployments need at least two environments:
**production** (the one users hit) and **staging** (a near-clone
where changes are validated before they reach production). This
chapter is about how to express that in `wrangler.toml`, what
each environment should and shouldn't share, and how a typical
change flows from local → staging → production.

## Environment hierarchy

```
local (Miniflare)
    │
    │  wrangler dev
    │
    ▼
staging  (Cloudflare, dedicated D1/KV/R2/DO)
    │
    │  wrangler deploy --env staging
    │
    ▼
production (Cloudflare, dedicated D1/KV/R2/DO)
    │
    │  wrangler deploy --env production
    │
    ▼
end users
```

The cardinal rule: **no environment shares state with another**.
Staging's D1 is not production's D1. Staging's R2 audit bucket
is not production's. A change that destroys staging's data must
not be capable of destroying production's.

## `wrangler.toml` shape

The shipped `wrangler.toml` is a starting point that defines the
top-level (default) environment. To add `staging` and
`production`, append per-environment overrides:

```toml
# --- Top-level (used by `wrangler dev`, no --env flag) -------------------
name               = "cesauth"
main               = "crates/worker/build/worker/shim.mjs"
compatibility_date = "2026-04-01"
compatibility_flags = ["nodejs_compat"]

[build]
command = "cargo install -q worker-build && worker-build --release crates/worker"

# Top-level bindings — used by `wrangler dev` only. Local Miniflare
# ignores the IDs entirely.
[[d1_databases]]
binding        = "DB"
database_name  = "cesauth-local"
database_id    = "REPLACE_WITH_LOCAL_D1_ID"
migrations_dir = "migrations"

# (other top-level bindings...)

[vars]
ISSUER         = "http://localhost:8787"
JWT_KID        = "cesauth-2026-01"
WRANGLER_LOCAL = "1"   # only here, never in deployed envs

[triggers]
crons = ["0 4 * * *"]


# --- Staging environment -------------------------------------------------
[env.staging]
name = "cesauth-staging"

[[env.staging.d1_databases]]
binding        = "DB"
database_name  = "cesauth-staging"
database_id    = "REAL_STAGING_D1_UUID"
migrations_dir = "migrations"

[[env.staging.kv_namespaces]]
binding = "CACHE"
id      = "REAL_STAGING_KV_ID"

[[env.staging.r2_buckets]]
binding     = "AUDIT"
bucket_name = "cesauth-audit-staging"

[[env.staging.r2_buckets]]
binding     = "ASSETS"
bucket_name = "cesauth-assets-staging"

[[env.staging.durable_objects.bindings]]
name       = "AUTH_CHALLENGE"
class_name = "AuthChallenge"

# (other staging DOs...)

[env.staging.vars]
ISSUER             = "https://staging-auth.example.com"
JWT_KID            = "cesauth-staging-2026-01"
WEBAUTHN_RP_ID     = "staging-auth.example.com"
WEBAUTHN_RP_NAME   = "cesauth (staging)"
WEBAUTHN_RP_ORIGIN = "https://staging-auth.example.com"
WRANGLER_LOCAL     = "0"
LOG_LEVEL          = "debug"   # noisier than prod

[env.staging.triggers]
crons = ["0 4 * * *"]


# --- Production environment ---------------------------------------------
[env.production]
name = "cesauth-production"

[[env.production.d1_databases]]
binding        = "DB"
database_name  = "cesauth-prod"
database_id    = "REAL_PROD_D1_UUID"
migrations_dir = "migrations"

# (other production bindings...)

[env.production.vars]
ISSUER             = "https://auth.example.com"
JWT_KID            = "cesauth-2026-01"
WEBAUTHN_RP_ID     = "auth.example.com"
WEBAUTHN_RP_NAME   = "cesauth"
WEBAUTHN_RP_ORIGIN = "https://auth.example.com"
WRANGLER_LOCAL     = "0"
LOG_LEVEL          = "info"

[env.production.triggers]
crons = ["0 4 * * *"]
```

## Things to override per environment

Always:

- **`name`** — different Worker name per env, so the dashboard
  doesn't conflate.
- **All resource IDs** (`d1_databases`, `kv_namespaces`,
  `r2_buckets`). DO bindings can use the same `class_name`
  because DO storage is namespaced per Worker; staging and
  production end up with isolated DO instances regardless.
- **`ISSUER`** — different hostname.
- **`WEBAUTHN_RP_*`** — must match the env's actual hostname.
- **`JWT_KID`** — staging keys are different from prod keys;
  prefix the kid (`cesauth-staging-…`) so a leaked staging
  token is obviously not a prod token.

Sometimes:

- **`LOG_LEVEL`** — staging at `debug` is normal; production
  at `info` is the default.
- **`LOG_EMIT_SENSITIVE`** — almost always `"0"`. Setting `"1"`
  in staging during incident reproduction is sometimes useful;
  never in production.
- **TTLs** — usually identical; some teams shorten staging
  TTLs to surface refresh-rotation bugs faster.

Never:

- **`WRANGLER_LOCAL`** — must be `"0"` in every deployed env.
  The fallthrough behavior of `[vars]` across Wrangler versions
  is subtle; set it explicitly per env.

## Things to NOT share across environments

- **Secrets.** `wrangler secret put --env production
  JWT_SIGNING_KEY` is a separate command from
  `wrangler secret put --env staging JWT_SIGNING_KEY`. Use
  different secret values. A leaked staging signing key must
  not let an attacker forge production tokens.
- **D1 data.** Production user data must never reach staging.
  See [Backup & restore](./backup-restore.md) for the
  prod → staging refresh pattern with PII redaction.
- **R2 audit objects.** The audit trail is per-environment.
- **Custom Domain.** Each env has its own hostname and edge
  cert.

## Promotion workflow

A typical change ships through this sequence:

### 1. Local development

```sh
# Run locally with Miniflare.
wrangler dev

# Run host-side tests.
cargo test --workspace
```

The local environment uses the top-level `wrangler.toml` config.
Local D1 is a SQLite file under `.wrangler/`; local KV/R2 are
in-memory. Reset with the [Resetting between runs](../beginner/resetting.md)
chapter.

### 2. Staging deploy

```sh
# Apply migrations to staging (separate from local + prod).
wrangler d1 migrations apply cesauth-staging --env staging

# Deploy the Worker.
wrangler deploy --env staging

# Tail logs.
wrangler tail --env staging --format=pretty
```

Run smoke tests against staging:

```sh
curl -s https://staging-auth.example.com/.well-known/openid-configuration | jq .
```

If staging surfaces a problem, fix locally and redeploy to
staging. Repeat until staging is green.

### 3. Production deploy

```sh
# Apply migrations to production.
wrangler d1 migrations apply cesauth-prod --env production

# Deploy.
wrangler deploy --env production

# Smoke test.
curl -s https://auth.example.com/.well-known/openid-configuration | jq .
```

The production deploy uses the same Worker bundle as staging,
but with prod-specific bindings, secrets, and vars. If staging
worked, production should work modulo prod-specific config.

### 4. Post-deploy verification

- `wrangler tail --env production` for a few minutes.
- Cloudflare dashboard → Workers & Pages → cesauth-production
  → Analytics for the request rate, error rate, p99 latency.
- For the first hours after a deploy with schema changes,
  diagnostic queries (residual-count, audit-event-presence)
  per the [Day-2 operations runbook](./runbook.md).

## Migration ordering across environments

When a release changes the schema (a new file under
`migrations/`), apply migrations in this order:

```
local    →  apply migration during dev
staging  →  apply, then deploy worker
production → apply, then deploy worker
```

**Never deploy a worker before applying its required
migrations.** The worker may issue queries against tables that
don't exist yet, returning 500s until the migration completes.
Apply migrations first; deploy second.

The reverse — applying a migration that the deployed worker
doesn't know about — is generally safe because cesauth's
migrations are additive (CREATE TABLE IF NOT EXISTS, ADD
COLUMN, etc.). But the migration-then-deploy ordering is the
contract; document any deviation in the CHANGELOG.

## When to skip staging

Almost never. The cases where it might be reasonable:

- **Pure documentation changes** — no code, no migration.
  Staging adds nothing; deploy directly.
- **Trivial config tweaks that you've validated locally** —
  e.g., bumping `LOG_LEVEL`. Use judgment; if there's any
  doubt, go through staging.
- **Emergency security patches** — sometimes the right call
  is to deploy directly to production. Document the decision
  in the postmortem.

The case where it's **never** reasonable to skip staging:

- **Schema migrations.** A bad migration on production D1 is
  the kind of incident that costs hours of recovery. Always
  test the migration against staging first.

## Multiple production environments

Some operators run cesauth in multiple regions (EU, US, APAC)
with separate Cloudflare accounts for data-residency reasons.
Each is its own "production" environment from cesauth's
perspective: separate D1, separate R2, separate `wrangler.toml`
env block.

The complexity that adds — synchronizing schema, key rotations,
deploy timing — is significant. cesauth doesn't ship tooling
for multi-region orchestration; you'll write a deploy script
that runs `wrangler deploy --env production-eu`,
`--env production-us`, etc. in sequence and aborts on the first
failure.

## See also

- [Wrangler configuration](./wrangler.md) — the top-level
  `wrangler.toml` semantics.
- [Pre-flight checklist](./preflight.md) — the per-environment
  readiness check.
- [Backup & restore](./backup-restore.md) — the prod → staging
  refresh procedure with PII redaction.
- [Disaster recovery](./disaster-recovery.md) — what to do
  when an environment is compromised.
