# Migrating from local to production

Your local setup has run end-to-end. This chapter covers what
changes when you point cesauth at real Cloudflare resources.

> **Read the [TERMS_OF_USE.md](https://github.com/…/cesauth/blob/main/TERMS_OF_USE.md)
> before proceeding.** cesauth binds you to Cloudflare's Terms of
> Service and Acceptable Use Policy; deploying is your agreement
> to operate within them.

This chapter is the **first-deploy walkthrough**. For ongoing
operation, the rest of the Deployment section has dedicated
chapters:

- [Pre-flight checklist](./preflight.md) — the consolidated
  "did I forget anything" before going live.
- [Cron Triggers](./cron-triggers.md) — required for the
  v0.18.0 anonymous-trial sweep.
- [Custom domains & DNS](./custom-domains.md) — `ISSUER`
  consistency rules, Custom Domain vs Route.
- [Multi-environment workflow](./environments.md) — staging
  → production promotion.
- [Backup & restore](./backup-restore.md), [Observability](./observability.md),
  [Day-2 operations runbook](./runbook.md), [Disaster recovery](./disaster-recovery.md).

Read this chapter once. Then bookmark the runbook and the
pre-flight checklist for the operator-facing day-to-day.

## Step 1 — Provision real resources

```sh
# D1
wrangler d1 create cesauth-prod
# → copy the database_id into wrangler.toml under [[d1_databases]]

# KV
wrangler kv namespace create CACHE
# → copy the id

# R2
wrangler r2 bucket create cesauth-audit-prod
wrangler r2 bucket create cesauth-assets-prod
# → copy the bucket_name values

# Durable Objects don't need create — the four classes are declared
# in wrangler.toml and provisioned on first deploy.
```

## Step 2 — Apply migrations remotely

```sh
wrangler d1 migrations apply cesauth-prod
# no --local flag
```

This talks to the Cloudflare control plane and applies
`migrations/0001_initial.sql` against the remote D1.

## Step 3 — Seed production rows

Only the first deploy needs this. For every environment:

```sh
# Register the production signing key's public half
PUBKEY_B64URL=…  # extract from your production JWT_SIGNING_KEY
wrangler d1 execute cesauth-prod --command "
  INSERT INTO jwt_signing_keys (kid, public_key, alg, created_at, retired_at)
  VALUES ('cesauth-prod-2026-01', '$PUBKEY_B64URL', 'EdDSA', strftime('%s','now'), NULL);
"

# Your real OIDC clients (replace demo-cli with production values)
wrangler d1 execute cesauth-prod --command "
  INSERT INTO oidc_clients (…) VALUES (…);
"
```

## Step 4 — Set production secrets

```sh
# Fresh signing key — don't reuse the local one
openssl genpkey -algorithm ed25519 |
  wrangler secret put JWT_SIGNING_KEY

# Fresh session key
openssl rand -base64 48 | tr -d '\n' |
  wrangler secret put SESSION_COOKIE_KEY

# Fresh admin key — at least 32 bytes of entropy
openssl rand -hex 24 |
  wrangler secret put ADMIN_API_KEY

# Optional: Turnstile
wrangler secret put TURNSTILE_SECRET
```

## Step 5 — Confirm `WRANGLER_LOCAL` is off

```toml
# wrangler.toml

[vars]
WRANGLER_LOCAL = "0"

# If you use environments:
[env.production.vars]
WRANGLER_LOCAL = "0"   # explicit, don't rely on inheritance
```

`WRANGLER_LOCAL="1"` in production would expose `/__dev/audit` and
`/__dev/stage-auth-code` on the public surface. This is catastrophic.

## Step 6 — Remove the Magic Link dev-delivery line

Currently `routes::magic_link::request` writes the plaintext OTP
into the audit log with `reason = "dev-delivery handle=… code=…"`.
This is a **release gate**. Before the first production deploy:

1. Implement a real mail provider call (Resend, Postmark,
   SendGrid, whatever you prefer) keyed by
   `MAGIC_LINK_MAIL_API_KEY`.
2. Replace the `dev-delivery` audit line with a real mail-sent
   audit event.
3. Stop writing the OTP plaintext anywhere except into the email
   body.

## Step 7 — Verify dependencies

Before deploying, confirm the dependency tree has no known CVEs.
The `audit.yml` GitHub Actions workflow does this on every push
and PR (and weekly via cron), but a local run before a manual
deploy gives a final check against the latest advisory database:

```sh
cargo install cargo-audit   # one-time, on each maintainer's machine
cd /path/to/cesauth
cargo audit
```

Expected output is `Success No vulnerable packages found`. If
the run reports findings, **stop and triage** before deploying:

- Check whether the affected crate is actually exercised by
  cesauth code paths (a transitive dep we don't call may be
  fine to ship while the upstream cuts a fix).
- Narrow `Cargo.toml` features if the dep is pulled in by a
  feature we don't need (this is how `rsa` was dropped from
  the tree — see CHANGELOG `[0.15.1]`).
- If neither applies, file the upgrade and re-run.
- Last resort: add the advisory id to `.cargo/audit.toml`
  with a one-line justification. Do not silently ignore.

## Step 7.5 — Configure Cron Triggers

The v0.18.0 anonymous-trial retention sweep requires the
`[triggers]` block in `wrangler.toml`. Without it, the
scheduled handler ships in the binary but Cloudflare never
invokes it, and anonymous users accumulate indefinitely.

```toml
# Append to wrangler.toml:
[triggers]
crons = ["0 4 * * *"]
```

Full chapter: [Cron Triggers](./cron-triggers.md).

## Step 8 — Deploy

```sh
wrangler deploy
# or for env-specific:
wrangler deploy --env production
```

Then smoke-test:

```sh
curl -s https://auth.example.com/.well-known/openid-configuration | jq .
curl -s https://auth.example.com/jwks.json | jq .
```

The discovery doc `issuer` should match `ISSUER` in `wrangler.toml`
exactly. If not, every token cesauth issues will fail validation
at the client.

## Step 9 — Monitor

- `wrangler tail --format=pretty` streams structured logs for the
  currently-deployed Worker. Use categories to filter.
- Cloudflare's Analytics tab tracks request rates, error rates,
  and p50/p95/p99 latency.
- The R2 audit bucket grows by one object per security-relevant
  event. Lifecycle rules (e.g., tier to Infrequent Access after 30
  days) are configured on the R2 bucket, not in cesauth.

## Rolling back

`wrangler rollback` reverts to the previous deployment. D1 schema
changes in `migrations/` are forward-only, so a rollback of the
Worker must be paired with a migration rollback plan if the schema
changed between versions. Add a `0002_rollback_something.sql` if
you need to undo a change; `wrangler d1 migrations apply` runs each
numbered migration in order.

For more involved recovery scenarios (bad migration, account
compromise, key loss, region outage), see
[Disaster recovery](./disaster-recovery.md).
