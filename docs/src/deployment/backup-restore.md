# Backup &amp; restore

cesauth's persistent state lives in three Cloudflare resources:
**D1** (relational data — users, tenants, OIDC clients,
authenticators, etc.), **R2** (audit objects + assets), and
**Durable Objects** (short-lived auth state — auth codes,
refresh-token families, active sessions, rate-limit counters).
Each has different durability and recovery characteristics.

This chapter covers how to back each up, how to restore from
those backups, and what the realistic recovery scenarios look
like.

## What's worth backing up

| Resource | Backup priority | Why |
|---|---|---|
| **D1** | **Critical** | Source of truth for users, tenants, OIDC clients, authenticators, signing keys. Loss is catastrophic. |
| **R2 audit** | **Important** | Compliance + incident forensics. Loss prevents post-incident investigation. |
| **R2 assets** | Low | Static UI assets, easily regenerated from the codebase. |
| **DO state** | **Don't bother** | Short-lived (minutes to a day). Loss only invalidates in-flight auth ceremonies; users re-auth and recover. |

Cloudflare's underlying infrastructure (replication, redundancy)
makes spontaneous data loss extremely rare. Backups exist to
recover from **operator error** (accidental delete, bad
migration, runaway script), not from infrastructure failure.

## D1 backups

### Manual export

```sh
wrangler d1 export cesauth-prod --remote \
  --output cesauth-prod-$(date +%Y%m%d).sql
```

`--remote` exports from the production D1, not the local one.
The output is a SQL dump (CREATE + INSERT statements) that
`wrangler d1 execute --file` can re-apply.

For a production deployment, run this:

- **Daily**, automated.
- **Before every production migration**, manually.
- **Before every deploy that includes schema changes**,
  manually (separate from the migration backup — the deploy
  may need to be rolled back independently).

### Automated daily backup

There's no first-class scheduled-export feature in Cloudflare
Workers (Cron Triggers run *inside* the Worker, which can't
shell out to `wrangler`). Practical options:

1. **GitHub Actions scheduled job** — a nightly cron-driven
   workflow that runs `wrangler d1 export` and uploads the
   output to R2 or to your off-Cloudflare backup target. The
   workflow needs a Cloudflare API token with D1 read
   permissions.

   ```yaml
   # .github/workflows/d1-backup.yml
   name: D1 backup
   on:
     schedule:
       - cron: '0 3 * * *'   # 03:00 UTC, before the cesauth sweep at 04:00
   jobs:
     backup:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - name: Install wrangler
           run: npm i -g wrangler
         - name: Export D1
           env:
             CLOUDFLARE_API_TOKEN: ${{ secrets.CF_API_TOKEN }}
             CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CF_ACCOUNT_ID }}
           run: |
             wrangler d1 export cesauth-prod --remote \
               --output cesauth-prod-$(date +%Y%m%d).sql
         - name: Upload to off-Cloudflare storage
           run: |
             # Upload to your backup target — S3, GCS, etc.
             # Out of scope for this chapter.
   ```

2. **Self-hosted cron + a CI runner with `wrangler`**. Same
   shape, your infrastructure.

3. **Manual only**, with calendar reminder. Acceptable for
   small deployments where automation overhead exceeds
   recovery-time-objective concerns.

The off-Cloudflare upload step is non-negotiable for
disaster-recovery scenarios that include "Cloudflare account
compromised" in their threat model. If your backups live in the
same Cloudflare account they're backing up, an account
compromise destroys both.

### Restoring D1

D1 has no "restore from backup" button. The procedure is to
apply the SQL dump against an empty database:

```sh
# 1) Create a fresh D1 (don't restore over the existing one — it
#    requires deleting+recreating, which is irreversible).
wrangler d1 create cesauth-restored

# 2) Apply the dump.
wrangler d1 execute cesauth-restored --remote \
  --file cesauth-prod-20260427.sql

# 3) Sanity-check.
wrangler d1 execute cesauth-restored --remote \
  --command="SELECT count(*) FROM users;"

# 4) Switch wrangler.toml's `database_id` to point at the
#    restored DB.
# 5) Apply any migrations the dump pre-dates.
wrangler d1 migrations apply cesauth-restored --remote

# 6) Deploy.
wrangler deploy --env production
```

Restoration is a **disruption event** — the gap between the
backup timestamp and the restore timestamp is data loss. Plan
backup frequency against your acceptable recovery-point
objective.

### Backup contents — what's there, what's not

A `wrangler d1 export` dump contains every row of every table
at the export moment. That includes:

- **`users`** with their emails (PII).
- **`oidc_clients`** with `client_secret_hash` (hash, not
  secret).
- **`authenticators`** with public-key material.
- **`jwt_signing_keys`** with the public-key half (private
  keys are NOT stored in D1 — they're in `wrangler secret`,
  see below).

The dump does NOT contain:

- **JWT private signing keys** (`wrangler secret`).
- **`SESSION_COOKIE_KEY`** or **`ADMIN_API_KEY`**
  (`wrangler secret`).
- **R2 audit objects.**
- **DO state.**

A full restore therefore requires three things in lockstep:
the D1 dump, the secrets backup (see below), and any post-dump
schema migrations.

## Secrets backups

`wrangler secret` values are write-only after they're set —
there's no API to read them back. This means **you must capture
secrets at generation time and store them somewhere safe**, or a
key-rotation event will lose them.

### Pattern: 1Password / vault as the source of truth

Generate the secret, store the canonical value in your team's
vault, then `wrangler secret put` from the vault:

```sh
# 1) Generate.
openssl genpkey -algorithm ed25519 > jwt-prod-2026-01.pem

# 2) Store in 1Password (or equivalent) under a stable name.

# 3) Push to wrangler.
cat jwt-prod-2026-01.pem | wrangler secret put JWT_SIGNING_KEY \
  --env production

# 4) Verify.
wrangler secret list --env production | grep JWT_SIGNING_KEY
```

The vault is now the single source of truth. If `wrangler
secret` ever loses the value (it shouldn't, but planning for
the worst is the point of backups), you can re-push from the
vault.

### Secret rotation mechanics

See [Secrets &amp; environment variables → Rotation](./secrets.md#rotation)
for the JWT-key, session-key, admin-key rotation procedures.
Each rotation is a backup event: the new secret value goes into
the vault before going into `wrangler`.

## R2 audit-bucket backups

R2's lifecycle rules can be configured to:

- **Replicate** to a second R2 bucket on a schedule (currently
  beta in some Cloudflare accounts).
- **Archive** to a colder tier after N days.
- **Delete** after retention expires.

For audit purposes, the conservative configuration is:

```
Hot:           first 30 days   (Standard tier)
Infrequent:    30-365 days     (IA tier, cheaper read)
Archive:       1-7 years       (Archive tier, cold)
Delete:        7+ years        (depending on jurisdiction)
```

cesauth doesn't enforce or assume any of this — the audit
writer just appends objects to the configured bucket. Lifecycle
is operator policy.

For backup-against-account-compromise scenarios, mirror to
off-Cloudflare storage:

```sh
# Pseudocode — actual implementation depends on your tooling.
rclone sync r2:cesauth-audit-prod backup:cesauth-audit-prod-mirror
```

## Restoring from compromise

The threat model: the production Cloudflare account is
compromised. An attacker has admin access to D1, R2, and
secrets. The recovery plan:

1. **Revoke the compromised credentials.** Cloudflare API
   tokens, dashboard logins.
2. **Provision a fresh Cloudflare account.** Backups must be
   restored to a different account; the compromised one is
   forfeit until forensics complete.
3. **Restore D1 from off-Cloudflare backup.** Section above.
4. **Re-generate every secret.** The old `JWT_SIGNING_KEY` is
   considered compromised — every token issued under it must
   be considered repudiable. Fresh keys, fresh `kid`, fresh
   `JWT_KID` in `wrangler.toml`.
5. **Force every user to re-authenticate.** Rotating
   `SESSION_COOKIE_KEY` invalidates all sessions; rotating
   `JWT_SIGNING_KEY` invalidates all access tokens. Both
   should rotate as part of compromise recovery.
6. **Re-deploy.** New `wrangler.toml` (with the new account's
   IDs), new secrets, the restored D1 data.
7. **Switch DNS.** The Custom Domain attaches to the new
   Worker in the new account. DNS update completes the cutover.
8. **Notify users.** Compromise of an auth provider is a
   disclosable event in most jurisdictions. Coordinate with
   counsel.

A full compromise recovery is a multi-hour to multi-day event.
Section is here so the plan exists; the detailed runbook is in
[Disaster recovery](./disaster-recovery.md).

## Production → staging refresh

A common operational need: refresh staging's data with a
sanitized snapshot of production, so QA can repro production
issues against realistic data.

**As of v0.20.0, the recommended path is `cesauth-migrate`** —
see the [Data migration](./data-migration.md) chapter. The
single command `cesauth-migrate export --profile prod-to-staging`
produces a redacted dump whose redaction is recorded in the
manifest (so the importer's later `--require-unredacted` flag
can refuse it for production-restore use cases).

The legacy `sed`-based procedure below is preserved for
operators on cesauth versions older than v0.20.0, or for
environments where `cesauth-migrate` is unavailable.

### Legacy procedure (pre-v0.20.0)

The procedure:

```sh
# 1) Export production.
wrangler d1 export cesauth-prod --remote \
  --output prod-snapshot.sql

# 2) Redact PII before importing to staging.
#    The cesauth-specific PII fields:
#    - users.email
#    - users.display_name
#    - magic_link_challenges.email_or_user
#    - audit_events (in R2, not in this dump)
#
#    Redact via sed/awk or a small script:
sed -E "s/[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/redacted-\1@example.invalid/g" \
  prod-snapshot.sql > staging-import.sql
#
#    NOTE: cesauth's email-uniqueness constraint will fail if all
#    redacted emails collapse to one value. Keep them distinct,
#    e.g. by hashing the original.

# 3) Drop staging's existing D1 contents.
#    There's no DROP DATABASE; recreate.
wrangler d1 delete cesauth-staging
wrangler d1 create cesauth-staging
#    Update wrangler.toml with the new database_id.

# 4) Import.
wrangler d1 execute cesauth-staging --remote \
  --file staging-import.sql

# 5) Apply migrations the snapshot pre-dates.
wrangler d1 migrations apply cesauth-staging --env staging
```

The redaction script is the load-bearing step. **Production
PII must never reach staging unredacted** — staging credentials
are weaker by design (debug logging, broader access), so a PII
leak via staging is an inversion of the access-control model.

## What backups don't protect against

- **Logical corruption that propagates to backups.** A bug
  that incorrectly deletes rows; the next day's backup
  captures the deleted state. Mitigate with multi-day backup
  retention.
- **Compromise of the backup destination.** Off-site backups
  in your AWS account don't help if your AWS account is also
  compromised.
- **Encryption-key loss.** If you encrypt backups (which you
  should, especially for off-Cloudflare destinations) and lose
  the key, the backup is unrecoverable.

The general defense: **multiple independent backup destinations
with different access paths**. cesauth doesn't prescribe a
specific architecture; this is operator territory.

## Cross-account moves — see `cesauth-migrate`

The procedures above cover **same-account** backup and restore.
For **cross-account** moves (M&A events, regional separation,
isolating a compromised account, operator preference shifts), the
dedicated `cesauth-migrate` CLI is now the right tool. Real
export and verify ship in v0.20.0; real import lands in
v0.21.0. See the [Data migration](./data-migration.md) chapter
for the operator-facing walkthrough; ADR-005 covers the design.

The hand-rolled `sed` script for production → staging email
redaction sketched earlier in this chapter is **obsolete as of
v0.20.0** — `cesauth-migrate export --profile prod-to-staging`
does the same thing properly, with the redaction recorded in
the dump's manifest so the importer knows what was scrubbed.

## See also

- [Pre-flight checklist § K](./preflight.md#k---backup-baseline)
- [Disaster recovery](./disaster-recovery.md) — the
  operational walkthrough for the compromise scenario.
- [Multi-environment workflow → Production → staging refresh](./environments.md)
