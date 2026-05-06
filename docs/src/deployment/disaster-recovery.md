# Disaster recovery

This chapter is for the worst-case scenarios — production is
broken, restoring from backup, account compromise, signing key
loss. The [Day-2 operations runbook](./runbook.md) covers
routine incident response; this is the page that takes over when
routine isn't enough.

DR procedures should be **drilled at least annually**. The first
time you walk through one of these scenarios should not be
during the actual incident.

## Recovery objectives

Every operator should pick concrete RPO and RTO targets and
write them down. cesauth-specific suggestions:

| Scenario | Suggested RPO | Suggested RTO |
|---|---|---|
| Bad deploy (rollback) | 0 (no data loss) | < 15 min |
| Schema-migration failure | 0 | < 1 hour |
| D1 corruption | < 24 hours | < 4 hours |
| Cloudflare account compromise | < 24 hours | < 12 hours |
| Region-wide Cloudflare outage | n/a | service down until restored |
| Signing key loss | 0 (data preserved) | < 4 hours (key rotation grace) |

These are starting points — your business needs may push tighter
or looser. The numbers drive backup frequency, off-site backup
locations, and on-call staffing.

## Scenario 1 — Bad deploy

**Symptom**: 5xx spike, users can't authenticate, recent deploy
in the suspect window.

**Recovery**:

```sh
# Roll back to the previous version.
wrangler rollback --env production
# Wait ~30 seconds for propagation. Smoke-test:
curl -sS https://auth.example.com/.well-known/openid-configuration \
  | jq -r .issuer
```

**Caveats**:

- If the bad deploy included a **schema migration**, rollback
  of the Worker alone may leave the Worker running against a
  newer-than-it-knows schema. cesauth's migrations are
  designed to be additive, so this should be safe (the
  Worker won't break if the schema has extra columns it
  doesn't know about). But verify against your specific
  migration.
- If the rollback target version itself had a known issue,
  pick an older version: `wrangler deployments list --env
  production` shows the history.
- After rollback, **do not redeploy the bad version** until
  the regression is fixed and tested in staging.

## Scenario 2 — Bad migration

**Symptom**: a `wrangler d1 migrations apply` ran against
production and broke something. Could be: dropped a column the
Worker still queries; introduced a constraint that data violates;
backfilled with wrong values.

**Recovery posture**: D1 migrations are forward-only. There's no
"undo" command. The recovery options, in order of preference:

### Option A — forward-fix migration

If the migration introduced a fixable error (e.g., a column
type that's wrong), write a follow-up migration that corrects
it:

```sh
# Author migrations/0007_fix_thing.sql with the corrective DDL.
wrangler d1 migrations apply cesauth-prod --remote
```

This is preferred when the bad migration didn't lose data.

### Option B — Restore from pre-migration backup

If the migration lost data (an unintended `DROP COLUMN` or a
backfill that overwrote rows):

```sh
# 1) Find the most recent pre-migration backup.
ls cesauth-prod-*.sql

# 2) Identify the tables that lost data.

# 3) Selectively re-import only the affected rows from the
#    backup into a temporary table:
wrangler d1 create cesauth-recovery
wrangler d1 execute cesauth-recovery --remote \
  --file cesauth-prod-pre-migration.sql

# 4) Copy the recovered rows back into production.
#    (D1 doesn't support cross-database SELECT — you'll
#    extract rows as SQL and apply.)
```

This is operator-script-heavy. Test the procedure against
staging first.

### Option C — Full restore

If the migration is irrecoverable:

1. Take production offline (route the Custom Domain to a
   maintenance page; or remove the domain entirely).
2. Restore D1 from pre-migration backup into a fresh
   database (see [Backup & restore →
   Restoring D1](./backup-restore.md#restoring-d1)).
3. Reapply only the migrations you actually want.
4. Re-deploy the Worker pointing at the restored DB.
5. Bring production back online.

Window of unavailability: minutes to hours depending on data
volume. Communicate.

### Prevention

The next time someone proposes a non-trivial migration:

- Test on staging first (it's in the [Multi-environment
  workflow](./environments.md) for a reason).
- Take a backup immediately before applying.
- Have a forward-fix migration drafted before applying.
- Schedule for low-traffic hours.

## Scenario 3 — D1 corruption

**Symptom**: queries return inconsistent results, or D1
returns errors for valid queries, with no recent operator
action that would explain it.

This is rare but possible. Cloudflare's underlying replication
should prevent it; when it happens, it's almost always
operator-action-induced (a script that ran rampant) rather
than infrastructure failure.

**Recovery**:

1. **Stop write traffic.** Take the Worker offline or set the
   `MAINTENANCE_MODE` flag (cesauth doesn't currently ship
   one — if this matters, file a feature request).
2. **Snapshot the corrupted state.** Even corrupted, the
   current state is forensic evidence; export it before
   restoring over it:
   ```sh
   wrangler d1 export cesauth-prod --remote \
     --output cesauth-corrupted-$(date +%Y%m%dT%H%M).sql
   ```
3. **Restore from the most recent clean backup.** See
   [Backup & restore](./backup-restore.md).
4. **Audit the gap.** Between the backup timestamp and
   "now", what data is lost? cesauth's audit log (R2) helps
   reconstruct: every meaningful state change emitted an
   audit event, so you can replay events from the audit log
   to recover the missing state.
5. **Resume traffic.**
6. **Postmortem the cause.** D1 doesn't corrupt itself; what
   ran?

## Scenario 4 — Cloudflare account compromise

**Symptom**: an attacker has admin credentials for the
Cloudflare account hosting cesauth.

**Recovery**: see [Backup & restore → Restoring from
compromise](./backup-restore.md#restoring-from-compromise) for
the detailed walkthrough. The high-level shape:

1. Revoke compromised credentials.
2. Provision a fresh Cloudflare account.
3. Restore D1 from off-Cloudflare backup.
4. Regenerate every secret.
5. Re-deploy.
6. Switch DNS.
7. Force every user to re-auth.
8. Notify users.

This is a multi-day operation. Practice the steps in advance
on staging — particularly the DNS cutover and the secret
regeneration.

## Scenario 5 — Region-wide Cloudflare outage

**Symptom**: cesauth is unreachable; Cloudflare's status page
shows widespread issues.

**Recovery**: nothing direct. cesauth is a Cloudflare-native
service; Cloudflare-side outage means cesauth is down. Options:

1. **Wait it out.** Cloudflare's outages are typically
   resolved within hours.
2. **Communicate.** Update your status channel; tell users.
3. **Plan ahead** if Cloudflare-coupling is a deal-breaker.
   cesauth is designed for the Workers runtime; running on
   any other platform is a port, not a switch.

## Scenario 6 — JWT signing key compromise

**Symptom**: the production `JWT_SIGNING_KEY` value has been
exposed (committed to a public repo, shared in a screen-share,
etc.).

**Recovery**: every JWT issued under the compromised key is
forgeable by the attacker. Treat all such tokens as
repudiable.

```sh
# 1) Generate fresh key, fresh kid.
openssl genpkey -algorithm ed25519 > new-jwt.pem

# 2) Insert new row into jwt_signing_keys with the new
#    public-key half.
wrangler d1 execute cesauth-prod --remote --command="\
INSERT INTO jwt_signing_keys (kid, public_key, created_at, retired_at) \
VALUES ('cesauth-2026-emergency', 'BASE64URL_PUBLIC_KEY', \
        unixepoch(), NULL);"

# 3) wrangler secret put JWT_SIGNING_KEY (new private key).
cat new-jwt.pem | wrangler secret put JWT_SIGNING_KEY \
  --env production

# 4) Update [vars] JWT_KID to the new kid.
# 5) wrangler deploy.

# 6) Mark the old kid as retired IMMEDIATELY. Do NOT use the
#    normal grace window — those tokens are repudiable.
wrangler d1 execute cesauth-prod --remote --command="\
UPDATE jwt_signing_keys SET retired_at=unixepoch() \
WHERE kid='cesauth-OLD-COMPROMISED';"

# 7) Force re-authentication: rotate SESSION_COOKIE_KEY too.
openssl rand -base64 48 | tr -d '\n' \
  | wrangler secret put SESSION_COOKIE_KEY --env production
wrangler deploy

# 8) Communicate. Users will re-authenticate; clients will
#    refresh JWTs against the new key.
```

The reason for IMMEDIATELY retiring (not grace-window
retiring) is that the attacker can mint forged tokens with
the leaked private key indefinitely while it's still in JWKS.

## Scenario 7 — Lost JWT signing key

**Symptom**: the production `JWT_SIGNING_KEY` value is gone.
Maybe the operator who generated it left without vaulting it,
or the vault was deleted.

**Recovery**: cesauth can't recover the private key —
`wrangler secret` is write-only; D1 only stores public-key
halves. The recovery is forced rotation:

```sh
# 1) Generate a new key. Vault the new key.
# 2) Insert new row.
# 3) wrangler secret put.
# 4) Update [vars] JWT_KID.
# 5) wrangler deploy.

# Tokens issued under the lost kid are still being verified
# by clients that have the old public key cached. Those tokens
# expire normally (within ACCESS_TOKEN_TTL_SECS for access
# tokens; within REFRESH_TOKEN_TTL_SECS for refresh).

# 6) Wait the grace window. Then retire the old kid.
wrangler d1 execute cesauth-prod --remote --command="\
UPDATE jwt_signing_keys SET retired_at=unixepoch() \
WHERE kid='cesauth-LOST';"
```

There is no data loss — the key is for signing, not
encryption. The tokens it signed remain valid until expiry;
clients refresh through the new key.

## Scenario 8 — `wrangler.toml` `database_id` accidentally pointed at wrong DB

**Symptom**: deploy went out, but cesauth is reading/writing
to staging's D1 instead of production's, or vice versa. Visible
as: tests pass, but production users see staging-shaped data
(or worse, no data).

**Recovery**:

1. **Stop the misdirected Worker immediately.** Roll back to
   the prior version, OR redeploy with the corrected
   `database_id`.
2. **Audit data divergence.** Did production writes go to
   the wrong DB during the window? Check the ts of the
   misdirected deploy and the audit log.
3. **Reconcile.** If writes landed in the wrong DB, you may
   need to copy them back to production manually:
   ```sh
   wrangler d1 export <wrong-db> --remote \
     --output divergent-writes.sql
   # Edit to extract only the writes that belong to production.
   wrangler d1 execute cesauth-prod --remote \
     --file production-recoveries.sql
   ```

The pull-quote: **`database_id` is the most dangerous value in
`wrangler.toml`**. Treat changes to it with the same care as
schema migrations.

## DR drills

Practice these scenarios annually:

- Restore a backup to a fresh Cloudflare account.
- Roll a JWT key.
- Apply a deliberately-broken migration to staging and use
  the forward-fix-or-restore procedure to recover.

The first drill of each scenario will surface gaps in this
chapter or in your specific deployment. Update accordingly.

## See also

- [Backup & restore](./backup-restore.md) — the procedural
  details this chapter assumes.
- [Day-2 operations runbook](./runbook.md) — for symptoms that
  resolve faster than full DR.
- [Pre-flight checklist](./preflight.md) — the readiness state
  that prevents most DR scenarios.
