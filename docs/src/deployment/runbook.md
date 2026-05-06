# Day-2 operations runbook

This is the page on-call reaches for at 3am. Each section is a
specific symptom, the diagnostic sequence, and the most-common
remediation. Optimized for speed of reading, not depth of
explanation; see linked chapters for the why.

This runbook complements (does not replace) the operational
runbook content in [Tenancy → Operator runbook](../expert/tenancy.md)
which covers tenancy-API-specific operations. Page-specific
runbooks for each scheduled task are in their respective
chapters.

## Symptom: users report "session expired" en masse

**Severity:** High if many users; otherwise low.

### Diagnose

```sh
# Was SESSION_COOKIE_KEY recently rotated?
wrangler secret list --env production | grep SESSION_COOKIE_KEY
# (timestamp of last rotation visible in the output)

# Are sessions writing to the active_session DO?
wrangler tail --env production --format=json \
  | jq 'select(.category == "Session" and .level == "error")'

# Has the SESSION_TTL_SECS [var] changed?
git log -p wrangler.toml | head -100
```

### Common causes

1. **`SESSION_COOKIE_KEY` rotated.** Every existing session
   becomes unverifiable; every user must re-authenticate.
   This is by design — see [Secrets → Rotation](./secrets.md#rotation).
2. **`SESSION_TTL_SECS` reduced.** Existing sessions older
   than the new TTL are immediately stale.
3. **`active_session` DO storage corrupted.** Rare; would
   show up as `Session/error` log entries.

### Remediate

If (1) was deliberate (e.g., post-incident response): nothing
to do; users will re-authenticate.

If (1) was accidental (e.g., someone ran the command without
intending to): cesauth doesn't keep the old key around. The
sessions are gone. Users will re-auth; communicate the cause
internally so the postmortem captures it.

If (2): adjust `SESSION_TTL_SECS` back. Already-stale sessions
stay stale; new sessions get the new TTL.

If (3): file a Cloudflare support ticket; provide the timestamp
of the failure burst.

---

## Symptom: anonymous user count is growing unbounded

**Severity:** Medium. Not user-visible immediately; eventual
storage cost.

### Diagnose

```sh
# How many anonymous rows past the retention window?
wrangler d1 execute cesauth-prod --remote --command=\
"SELECT count(*) FROM users
   WHERE account_type='anonymous' AND email IS NULL
     AND created_at < unixepoch() - 7 * 86400;"
# Healthy: 0 shortly after each daily sweep.

# Did the sweep run yesterday?
# In your Logpush destination:
#   category=Storage AND msg=*"anonymous sweep complete"*
#     AND ts > yesterday_04_00 AND ts < yesterday_04_30

# Is the [triggers] block in wrangler.toml?
grep -A2 '\[triggers\]' wrangler.toml
```

### Common causes

1. **`[triggers]` block missing from `wrangler.toml`** — the
   most common cause. The deployed Worker has the
   `#[event(scheduled)]` handler in its bundle, but
   Cloudflare doesn't invoke it without the trigger
   registration.
2. **Sweep is running but row deletes are failing** — visible
   in the per-row `Warn` log: `"anonymous sweep delete user_id=…
   failed:"`. Storage backend issue.
3. **Sweep is running but the cutoff math is wrong** — would
   only happen after a code change to `sweep::run`. Check
   recent commits.

### Remediate

(1): Add the block, `wrangler deploy`. The first run is at the
next 04:00 UTC. To force-run sooner, see
[Cron Triggers → Manual invocation](./cron-triggers.md#manual-invocation-for-smoke-testing).

(2): Each failed-delete `Warn` line names the user_id. If a
single row is poisoning the sweep (e.g., an FK constraint
that shouldn't exist), delete it manually:

```sh
wrangler d1 execute cesauth-prod --remote --command=\
"DELETE FROM users WHERE id='<the-id>';"
```

(3): Revert the sweep code change; investigate the cutoff
arithmetic.

---

## Symptom: a specific user can't log in

**Severity:** Low (one user); High if many.

### Diagnose

```sh
# Does the user exist?
wrangler d1 execute cesauth-prod --remote --command=\
"SELECT id, email, status, account_type
   FROM users WHERE email = 'alice@example.com' COLLATE NOCASE;"

# Recent auth events for this user:
# (in Logpush, or via the admin console audit page)
#   subject="<user-id>" AND category=Auth
#   ORDER BY ts DESC LIMIT 20

# Did the user trigger rate limiting?
# Check the rate_limit DO state via the admin console.
```

### Common causes

1. **`status='disabled'` or `'deleted'`** — admin action
   suspended the user.
2. **Email mismatch** — the user is typing an email that's
   close to but not exactly the one in `users`. Check for
   typos.
3. **Magic Link delivery failure** — the OTP email isn't
   arriving. Check the mail provider's logs.
4. **Rate-limit lockout** — too many recent attempts have
   triggered the rate limiter.
5. **WebAuthn authenticator decommissioned** — the user lost
   their security key. They need a recovery path.

### Remediate

(1): If the disable was deliberate, do not undo it. If
accidental, an admin can re-enable via the admin console.

(2): User-side issue; instruct them on the correct email.

(3): Check `MAGIC_LINK_MAIL_API_KEY` is set and the mail
provider is healthy. Check the cesauth audit log for
`magic_link_issued` events for this email.

(4): Wait for the rate-limit window to reset (default 5–10
minutes), or as a system-admin, clear the bucket via the
admin console.

(5): The user needs at least one alternative authenticator
(another passkey, magic link to a verified email). cesauth
doesn't ship a "reset all my authenticators" admin flow as of
0.5.x; the recovery path is admin-mediated case-by-case.

---

## Symptom: 5xx error rate spike

**Severity:** Critical.

### Diagnose

```sh
# Is the spike concentrated on one route?
# Cloudflare dashboard → Analytics → Status code → Filter by URL.

# Storage errors?
wrangler tail --env production --format=json \
  | jq 'select(.category == "Storage" and .level == "error")'

# CPU time approaching the limit?
# Cloudflare dashboard → Analytics → CPU time.

# Recent deploy? Check the deploy timestamps.
wrangler deployments list --env production
```

### Common causes

1. **Recent deploy introduced a regression.**
2. **D1 brownout / account-level issue** — Cloudflare's status
   page (https://www.cloudflarestatus.com) will tell you.
3. **CPU limit exceeded** — a route is doing more work than
   expected (e.g., unbounded loop, large response build).
4. **Migration applied to production but Worker not yet
   redeployed** — schema doesn't match the running Worker's
   queries.

### Remediate

(1): Roll back. `wrangler rollback --env production` to the
previous deployment. Investigate before re-deploying.

(2): Wait. Cloudflare-side incidents are out of cesauth's
control. Communicate impact to users via your status channel.

(3): Roll back the Worker that introduced the heavy code
path. Profile locally before re-deploying.

(4): Deploy the Worker. Migration → deploy is the correct
ordering; if you got it backward, finish the deploy.

---

## Symptom: signing key rotation needs to happen

This is **planned operational work**, not an alert. Walk-through
in [Secrets → Rotation](./secrets.md#rotation). High-level:

```
1. Generate new key locally; vault it.
2. INSERT new row into jwt_signing_keys (retired_at NULL).
3. wrangler secret put JWT_SIGNING_KEY (new value).
4. Update [vars] JWT_KID to the new kid.
5. wrangler deploy.
6. Wait one REFRESH_TOKEN_TTL_SECS (default 30 days).
7. UPDATE jwt_signing_keys SET retired_at=... WHERE kid='<old>'.
```

The grace window keeps the old key in JWKS so clients can
still verify tokens issued before the rotation.

---

## Symptom: admin token suspected leaked

**Severity:** Critical.

### Diagnose

```sh
# Recent admin actions for the suspected token's principal:
# Audit log:
#   subject=<admin-principal-id> AND ts > suspected_compromise_ts
```

### Remediate

```sh
# 1) Disable the token immediately (via the admin console
#    or the API).
curl -X POST https://auth.example.com/admin/console/admin-tokens/<id>/disable \
  -H "Authorization: Bearer $ADMIN_API_KEY"

# 2) Audit everything the token did since suspected
#    compromise:
# (manual investigation; the audit log is the source of truth)

# 3) Mint replacement tokens for legitimate operators.
# 4) If ADMIN_API_KEY itself was leaked, rotate it.
wrangler secret put ADMIN_API_KEY
# (paste new value)
wrangler deploy
```

---

## Symptom: discovery doc says wrong issuer

**Severity:** Critical. Every existing client will break.

### Diagnose

```sh
curl -sS https://auth.example.com/.well-known/openid-configuration \
  | jq -r .issuer
# Compare to the ISSUER [var] in wrangler.toml.
```

### Common causes

1. `ISSUER` `[var]` was changed and deployed without a
   coordinated client update.
2. Custom Domain was changed without updating `ISSUER`.

### Remediate

If clients are already validating against the OLD `iss`:

- **Roll back `ISSUER` to the old value** — fastest fix.
  Schedule a coordinated rotation once you've worked out the
  client-update plan.

If you've validated all clients can handle the new `iss`:

- Continue with the new value; communicate that old tokens
  (issued under the old `iss`) will fail validation as they
  expire.

The cardinal rule: **never change `ISSUER` without a planned
client coordination**. See
[Custom domains → Common mistakes](./custom-domains.md#common-mistakes).

---

## Operation: cross-account data migration

This is **planned operational work**, not an alert. Use when
moving cesauth's data from one Cloudflare account to another:
M&A integration, region separation for data residency, isolating
a compromised account from a fresh one. Full walkthrough in the
[Data migration](./data-migration.md) chapter; this is the
runbook quick-reference.

### Pre-flight before invoking `cesauth-migrate export`

Source side:

```sh
# Confirm wrangler is authenticated to the source.
wrangler whoami

# Confirm the source D1 size is what you expect.
wrangler d1 info <source-database>
```

Destination side, before the importing operator runs `import`:

```sh
# 1. Mint and push fresh secrets.
openssl genpkey -algorithm ed25519 \
  | wrangler secret put JWT_SIGNING_KEY    --env production
openssl rand -base64 48 | tr -d '\n' \
  | wrangler secret put SESSION_COOKIE_KEY --env production
openssl rand -base64 32 | tr -d '\n' \
  | wrangler secret put ADMIN_API_KEY      --env production
# (Plus MAGIC_LINK_MAIL_API_KEY, TURNSTILE_SECRET if applicable.)

# 2. Apply schema migrations.
wrangler d1 migrations apply <destination-database> --remote
```

### Running the move

Source side:

```sh
cesauth-migrate export \
  --output     cesauth-prod-$(date +%Y%m%d).cdump \
  --account-id <source-account-id> \
  --database   <source-database>
```

The CLI prints a 16-hex-char fingerprint to stderr at start.
**Note this fingerprint somewhere persistent** (incident
channel, runbook, password manager). Read it aloud to the
destination operator over a separate channel.

Transmit the dump file to the destination operator out-of-band
from the fingerprint.

Destination side:

```sh
cesauth-migrate verify --input cesauth-prod-20260428.cdump
# Confirm the printed fingerprint matches what the source
# operator told you. If not, abort.

cesauth-migrate import \
  --input      cesauth-prod-20260428.cdump \
  --account-id <destination-account-id> \
  --database   <destination-database> \
  --commit
```

The importer walks five gates (verify, fingerprint handshake,
secret pre-flight, invariant checks, final commit confirmation).
At each gate the operator can decline; the destination D1 is
left untouched until the final commit prompt is answered yes.

### Post-import verification

Immediately after the importer's `✓ Import complete` line:

```sh
# 1. Confirm row counts match expectation.
wrangler d1 execute <destination-database> --remote \
  --command="SELECT count(*) FROM users;"

# 2. Update destination wrangler.toml's JWT_KID to match the
#    new signing key.
# (edit wrangler.toml)

# 3. Deploy the Worker against the destination.
wrangler deploy --env production

# 4. Smoke-test the discovery doc.
curl -s https://<destination-host>/.well-known/openid-configuration \
  | jq -r .issuer

# 5. Switch DNS. (Outside cesauth's surface; your registrar/
#    Cloudflare DNS console.)

# 6. Source-side cleanup, after grace window:
#    - Revoke source admin tokens.
#    - Retire source signing keys (set retired_at).
```

### Common failure modes

**Fingerprint mismatch at handshake.** The dump was tampered
or substituted in transit. Do NOT continue. Re-export from
the source and retransmit through a different channel.

**Secret pre-flight fails (`JWT_SIGNING_KEY` not set).** Run
`wrangler secret put JWT_SIGNING_KEY` at the destination first.
ADR-005 §Q6.

**Violation report has entries.** Read the violations. If a
small number (single digits), the source dump may have caught
mid-action state — re-export. If many, the source schema is
inconsistent and needs investigation before migration.

**`wrangler d1 execute` fails mid-commit.** A wrangler-side
or Cloudflare-side issue. The importer surfaces the wrangler
stderr verbatim. Re-running the import is safe — staged rows
are in memory only, the destination D1 will not have been
partially populated by the failed call (D1 batches are
atomic per call). Note: if SOME table commits succeeded and
THEN a later table failed, the destination has those earlier
tables' rows. v0.21.0 doesn't roll those back automatically;
the operator runs `wrangler d1 execute --command="DROP TABLE x"`
or applies a fresh-DB cleanup before retrying.

## Periodic operator tasks

These aren't alerts; they're recurring chores.

### Daily

- **Check sweep ran and was clean.** Logpush query for
  yesterday's `"anonymous sweep complete"` line.

### Weekly

- **Review audit-log for unusual admin activity.**
  `kind=admin_*` events.
- **Check `cargo audit` is still green** in CI. (The weekly
  cron in `.github/workflows/audit.yml` runs Mondays.)
- **Review backups completed and restorable** — restore-test
  one backup against a staging environment.

### Monthly

- **Capacity review.** Cloudflare dashboard → Analytics. If
  request rates are trending toward subscription limits,
  plan an upgrade.
- **Review [vars] for stale values.** Magic-link TTL too long?
  Token TTLs need adjustment? Document any change.
- **Dependency upgrade pass.** `cargo update`,
  `cargo audit`, smoke-test.

### Quarterly

- **JWT signing key rotation.** Even if not compromised, key
  hygiene benefits from rotation cadence.
- **Postmortem review.** Which incidents recurred? Is there
  a class-of-bug fix that should land?

### Annually

- **Disaster recovery drill** — full restore from off-site
  backups to a fresh Cloudflare account. The first time you
  do this, it will be educational; subsequent drills should
  go more smoothly.
- **Threat model review.** [Security considerations](../expert/security.md)
  — has anything changed that invalidates an assumption?

## See also

- [Disaster recovery](./disaster-recovery.md) — for incidents
  beyond the scope of this runbook.
- [Observability](./observability.md) — the queries this
  runbook references.
- [Tenancy → Operator runbook](../expert/tenancy.md) — the
  tenancy-service-specific equivalent of this page.

---

## Operation: purge plaintext OTP audit leaks (one-time, v0.50.1 → v0.50.3 upgrade)

**When to run**: once, after upgrading to v0.50.3, if you ran any version
between v0.16.0 and v0.50.1 inclusive in production. Those versions wrote
the Magic Link OTP plaintext into `audit_events.reason` for every issuance
(`EventKind::MagicLinkIssued`). v0.50.3 (RFC 008) stops the bleed; this
procedure sanitises already-persisted rows.

**Who is affected**: operators who used Magic Link or anonymous-promote
in production during the affected version window. Fresh deployments that
never ran ≤ v0.50.1 do not need this procedure.

### Step 1 — Verify the leak exists

```bash
wrangler d1 execute cesauth-db --command \
  "SELECT COUNT(*) AS leaked_rows FROM audit_events
    WHERE kind = 'magic_link_issued'
      AND reason LIKE '%code=%';"
```

If `leaked_rows` is 0, your deployment is clean and you can skip the rest.

### Step 2 — (Optional) Export for forensic preservation

Before purging, you may want to keep a private record of the leaked rows.
Run this and store the output offline if needed:

```bash
wrangler d1 execute cesauth-db --command \
  "SELECT id, ts, subject, reason FROM audit_events
    WHERE kind = 'magic_link_issued'
      AND reason LIKE '%code=%'
   ORDER BY ts;" > leaked-otp-rows-$(date +%Y%m%d).jsonl
```

### Step 3 — Purge plaintext OTP from reason field

```sql
UPDATE audit_events
   SET reason = NULL
 WHERE kind = 'magic_link_issued'
   AND reason LIKE '%code=%';
```

Via wrangler:

```bash
wrangler d1 execute cesauth-db --command \
  "UPDATE audit_events
      SET reason = NULL
    WHERE kind = 'magic_link_issued'
      AND reason LIKE '%code=%';"
```

This rewrites only the `reason` column. The `kind`, `subject`, `ts`, and
chain fields are untouched; the row itself and its hash remain in the chain.
The chain hash over `reason` now covers `NULL` instead of the original
value, so the verifier will detect a mismatch.

### Step 4 — Re-baseline the audit hash chain

The UPDATE in step 3 breaks the SHA-256 hash chain at every modified row.
The next `audit_chain_cron` run will fail-closed and block further
verification until the chain is re-baselined.

```bash
# Clear the stored checkpoint so the verifier re-walks from genesis.
wrangler d1 execute cesauth-db --command \
  "DELETE FROM audit_chain_checkpoints;"
```

> **Note**: the checkpoint is also stored in KV under the `chain:checkpoint`
> key in the `CACHE` namespace. Wrangler KV delete:
>
> ```bash
> wrangler kv key delete --binding=CACHE "chain:checkpoint"
> wrangler kv key delete --binding=CACHE "chain:last_result"
> ```

Then trigger a manual chain re-walk (or wait for the next 04:00 UTC cron).
The verifier will re-walk all rows from seq=1, compute chain hashes over the
post-purge state, and write a fresh checkpoint. After the first successful
run the admin console `/admin/console/audit/chain` will show ✓ valid again.

### Step 5 — Verify cleanup

```bash
# Should return 0.
wrangler d1 execute cesauth-db --command \
  "SELECT COUNT(*) FROM audit_events
    WHERE kind = 'magic_link_issued'
      AND reason LIKE '%code=%';"
```

### Security notes

- **Do not roll back to v0.50.1 after running step 3.** v0.50.1 and earlier
  reintroduce the audit-as-delivery path. If you must roll back for an
  incident, do so only in a non-production environment with synthetic data.
- **The purge is irreversible** once you run `VACUUM` (which Cloudflare D1
  does automatically). Steps 2–3 together give you a private record before
  the data is gone permanently.
- **The chain re-baseline accepts the loss** of the verifiable-chain-back-
  to-genesis property in exchange for a clean post-purge state. Future
  verification runs from the new baseline forward.
