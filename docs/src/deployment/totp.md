# TOTP configuration

> Time-based One-Time Password (TOTP) is the second factor for
> Magic Link logins. Configuration is operator-driven: the worker
> needs an encryption key for storing TOTP secrets at rest, and
> the operator chooses when to roll that key.

This chapter covers the env vars cesauth needs to run TOTP, the
key rotation procedure, the admin reset path for users locked out
of their authenticator, and the operational invariants you should
know about. The end-user-facing experience (enroll, verify,
disable) is documented separately in the user guide; this chapter
is for the operator.

## When TOTP fires

TOTP is a **post-MagicLink gate**. After a user successfully
verifies a magic link, the worker checks whether they have a
confirmed TOTP authenticator. If yes, they're redirected to
`/me/security/totp/verify` and prompted for a 6-digit code. If
no, they proceed straight to the session.

Per ADR-009 §Q7, **WebAuthn (Passkey) logins do not trigger the
TOTP gate**. WebAuthn is itself MFA-strong (device possession +
on-device user verification), so a second factor would be
redundant friction. Admin auth is bearer-token-only and doesn't
go through `complete_auth` at all — also no gate.

This means an operator considering enabling TOTP for their user
base should think of TOTP as "MFA for users who chose magic
links". Users with passkeys never see a TOTP prompt.

## Required configuration

### `TOTP_ENCRYPTION_KEY` (secret)

A 32-byte AES-256-GCM key, base64-encoded. Used to encrypt TOTP
secrets at rest in the `totp_authenticators.secret_ciphertext`
column.

```sh
openssl rand -base64 32 | wrangler secret put TOTP_ENCRYPTION_KEY
```

The encryption is symmetric; the same key must be present for
both encrypt (enrollment) and decrypt (verify). Workers cold-loads
the key at boot from the secret store.

If `TOTP_ENCRYPTION_KEY` is **unset**, the worker still boots, but:

- `GET /me/security/totp/enroll` responds 503 with the message
  "TOTP is not configured by the operator (TOTP_ENCRYPTION_KEY
  missing)".
- The TOTP gate in `complete_auth` does not fire (because no users
  can have confirmed TOTP authenticators — they couldn't enroll).
- The worker logs do not warn about this — by design, TOTP is
  optional.

This means a deployment can run cesauth without TOTP indefinitely.
The cost is just that users on Magic Link have only single-factor
authentication.

### `TOTP_ENCRYPTION_KEY_ID` (var)

A short human-readable identifier for the encryption key
currently in use. Stored in
`totp_authenticators.secret_key_id` on each row created. Required
when `TOTP_ENCRYPTION_KEY` is set.

```toml
# wrangler.toml
[vars]
TOTP_ENCRYPTION_KEY_ID = "k-2026-04"
```

The id is opaque to cesauth — it's a lookup key the operator
chooses. The format is your call; date-tagged ids
(`k-YYYY-MM`, `k-2026-04-rotate-after-incident`) make the
rotation trail self-documenting. Length is unbounded but
practical limits apply (a 200-character id will just look strange
in logs).

The id matters at decrypt time. When a user verifies their TOTP
code, the worker reads the `secret_key_id` column on their row,
then looks up the matching key from the env. As long as both the
old and new keys are in the env during a rotation, both old and
new rows decrypt cleanly.

## Pre-production release gate

`TOTP_ENCRYPTION_KEY` is on the
[pre-production release gate checklist](../expert/security.md#pre-production-checklist).
If you're deploying to production for the first time, set the
key BEFORE you allow real users to enroll. A user who enrolls
when the key is unset would either see the 503 (refused) or — in
a future implementation defect — get an unencrypted secret
written to D1, which would be a serious incident.

The same checklist also covers the other "must-be-set-before-
production" secrets: `JWT_SIGNING_KEY`, `SESSION_COOKIE_KEY`,
etc. TOTP just adds one more line.

## Key rotation

Symmetric key rotation has two operator-visible phases:

1. **Mint a new key with a new id, deploy, both old and new keys
   present in env.** New writes use the new key. Old reads find
   the old key by `secret_key_id`. No user-visible change.
2. **Re-encrypt old rows with the new key, then retire the old
   key.** Optional but eventually necessary if you want to fully
   decommission the old key.

### Phase 1: dual-key deployment

```sh
# Generate the new key.
openssl rand -base64 32 | wrangler secret put TOTP_ENCRYPTION_KEY_NEXT
```

In `wrangler.toml`:
```toml
[vars]
TOTP_ENCRYPTION_KEY_ID = "k-2027-01"  # the NEW id
```

Cesauth resolves `TOTP_ENCRYPTION_KEY` (new writes) and any
secrets matching `TOTP_ENCRYPTION_KEY_<ID>` for old reads. Roll
the deployment.

> **Note:** the dual-key resolution path is **not yet
> implemented in cesauth 0.30.0**. The current implementation
> reads only `TOTP_ENCRYPTION_KEY`. Operators who need to rotate
> today must either (a) re-enroll all users (the simplest
> approach if your user count is small), or (b) write a one-shot
> migration tool that decrypts with the old key and re-encrypts
> with the new one in a single transaction. The dual-key
> resolution path is tracked in ROADMAP under "Later".

### Phase 2: re-encryption (deferred work)

A re-encryption helper is not shipped in 0.30.0. The intended
shape is a `cesauth-migrate totp re-encrypt` subcommand that:

1. Reads each row from `totp_authenticators`.
2. Looks up the old key by `secret_key_id`, decrypts.
3. Encrypts with the current `TOTP_ENCRYPTION_KEY`, updates the
   row's `secret_ciphertext`, `secret_nonce`, `secret_key_id`.
4. Refuses to proceed if any row has a `secret_key_id` not
   present in the env.

Until this lands, operators who want to rotate must use the
re-enrollment workaround.

## Admin reset (lockout recovery)

A user who loses both their authenticator AND their recovery
codes is locked out of Magic Link login. The TOTP gate fires on
every login attempt, the user can't produce a valid code, and
the verify form bounces them to `/login` after `MAX_ATTEMPTS=5`
failed attempts (each attempt requires a fresh magic link, so
this is per-magic-link-cycle friction).

There is no self-service "I lost everything" flow today
(rationale: a self-service path that bypasses TOTP without ANY
proof of possession reduces TOTP to a soft-recommendation rather
than an actual second factor).

The operator escape hatch is **direct D1 deletion**:

```sh
# 1. Identify the user_id (from your support tooling).
USER_ID=u-abc123

# 2. Delete the user's TOTP authenticator rows.
wrangler d1 execute cesauth-prod \
  --command "DELETE FROM totp_authenticators WHERE user_id = '$USER_ID'"

# 3. Delete the user's recovery codes (these are useless without
#    the authenticator anyway, but cleanly remove them too).
wrangler d1 execute cesauth-prod \
  --command "DELETE FROM totp_recovery_codes WHERE user_id = '$USER_ID'"
```

The user's next Magic Link login skips the TOTP gate (because
`find_active_for_user` returns `None`). They can then re-enroll
TOTP at `/me/security/totp/enroll` if they choose to.

This procedure has no audit-trail emission today (the audit log
records logins, not direct DB ops). For an audit trail, log the
operator support ticket out-of-band; the v0.31.0+ audit-log-
hash-chain track will tighten this surface.

## Cron sweep

A daily sweep at 04:00 UTC (configured in `wrangler.toml`
`[triggers]` `crons = ["0 4 * * *"]`) prunes unconfirmed
enrollment rows older than 24 hours.

```text
totp_authenticators
  WHERE confirmed_at IS NULL
    AND created_at < now - 86400
```

The 24-hour window is per ADR-009 §Q9: long enough that a user
who got distracted mid-enrollment can come back the same day,
short enough that abandoned enrollment doesn't pollute storage.

The partial index `idx_totp_authenticators_unconfirmed` (created
in migration 0007) makes this query cheap. The cron runs as a
follow-up to the anonymous-trial sweep — same cron entry, same
04:00 UTC tick, sequential execution. Both are best-effort: per-
row delete failures log and continue.

The sweep emits one log line per run:

```
totp unconfirmed sweep complete: N rows deleted
```

If you see this number consistently growing without bound,
something is wrong — either the partial index dropped, or rows
are being created faster than 24h-old rows can be deleted.
Investigate by querying:

```sql
SELECT COUNT(*) FROM totp_authenticators
WHERE confirmed_at IS NULL
  AND created_at < unixepoch() - 86400;
```

This should be 0 immediately after a sweep tick and tend toward
0 between ticks.

## Disable flow

A user who wants to remove TOTP from their account uses
`POST /me/security/totp/disable` (the corresponding GET shows a
confirmation page first, per POST/Redirect/GET).

The disable handler:

1. Resolves the session via `__Host-cesauth_session`.
2. Validates CSRF.
3. Calls `delete_all_for_user(user_id)` on
   `totp_authenticators` (best-effort; storage failure → 500).
4. Calls `delete_all_for_user(user_id)` on
   `totp_recovery_codes` (best-effort; failure logged but not
   surfaced — an authenticator-less recovery code is useless).
5. Redirects to `/`.

The user is now in the "no TOTP" state. Their next Magic Link
login skips the gate. They can re-enroll later if they choose to.

The disable flow does NOT require the user to type a current
TOTP code. Rationale: the user already has a live session
(authenticated for primary), so requiring a TOTP code would be
double-authentication for a user-initiated removal. A user who
has lost their authenticator AND wants to remove TOTP can use
this flow if they're already signed in (e.g., from another
device or earlier session).

## Redaction profile (`cesauth-migrate`)

Both `prod-to-staging` and `prod-to-dev` redaction profiles
**drop** the `totp_authenticators` and `totp_recovery_codes`
tables entirely. TOTP secrets must NOT survive redaction, even
encrypted, because a staging deployment with real users'
encrypted secrets would let any staging operator authenticate as
those users (the encryption key is just a deployment secret,
which staging has access to).

```sh
cesauth-migrate export \
  --account-id ... \
  --database cesauth-prod \
  --profile prod-to-staging \
  --output prod.cdump

# Output includes:
#   Exporting totp_authenticators... 0 rows (dropped by `prod-to-staging` profile)
#   Exporting totp_recovery_codes... 0 rows (dropped by `prod-to-staging` profile)
```

The staging deployment imports the dump and has zero TOTP rows.
Existing staging TOTP rows from a prior import are not affected
(import is row-add, not table-replace). If you need to wipe
staging TOTP state too, use the `delete_all_for_user` admin
escape hatch above — but in practice, the simpler procedure is
`DROP TABLE` + reapply migration 0007.

See ADR-009 §Q5/§Q11 for the full rationale on why TOTP secrets
are non-redactable.

## Operational invariants

- **The `secret_key_id` column is load-bearing.** Future dual-key
  rotation depends on it. Don't NULL it in any migration or data
  fixup.
- **The partial index** `idx_totp_authenticators_unconfirmed`
  is load-bearing for the cron sweep. Don't drop it.
- **The TOTP cookie is `__Host-cesauth_totp`** with
  `SameSite=Strict`. If you find yourself proxying cesauth
  behind a path that needs `SameSite=Lax` (some CSRF-aware
  reverse proxies), the TOTP gate will break. The verify page
  is a same-origin form post; the strict scope is correct.
- **Recovery codes are SHA-256 hashed at rest.** The plaintext
  is shown to the user once at enrollment and never stored. If
  a user reports they've lost their recovery codes, you cannot
  retrieve them — they have to go through the admin reset path.
- **TOTP authenticator rows are user-scoped, not session-scoped.**
  A user with TOTP enrolled on phone A logging in from laptop B
  uses the same secret. If they want device-specific
  authenticators, they enroll separately — but cesauth treats
  the FIRST confirmed authenticator as canonical for verify
  (`find_active_for_user` returns the most recently confirmed
  row). Multi-authenticator support is intentional but
  under-exercised — pin its semantics by re-reading
  `find_active_for_user`'s test before relying on it.

## Diagnostic queries

How many users have TOTP enrolled?

```sql
SELECT COUNT(DISTINCT user_id) FROM totp_authenticators
WHERE confirmed_at IS NOT NULL;
```

How many users have unredeemed recovery codes left?

```sql
SELECT user_id, COUNT(*) AS remaining
FROM totp_recovery_codes
WHERE redeemed_at IS NULL
GROUP BY user_id
ORDER BY remaining ASC;
```

A user with 0 remaining recovery codes is one lost authenticator
away from the admin reset path. You may want to surface this in
your support tooling proactively.

How many enrollment rows are in the unconfirmed sweep window
right now?

```sql
SELECT COUNT(*) FROM totp_authenticators
WHERE confirmed_at IS NULL
  AND created_at < unixepoch() - 86400;
```

Should be 0 immediately after the daily 04:00 UTC sweep, growing
modestly during the day, falling to 0 again after the next sweep.

## See also

- [ADR-009 — TOTP design](../expert/adr/009-totp.md) — the
  authoritative source for "why TOTP is shaped this way".
- [Security headers](./security-headers.md) — the HSTS / CSP
  story, distinct from but related to the TOTP cookie scoping.
- [Pre-flight checklist](./preflight.md) — `TOTP_ENCRYPTION_KEY`
  is on the production-deployment gate.
- [Data migration](./data-migration.md) — redaction profile
  details, including the TOTP table-drop behavior.
