# ADR-009: TOTP (RFC 6238) as a second factor

**Status**: Draft (v0.26.0). Will graduate to `Accepted` in
v0.27.0 when enrollment + verify wire-up lands.

**Context**: cesauth's two existing credential paths (Magic Link
and WebAuthn) cover most of the IDaaS authentication surface.
WebAuthn is the strongest passwordless option and is preferred,
but it requires a hardware authenticator or platform-specific
synced passkeys, neither of which every user can produce.
Magic Link works for everyone with a working email but is a
single factor — successful Magic Link login means "this person
controlled this email at this moment", which is a weaker
guarantee than "this person possesses this device".

TOTP (RFC 6238) is the pragmatic second factor: every user can
install Google Authenticator or Authy (or a password manager
with TOTP support like 1Password / Bitwarden), and TOTP codes
are reasonably resistant to phishing **when used as a true
second factor on top of a primary** (not as the primary itself,
which is phishable).

This ADR defines:

- The TOTP value types, secret encoding, and verification
  semantics in `cesauth_core::totp`.
- The schema additions for storing per-user TOTP secrets at
  rest.
- The encryption-at-rest scheme (no plaintext TOTP secrets in
  D1).
- The recovery code scheme (rescue path when the user loses
  their authenticator device).
- How TOTP composes with Magic Link and WebAuthn (it's a
  second factor, never a sole factor).
- What v0.27.0 must add to make this user-visible.

## Q1 — TOTP algorithm parameters

**Question**: which RFC 6238 parameters does cesauth support?

**Decision**:

- **Hash algorithm**: SHA-1 only. The RFC permits SHA-256 and
  SHA-512 but every shipping authenticator app supports SHA-1
  and only some support the wider hashes. Google Authenticator
  silently falls back to SHA-1 on SHA-256 secrets, producing
  wrong codes — the worst possible UX. Locking to SHA-1 avoids
  this entire class of footgun.

  SHA-1's collision-resistance weakness is irrelevant for TOTP.
  The HMAC construction is keyed; the threat model is "given
  observed (time, code) pairs, predict next code", which is
  unrelated to collision-finding.

- **Code digits**: 6. RFC permits 6, 7, or 8. Authenticator
  apps default to 6 and many display 6 even when an 8-digit
  code is requested (truncating the display silently — wrong-
  code UX again). Lock to 6.

- **Step (period)**: 30 seconds. RFC default. Universal in
  authenticator apps.

- **Secret length**: 20 bytes (160 bits). RFC 6238 §5.1
  recommends ≥ 128 bits; 160 matches the SHA-1 output width
  and is what Google Authenticator generates.

These are baked into the library as constants. A future
release may add per-tenant policy if a deployment needs
SHA-256 for a specific reason; the current implementation has
no such knob.

## Q2 — Skew tolerance

**Question**: how much clock skew between the user's device and
the cesauth Worker is tolerated?

**Decision**: ±1 step (±30 seconds). Verify against the current
step, the previous step, and the next step. Three windows
total.

The user's device clock and Cloudflare's clock should both be
within seconds of UTC; ±1 step covers small drift, network
latency between the user typing the code and the request
reaching the Worker, and the user starting to type just before
a step boundary.

A wider window (±2 steps, etc.) makes brute-force easier:
verifying against more windows means the attacker's brute-force
candidate has more chances to hit a valid step. ±1 is the
conservative-enough choice for the threat model and the
universal-enough choice for the UX.

## Q3 — Replay protection

**Question**: a TOTP code is valid for 30 seconds. If an
attacker observes the user typing a code (over the user's
shoulder, or via a phishing site that proxies in real time),
the attacker has up to 30 seconds (less skew) to replay it.
What stops this?

**Decision**: per-secret last-used-step tracking. The library
exposes a `verify_with_replay_protection(secret, code, last_used_step, now)`
API that returns the new `last_used_step` on success. The
storage layer persists this per TOTP authenticator. A second
verify against the same step is rejected as already-used.

This is single-window replay protection, not single-code: the
attacker who observed the code at step N cannot replay the
same code at step N+0 (already used), but the NEXT verification
at step N+1 (a fresh code, derived from the same secret but a
different time) is still allowed because the user is the only
one who knows the secret.

In other words: **we record the latest step that succeeded;
any verify that falls within or before that step fails**. The
window-of-three check (Q2) becomes window-of-three-but-not-
including-or-before-last-used-step.

Edge case: if the user's clock runs fast and they enter a code
from step N+1 before the Worker hits step N+1, then later
their device's step N tries to verify, the step-N attempt
fails. This is correct (the user moved forward in time on
their own device; the older step is already-used logically).

## Q4 — Storage shape

**Question**: where do TOTP secrets live?

**Options**:
- (a) Add `totp_secret_encrypted` columns to `authenticators`
  table.
- (b) New `totp_authenticators` table.

**Decision**: (b). The `authenticators` table is WebAuthn-
specific (`credential_id`, `public_key COSE`, `sign_count`,
`aaguid`, `transports`). TOTP shares none of these. Forcing
TOTP into the same table forces every column to be nullable
and every consumer to discriminate between authenticator
types. A separate table is clean.

Schema (migration 0007):

```sql
CREATE TABLE IF NOT EXISTS totp_authenticators (
    id                       TEXT    PRIMARY KEY,
    user_id                  TEXT    NOT NULL,
    secret_ciphertext        BLOB    NOT NULL,    -- AES-GCM ciphertext
    secret_nonce             BLOB    NOT NULL,    -- 12-byte AES-GCM nonce
    secret_key_id            TEXT    NOT NULL,    -- which key encrypted; for rotation
    last_used_step           INTEGER NOT NULL DEFAULT 0,
    name                     TEXT,                -- user-supplied label
    created_at               INTEGER NOT NULL,
    last_used_at             INTEGER,
    confirmed_at             INTEGER             -- NULL until enrollment confirmed
);

CREATE INDEX IF NOT EXISTS idx_totp_authenticators_user
  ON totp_authenticators(user_id);
```

`confirmed_at` is the enrollment-completion marker. A row
exists during enrollment (the user has scanned the QR code
into their authenticator app but hasn't yet typed a verifying
code) with `confirmed_at IS NULL`; the first successful verify
flips it to `now`. This way a half-enrollment can be rolled
back by the user (via re-enrollment) or by an admin without
needing to track ephemeral state in a Durable Object.

Pre-enrollment rows that never get confirmed are pruned by a
cron sweep — see Q9.

`last_used_step` defaults to 0 because no real TOTP step is
0 (step 0 = unix epoch, which any real verification beats by
≥ 50 years). Making the default 0 means the first real
verify always passes the "step > last_used_step" check.

## Q5 — Encryption at rest

**Question**: TOTP secrets are bearer secrets — anyone who
reads them can produce valid codes for that user. How are
they protected against a D1 backup leak?

**Decision**: AES-GCM with a deployment-wide key.

- `secret_ciphertext` = `AES-GCM-256(plaintext_secret, key, nonce, aad="totp:" + id)`.
- `secret_nonce` = 12 random bytes from CSPRNG, stored
  alongside.
- `secret_key_id` = identifier of which key encrypted this
  row; allows rotation. New writes use `current_key_id` from
  env; old reads find the right key by id.
- AAD (`additional authenticated data`) = `"totp:" + id`.
  This binds the ciphertext to its row's primary key, so an
  attacker can't take ciphertext from row A and stuff it into
  row B (a "swap" attack against a stolen D1 backup).

Key management:

- `TOTP_ENCRYPTION_KEY` env var holds the active key. 32
  bytes, base64-encoded. Operators generate fresh keys with
  `openssl rand -base64 32`.
- `TOTP_ENCRYPTION_KEY_ID` env var holds the human-readable
  id (e.g., `"k-2026-04"`). Stored in
  `secret_key_id` for rotation.
- Old keys live in `TOTP_ENCRYPTION_KEY_<id>` as additional
  env vars. Rotation = mint new key, set new id, restart
  Worker. Old rows still decrypt because their `secret_key_id`
  points to the old env var.
- Re-encryption is a separate operator job, not on the hot
  path. A future cesauth-rotate-totp-keys CLI subcommand can
  bulk-reencrypt rows from old key to new.

Pre-1.0 deployments without `TOTP_ENCRYPTION_KEY` set: the
TOTP enroll/verify routes (v0.27.0) refuse to run. Operators
who don't want TOTP simply leave the env var unset; the
release-gate documentation makes this explicit.

## Q6 — Recovery codes

**Question**: a user loses their phone (or the authenticator
app's database). They can't generate codes. What's the
recovery path?

**Decision**: per-user single-use recovery codes minted at
enrollment.

- 10 codes per user, generated at enrollment time.
- Each code is 10 base32 characters (≈ 50 bits of entropy).
  Format: `XXXXX-XXXXX` for human-readability.
- Codes are stored hashed with **SHA-256**, matching cesauth's
  existing pattern for high-entropy server-issued bearer
  secrets (admin tokens in `admin_tokens.token_hash`,
  magic-link OTPs in `cesauth_core::magic_link::hash`,
  anonymous trial tokens). Argon2 would be the right choice
  for user-chosen passwords, but recovery codes are CSPRNG-
  generated with ~50 bits of entropy already — password-
  stretching adds CPU cost without security gain.

  (Note: the schema comment in `0001_initial.sql` says
  `oidc_clients.client_secret_hash` is "argon2id(secret) or
  NULL" but that comment is aspirational — no Argon2 is wired
  in cesauth as of v0.26.0. A separate ROADMAP item tracks
  whether `client_secret_hash` should switch to Argon2 or
  whether the schema comment should be relaxed to match
  reality. TOTP recovery codes follow what's actually
  implemented today.)
- Plaintext is shown to the user **once** at enrollment time
  and never again.
- A code, once used, is marked redeemed and cannot be reused.
  If the user runs out, they re-enroll TOTP from scratch
  (which mints fresh codes).
- Schema: `totp_recovery_codes(id, user_id, code_hash,
  redeemed_at)`. See migration below.

```sql
CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id                TEXT    PRIMARY KEY,
    user_id           TEXT    NOT NULL,
    code_hash         TEXT    NOT NULL,            -- argon2id
    redeemed_at       INTEGER,                     -- NULL = unused
    created_at        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_totp_recovery_codes_user
  ON totp_recovery_codes(user_id);
```

Recovery via a code:

1. User clicks "I lost my authenticator" on the TOTP-required
   screen.
2. Form prompts for a recovery code.
3. v0.27.0's verify path: hash the input, look it up in
   `totp_recovery_codes` for this user, check `redeemed_at IS
   NULL`. On match, mark redeemed. The user is logged in.
4. Side effect: the matched TOTP authenticator's
   `last_used_step` is **not** advanced (the recovery path
   bypasses TOTP, doesn't use it).
5. The post-recovery experience prompts the user to either
   re-enroll a new TOTP authenticator or remove TOTP entirely.

## Q7 — Composition with primary credentials

**Question**: when does TOTP fire?

**Decision**: TOTP is **always a second factor**, never a sole
factor.

- After a successful Magic Link verify → if the user has TOTP
  configured, prompt for code.
- After a successful WebAuthn authentication → no TOTP prompt.
  WebAuthn is itself MFA-strong (the device has a per-RP key
  that proves possession; the device-local user-verification
  step proves who's holding the device). Forcing TOTP on top
  of WebAuthn is bad UX with no security gain.
- Anonymous-trial users → no TOTP prompt. Anonymous users
  have no email yet; TOTP enrollment requires a real account.

Per-tenant policy could in the future force TOTP on top of
WebAuthn for high-security deployments. v0.27.0 ships the
default-only policy (Magic Link → TOTP if configured;
WebAuthn → no TOTP).

## Q8 — Enrollment flow shape

**Question**: how does the user enroll TOTP?

**Decision** (designed here, implemented in v0.27.0):

1. User logs in (Magic Link or WebAuthn).
2. Navigates to `/me/security/totp/enroll` (v0.27.0).
3. Worker generates a fresh secret, stores a new row in
   `totp_authenticators` with `confirmed_at IS NULL`, and
   renders a page containing:
   - The secret as a base32 string for manual entry.
   - A QR code encoding `otpauth://totp/cesauth:<email>?secret=<base32>&issuer=cesauth&algorithm=SHA1&digits=6&period=30`.
   - A form prompting "type the 6-digit code your authenticator
     shows".
4. User scans the QR code, types the displayed code.
5. Worker verifies the code; on success, marks
   `confirmed_at=now`, mints 10 recovery codes, hashes and
   stores them, displays the plaintext recovery codes **once**
   with a strong "save these now" warning.
6. User confirms they've saved the codes; flow ends.

Edge cases:
- User abandons enrollment → pre-confirmed row stays around.
  Cron sweep prunes (Q9).
- User scans QR but never types code → same.
- User types wrong code → re-prompt; the
  `pre-confirmation row` stays; the correct code on the next
  attempt confirms it.
- User has TOTP already → enrollment of a second TOTP
  authenticator is allowed (some users want backup
  authenticators); recovery codes are minted ONCE per user
  (the first enrollment), subsequent enrollments don't
  re-mint codes — the user already has them.

The QR code is generated server-side as SVG (no JavaScript
dependency, no third-party CDN).

## Q9 — Pruning unconfirmed enrollments

**Question**: rows with `confirmed_at IS NULL` accumulate.
What prunes them?

**Decision**: extend the existing daily cron (the
`anonymous-trial-cleanup` cron at 04:00 UTC, see ADR-004) to
also prune `totp_authenticators` rows where `confirmed_at IS
NULL AND created_at < now - 24h`.

24 hours is generous — a user who started enrollment, got
distracted, and came back the next day finds their flow is
clean. They re-start the enrollment with a fresh row.

## Q10 — Out of scope for v0.26.0/v0.27.0

Explicitly deferred:

- **Per-tenant TOTP policy** (force TOTP on, force TOTP off,
  TOTP-required-for-admin-operations, etc.). The library
  takes no policy input today; v0.27.0 ships default-only.
- **TOTP for admin tokens** (`cesauth-admin-token` cookies).
  Currently admin auth is bearer-only via `Authorization`
  header. A TOTP gate on admin operations is interesting but
  belongs in the admin-auth track, not the user-auth track.
- **Backup-code import from existing TOTP libraries**. Users
  enrolling from scratch is the only flow.
- **WebAuthn-backed TOTP** (CTAP-3 hmac-secret extension).
  Not widely supported.
- **Per-authenticator name editing post-confirmation**. Read-
  only after confirm; users delete and re-enroll if they want
  to rename.

## Q11 — Migration

**Decision**: `SCHEMA_VERSION` 6 → 7. Two new tables:
`totp_authenticators` and `totp_recovery_codes`. Both empty
on first deploy. No data backfill.

Cesauth-migrate's table list (`MIGRATION_TABLE_ORDER`) gains
two entries. Both are tenant-scoped via `user_id` →
`users.tenant_id`. The `--tenant` filter (v0.22.0) extends
to include them via the existing pattern.

The redaction profiles need to handle the new tables: TOTP
secrets must NOT survive redaction in any form — the
prod-to-staging redaction profile drops both tables entirely
(because a staging deployment with a real user's TOTP secrets
would let any staging operator authenticate as that user).
This is documented in v0.27.0's redaction profile additions.

## Decision summary

| Question | Decision |
|---|---|
| Q1 — algorithm parameters | SHA-1, 6 digits, 30s step, 160-bit secret. Lock all four; no per-tenant knobs |
| Q2 — skew tolerance | ±1 step (verify against current, previous, next) |
| Q3 — replay protection | Per-secret `last_used_step`; reject ≤ last used |
| Q4 — storage | Separate `totp_authenticators` table, not WebAuthn's `authenticators` |
| Q5 — encryption at rest | AES-GCM-256 with deployment key, AAD bound to row id, rotation via `secret_key_id` |
| Q6 — recovery codes | 10 codes per user, base32 ≈ 50 bits each, Argon2id-hashed at rest, single-use |
| Q7 — composition | Always 2nd factor: Magic Link + TOTP yes, WebAuthn alone yes (no TOTP), Anonymous no TOTP |
| Q8 — enrollment | QR code + manual-entry secret; first verify confirms, mints recovery codes once |
| Q9 — pruning | Extend daily cron at 04:00 UTC; drop unconfirmed rows older than 24h |
| Q10 — out of scope | Per-tenant policy, admin TOTP, backup-code import, WebAuthn-backed TOTP, name-editing |
| Q11 — migration | SCHEMA_VERSION 6 → 7. Two new tables; redaction drops both for prod→staging |

## Phasing

The original plan was a two-release split (foundation + wire-up).
During v0.27.0 implementation it became clear that the storage
layer (port traits, adapters, encryption key plumbing) was its
own substantial slice and deserved a separate release for
review-ability. The same realization arrived during v0.28.0
when the presentation layer (templates + QR generator) again
proved review-able as its own slice without the HTTP routes
that consume it. The phasing has been revised twice now and
currently spans **five releases**:

- **v0.26.0** ✅ — ADR (this document, Draft) + schema migration
  0007 + `cesauth_core::totp` pure-function library (TOTP
  generation, verification with replay protection,
  recovery-code generation, secret encryption helpers). NO
  HTTP routes, NO enrollment UI, NO redaction profile updates.
- **v0.27.0** ✅ — Storage layer: `TotpAuthenticatorRepository`
  and `TotpRecoveryCodeRepository` port traits in
  `cesauth_core::totp::storage`; in-memory adapters in
  `cesauth-adapter-test` (19 tests); D1 adapters in
  `cesauth-adapter-cloudflare`; `Challenge::PendingTotp`
  variant for the post-MagicLink intermediate state;
  `TOTP_ENCRYPTION_KEY` and `TOTP_ENCRYPTION_KEY_ID` env vars
  with parser unit-tests (5 tests). No HTTP routes still —
  the storage layer alone is testable via the in-memory
  adapter and the D1 adapter compiles against worker-rs.
- **v0.28.0** ✅ — Presentation layer: three new UI templates
  (`totp_enroll_page`, `totp_recovery_codes_page`,
  `totp_verify_page`) in `cesauth_ui` with 18 tests pinning
  CSRF inclusion / escape behavior / `<details>` placement
  for the recovery alternative form / no-email-leak from the
  verify page; QR code SVG generator
  (`cesauth_core::totp::qr::otpauth_to_svg`) using the
  `qrcode` crate at EcLevel::M with 7 tests pinning
  determinism, dark-color emission, and long-URI handling;
  `cesauth_worker::routes::me` parent module + `me::auth`
  helper (`resolve_or_redirect`, `redirect_to_login`)
  centralizing the cookie → session → redirect-or-state
  pipeline for `/me/*` routes. No HTTP routes still — the
  templates render in unit tests and the QR generator runs
  pure-function; the HTTP wire-up is v0.29.0.
- **v0.29.0** (planned) — HTTP routes: `GET /me/security/totp/enroll`,
  `POST /me/security/totp/enroll/confirm`,
  `GET /me/security/totp/verify`,
  `POST /me/security/totp/verify`,
  `POST /me/security/totp/recover`. TOTP verify gate insertion
  in `post_auth::complete_auth` (peek-not-take the
  PendingAuthorize, gate on `find_active_for_user`, park
  PendingTotp + redirect to verify page). Routing wired in
  `worker::lib::main`. Recovery code redemption.
- **v0.30.0** (planned) — Polish + operations: disable flow
  (`POST /me/security/totp/disable`), cron sweep extension
  (drops unconfirmed rows older than 24h), `cesauth-migrate`
  redaction profile drops both new tables for prod→staging,
  new chapter `docs/src/deployment/totp.md` documenting
  encryption key configuration / rotation / admin reset path,
  `TOTP_ENCRYPTION_KEY` added to pre-production release gate
  in `docs/src/expert/security.md`. **ADR graduates from
  Draft to Accepted** at this point — the design has been
  validated end-to-end by the prior releases.

Each operator-deploy boundary leaves the system in a
coherent state. v0.27.0 → v0.28.0 is code-only. v0.28.0 →
v0.29.0 is route-additive. v0.29.0 → v0.30.0 is
polish-additive. No release introduces breaking changes to
schema or wire surface.

## Acceptance criteria for v0.30.0

- ADR graduates from `Draft` to `Accepted`.
- All prior-release library/storage/presentation tests pass
  plus HTTP handler tests added in v0.29.0.
- Enrollment flow's QR code renders; manual flow works.
- TOTP verify gate fires after Magic Link primary auth iff
  the user has a confirmed TOTP authenticator.
- Recovery code redemption flow works.
- Pre-confirmation pruning cron extension is live.
- Discovery doc and `docs/src/expert/oidc-internals.md`
  unchanged (TOTP is not visible at the OIDC layer; it's a
  pre-token gate).
- Redaction profile drops `totp_authenticators` and
  `totp_recovery_codes` for prod→staging.
- New chapter `docs/src/deployment/totp.md` documents the
  encryption key configuration, key rotation, and operator
  reset path.

## See also

- [ADR-002](./002-user-as-bearer-mechanism.md) — user-as-bearer
  mechanism, the auth-cookie pattern that TOTP fits into.
- [ADR-004](./004-anonymous-trial-promotion.md) — anonymous
  trial promotion, the cron sweep we extend in Q9.
- [`docs/src/expert/email-verification-audit.md`](../email-verification-audit.md)
  — v0.25.0 audit; the email_verified column is what TOTP
  composes on top of (TOTP enrollment requires
  email_verified=true; v0.27.0 enforces).
- RFC 6238 — TOTP definition.
- RFC 4226 — HOTP, the underlying construction.
