# Data migration

cesauth ships a first-class tool for moving deployment data from
one Cloudflare account to another: `cesauth-migrate`. This is the
operator-facing chapter; the design is in
[ADR-005](../expert/adr/005-data-migration-tooling.md) and the
on-disk format is documented in the `cesauth_core::migrate`
module.

## Status as of v0.21.0

| Subcommand | Status |
|---|---|
| `cesauth-migrate list-profiles` | Implemented (v0.19.0) |
| `cesauth-migrate export`        | Implemented (v0.20.0) |
| `cesauth-migrate verify`        | Implemented (v0.20.0) |
| `cesauth-migrate import`        | **Implemented (v0.21.0, this release)** |

This means the cross-account move workflow is end-to-end functional
as of v0.21.0. The polish work (resume support, multi-tenant
filtered exports, the staging-refresh combinator, native HTTP API
client, per-row progress) lands in v0.22.0.

## When to use this versus `wrangler d1 export`

| Need | Use |
|---|---|
| Same-account D1 backup | [`wrangler d1 export`](./backup-restore.md). Faster, no signature ceremony, raw SQL is fine. |
| Cross-account move | `cesauth-migrate`. Schema-aware, signed, secrets coordination. |
| Prod → staging refresh with PII redaction | `cesauth-migrate --profile prod-to-staging`. The `sed`-script-in-docs pattern from v0.18.1 backup-restore is now obsolete. |
| Recovery from corrupted state | `wrangler d1 execute --file <restored.sql>`. Forward-fix migration is usually faster than full migration tooling. |

The rule of thumb: `cesauth-migrate` shines when **the destination is
a different cesauth deployment**. For "I want a backup of *this*
deployment", reach for `wrangler d1 export` first.

## Installing the CLI

The `cesauth-migrate` binary is a host-side tool that runs on
operator machines, not inside the Worker. Install it from the repo
checkout:

```sh
cd /path/to/cesauth
cargo install --path crates/migrate
which cesauth-migrate     # confirm it's on $PATH
```

Or build without installing:

```sh
cargo build --release -p cesauth-migrate
./target/release/cesauth-migrate --help
```

The binary needs:

- **`wrangler` on `$PATH`**. The exporter shells out to
  `wrangler d1 execute --remote --json`, so wrangler must be
  installed and authenticated against the source account. The
  v0.20.0 exporter uses wrangler exclusively; a native
  Cloudflare HTTP API client lands in a future release.
- **Network access from the operator host to Cloudflare**.

## Exporting

The end-to-end happy path:

```sh
cesauth-migrate export \
  --output  cesauth-prod-2026-04-28.cdump \
  --account-id      "abc123def456..." \
  --database        cesauth-prod
```

What happens:

1. The CLI prints the **public-key fingerprint** to stderr —
   16 hex chars, deterministic for this dump. Read this aloud
   to the importing operator over a separate channel (Slack,
   phone, in-person). They will compare it to what their
   `cesauth-migrate verify` prints; a mismatch means the dump
   was substituted in transit.
2. The CLI walks the cesauth tables in topological order
   (parents before children — `tenants` before `users`,
   `users` before `memberships`, etc.) and writes them to the
   `.cdump`. Per-table progress reports go to stderr.
3. The CLI prints the **secrets-coordination checklist** at
   the end. The destination operator must mint these before
   importing.

The output file is a single text file: a JSON manifest line
followed by NDJSON payload rows. It can be reviewed with
`head -5 file.cdump | jq` for the manifest, or
`cesauth-migrate verify --input file.cdump` for a structured
summary.

### Refusing to clobber

The exporter refuses if `--output` points at an existing file.
This is intentional: a previous run that the operator forgot
about is the most common cause of "two dumps with the same
name in the move folder", and silent overwrite produces
diagnostics that are hard to disentangle.

If you really want to overwrite, delete the existing file
first.

### With redaction (prod → staging)

```sh
cesauth-migrate export \
  --output     cesauth-staging-refresh.cdump \
  --account-id "abc123def456..." \
  --database   cesauth-prod \
  --profile    prod-to-staging
```

The profile is recorded in the dump's manifest — the importer
will surface "this dump was redacted" in its summary. If the
destination operator passes `--require-unredacted` to a future
import command, a redacted dump is refused.

List available profiles:

```sh
cesauth-migrate list-profiles
```

The two built-ins as of v0.20.0:

- **`prod-to-staging`** — replaces `users.email` with synthetic
  `anon-<hash>@example.invalid` values that preserve the
  UNIQUE invariant. Drops `users.display_name`. Authenticator
  public-key material is preserved (it's not PII; passkey
  challenges live in DO state and aren't dumped).
- **`prod-to-dev`** — stricter than `prod-to-staging`: also
  redacts OIDC client display names and clears admin token
  names. Use for `wrangler dev`-bound dumps.

### What's NOT in the dump

ADR-005 §Q1 forbids the dump from carrying secrets. After
exporting, the destination operator must mint:

- `JWT_SIGNING_KEY` — Ed25519 PKCS#8 PEM. The dump carries
  the **public-key half** of the source's signing keys (so
  destination clients verifying access tokens issued
  pre-migration can still validate them through the grace
  window). The destination mints a fresh private key and
  publishes its public half via the existing JWKS endpoint.
- `SESSION_COOKIE_KEY` — 48 random bytes, base64.
- `ADMIN_API_KEY` — opaque bearer.
- `MAGIC_LINK_MAIL_API_KEY` (if Magic Link is enabled).
- `TURNSTILE_SECRET` (if Turnstile is enabled).

R2 audit objects are not in the dump either. Audit history
stays at the source unless the operator separately replicates
the R2 bucket.

DO state (active sessions, refresh-token families, auth
challenges, rate-limit counters) is not in the dump. After
migration, every user re-authenticates (which is the point —
the migration is a fresh-start moment).

## Verifying

The destination operator runs `verify` before considering the
dump trustworthy:

```sh
cesauth-migrate verify --input cesauth-prod-2026-04-28.cdump
```

Sample output:

```
Dump format:       v1
cesauth version:   0.20.0
Schema version:    6 (this build supports 6)
Source account:    abc123def456...
Source database:   cesauth-prod
Exported at:       1714287000 (Unix)
Redaction profile: (none — full unredacted dump)

Public-key fingerprint: 7a3f1e2d9c8b4f6a
  ↑ confirm this matches the value the EXPORTING operator printed at export time.
    If it does not match, refuse to import.

Tables:
  tenants                        3 rows
  organizations                  5 rows
  groups                         12 rows
  users                          247 rows
  ... (etc)

Total: 1042 rows across 18 tables
Signature verified ✓
```

The fingerprint comparison is the load-bearing step. **Do not
proceed to import if the fingerprint differs from what the
exporting operator told you.** Either the dump was tampered
with in transit, or you have the wrong file.

`verify` does not need any D1 contact — you can run it from a
laptop with no Cloudflare credentials. The only thing it
touches is the `.cdump` file.

### What `verify` checks

1. **Format version** is recognized. Refuses dumps from a
   future cesauth release whose format this build doesn't know.
2. **Per-table SHA-256s** match what's declared in the manifest.
   Localizes any corruption to a specific table.
3. **Whole-payload SHA-256** matches what's declared. Catches
   payload-level substitution.
4. **Signature** verifies against the manifest's embedded
   public key.

Any failure is reported with a typed error category — the CLI
exits non-zero and prints the kind. A `SignatureMismatch` is a
security event (loud, postmortem-grade); a `Parse` error is a
corruption event (retransmit); a `TableHashMismatch` is a
storage event (likely disk corruption between transit and
verify).

## Operator runbook (export)

Pre-flight before invoking `cesauth-migrate export`:

1. **Decide the maintenance window**. The export itself is read-
   only against the source — it doesn't take writes offline.
   But changes to source data after export are NOT in the dump,
   so plan to either (a) take source writes offline at export
   time, or (b) accept that recent activity won't migrate.
2. **Confirm wrangler authentication.** `wrangler whoami`
   should show the source account.
3. **Confirm disk space.** The dump is roughly 1.5× the size
   of the source D1 (UTF-8 JSON is verbose). For a 100 MB D1,
   plan ~150 MB.
4. **Pick the dump filename to encode the source account +
   date**: `cesauth-<env>-<YYYYMMDD>.cdump`. A folder of dumps
   from different environments without dates is a forensic
   nightmare during incident response.
5. **Brief the destination operator** on the upcoming
   handshake. They need to be ready to compare the
   fingerprint when the dump arrives.

During the run:

- Watch the per-table progress lines on stderr. A table that
  doesn't report its row count within a reasonable time
  suggests wrangler is hung; abort with Ctrl-C and investigate.

After:

- **Note the fingerprint somewhere persistent** (incident
  channel, runbook, password manager). The exporting host's
  terminal scrollback is not durable enough.
- **Transmit the dump out-of-band from the fingerprint.** If
  both the dump and the fingerprint travel through the same
  channel, a compromised channel can substitute both.
- The exporting host can be wiped after transmission — there's
  nothing recoverable on it (the signing key was discarded
  after `finish`).

## Operator runbook (verify)

When the dump arrives at the destination:

1. **Run `cesauth-migrate verify`** before doing anything else
   with the file.
2. **Compare fingerprints out-of-band** (Slack call, phone, in
   person). If the exporting operator dictated a value via
   email, treat that with skepticism — email is the
   most-likely-tampered channel.
3. If the fingerprints match → the dump is intact. Proceed to
   the import phase (next section).
4. If the fingerprints **do not match** → DO NOT import.
   - Investigate the transmission path.
   - Re-request a fresh export from the source.
   - File an incident if you suspect deliberate tampering.

`verify` is idempotent and free; run it again after any
suspicion that the file might have been touched.

## Importing

The end-to-end happy path:

```sh
cesauth-migrate import \
  --input      cesauth-prod-2026-04-28.cdump \
  --account-id "destination-account-id..." \
  --database   cesauth-prod-new \
  --commit
```

The `--commit` flag is **required** to actually write rows. Without
it, the importer runs through every step (verify, handshake,
staging, invariant checks, violation report) and then rolls back —
useful for rehearsing before the real move window.

### What happens

The importer is conservative by design. It does not write a single
row to the destination D1 until five gates have all passed:

1. **Verification.** `verify` runs against the dump in full
   (signature + per-table SHA-256 + whole-payload SHA-256). A
   tampered dump aborts here, before any operator prompt is
   shown — the runbook page below assumes you've already verified
   separately.
2. **Fingerprint handshake.** The importer prints the dump's
   public-key fingerprint and asks `[y/N]`. The operator must type
   `y` after confirming — over a separate channel — that the
   fingerprint matches what the exporting operator printed at
   export time. EOF on stdin (scripted invocations) is treated as
   decline; this is intentional, the import requires a human in
   the loop.
3. **Destination secret pre-flight.** `wrangler secret list`
   must show `JWT_SIGNING_KEY` already set at the destination.
   ADR-005 §Q6 — the destination operator mints fresh secrets
   *before* invoking import; the importer refuses to commit
   otherwise.
4. **Schema invariant checks.** Every row passes through the
   default invariant set:
   - `users.tenant_id` references a tenant present in the dump.
   - Memberships' `user_id` and container_id (`tenant_id` /
     `organization_id` / `group_id`) reference present rows.
   - `role_assignments.role_id` and `user_id` reference present
     rows.

   Each violating row is collected into a report. Rows are still
   *staged* (queued in memory) — they're just blocked from
   committing.
5. **Final commit confirmation.** Even with everything clean,
   the importer asks one more `[y/N]` before writing. The prompt
   names the destination database for last-minute "wait, wrong
   account" catches.

If any gate fails or the operator declines, the staged rows are
discarded via the sink's rollback. The destination D1 is
untouched.

### Sample successful import

```
Reading cesauth-prod-2026-04-28.cdump...

Dump verified ✓
  cesauth version:   0.21.0
  Source account:    abc123def456...
  Schema version:    6 (this build supports 6)
  Redaction profile: (none — full unredacted dump)

Public-key fingerprint of this dump:
    7a3f1e2d9c8b4f6a

Confirm with the EXPORTING operator (over a separate channel)
that this fingerprint matches what they printed at export time.

Does the fingerprint match? Proceed with import? [y/N] y
Checking destination has required secrets set...
  JWT_SIGNING_KEY: set ✓

Staging rows to destination D1 `cesauth-prod-new`...

Import staging complete.
  Rows seen:    1042
  Rows staged:  1042
  Violations:   0

Commit 1042 rows to destination `cesauth-prod-new` (account dest-...)? [y/N] y

Committing to destination...

✓ Import complete. 1042 rows written to D1 `cesauth-prod-new`.

Post-commit checklist:
  1. Update destination wrangler.toml's JWT_KID to match the new signing key.
  2. Deploy: wrangler deploy --env production
  3. Smoke-test: curl -s https://<destination>/.well-known/openid-configuration
  4. Update DNS to direct user traffic to the destination.
  5. Source-side: revoke old admin tokens, retire old signing keys per ADR-005 §Q6.
```

### Handling violations

A violation report means the dump's row references don't all
resolve. Most often this is one of:

- The dump came from a partial source — a tenant was being
  deleted while the export ran, and one of its memberships
  referenced the half-deleted user.
- A schema bug at the source somehow let dangling references
  exist (FK enforcement was off or there's a race condition).
- The dump was re-written by hand and someone made a typo.

The importer's default behavior — refuse commit on any
violation — is the right answer for production restores. For
recovery scenarios where partial integrity is acceptable
(e.g., reconstructing what data you can after a corruption
event), pass `--accept-violations` to commit despite the
report:

```sh
cesauth-migrate import \
  --input recovery.cdump \
  --account-id ... --database ... \
  --commit \
  --accept-violations
```

`--accept-violations` does NOT skip the violation report — it's
still printed for the audit trail. It only changes the gate.

### Refusing redacted dumps for production

A redacted dump (from `--profile prod-to-staging` or
similar) is fine for staging, dangerous for a production
restore. To make sure a stray redacted dump can't accidentally
land in production, pass `--require-unredacted`:

```sh
cesauth-migrate import \
  --input ... --account-id ... --database ... --commit \
  --require-unredacted
```

The importer aborts pre-staging if the dump's manifest names a
redaction profile.

### Operator runbook (import)

Pre-flight, in order:

1. **Generate destination secrets.** `JWT_SIGNING_KEY`,
   `SESSION_COOKIE_KEY`, `ADMIN_API_KEY`, plus
   `MAGIC_LINK_MAIL_API_KEY` / `TURNSTILE_SECRET` if those
   features are enabled. Push each via
   `wrangler secret put --env production`.
2. **Apply schema migrations** to the destination D1.
   `wrangler d1 migrations apply <destination> --remote`.
3. **Confirm the destination D1 is empty** (or expected to
   merge cleanly with the dump's contents). The importer
   does not detect pre-existing rows; an INSERT collision
   surfaces as a wrangler error mid-commit.
4. **Verify the dump first.** Run `cesauth-migrate verify`
   on the file before invoking `import`. If verify fails,
   import would too.
5. **Schedule a maintenance window.** The actual commit is
   fast (one batched wrangler call per table) but the
   pre-commit phases — fingerprint handshake, secret
   pre-flight, invariant checks — wait on operator input.
   Plan ~10 minutes of attention.

During the run:

- Read the fingerprint **out loud** to the exporting operator;
  do not paste it into a shared channel and ask them to look.
  The point is to defeat substitution attacks where the
  attacker controls one channel.
- If the violation report has any entries, **read every
  violation** before deciding to `--accept-violations`. The
  CLI prints up to 10; if there are more, that's a strong
  signal the dump came from a corrupted source and you should
  re-export rather than force-commit.

After the commit:

- Walk the post-commit checklist the importer printed. The
  destination is **not yet operational** — it has the data,
  but the deployed Worker still points at the source.
- Run a smoke test against the destination's URL before
  switching DNS.
- Once DNS is switched, the source can be retired. Revoke
  source admin tokens, retire source signing keys
  (after the configured grace window).

## Limitations as of v0.21.0

- **`--tenant` filtering is not yet implemented.** Export is
  whole-database. Filtered exports land in v0.22.0.
- **Resume on interruption is not implemented.** A
  Ctrl-C during export leaves a partial file behind; delete it
  and start over. Mid-import Ctrl-C rolls back staged rows
  without writing — safe to retry from scratch.
  Streaming-resume support lands in v0.22.0.
- **No incremental dumps.** Every export is a fresh full
  snapshot. Not on the roadmap; the use cases for incremental
  migration are narrow enough that the engineering cost
  exceeds the benefit.
- **Progress reporting is per-table, not per-row.** A 50 MB
  `users` table will appear to "hang" during the wrangler
  fetch. No streaming progress until v0.22.0.
- **Native Cloudflare HTTP API client is not implemented.**
  Both export and import shell out to `wrangler`. A native
  client (no wrangler dependency, faster, fewer subprocess
  spawn costs) lands in v0.22.0.
- **Schema invariant set is fixed.** v0.21.0 ships four
  default checks (user→tenant, membership→user,
  membership→container, role_assignment→role+user).
  Custom invariants supplied at the CLI are not yet
  exposed; the library accepts a slice but the CLI
  hardcodes `default_invariant_checks()`. Custom-check
  registration lands when an operator hits a case the
  defaults miss.
- **Email-uniqueness-within-tenant is not checked.** This
  is the one obvious invariant the v0.21.0 set deliberately
  omits, because a redacted dump may collapse emails into
  shapes that look duplicate but resolve under the
  destination's redaction profile (which is identity, not a
  re-redaction). A future check that's redaction-aware lands
  in v0.22.0 or later.

## See also

- [ADR-005](../expert/adr/005-data-migration-tooling.md) — the
  design rationale.
- [Backup &amp; restore](./backup-restore.md) — when
  `wrangler d1 export` is the right answer instead.
- [Disaster recovery](./disaster-recovery.md) §Scenario 4 — the
  cross-account compromise scenario where `cesauth-migrate` is
  one of the recovery primitives.
- `cesauth_core::migrate` module documentation — the on-disk
  format spec.
