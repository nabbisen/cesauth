# Data migration

cesauth ships a first-class tool for moving deployment data from
one Cloudflare account to another: `cesauth-migrate`. This is the
operator-facing chapter; the design is in
[ADR-005](../expert/adr/005-data-migration-tooling.md) and the
on-disk format is documented in the `cesauth_core::migrate`
module.

## Status as of v0.20.0

| Subcommand | Status |
|---|---|
| `cesauth-migrate list-profiles` | Implemented (v0.19.0) |
| `cesauth-migrate export`        | **Implemented (v0.20.0, this release)** |
| `cesauth-migrate verify`        | **Implemented (v0.20.0)** |
| `cesauth-migrate import`        | Skeleton only — explanatory error. Lands in v0.21.0. |

This means as of v0.20.0 you can produce signed `.cdump` files
from a live D1 source and verify them on the destination operator's
host. The import path (writing the dump back into a destination
D1) ships in v0.21.0; until then, a v0.20.0 dump is the canonical
"snapshot for migration" artifact, but the destination side
applies it via manual `wrangler d1 execute` or the v0.21.0 tool
when it lands.

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
   the import phase (v0.21.0+).
4. If the fingerprints **do not match** → DO NOT import.
   - Investigate the transmission path.
   - Re-request a fresh export from the source.
   - File an incident if you suspect deliberate tampering.

`verify` is idempotent and free; run it again after any
suspicion that the file might have been touched.

## Limitations as of v0.20.0

- **`--tenant` filtering is not yet implemented.** Export is
  whole-database. Filtered exports land in v0.22.0.
- **Resume on interruption is not implemented.** A
  Ctrl-C during export leaves a partial file behind; delete it
  and start over. Resume support lands in v0.22.0.
- **No incremental dumps.** Every export is a fresh full
  snapshot. Not on the roadmap; the use cases for incremental
  migration are narrow enough that the engineering cost
  exceeds the benefit.
- **Progress reporting is per-table, not per-row.** A 50 MB
  `users` table will appear to "hang" during the wrangler
  fetch. No streaming progress until v0.22.0.

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
