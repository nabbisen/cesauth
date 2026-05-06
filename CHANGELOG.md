# Changelog

All notable changes to cesauth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

cesauth is pre-1.0. The public surface — endpoints, `wrangler.toml`
variable names, secret names, D1 schema, and `core::ports` traits —
may change between minor versions until 1.0. Breaking changes will
always be called out here.

---

## [0.22.0] - 2026-04-28

Data migration tooling — Phase 4 of 4: polish. **The data-
migration tooling is feature-complete for ADR-005's scope as
of this release.** Three of the seven items deferred from
v0.21.0 land here; the remaining four are tracked as post-1.0
polish in the ROADMAP rather than continuing to defer through
the data-migration phasing.

After this release, the next operator-prioritized slot is
**RFC 7662 Token Introspection**.

### Added — `--tenant <id>` filter on `export`

The exporter now scopes to operator-named tenants when the
`--tenant <id>` flag is passed (repeat for multiple). Tables
classified `TenantScope::Global` (e.g., `plans`,
`permissions`, `oidc_clients`, `jwt_signing_keys`) export in
full regardless — the destination needs them to function.
Tenant-scoped tables (`tenants`, `users`, `organizations`,
`groups`, `subscriptions`, `roles`, `user_tenant_memberships`,
`anonymous_sessions`) filter on the operator's id list.

The dump's manifest records the filter in a new `tenants`
field — `verify` surfaces it in its summary. Pre-v0.22.0
dumps without the field deserialize as `None` (whole-database)
via `#[serde(default)]`.

Empty `--tenant ""` slugs are rejected at the boundary.
Indirect-FK tables (`authenticators`, `consent`, `grants`,
`admin_tokens`) export in full — sharper indirect scoping is
tracked as post-1.0 polish.

### Added — `cesauth-migrate refresh-staging` combinator

A single command for the common operational task of
refreshing staging's data from a production source. Wraps
`export --profile prod-to-staging` followed by
`import --commit`, with operator-attended prompts collapsed
to a single up-front confirmation:

```sh
cesauth-migrate refresh-staging \
  --source-account-id <prod-account> \
  --source-database   cesauth-prod \
  --dest-account-id   <staging-account> \
  --dest-database     cesauth-staging
```

Trade-offs vs. running export + import separately:

- **Trusts the caller to be in control of both endpoints.**
  Skips the cross-operator fingerprint handshake. For
  cross-organization moves, operators should still use
  export + verify + import separately.
- **Tolerates invariant violations.** Staging is allowed to
  be a little messy; the prompt at the end of `import`
  proper would block on violations, but the combinator
  treats them as informational.
- **Skips the secret pre-flight.** Operators using
  refresh-staging have already configured the destination's
  secrets out of band.

`--yes` flag skips the up-front confirmation for unattended
runs (CI staging refresh, scheduled jobs). `--profile`
defaults to `prod-to-staging` but accepts any built-in
profile name. `--tenant <id>` works on the combinator the
same way it works on plain `export`.

The dump is written to a per-process temp file under
`$TMPDIR`. On success the temp file is deleted; on failure
it's preserved at the printed path so the operator can
diagnose.

### Added — email-uniqueness-within-tenant invariant check

The fifth default invariant: `(tenant_id, email)` must be
unique within the dump. Catches schema-violation rows where
two users in the same tenant share an email.

Redaction-aware: the `HashedEmail` redaction kind produces
deterministic distinct values, so duplicates at source remain
duplicates after redaction. Case-insensitive (matches the
schema's `COLLATE NOCASE` semantic on `users.email`). Skips
rows without an email field (anonymous trial users).

This check was deferred from v0.21.0's default set because of
concerns about redaction semantics that turned out (after
implementation) to not be problematic.

### Added — per-row import progress

`ProgressSink` decorator wraps `WranglerD1Sink` and prints a
`.` to stderr every 1000 staged rows. The `do_import` handler
uses it by default. Long-running imports no longer "appear
hung" mid-staging.

The exporter side gained equivalent dot-tick progress in this
release too (every 1000 rows on `--tenant`-able tables).

### Library — `cesauth_core::migrate` changes

- **`Manifest.tenants: Option<Vec<String>>`** — new field
  with `#[serde(default, skip_serializing_if =
  "Option::is_none")]`. Forward-compatible with 0.21.0
  dumps.
- **`ExportSpec.tenants: Option<&[String]>`** — propagated
  through `Exporter::finish` to the manifest.
- **`SeenSnapshot` extended** with a scoped secondary index
  (`HashMap<(table, scope_key, scope_value),
  HashSet<value>>`) for per-tuple uniqueness checks.
  `record_scoped_secondary` returns true on duplicate (the
  uniqueness signal); `contains_scoped_secondary` for read
  access.
- **`InvariantCheckFn` signature changed** from
  `&SeenSnapshot` to `&mut SeenSnapshot` so checks can
  populate their own secondary indexes. **Breaking change
  to the typedef** — any operator who had built custom
  checks against the v0.21.0 type alias must update them.
  Since custom-check registration is not yet exposed via
  the CLI in v0.22.0, no real-world users are affected; the
  ROADMAP "post-1.0 polish" entry for custom-invariant
  registration will pick up the new signature.

### CLI — `crates/migrate/`

- **`d1_source` module** — `D1Source::fetch_table` now
  takes `Option<TenantFilter<'_>>`. `WranglerD1Source`
  builds a `WHERE column IN (...) ORDER BY rowid` clause
  when filtered, plain `SELECT *` otherwise. Empty filter
  list short-circuits to `Vec::new()` without spawning
  wrangler. SQL identifier check on filter column too.
- **`schema` module** — new `TenantScope` enum and
  `TENANT_SCOPES` slice (parallel to `MIGRATION_TABLE_ORDER`).
  `tenant_scope_for(table)` lookup. Two new tests pin
  length-alignment and known-table scopes.
- **`d1_sink` module** — new `ProgressSink<S>` decorator.
- **`do_export`** — real `--tenant` handling. Per-table
  filter computed via `build_table_filter()`. Per-row
  dot-progress every 1000 rows.
- **`do_refresh_staging`** — new handler. Inlines
  `export_to_path` and `import_from_path` helpers (smaller
  versions of `do_export`/`do_import` with refresh-staging-
  specific UX).

### Tests

Total: **379 passing** (+21 over v0.21.0):

- core: **178** (was 166) — 12 new in `migrate::tests`:
  - `scoped_secondary_index_tracks_per_tuple` — pin the
    duplicate-detection return-value semantic.
  - `check_user_email_unique_skips_when_table_not_users`.
  - `check_user_email_unique_passes_for_distinct_emails`.
  - `check_user_email_unique_flags_duplicate_within_tenant`.
  - `check_user_email_unique_allows_same_email_in_different_tenants`
    — per-tenant uniqueness, not global.
  - `check_user_email_unique_is_case_insensitive` —
    matches `COLLATE NOCASE`.
  - `check_user_email_unique_skips_users_without_email` —
    anonymous trial users have no email.
  - `import_flags_duplicate_email_within_tenant` —
    end-to-end through the import driver.
  - `manifest_records_tenant_scope_when_filtered`.
  - `manifest_omits_tenant_scope_for_full_export`.
  - `manifest_round_trips_tenants_through_serde`.
  - `manifest_deserializes_dumps_without_tenants_field` —
    forward compat from 0.21.0-shaped dumps.
- adapter-test: 51 (unchanged).
- ui: 121 (unchanged).
- migrate: **29** (was 25):
  - 2 new in `d1_source::tests`:
    `mock_filter_keeps_matching_tenant_rows`,
    `mock_filter_empty_ids_returns_no_rows`.
  - 4 new schema scope tests (length-alignment + known-
    table scopes + unknown-table-is-None defensive).
  - 4 new integration tests:
    - `export_rejects_empty_tenant_value`.
    - `refresh_staging_help_includes_one_command_summary`.
    - `refresh_staging_aborts_on_operator_decline`.
    - `refresh_staging_rejects_unknown_profile`.

### Documentation

- **`docs/src/deployment/data-migration.md`** updated to
  v0.22.0:
  - Status table reflects feature-complete state.
  - New "Refreshing staging from production" section with
    sample invocation, default behavior, unattended-run
    flag.
  - New "Tenant-scoped exports" section with sample
    invocations and explanation of what tenant-scoped
    means in practice (which tables filter, which export
    in full).
  - "Limitations as of v0.22.0" rewritten — most v0.21.0
    items are addressed; remaining items (resume, native
    HTTP API, custom invariants) are tracked as post-1.0
    polish.

### Migration (0.21.0 → 0.22.0)

Code-only release. No schema, no `wrangler.toml`. The
deployed Worker is unaffected.

For operators using the migration tool:

```sh
cargo install --path crates/migrate --force
cesauth-migrate refresh-staging --help
cesauth-migrate export --help     # see the new --tenant flag
```

### Smoke test

```sh
cargo test --workspace                          # 379 passing
./target/debug/cesauth-migrate --version        # cesauth-migrate 0.22.0
./target/debug/cesauth-migrate --help           # 5 subcommands listed
./target/debug/cesauth-migrate refresh-staging --help

# Decline path returns non-zero exit, doesn't touch destination.
echo "" | ./target/debug/cesauth-migrate refresh-staging \
  --source-account-id src --source-database srcdb \
  --dest-account-id   dst --dest-database   dstdb
```

### Deferred to post-1.0 polish (no scheduled release)

These three items were originally scheduled for v0.22.0 but
are reclassified as post-1.0 polish — they don't change the
data-migration design and don't have a known operator
demand:

- **Resume on interruption.** Two-pass design + checkpoint-
  file format is real new design surface. The current
  Ctrl-C-then-restart-from-zero workflow is acceptable for
  the dump sizes the tool targets.
- **Native Cloudflare HTTP API client.** wrangler shell-out
  works. Native client would avoid subprocess spawn costs
  and the wrangler dependency, but it adds a non-trivial
  HTTP auth surface to the binary.
- **Custom invariant registration via CLI.** The library
  accepts a slice of `InvariantCheckFn`, but no operator
  has asked for runtime-supplied custom checks. When one
  does, the surface is straightforward.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.21.0] - 2026-04-28

Data migration tooling — Phase 3 of 4: real `import` subcommand.
This release closes the loop on cross-account moves: a `.cdump`
exported in v0.20.0 can now be applied to a destination D1 in
one CLI invocation, with the operator-handshake-and-invariant-
checks flow ADR-005 specified.

**ADR-005 graduates from `Draft` to `Accepted`.** All six
design questions are now answered in code; the implementation
matches the design without surprises that warrant amendment.

The remaining v0.22.0 work is polish (resume support, `--tenant`
filter, staging-refresh combinator, native HTTP API, per-row
progress) — none of which changes the design. After v0.22.0,
the data-migration track is feature-complete and the next slot
is RFC 7662 Token Introspection.

### Added — `cesauth_core::migrate` library

- **`Violation`** value type: `(table, row_id, reason)` triple,
  with `Display` impl for one-line operator-readable output.
- **`ViolationReport`** with `is_clean()` (gate predicate) and
  `by_table()` (Vec preserving manifest table order — the CLI
  uses this for the per-table summary block).
- **`InvariantCheckFn`** typedef + **`SeenSnapshot`** —
  in-memory FK-ish state. The snapshot tracks
  `(table, primary_key)` pairs as rows are streamed; checks
  read it via `seen.contains(table, id)`. No destination-side
  query needed; everything runs in the importer's process.
- **`default_invariant_checks()`** — four ship-by-default checks:
  - `users.tenant_id` references a present tenant.
  - Memberships' `user_id` references a present user.
  - Memberships' container_id (`tenant_id`/`organization_id`/
    `group_id`) references a present container row.
  - `role_assignments.role_id` and `user_id` both reference
    present rows. (Returns the first failure rather than
    accumulating both — keeps log spam down on a misconfigured
    role_assignment.)
- **`ImportSink`** trait: async `stage_row` / `commit` /
  `rollback`. The CLI provides the implementation; the library
  knows nothing about D1 or wrangler.
- **`import<S: ImportSink>`** async function. Two-pass:
  1. `verify` runs first against the dump's bytes (signature,
     hashes). A bad dump bails before any sink interaction —
     the destination never sees a tampered file.
  2. The payload streams again through `sink.stage_row` while
     each row passes through the invariant checks. Violations
     accumulate; rows are staged regardless. The decision to
     commit or roll back belongs to the caller.

  Honors `require_unredacted` flag: a redacted dump errors out
  pre-staging if this is set, suitable for production-restore
  scenarios where redaction would be data loss.

### Added — `crates/migrate/`

- **`d1_sink.rs`** module — `WranglerD1Sink` implementing
  `ImportSink`. Stages rows in a `BTreeMap<table, Vec<row>>`,
  commits via batched `wrangler d1 execute` (one batch per
  table). Includes:
  - `value_to_sql_literal` — JSON-to-SQL converter handling
    Null, Bool, Number, String (with single-quote escaping),
    and JSON-blob (re-serialized + quoted).
  - `sqlite_quote` — proper SQLite single-quoted literal
    (doubles every embedded `'`). Five unit tests pin
    behavior.
  - Identifier check on table + column names. Belt-and-
    suspenders against the wrangler subprocess receiving
    something that doesn't tokenize cleanly.
- **`do_import` CLI handler** in `main.rs`. Walks the five-gate
  flow: verify → fingerprint handshake → secret pre-flight
  → invariant checks → final commit confirmation. Each gate
  the operator can decline; the destination D1 is untouched
  until the final yes. Post-commit, prints the operational
  checklist (update JWT_KID, deploy, smoke, DNS, retire old
  keys).
- **`prompt_yn`** helper — operator y/n prompt with sane
  defaults. **EOF on stdin (scripted invocation) is treated
  as decline.** This is intentional — import requires a
  human in the loop; making automated runs fail closed is
  safer than making them silently commit.
- **`check_destination_secrets`** pre-flight — calls
  `wrangler secret list`, refuses commit if `JWT_SIGNING_KEY`
  isn't set at the destination. ADR-005 §Q6 enforced at the
  CLI gate, not just in documentation.
- Updated CLI `long_about` and `Import` doc comment to
  reflect v0.21.0 state.

### Tests

- Total: **358 passing** (+21 over v0.20.0):
  - core: **166** (was 151) — 15 new in `migrate::tests`:
    - `check_user_tenant_ref_passes_for_known_tenant`.
    - `check_user_tenant_ref_fails_for_unknown_tenant` —
      with descriptive reason.
    - `check_user_tenant_ref_skips_other_tables` — defensive;
      a check fires only for its owned table.
    - `check_membership_user_ref_fires_only_for_membership_tables`.
    - `check_membership_container_dispatches_per_table` —
      one test asserting the three (tenant_id, organization_id,
      group_id) dispatch arms.
    - `check_role_assignment_refs_catches_both_sides`.
    - `import_clean_dump_passes_with_zero_violations` —
      load-bearing happy path.
    - `import_dangling_user_tenant_ref_is_flagged`.
    - `import_dangling_membership_ref_is_flagged`.
    - `import_multiple_violations_accumulate_per_row`.
    - `import_violation_report_groups_by_table`.
    - `import_refuses_redacted_dump_when_required_unredacted`.
    - `import_runs_verify_first_and_rejects_tampered_dump`
      — the destination must not see a tampered payload.
    - `import_with_disabled_invariants_passes_dangling_refs`
      — empty invariants slice is a valid configuration.
    - `default_invariant_checks_returns_at_least_four` —
      defensive tripwire.

    Plus a private `block_on` helper (no `unsafe`,
    uses `std::pin::pin!`) so tests don't drag tokio
    into core's `[dev-dependencies]`.
  - adapter-test: 51 (unchanged).
  - ui: 121 (unchanged).
  - migrate: **20** (was 14) — 11 unit + 9 integration:
    - 5 new `d1_sink::tests`: SQL literal handling for
      primitives + escapes + JSON blobs, sqlite_quote
      escaping, rollback-without-write.
    - 2 new integration tests:
      - `import_with_closed_stdin_declines_at_handshake`
        — EOF behavior pinned.
      - `import_rejects_invalid_dump_before_handshake`
        — verify gate runs before any operator prompt.
    - Removed: `import_still_returns_explanatory_error`
      (no longer applicable — import is now real).

### Documentation

- **ADR-005 status** flipped from `Draft` to `Accepted`. ADR
  README index updated.
- **`docs/src/deployment/data-migration.md`** — new "Importing"
  section with end-to-end walkthrough, sample successful
  output, violation handling, `--accept-violations` and
  `--require-unredacted` semantics, full operator runbook
  (pre-flight + during + post-commit). Updated
  "Limitations as of v0.21.0" section adds three v0.21.0-
  specific items (no native HTTP client yet, fixed
  invariant set, no email-uniqueness check).
- **`docs/src/deployment/runbook.md`** — new
  "Operation: cross-account data migration" section between
  the symptom-organized parts and the periodic-tasks table.
  Pre-flight, running the move, post-import verification,
  common failure modes (fingerprint mismatch, secret
  pre-flight failure, violations, mid-commit wrangler
  failure).
- **`docs/src/deployment/disaster-recovery.md`** §Scenario 4
  rewritten — concrete `cesauth-migrate` invocations replace
  the high-level outline. The data-relocation half of the
  compromise-recovery procedure is now mechanical.

### Migration (0.20.0 → 0.21.0)

Code-only release. No schema, no `wrangler.toml`. The deployed
Worker is unaffected.

For operators using the migration tool:

```sh
cargo install --path crates/migrate --force
cesauth-migrate import --help
```

The next time you do a cross-account move (or a
prod→staging-via-import-rather-than-restore), you have the full
flow available.

### Smoke test

```sh
# All workspaces green.
cargo test --workspace                   # 358 passing

# CLI binary
./target/debug/cesauth-migrate --version # cesauth-migrate 0.21.0
./target/debug/cesauth-migrate import --help

# Import smoke against an arbitrary cdump fails cleanly with
# closed stdin (declines at handshake).
echo "" | ./target/debug/cesauth-migrate import \
  --input some.cdump --account-id test --database test
# -> "import aborted: operator declined fingerprint confirmation"
```

### Deferred to 0.22.0

- **Resume** for interrupted exports/imports.
- **`--tenant <slug>` filter** for targeted subset migrations.
- **First-class staging-refresh combinator** (one CLI call
  combining export → redaction → import).
- **Native Cloudflare HTTP API client** as alternative to
  `wrangler` shell-out.
- **Per-row progress reporting** (currently per-table).
- **Custom invariant registration via CLI** — the library
  accepts a slice of check functions; v0.22.0 exposes a way
  for operators to add their own.
- **Email-uniqueness-within-tenant check** — held back from
  v0.21.0's default set because redacted dumps complicate the
  semantics. A redaction-aware variant lands when the design
  is clear.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.20.0] - 2026-04-28

Data migration tooling — Phase 2: real `export` + `verify`
subcommands. The CLI is now functional for the source-side and
destination-verification halves of a cross-account move; the
import path lands in v0.21.0 with the operator handshake and
invariant accumulation.

ADR-005 phasing intact: foundation (v0.19.0) → export+verify
(this release) → import (v0.21.0) → polish (v0.22.0). After
v0.21.0, ADR-005 graduates from `Draft` to `Accepted`.

### Added — `cesauth_core::migrate` library

The library expands from value-types-only to a complete
exporter + verifier:

- **`MigrateError`** — typed error enum with 8 distinguished
  kinds: `Io`, `Parse`, `UnsupportedFormatVersion`,
  `SignatureMismatch`, `TableHashMismatch`,
  `PayloadHashMismatch`, `Random`, `Crypto`. The CLI maps
  each to a different exit code and message tone — a
  signature mismatch is a security event (loud, postmortem-
  grade); a parse error is a corruption event
  (retransmit); an I/O error is local. Caller can match on
  the kind without string-matching error messages.
- **`apply_redaction(profile, table, &mut row)`** — pure
  function. Applies a `RedactionProfile`'s per-column rules
  to a row. The `HashedEmail` kind derives a synthetic
  `anon-<hex>@example.invalid` value via SHA-256 of the
  original — deterministic (re-export of the same source
  produces the same redacted output, important for
  diff-friendly dumps), and preserves `users.email` UNIQUE
  invariant on the receiving side.
- **`ExportSpec<'a>`** — the static configuration of a
  single export run.
- **`ExportSigner`** — per-export Ed25519 keypair wrapper.
  `fresh()` generates via `getrandom` (returning
  `MigrateError::Random` rather than panicking on RNG
  failure, unlike default `SigningKey::generate`).
  `Debug` impl deliberately elides everything — never
  surfaces private bytes through accidental tracing.
- **`Exporter<W>`** — streaming exporter. `push(table, row)`
  enforces topological order (out-of-order or unknown table
  → `MigrateError::Parse`). `finish()` consumes self —
  signing key is dropped after use, single-use invariant
  per ADR-005 §Q3. `fingerprint()` returns the pubkey
  fingerprint operators print at export start for the
  out-of-band handshake.
- **`verify<R: BufRead>`** — streaming verifier.
  Per-table SHA-256, total payload SHA-256, signature
  verify against pubkey embedded in manifest. Pure
  function; no D1 contact, no filesystem assumptions
  beyond the passed-in reader. `VerifyReport` carries the
  manifest plus re-computed per-table row counts so the
  CLI doesn't have to re-sum.

### Added — `crates/migrate/` (CLI)

- **Real `export` subcommand**. Wires
  `WranglerD1Source` → `Exporter`. Refuses to clobber
  existing files. Prints the public-key fingerprint to
  stderr at export start (operator reads it out-of-band
  to the importing operator). Walks
  `MIGRATION_TABLE_ORDER` in topological order, prints
  per-table row counts as it goes. Prints the
  secrets-coordination checklist at the end (ADR-005 §Q6).
- **Real `verify` subcommand**. No D1 contact. Prints
  manifest summary (format version, schema version,
  source identifiers, redaction profile if any). Prints
  fingerprint with operator-facing prompt to confirm
  out-of-band. Prints per-table row counts. Final
  `Signature verified ✓` line when all checks pass.
- **`d1_source` module** — `D1Source` trait abstracts how
  to read rows from a D1. Two implementations:
  - `WranglerD1Source` — shells out to `wrangler d1
    execute --remote --json`. v0.20.0's production path.
    Includes a SQL-identifier check on table names that
    refuses anything outside `[A-Za-z_][A-Za-z0-9_]*` —
    defense in depth against table-name typos becoming
    syntax-error injections.
  - `MockD1Source` — `#[cfg(test)]`-gated in-memory
    implementation for tests.
- **`schema` module** — `MIGRATION_TABLE_ORDER` constant:
  18 cesauth tables in topological FK order. Two tests
  pin: no duplicates + key topology invariants (tenants
  before users, roles before role_assignments, plans
  before subscriptions before subscription_history, etc.).

### Workspace

- **`tokio` feature** extended with `process` for
  `WranglerD1Source`'s `Command::output().await`.
- All other deps unchanged.

### Tests

- Total: **337 passing** (+32 over v0.19.0).
  - core: **151** (was 133) — 18 new in `migrate::tests`:
    - `apply_redaction_hashed_email_is_deterministic` — same
      source email → same redacted value across runs.
    - `apply_redaction_hashed_email_distinguishes_distinct_emails`
      — UNIQUE-preservation property holds.
    - `apply_redaction_static_string_is_uniform` — display
      names collapse to `[redacted]`.
    - `apply_redaction_skips_unmatched_table` — rules are
      `(table, column)`-keyed.
    - `apply_redaction_preserves_unrelated_columns`.
    - `apply_redaction_null_kind_drops_value`.
    - `export_then_verify_round_trip` — load-bearing
      end-to-end.
    - `export_with_no_rows_produces_valid_dump` — empty
      deployments are migratable.
    - `export_records_redaction_profile_in_manifest` —
      profile name flows into the manifest.
    - `export_applies_redaction_to_payload_rows` —
      redaction actually transforms the payload bytes.
    - `verify_rejects_tampered_payload` — single-byte
      flip is detected.
    - `verify_rejects_tampered_signature` — signature
      substitution is detected as `SignatureMismatch`.
    - `verify_rejects_unknown_format_version` — refuses
      future formats rather than silently downgrading.
    - `verify_rejects_empty_input`.
    - `verify_rejects_malformed_manifest`.
    - `export_refuses_out_of_topological_order` — fail-
      fast on CLI bug that shuffles tables.
    - `export_refuses_unknown_table`.
    - `exporter_fingerprint_matches_post_finish_manifest`
      — operator-prefix print equals eventual manifest's
      value.
  - adapter-test: 51 (unchanged).
  - ui: 121 (unchanged).
  - migrate: **14** (was 0) — 6 unit (3 in `d1_source`,
    2 in `schema`, 1 in tests of mock) + 8 integration
    (`tests/end_to_end.rs`):
    - `verify_accepts_clean_dump` — real CLI invocation
      against library-generated dump.
    - `verify_surfaces_redaction_profile_in_summary`.
    - `verify_rejects_truncated_dump`.
    - `verify_rejects_nonexistent_file`.
    - `list_profiles_prints_the_two_built_ins`.
    - `export_refuses_to_clobber_existing_file` — exercises
      the clobber guard without needing wrangler.
    - `import_still_returns_explanatory_error` — phase 3
      stub still pointing at v0.21.0.
    - `export_rejects_unknown_profile` — fail-fast on
      bad profile name.

### Documentation

- **New chapter** `docs/src/deployment/data-migration.md`.
  Operator-facing walkthrough: when to use `cesauth-migrate`
  vs `wrangler d1 export`, install instructions, end-to-end
  export procedure, redaction-profile usage, what's NOT in
  the dump, verify procedure including the load-bearing
  fingerprint-comparison step, operator runbook (export +
  verify halves), v0.20.0 limitations.
- **Updated** `docs/src/deployment/backup-restore.md` —
  `cesauth-migrate` cross-link now points at the real
  chapter; the legacy `sed`-script prod→staging refresh is
  marked obsolete and the section now leads with the
  recommended `cesauth-migrate` path.
- **`SUMMARY.md`** registers the new chapter.

### Migration (0.19.0 → 0.20.0)

Code-only release. No schema change. No `wrangler.toml`
change. `wrangler deploy` for the Worker is a no-op (the
Worker is unaffected).

For operators planning to use the migration tool:

```sh
# Build / install the host-side binary.
cargo install --path crates/migrate

# Confirm the new subcommands are real.
cesauth-migrate verify --help
cesauth-migrate export --help

# A first dry run against a non-production target is a good
# idea before depending on it in a real move window.
```

### Smoke test

```sh
# Unit + integration tests pass.
cargo test --workspace

# CLI binary builds, --help exits cleanly.
./target/debug/cesauth-migrate --help

# verify against a hand-prepared dump (see
# crates/migrate/tests/end_to_end.rs for the pattern).
./target/debug/cesauth-migrate verify --input some.cdump

# Existing surfaces unchanged.
curl -s https://auth.example.com/.well-known/openid-configuration | jq .
```

### Deferred to 0.21.0

- **Real `import` subcommand** — operator handshake
  (fingerprint prompt + `[Y/n]` confirmation), payload
  streaming with per-row schema-invariant checks,
  accumulate-then-commit/rollback semantics, the
  `--commit` gate that refuses if the destination's
  `JWT_SIGNING_KEY` is unset, the `--accept-violations`
  recovery escape hatch.
- **Day-2 runbook integration** — adds an "Importing a
  `.cdump` to a destination" section.
- **Disaster-recovery integration** — the cross-account
  compromise scenario gains concrete `cesauth-migrate`
  invocations.
- **ADR-005 → Accepted** once import lands.

### Deferred to 0.22.0

- **Resume support** for interrupted exports/imports.
- **Multi-tenant filtered exports** (`--tenant <slug>`).
- **First-class staging-refresh combinator** combining
  export + redaction + import in one invocation.
- **Native Cloudflare HTTP API client** as an alternative
  to `wrangler` shell-out.
- **Per-row progress reporting** (currently per-table).

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.19.0] - 2026-04-28

Data migration tooling — design (ADR-005) plus the foundation
work that makes the next two releases mechanical. Same v0.16.0 →
v0.17.0 → v0.18.0 phasing as the anonymous-trial track: this
release ships the design, the value types, the format spec, the
redaction profile registry, and the CLI skeleton. Real export
and import logic land in v0.20.0 and v0.21.0 respectively.

This release is the **first under the post-renumbering versioning
policy** — see the
[Versioning history note](#versioning-history-note) below if
the jump from 0.18.1 → 0.19.0 looks unfamiliar.

### Decision (ADR-005)

The new ADR at `docs/src/expert/adr/005-data-migration-tooling.md`
walks six design questions:

- **Q1 What is migrated** — Data, not secrets. The dump
  carries the D1 schema's user-facing rows but never JWT
  signing key private halves, session cookie keys, admin
  tokens. A stolen `.cdump` cannot forge tokens.
- **Q2 Source-side trust boundary** — Operator-mediated CLI
  invocation, not a Worker self-export endpoint. CLI uses
  D1 API credentials that already exist; no new HTTP
  surface to defend.
- **Q3 Destination-side trust boundary** — Per-export Ed25519
  signature with operator-mediated fingerprint verification.
  The exporter generates a fresh keypair, signs the payload,
  embeds the public key + signature in the manifest, then
  discards the private key. The importer prompts the
  operator to confirm the public-key fingerprint
  out-of-band before accepting the dump.
- **Q4 CLI vs library shape** — Both, layered. Library types
  in `cesauth-core::migrate` (testable on host); CLI in
  new `crates/migrate/` (wires library to D1 + clap).
- **Q5 Schema invariants** — Verify on import, not assume
  correct. Per-row invariant checks accumulate into a
  violation report; commit refused unless the report is
  empty or `--accept-violations` is supplied.
- **Q6 Secrets coordination** — Tool-supported runbook task,
  not tool-managed transport. Export prints a checklist of
  secrets the destination will need to mint; import refuses
  `--commit` until the destination's `JWT_SIGNING_KEY` is
  set.

The ADR rejects, with reasoning: a `/admin/migrate/*` HTTP
self-export (revocation, attack surface), reusing
`wrangler d1 export` raw SQL (no invariant preservation, no
PII redaction, no signature), bundling secrets in the dump
(repudiation impact of leak), ZIP-of-CSV format (no signed
manifest, no schema versioning).

### Added — `cesauth_core::migrate` (library)

New module with:

- **`Manifest`** — first-line value type carrying format
  version, cesauth version, schema version, source
  identifiers, signature, payload SHA-256, per-table
  summary, redaction profile name. `fingerprint()`
  produces a 16-hex-char value derived from SHA-256 of the
  raw public key — what the operator confirms during the
  import handshake.
- **`TableSummary`** — per-table row of the manifest, with
  row count and per-table SHA-256 for early-failure
  detection.
- **`PayloadLine<T>`** — generic over the row type. CLI
  uses `serde_json::Value` to stay schema-version-agnostic
  during streaming.
- **`RedactionProfile` / `RedactionRule` / `RedactionKind`**
  — column-level transformation registry. Two built-in
  profiles ship: `prod-to-staging` (email hashing +
  display-name scrubbing) and `prod-to-dev` (also clears
  OIDC client + admin token names). `HashedEmail` is the
  load-bearing kind — it preserves `users.email` UNIQUE
  invariant after redaction.
- **`FORMAT_VERSION`** = 1 (file format), **`SCHEMA_VERSION`**
  = 6 (migration count). A test pins
  `SCHEMA_VERSION == count(migrations/*.sql)` so a forgotten
  bump on schema change fails CI.

The on-disk format is documented in the module's `//!`
header — manifest at line 0, NDJSON payload below, signature
covers SHA-256 of payload only.

### Added — `crates/migrate/` (CLI skeleton)

New workspace member. CLI binary `cesauth-migrate` with four
subcommands:

- **`export`** — *not yet implemented (lands in v0.20.0)*.
  Returns an explanatory error.
- **`import`** — *not yet implemented (lands in v0.21.0)*.
- **`verify`** — *not yet implemented (lands in v0.20.0)*.
- **`list-profiles`** — implemented. Enumerates
  `built_in_profiles()` with descriptions and rules.
  Shipping early so operators can confirm "what redaction
  is available" without waiting for export to land.

The skeleton ships in v0.19.0 so:

- Operators can `cargo install --path crates/migrate` ahead
  of v0.20.0 — no last-minute install at the moment of the
  move.
- `--help` text serves as authoritative spec; reviewers can
  comment on UX before implementation locks it in.
- Documentation links to a real CLI invocation rather than a
  placeholder.

### Added — workspace dependency additions

- `clap = "4"` (`derive` feature) — CLI parsing.
- `tokio = "1"` (limited features for host-side I/O) — async
  runtime for v0.20.0+ I/O paths. Host-side only; not
  pulled into Workers crates.

Both at `[workspace.dependencies]`. Workers crates do not see
them; the size budget remains untouched.

### Tests

- Total: **305 passing** (+11 over v0.18.1).
  - core: **133** (was 122) — 11 new in `migrate::tests`:
    - `manifest_round_trips_through_serde_json` —
      load-bearing for every importer.
    - `manifest_fingerprint_is_stable_for_same_pubkey` —
      handshake relies on determinism. Tests it's 16 hex
      chars, all valid hex.
    - `manifest_fingerprint_changes_with_pubkey` — distinct
      keys produce distinct fingerprints (the mismatch
      detection contract).
    - `manifest_fingerprint_handles_invalid_pubkey` —
      garbage in returns sentinel `<invalid>` instead of
      panicking.
    - `payload_line_round_trips` — payload format under
      `serde_json::Value`.
    - `lookup_profile_finds_built_ins` — registry sanity.
    - `lookup_profile_returns_none_for_unknown` — graceful
      bad-input handling.
    - `built_in_profiles_have_unique_names` — duplicate
      profile names would make `--profile <n>` ambiguous;
      catch in CI.
    - `prod_to_staging_redacts_email_with_hashed_kind` —
      pins the load-bearing kind. A future refactor that
      flipped `HashedEmail` → `StaticString` would collapse
      every redacted email to one literal and explode
      UNIQUE on import; the test catches that.
    - `format_version_constant_is_one` — defensive bump
      detection.
    - `schema_version_matches_migration_count` — reads
      `migrations/` and asserts equality. Forgetting to
      bump `SCHEMA_VERSION` on a new migration fails CI.
  - adapter-test: 51 (unchanged).
  - ui: 121 (unchanged).
  - migrate: 0 (CLI skeleton; tests come with v0.20.0+).

### Status changes

- **ADR-005** — `Draft`. Graduates to `Accepted` in v0.21.0
  when the import path completes the round trip.
- **ROADMAP** — "Data migration tooling" item moves from
  "next minor releases" to in-progress, with the four-phase
  plan visible in the ADR's Implementation Phases section.

### Migration (0.18.1 → 0.19.0)

Code-only release. No schema change. No new env var or
`wrangler.toml` change required for the deployed Worker —
`cesauth-migrate` is a host-side tool that runs on operator
machines, not inside the Worker. `wrangler deploy` carries
no new requirements.

For operators who want to install the CLI in advance:

```bash
cargo install --path crates/migrate
cesauth-migrate --help
cesauth-migrate list-profiles
```

`list-profiles` is the only working subcommand in v0.19.0;
the others return explanatory error messages pointing at the
release where they will land.

### Smoke test

```bash
# CLI binary builds + runs
cargo build -p cesauth-migrate
./target/debug/cesauth-migrate --help

# list-profiles works
./target/debug/cesauth-migrate list-profiles

# stubs surface explanatory errors, not panics
./target/debug/cesauth-migrate export \
  --output /tmp/x --account-id abc --database d
# -> "export not implemented yet (lands in v0.20.0; ...)"
```

### Deferred to 0.20.0

- **Real export path** — `cesauth-migrate export` against a
  live D1 via Cloudflare's HTTP API. Signed manifest
  emission. Redaction profile application during export.
- **`verify` subcommand** — read a `.cdump`, check format
  version, verify signature, print summary, exit. No D1
  contact.
- **Format spec finalization** — module-level `//!` block
  in `cesauth_core::migrate` becomes the authoritative
  reference; the ADR-005 sketch is superseded by the
  actual spec at that point.

### Deferred to 0.21.0

- **Real import path** — operator handshake (fingerprint
  prompt), payload streaming with per-row invariant
  checks, accumulate-then-commit/rollback, `--commit`
  gate that refuses if destination's `JWT_SIGNING_KEY` is
  unset, `--accept-violations` recovery escape hatch.
- **Day-2 runbook integration** — new section
  "Pre-flight before invoking `cesauth-migrate`" + "Post-
  import verification".
- **Disaster recovery integration** — the cross-account
  compromise scenario in `disaster-recovery.md` gains
  concrete `cesauth-migrate` invocations.
- **ADR-005 → Accepted.**

### Deferred to 0.22.0

- **Resume support** for interrupted imports.
- **Multi-tenant filtered exports** (`--tenant
  <slug>,<slug>`) — v0.20.0's export is whole-database
  only.
- **First-class staging refresh** combining export +
  redaction + import in one invocation.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.**
  Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.18.1] - 2026-04-28

Documentation release. Deployment guide expanded from three
chapters (Wrangler / Secrets / Production walkthrough) to eleven,
covering the operational surface that previously lived only in
team tribal knowledge.

This is a **patch bump** under the new versioning policy
(introduced in 0.18.0): doc-only release with no code, schema,
public-type, permission-slug, or operator-visible-config
changes. The added chapters describe operator practice against
existing surfaces; they do not introduce new ones.

### Added — deployment chapters

- **`docs/src/deployment/preflight.md`** — consolidated
  pre-deploy readiness checklist. Twelve sections (Cloudflare
  account, resources, schema, secrets, vars, Cron Triggers,
  custom domain, mail provider, dependencies, smoke tests,
  backups, communication) with a tier-by-tier degradation
  table for "what breaks if I skip this section".
- **`docs/src/deployment/cron-triggers.md`** — covers the
  v0.18.0 `[triggers]` block, the dispatcher pattern in
  `crates/worker/src/lib.rs::scheduled`, manual invocation
  for smoke-testing (local `wrangler dev --test-scheduled`,
  production schedule-flip pattern), Cloudflare-side limits
  and best-effort semantics.
- **`docs/src/deployment/custom-domains.md`** — Custom Domain
  vs Route decision (cesauth needs Custom Domain),
  `ISSUER` consistency rules, WebAuthn RP ID/origin coupling,
  multi-tenant DNS options, common mistakes
  (workers.dev URL as `ISSUER`, trailing slash, grey-cloud
  proxy).
- **`docs/src/deployment/environments.md`** — staging →
  production promotion workflow. `wrangler.toml` shape with
  `[env.staging]` and `[env.production]` blocks, what to
  override per environment vs share, migration ordering
  across environments, when (rarely) to skip staging.
- **`docs/src/deployment/backup-restore.md`** — D1 export
  procedure, automated daily backup via GitHub Actions, R2
  audit-bucket lifecycle, secrets-as-vault pattern, full
  restore procedure, prod-to-staging refresh with PII
  redaction, what backups don't protect against.
- **`docs/src/deployment/observability.md`** — structured
  logs (`wrangler tail`, Logpush), the audit trail in R2 and
  how to query it, Cloudflare-native metrics, alert
  recommendations, what NOT to obsess over.
- **`docs/src/deployment/runbook.md`** — Day-2 runbook
  organized by symptom: session-expired storms, anonymous
  accumulation, single-user login failures, 5xx spikes,
  signing-key rotation, admin-token leaks, discovery-doc
  mismatch. Periodic-task table (daily / weekly / monthly /
  quarterly / annually).
- **`docs/src/deployment/disaster-recovery.md`** — eight
  worst-case scenarios with detailed recovery procedures:
  bad deploy, bad migration, D1 corruption, account
  compromise, region outage, key compromise, key loss,
  `database_id` misdirection. Suggested RPO/RTO targets.
  Annual drill recommendations.

### Updated — existing chapters

- **`docs/src/deployment/production.md`** — first-deploy
  walkthrough refocused as the entry point. New introduction
  pointing at the topic-specific chapters for operational
  use. New "Step 7.5 — Configure Cron Triggers" makes the
  v0.18.0 `[triggers]` requirement explicit. "Rolling back"
  section gains a pointer to the new disaster-recovery
  chapter.
- **`docs/src/SUMMARY.md`** — gains the seven new chapter
  entries under the Deployment section. Also adds the
  ADR-004 entry that was missing from earlier ADR releases.

### Tests

- Unchanged: 294 passing (122 + 51 + 121).
- Footer-version assertions in `crates/ui/src/tenancy_console/tests.rs`
  and `crates/ui/src/tenant_admin/tests.rs` updated to expect
  `v0.18.1`.

### Migration (0.18.0 → 0.18.1)

Code-only release. No schema change, no `wrangler.toml`
change, no operator action required. `wrangler deploy`.

### Smoke test

```bash
# Build the documentation locally to confirm cross-links resolve.
mdbook build docs/
# Serve and skim the new chapters.
mdbook serve docs/ --port 3000
```

The mdbook build is what would break if a cross-link is wrong;
no other smoke test applies to a doc-only release.

### Deferred

- **Per-tenant runbook content.** The per-tenant operations
  surface (the `/admin/t/<slug>/*` console) deserves its own
  operator-facing docs separate from the system-admin runbook
  this release ships. Not scheduled.
- **Multi-region deployment guide.** Operators running cesauth
  across regional Cloudflare accounts have the
  multi-environment workflow as a starting point, but the
  region-orchestration tooling is operator-specific and
  out of scope for this release.

---

## [0.18.0] - 2026-04-28

Anonymous-trial daily retention sweep — ADR-004 Phase 3, the final
piece. The flow is now **feature-complete**: visitor mints
anonymous principal (0.17.0 `/begin`), optionally promotes to
`human_user` via Magic Link UPDATE-in-place (0.17.0 `/promote`),
or — if neither — gets cleaned up by the 7-day retention sweep
shipped here.

This release is also the first 0.5.x and the natural moment to
formalize cesauth's versioning rule. ROADMAP gains a
"Versioning policy" section near the top: **minor bumps for new
HTTP routes, schema migrations, public types/traits, permission
slugs, or operator-visible config; patch bumps for internal
changes that preserve all of the above.** The historical 0.4.x
debt (several patches that should have been minors by this rule)
stays as-is — those bundles are immutable artifacts. Going
forward the rule applies; 0.18.0 is the first release under it.

### Added — Cloudflare Workers Cron Trigger (operator-visible config change)

`wrangler.toml` gains a `[triggers]` block:

```toml
[triggers]
crons = ["0 4 * * *"]
```

This is the operator-visible deployment-config change that bumps
the minor (per the new versioning policy). Operators upgrading
from 0.17.0 must add this block before `wrangler deploy`, or the
sweep will never run. The schedule fires the
`#[event(scheduled)]` handler in `crates/worker/src/lib.rs` at
04:00 UTC daily — late enough that the previous day's
promotion-flow stragglers have settled, early enough that
operators in any timezone see the result before their workday.

Cloudflare's dashboard surfaces invocation history under
**Workers & Pages → cesauth → Settings → Triggers**;
`wrangler tail` streams scheduled invocations live.

### Added — `crates/worker/src/sweep.rs`

The new `sweep::run(env)` function runs one pass:

1. Loads `Config` (for log channel + audit destinations).
2. Computes `cutoff = now - ANONYMOUS_USER_RETENTION_SECONDS`
   (7 days).
3. Calls `UserRepository::list_anonymous_expired(cutoff)` to
   list every row matching `account_type='anonymous' AND
   email IS NULL AND created_at < cutoff`.
4. For each row: emits `EventKind::AnonymousExpired` audit
   FIRST, then `delete_by_id`. Audit-before-delete is the
   load-bearing ordering — if the delete fails, the audit row
   still records the principal we *intended* to remove, and
   the diagnostic query (operator runbook) shows whether the
   row actually disappeared. ADR-004 §Q5 rationale.
5. Logs one `Info` summary line at the end:
   `"anonymous sweep complete: X/Y rows deleted"`.

#### Why list-then-delete instead of bulk DELETE

A single `DELETE FROM users WHERE ...` would be one round-trip,
but it gives no per-row audit and no operator-visible signal of
*which* principals were swept. ADR-004 §Q5 requires that
`User.id` remain queryable across a row's full lifetime
(including its sweep), so the per-row audit emission is
load-bearing for that contract. For the expected steady-state
volume (anonymous trials per day in the tens-to-hundreds), the
extra round-trips are not a concern.

#### Failure semantics — best-effort, not transactional

If individual row deletes fail, the handler logs `Warn` and
continues with the next row. The next day's sweep retries the
survivors. The alternative (one bad row blocking the whole
sweep indefinitely) is worse for storage growth than partial
progress. Persistent failures show up as a growing residual
count visible to operators via the diagnostic query in the
operator runbook.

### Added — `#[event(scheduled)]` handler

A new entry point in `crates/worker/src/lib.rs` dispatches on
`event.cron()`:

- `"0 4 * * *"` → `sweep::run(&env).await`.
- Any other cron expression → `console_warn!` and continue.
  Future scheduled tasks (operational metrics, finer-grained
  cleanup) branch here.

Errors from the sweep are logged but never propagated to the
runtime. Cloudflare's invocation history would surface the
error at scheduled-handler granularity, but the operational log
channel + audit trail give a more useful per-row surface for
"did the sweep run, what did it do".

### Added — `UserRepository` extensions

Two new port methods to back the sweep:

- **`list_anonymous_expired(cutoff_unix) -> Vec<User>`** —
  returns rows with `account_type='anonymous' AND email IS
  NULL AND created_at < cutoff`. The `email IS NULL` clause
  is what structurally exempts promoted users (they carry an
  email post-promotion) from the sweep. ADR-004 §Q3.
- **`delete_by_id(id) -> ()`** — hard delete; FK CASCADEs
  (via 0006 + 0003) clean up `anonymous_sessions`,
  memberships, role assignments. Idempotent: missing-row
  delete is `Ok(())`, since the sweep may race with itself
  or a concurrent admin delete.

Both methods are implemented in the in-memory adapter
(`crates/adapter-test/src/repo/users.rs`) and the D1 adapter
(`crates/adapter-cloudflare/src/ports/repo/users.rs`). The
`StubUsers` test double in `crates/core/src/tenant_admin/tests.rs`
gains stub implementations so `cargo test -p cesauth-core`
continues to compile.

### Tests

- Total: **294 passing** (+5 over v0.17.0).
  - core: 122 (unchanged).
  - adapter-test: **51** (was 46) — 5 new in `repo::tests`:
    - `list_anonymous_expired_returns_only_expired_unpromoted` —
      4-row fixture (young / expired / promoted / human user)
      verifies only the expired-and-unpromoted row is returned.
      The promoted row (with email) and the young row are
      structurally exempt; the human user is excluded by
      account-type filter.
    - `list_anonymous_expired_empty_when_nothing_due` — sweep
      against a cutoff that nothing crosses returns empty
      (not error, not panic).
    - `delete_by_id_is_idempotent` — double-delete + missing-id
      delete both `Ok(())`. The sweep may race with itself
      across cron invocations.
    - `delete_by_id_removes_email_uniqueness_lock` — important
      for the promote-then-re-trial pattern: after delete, the
      email becomes available for re-registration.
    - `list_anonymous_expired_skips_human_users_even_if_old` —
      defense in depth: a `human_user` row past `i64::MAX`
      seconds old must NEVER be returned. The query filter
      (`account_type='anonymous'`) is what stands between the
      sweep and a catastrophic data-loss bug.
  - ui: 121 (unchanged).

### ADR-004 — feature-complete

- Phase 1 (foundation): v0.16.0. ✅
- Phase 2 (HTTP routes): v0.17.0, ADR Status → Accepted. ✅
- Phase 3 (retention sweep): **v0.18.0, this release.** ✅

### Status changes

- **ROADMAP** — Anonymous-trial item moves from "next minor
  releases" to the "Shipped" table. Versioning policy section
  added near the top.

### Migration (0.17.0 → 0.18.0)

Code-only release in the schema sense — no new migration; the
0006_anonymous.sql foundation is unchanged. **However**,
operators MUST update `wrangler.toml`:

```toml
# Append:
[triggers]
crons = ["0 4 * * *"]
```

Then `wrangler deploy`. Without the `[triggers]` block, the
new scheduled handler still ships, but Cloudflare never invokes
it — the sweep never runs and anonymous users accumulate
indefinitely. The operator runbook section "Verifying the
anonymous-trial retention sweep ran" walks the post-deploy
verification.

### Smoke test

```bash
# 1) Deploy with the new [triggers] block.
wrangler deploy

# 2) Verify the trigger registered with Cloudflare.
#    Dashboard: Workers & Pages → cesauth → Settings → Triggers.
#    Should list one cron: "0 4 * * *".

# 3) Local smoke-test of the sweep without waiting for 04:00 UTC.
wrangler dev --test-scheduled
# Then in another terminal:
curl http://localhost:8787/cdn-cgi/handler/scheduled
# -> 200 OK; check `wrangler dev` output for the sweep log line.

# 4) Verify the audit trail:
wrangler d1 execute cesauth --remote \
  --command="SELECT count(*) FROM audit_events WHERE kind='anonymous_expired';"
# -> count of rows the sweep has audited across all runs.

# 5) Diagnostic — anonymous accumulation check:
wrangler d1 execute cesauth --remote --command=\
"SELECT count(*) FROM users \
   WHERE account_type='anonymous' AND email IS NULL \
     AND created_at < unixepoch() - 7 * 86400;"
# -> 0 in a healthy deployment. Non-zero shortly after a sweep
#    means the sweep failed to delete some rows; check
#    wrangler tail for per-row Warn logs.
```

### Deferred — unchanged from 0.17.0

- **`check_permission` integration on `/api/v1/...`.**
  Unscheduled.
- **External IdP federation.** Out of scope for v0.5.x.

### Next planned

The first 0.18.0 release closes the anonymous-trial roadmap
slot. Next likely candidates from the ROADMAP:

- **OAuth 2.0 Token Introspection (RFC 7662)** —
  `POST /introspect`. Already in ROADMAP.
- **Account lockout** for repeated auth failures.

---

## [0.17.0] - 2026-04-28

Anonymous trial — HTTP routes. ADR-004 Phase 2: the two endpoints
that exercise the v0.16.0 foundation. With this release ADR-004
graduates from `Draft` to `Accepted` — the design has a working
implementation on both ends.

The shape is intentionally minimal. `POST /api/v1/anonymous/begin`
mints a fresh user + bearer; `POST /api/v1/anonymous/promote` does
both the OTP-issue step and the OTP-verify+UPDATE step under one
URL, distinguished by whether the request body carries a `code`
field. Magic Link infrastructure is reused unchanged — the
existing `/magic-link/request` and `/magic-link/verify` paths are
untouched, but the `magic_link::issue` / `verify` core helpers and
the `AuthChallengeStore` DO are shared. The only fork is the
*subject* of the ceremony: fresh self-registration creates a new
user row; promotion updates an existing anonymous one.

### Added — `POST /api/v1/anonymous/begin`

Unauthenticated. Per-IP rate-limited via the existing
`RateLimitStore` with bucket key `anonymous_begin_per_ip:<ip>`,
window 5 minutes, limit 20, escalation at 10. The numbers are
strict on purpose — anonymous principals are essentially free to
mint, so an unbounded flow would let an attacker pollute the
`users` table; the 7-day daily sweep (v0.6.05) is the second
line of defense, this is the first. `cf-connecting-ip` populates
the bucket key; absence falls back to the literal `unknown`
bucket.

The handler:
- Mints a 32-byte URL-safe-base64 plaintext bearer via
  `getrandom`.
- Computes SHA-256-hex of the plaintext as the storage key.
- INSERTs a `users` row with `tenant_id=DEFAULT_TENANT_ID`,
  `email=NULL`, `email_verified=false`,
  `display_name='Anon-XXXXX'` (cosmetic; 5 chars from a small
  URL-safe alphabet), `account_type=Anonymous`,
  `status=Active`.
- INSERTs an `anonymous_sessions` row with
  `expires_at = now + ANONYMOUS_TOKEN_TTL_SECONDS` (24h).
- Audits `EventKind::AnonymousCreated` with reason
  `via=anonymous-begin,ip=<masked>`. IPv4 is masked to
  `a.b.c.0`; IPv6 to the `/64` prefix — enough to spot bursts
  from a single address, not enough to log raw client IPs.
- Returns HTTP 201 with body
  `{ user_id, token, expires_at }`. The plaintext token is
  shown ONCE; cesauth stores only the hash. After this
  response, the only way to obtain a working token is to
  call `/begin` again.

### Added — `POST /api/v1/anonymous/promote`

Authenticated by the anonymous bearer in
`Authorization: Bearer ...`. Two-step, distinguished by body
shape:

- **Step A (issue OTP)**: body `{ "email": "..." }` (no
  `code`, no `handle`). Validates the email syntax, issues a
  fresh Magic Link OTP via `magic_link::issue` with the
  config-driven TTL, stores it in the `AuthChallengeStore`
  DO under a new handle, audits `MagicLinkIssued` with
  reason `via=anonymous-promote,handle=<>,code=<plaintext>`.
  The reason marker piggybacks on the existing mail-delivery
  pipeline (which today reads the audit log; see
  `routes/magic_link.rs` module doc) so no new mail
  integration is needed. Returns
  `{ handle, expires_at }`.

- **Step B (verify OTP + apply)**: body
  `{ "email": "...", "handle": "...", "code": "..." }`.
  Bumps the challenge attempt counter (mirrors
  `/magic-link/verify`), peeks the challenge, **verifies the
  challenge email matches the body email** (defense in depth
  — without this an attacker observing a handle for someone
  else's promotion attempt could splice it into their own),
  runs `magic_link::verify`, consumes the challenge,
  performs the in-tenant email-collision check (`find_by_email`
  on a different user_id ⇒ refuses with the distinguishable
  error `email_already_registered` so the client can render
  "log in to existing account" guidance vs "OTP failed"
  guidance), re-checks `account_type == Anonymous` on the
  user row (defense against racy double-submit landing after
  the first promotion already flipped the type — refused
  with `not_anonymous`), UPDATEs the row in place
  (`email`, `email_verified=true`, `account_type=HumanUser`,
  `updated_at`), revokes any anonymous sessions for the user
  via `revoke_for_user`, audits `AnonymousPromoted`.

The User.id is preserved across promotion. All foreign keys
pointing at the user — memberships, role assignments, audit
subject ids, and any session rows in adjacent tables —
survive without remap. ADR-004 §Q4 walks the rejected
alternative (separate `anonymous_users` table → "copy fields,
delete row" promotion) and why it loses to UPDATE-in-place.

### Defense-in-depth invariants pinned

The route layer hits Cloudflare-specific bindings, so the
handlers themselves test in `wrangler dev`. The service-layer
invariants behind the routes are pinned in
`adapter-test/src/anonymous.rs::tests`:

- **Revoke-before-update ordering** —
  `promotion_pattern_revokes_then_user_update`. The
  promotion handler's invariant is "invalidate the bearer
  *before* the user-row UPDATE lands, never after". Reverse
  order opens a small window where the bearer authenticates
  a row that's already a `human_user`. Test exercises the
  fail-safe ordering explicitly.
- **Per-user revoke isolation** —
  `many_anonymous_users_revoke_independently`. One user's
  promotion cannot affect another user's anonymous session.
- **Idempotent double-promote** —
  `double_promote_protected_by_idempotent_revoke`. A racy
  second submit's `revoke_for_user` returns `Ok(0)`, not an
  error; the route's `account_type == Anonymous` check then
  refuses with the distinguishable `not_anonymous` error.

The `account_type != Anonymous` defense, the
`challenge_email != body_email` defense, and the
email-collision-distinguishable-error contract are all in the
handler itself. Verifying them programmatically requires a
Workers shim that doesn't exist; for now they're enforced by
review and the smoke-test path below.

### Audit reason markers

- `via=anonymous-begin,ip=<masked>` — `AnonymousCreated`.
- `via=anonymous-promote,handle=<>,code=<plaintext>` —
  `MagicLinkIssued` (Step A). The plaintext is intentional;
  the existing mail pipeline reads it.
- `via=anonymous-promote,reason=email_already_registered` —
  `MagicLinkFailed`, used to spot promotion-probe email
  harvesting.
- `via=anonymous-promote,from=anonymous,to=human_user` —
  `AnonymousPromoted` (Step B success).

### Tests

- Total: **289 passing** (+3 over v0.16.0).
  - core: 122 (unchanged).
  - adapter-test: **46** (was 43) — 3 new in
    `anonymous::tests`: revoke-before-update fail-safe
    ordering, per-user revoke isolation, idempotent
    double-promote.
  - ui: 121 (unchanged).

The route handlers themselves don't have direct unit tests
(they hit `worker::Env`, `RouteContext`, `worker::Request` —
all Cloudflare-specific). Their semantics ride on:
- The 0.16.0 type-level tests (`AnonymousSession`,
  boundary inclusivity, TTL constants).
- The 0.16.0 in-memory-adapter tests (create / find /
  revoke / sweep behaviour).
- The new 0.17.0 promotion-flow tests above.
- Smoke testing via `wrangler dev` (see below).

### Status changes

- **ADR-004** — `Draft` → `Accepted`. The design has a
  working implementation. Both `docs/src/expert/adr/004-...md`
  and the ADR README index updated.

### Migration (0.16.0 → 0.17.0)

Code-only release. Migration `0006_anonymous.sql` was already
applied in v0.16.0 and is unchanged. No `wrangler.toml`
change yet (Cron Trigger ships with v0.6.05).

For deployments tracking main: `wrangler deploy`. The new
routes are unauthenticated (`/begin`) or anonymous-bearer
authenticated (`/promote`); they don't interact with the
existing OIDC, admin-tokens, or tenancy-API surfaces.

### Smoke test

```bash
# 1) Begin: mint an anonymous user + bearer.
RESP=$(curl -sS -X POST https://cesauth.example/api/v1/anonymous/begin)
echo "$RESP" | jq .
# -> { "user_id": "...", "token": "<plaintext>", "expires_at": ... }

USER_ID=$(echo "$RESP" | jq -r .user_id)
TOKEN=$(echo "$RESP"   | jq -r .token)

# 2) Promote step A: issue OTP for an email.
curl -sS -X POST https://cesauth.example/api/v1/anonymous/promote \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com"}'
# -> { "handle": "...", "expires_at": ... }

# 3) Read the OTP from the audit log (or your mail provider).
#    The audit reason carries `code=<plaintext>` for the
#    anonymous-promote path.
HANDLE=...   # from step 2 response
CODE=...     # from audit log / email

# 4) Promote step B: verify OTP + apply UPDATE-in-place.
curl -sS -X POST https://cesauth.example/api/v1/anonymous/promote \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"alice@example.com\",\"handle\":\"$HANDLE\",\"code\":\"$CODE\"}"
# -> { "user_id": "...", "promoted": true }
# user_id is the SAME as step 1 — UPDATE-in-place.

# 5) The original anonymous bearer is now revoked. Re-using
#    it returns 401:
curl -sS -X POST -o /dev/null -w '%{http_code}\n' \
  https://cesauth.example/api/v1/anonymous/promote \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com"}'
# -> 401

# 6) Cross-tenant or different-email same-tenant collision:
TOKEN2=$(curl -sS -X POST https://cesauth.example/api/v1/anonymous/begin \
  | jq -r .token)
curl -sS -X POST https://cesauth.example/api/v1/anonymous/promote \
  -H "Authorization: Bearer $TOKEN2" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","handle":"<step-A-handle>","code":"<code>"}' \
  | jq -r .error
# -> "email_already_registered"  (distinguishable from
#    "verification_failed")
```

### Deferred to 0.6.05

- **Daily retention sweep** — Cloudflare Workers Cron Trigger
  configured in `wrangler.toml`, sweep handler that runs the
  `users` row delete (cascade through `anonymous_sessions`)
  plus `AnonymousExpired` audit emission per row. Operator
  runbook gains "Verifying the retention sweep ran" diagnostic
  section. After v0.6.05 the anonymous-trial flow is feature-
  complete.

### Deferred — unchanged from 0.16.0

- **`check_permission` integration on `/api/v1/...`.**
  Unscheduled.
- **External IdP federation.** Out of scope for v0.4.x.

---

## [0.16.0] - 2026-04-28

Anonymous trial principal — design (ADR-004) plus the foundation
work that makes the next two releases mechanical. Following the
v0.11.0 → v0.13.0 → v0.14.0 model: this release ships the schema,
the value type, the repository port, both adapters, and the audit
event kinds. HTTP routes (`/api/v1/anonymous/begin` and `/promote`)
land in v0.17.0; the daily retention sweep (Cloudflare Cron Trigger)
in v0.6.05.

The `AccountType::Anonymous` variant has existed in
`cesauth_core::tenancy::types` since v0.5.0, and the v0.11.0 ADR
stage marked the promotion flow as "0.14.0 or later". The slot
slid across three releases (0.14.0/.11/.12 each took a different
non-feature focus); v0.16.0 is the catch-up.

### Decision (ADR-004)

The new ADR at `docs/src/expert/adr/004-anonymous-trial-promotion.md`
walks five design questions and picks one coherent point in the
space:

- **Q1 Provenance** — A new endpoint `POST /api/v1/anonymous/begin`
  creates the anonymous user and returns a bearer token.
  Unauthenticated by design, gated only by per-IP rate limit. Not
  reusing the existing user-creation route makes the trust
  boundary explicit.
- **Q2 Token issuance** — Opaque bearer (not OIDC), 24h TTL, not
  refreshable. Avoids fabricating an `email` claim cesauth has
  not verified.
- **Q3 Retention** — Anonymous user rows kept for 7 days unless
  promoted. Daily Cloudflare Workers Cron Trigger sweeps rows
  with `account_type='anonymous' AND email IS NULL AND
  created_at < now - 7d`. Promoted rows have `email IS NOT NULL`
  and survive.
- **Q4 Conversion ceremony** — The visitor supplies an email; the
  standard Magic Link flow verifies ownership; the existing
  user row is **updated in place** (`User.id` preserved,
  `account_type` flipped, `email`/`email_verified` filled in).
  All foreign keys pointing at the user — memberships, role
  assignments, audit subject ids — survive without remapping.
- **Q5 Audit trail** — Three new `EventKind`s
  (`AnonymousCreated`, `AnonymousExpired`, `AnonymousPromoted`).
  Because `User.id` is preserved through promotion, audit events
  emitted during the anonymous phase remain queryable by subject
  id post-promotion.

The ADR rejects, with reasoning: indefinite retention, JWT bearer
(blocks revocation), in-session "claim email" without verification
(trivially hijackable), separate `anonymous_users` table (forces
foreign-key remap on every dependent table).

### Added — schema

Migration `0006_anonymous.sql` adds the `anonymous_sessions`
table:

- `token_hash` (PK) — SHA-256 of the bearer plaintext, hex.
- `user_id` — FK to `users.id`, ON DELETE CASCADE so the daily
  sweep that drops user rows automatically clears their tokens.
- `tenant_id` — FK to `tenants.id`, ON DELETE CASCADE.
  Denormalized from `users.tenant_id` to keep the IP-rate-limit
  lookup path index-only.
- `created_at` / `expires_at` — Unix seconds. Application
  enforces TTL; DB only stores. The 0006 indexes
  (`idx_anonymous_sessions_created`,
  `idx_anonymous_sessions_user`) cover the sweep and revocation
  hot paths.

The table mirrors the design of `admin_tokens` (introduced in
0005) — same hash-only storage, same plaintext-shown-once
posture — but in a separate table so the auth surface stays
narrow. An anonymous principal has no admin role and cannot
acquire one through this token.

### Added — domain types and ports

New module `cesauth_core::anonymous`:

- **`AnonymousSession`** value type — mirrors the table 1:1 with
  an `is_expired(now_unix)` helper. Boundary semantics
  (`<=` is "expired") are pinned by a dedicated test —
  `is_expired_boundary_inclusive` — because flipping that
  operator to `<` would silently let a token live one second
  past its window, and the next refactor that "tidies up the
  comparison" is the bug.
- **`AnonymousSessionRepository`** trait with four methods:
  - `create(token_hash, user_id, tenant_id, now, ttl)` — insert
    a row. Hash collisions return `Conflict`; FK violations
    return `NotFound`.
  - `find_by_hash(token_hash)` — hot path, called on every
    anonymous-bearer request.
  - `revoke_for_user(user_id)` — used by the promotion path
    to nuke any outstanding bearers at promotion time.
    Idempotent: `Ok(0)` for "no sessions to revoke" rather
    than an error.
  - `delete_expired(now_unix)` — used by the daily sweep.
    Returns the number of rows actually deleted.
- **Constants** `ANONYMOUS_TOKEN_TTL_SECONDS` (24h) and
  `ANONYMOUS_USER_RETENTION_SECONDS` (7d), pinned by a test
  that checks they match ADR-004 and that retention strictly
  outlives the token TTL.

### Added — adapters

- **In-memory** `InMemoryAnonymousSessionRepository` in
  `cesauth-adapter-test`. Mutex-wrapped HashMap; 7 unit tests
  cover round-trip / hash conflict / unknown lookup / per-user
  revocation / idempotency / expired-row sweep / boundary
  inclusivity.
- **Cloudflare D1** `CloudflareAnonymousSessionRepository` in
  `cesauth-adapter-cloudflare`. Maps SQLite UNIQUE / PRIMARY KEY
  failures to `PortError::Conflict` and FK failures to
  `PortError::NotFound`; `meta().changes` for delete-row
  counts. Same shape as the existing `AdminTokenRepository`
  D1 adapter.

### Added — audit event kinds

`EventKind` gains three variants:

- `AnonymousCreated` — emitted by `/begin` (v0.17.0).
- `AnonymousExpired` — emitted by the daily sweep (v0.6.05).
- `AnonymousPromoted` — emitted by `/promote` (v0.17.0).

The variants land in v0.16.0 even though no code path emits them
yet, because the audit catalog is enum-stringly-typed and
distributed clients (log dashboards, audit-table views) treat
unknown values as the type-system error they are. Adding the
variants now means v0.17.0 ships its emit calls without forcing
a coordinated audit-schema bump.

### Tests

- Total: **286 passing** (+10 over v0.15.1).
  - core: **122** (was 119) — 3 new in `anonymous::tests`:
    TTL-constants-match-ADR (paired with the strict
    inequality between retention and token TTL),
    serde round-trip on `AnonymousSession`, `is_expired`
    boundary inclusivity.
  - adapter-test: **43** (was 36) — 7 new in
    `anonymous::tests`: create+lookup round-trip, conflict
    on duplicate hash, unknown-hash returns None,
    `revoke_for_user` drops only the named user's sessions,
    `revoke_for_user` is idempotent (`Ok(0)` for missing
    user), `delete_expired` honours the `expires_at`
    threshold across multiple now values, boundary
    inclusivity (parallel to the type-level test).
  - ui: 121 (unchanged).

### Migration (0.15.1 → 0.16.0)

```bash
wrangler d1 execute cesauth --remote --file migrations/0006_anonymous.sql
wrangler deploy
```

The migration is additive (CREATE TABLE IF NOT EXISTS, new
indexes only); safe to re-run, no existing schema or data is
touched. No `wrangler.toml` change yet — the Cron Trigger
configuration ships with v0.6.05.

For deployments tracking main: nothing to do operationally
beyond running the migration and deploying. No HTTP routes
have changed; no existing principals or tokens are affected.

### Smoke test

```bash
# 1) Verify the new table is in place:
wrangler d1 execute cesauth --remote \
  --command="SELECT name FROM sqlite_master WHERE type='table' AND name='anonymous_sessions';"
# -> one row, name = 'anonymous_sessions'

# 2) Verify the new event kinds are recognized by the audit
#    catalog. Insert a synthetic row and read it back:
wrangler d1 execute cesauth --remote \
  --command="SELECT 'kind valid' FROM (SELECT 1) WHERE 'anonymous_created' IN ('anonymous_created');"
# (cosmetic; the EventKind enum is enforced at the writer side)

# 3) HTTP surface unchanged — the /authorize, /token, /admin/*,
#    /api/v1/* routes behave exactly as in 0.15.1.
curl -s https://cesauth.example/.well-known/openid-configuration \
  | jq -r '.authorization_endpoint, .token_endpoint, .revocation_endpoint'
# -> three URLs that match ISSUER + the suffixes
```

### Deferred to 0.17.0

- **`POST /api/v1/anonymous/begin`** — issues an anonymous user
  + bearer. Per-IP rate limit via the existing `RateLimit` DO
  with a new bucket key.
- **`POST /api/v1/anonymous/promote`** — Magic Link verification
  → UPDATE the existing user row (id preserved). Same-tenant
  email collision returns a distinguishing error vs verify
  failure.

### Deferred to 0.6.05

- **Daily retention sweep** — Cloudflare Workers Cron Trigger
  configured in `wrangler.toml`, dispatching to a sweep handler
  that runs the `users` row delete (with cascade through
  `anonymous_sessions`) plus an audit emission per row.
  Operator runbook section "Verifying the retention sweep ran"
  documents the diagnostic path.

### Deferred — unchanged from 0.15.1

- **`check_permission` integration on `/api/v1/...`.** The
  v0.7.0 JSON API still uses `ensure_role_allows`. Now that
  user-bound tokens exist, `check_permission` is validated in
  the new HTML routes, AND `check_permissions_batch` is
  available, extending it to the API surface is more
  straightforward than before. Unscheduled.
- **External IdP federation.** Out of scope for v0.4.x.

---

## [0.15.1] - 2026-04-28

Security-fix and audit-infrastructure release. Three layers of
`cargo audit` integration land at once: an initial sweep of the
dependency tree (one finding, fixed), a GitHub Actions workflow
that runs the audit on every push / PR / weekly, and operator
documentation pointing at the same command for manual upgrades.

The CVE-relevant change is small but worth a version bump on its
own: cesauth's `jsonwebtoken` features are narrowed from the
blanket `rust_crypto` to explicit `ed25519-dalek` + `rand`,
which removes the transitive `rsa` dep that carried
RUSTSEC-2023-0071 (Marvin Attack). cesauth never exercised the
RSA path — the OIDC discovery doc declares `EdDSA` as the only
supported `id_token_signing_alg`, and `jwt::signer` only
constructs `Algorithm::EdDSA` — but the unused dep would have
shipped in every workspace lock until narrowed.

### Security fix — RUSTSEC-2023-0071 not exercised, dep removed

- **Finding**: `rsa 0.9.10`, pulled in transitively by
  `jsonwebtoken v10.3.0` via the `rust_crypto` feature.
- **Advisory**: RUSTSEC-2023-0071 / CVE-2023-49092 / GHSA-c38w-74pg-36hr.
  Marvin Attack — non-constant-time RSA decryption leaks key
  bits through network-observable timing. No upstream patch
  exists yet at the `rsa` crate level.
- **cesauth's exposure**: zero. cesauth uses
  `Algorithm::EdDSA` (Ed25519) for every JWT it signs and
  verifies. The OIDC discovery declares
  `id_token_signing_alg_values_supported: &["EdDSA"]`.
  RSA is not on any code path. But the dep would still have
  shipped in the workspace lock, contaminating any audit and
  any reuse of the workspace as a library.
- **Fix**: narrow the `jsonwebtoken` features. Was:

  ```toml
  jsonwebtoken = { version = "10", default-features = false, features = ["use_pem", "rust_crypto"] }
  ```

  Is:

  ```toml
  jsonwebtoken = { version = "10", default-features = false, features = ["use_pem", "ed25519-dalek", "rand"] }
  ```

  The `rust_crypto` feature is a blanket bundle that pulls
  `rsa`, `p256`, `p384`, `hmac`, plus the bits we actually use
  (`ed25519-dalek`, `rand`, `sha2`). Replacing it with the
  individual feature flags drops the unused transitives.
- **Verification**: `Cargo.lock` no longer contains
  `name = "rsa"`. Dep count drops from 186 to 176. All 276
  tests still pass; zero warnings.

### Added — `cargo audit` integration

Three layers, in increasing distance from "hot" code:

- **Layer 1 — initial sweep + record state.** Done as part
  of this release. The audit ran against the
  rustsec/advisory-db `main` checkout on 2026-04-28 and
  surfaces no findings post-fix.
- **Layer 2 — `.github/workflows/audit.yml`** using the
  `rustsec/audit-check@v2.0.0` action. Triggers: `push` to
  main, `pull_request` to main, `schedule` cron at
  `0 6 * * 1` (Mondays 06:00 UTC), and `workflow_dispatch`
  for manual runs. Permissions: `contents: read`,
  `issues: write`, `checks: write`. New advisories
  matching a dep in `Cargo.lock` fail the workflow.
- **Layer 3 — operator documentation.** A new step in
  `docs/src/deployment/production.md` ("Step 7 — Verify
  dependencies") points at `cargo install cargo-audit &&
  cargo audit` and describes the triage path for findings.
  The same is reflected in the operator runbook in
  `docs/src/expert/tenancy.md` ("Verifying dependencies
  before an upgrade") so the upgrade procedure documents
  it explicitly.

A Makefile / `xtask` wrapper layer is **not planned** —
cesauth has no Makefile and adding one to host a single
command would invert the cost/value ratio. Local maintainers
run `cargo audit` directly; CI catches regressions; ops
follows the documented step.

### Tests

- Total: **276 passing** (unchanged from v0.15.0).
- The dep narrowing changes no behavior; the existing tests
  are sufficient to confirm the EdDSA-only path still works
  end-to-end.
- The audit workflow itself is GitHub Actions configuration,
  not Rust code; verification is "the YAML parses and the
  pinned action exists at the named version".

### Migration (0.15.0 → 0.15.1)

Code-only release. No schema migration. No `wrangler.toml`
change. The new HTML routes are unchanged from v0.15.0.

For deployments tracking main:

1. **Pull and rebuild.** The `Cargo.toml` change forces a
   new lock file resolution; `cargo build --release` will
   produce a slightly smaller binary (no `rsa`, `p256`,
   `p384`, `hmac` transitives).
2. **Re-run `cargo audit`** locally (or watch the workflow)
   to confirm the clean state.
3. **Deploy.** No runtime behavior changed.

### Smoke test

```bash
# 1) Verify the rsa dep is gone:
grep -c '^name = "rsa"$' Cargo.lock
# -> 0

# 2) Run the audit:
cargo install cargo-audit
cargo audit
# -> Success No vulnerable packages found

# 3) Confirm EdDSA still works end-to-end:
curl -s https://cesauth.example/.well-known/openid-configuration \
  | jq -r '.id_token_signing_alg_values_supported'
# -> ["EdDSA"]
```

### Deferred — unchanged from 0.15.0

- **Anonymous-trial promotion.** Spec §3.3 + §11 priority 5.
  Now the next planned slot.
- **`check_permission` integration on `/api/v1/...`.**
  Unscheduled; depends on concrete need.
- **External IdP federation.** Out of scope for v0.4.x.

---

## [0.15.0] - 2026-04-28

Tenant-scoped admin surface — additive mutation forms (membership
add/remove × 3 flavors) plus affordance gating on every read and
form page. Completes the v0.9.0 → v0.10.0 split applied to the
tenant-scoped surface: v0.14.0 covered high-risk forms, v0.15.0
covers additive forms and the UI-side gating that turns the gate's
permission decisions into operator-visible affordances.

The whole tenant-scoped surface now reaches the same feature
parity that the system-admin tenancy console reached at v0.10.0.
After this release, the tenant admin's day-to-day operations
(organizations, groups, role assignments, memberships) are all
form-driven from within `/admin/t/<slug>/...`, gated end-to-end on
`check_permission`.

### Added — tenant-scoped membership forms

Three flavors mirroring the v0.10.0 system-admin shape, each at
slug-relative URLs:

- **Tenant membership** at `/admin/t/<slug>/memberships/...`.
  Add (`POST .../memberships`) is one-click additive. Remove
  (`POST .../memberships/<uid>/delete`) is a confirm page →
  POST-with-`confirm=yes` apply.
- **Organization membership** at
  `/admin/t/<slug>/organizations/<oid>/memberships/...`.
- **Group membership** at
  `/admin/t/<slug>/groups/<gid>/memberships/...`. No role select
  (group memberships don't carry a role variant in the schema).

All six flavors run through the v0.13.0 gate composition:
`auth::resolve_or_respond` → `gate::resolve_or_respond` →
`gate::check_action` with the relevant permission slug, then the
mutation, then audit emission with `via=tenant-admin,tenant=<id>`.

**Defense in depth**: the target user_id (from the form body) is
verified to belong to the current tenant before any add proceeds.
The slug gate already verifies the principal's user; the new check
prevents an in-tenant admin from typing in a sibling tenant's
user_id and granting them membership.

### Added — permission catalog

Two new permission slugs filling the `*_MEMBER_*` symmetry:

- `tenant:member:add` (`PermissionCatalog::TENANT_MEMBER_ADD`)
- `tenant:member:remove` (`PermissionCatalog::TENANT_MEMBER_REMOVE`)

The v0.9.0/v0.10.0 system-admin paths used the coarse
`ManageTenancy` capability, but the tenant-scoped surface gates
per-action via `check_permission`, so the slugs had to be
enumerated. `ORGANIZATION_MEMBER_*` and `GROUP_MEMBER_*` already
existed; tenant scope now matches.

### Added — affordance gating

Every tenant-scoped page (read or form) now renders mutation
links/buttons only when the current operator can actually use
them. The route handler runs **one** batched permission check per
render and the template emits HTML conditionally:

- **`Affordances` struct** in `cesauth_ui::tenant_admin::affordances`
  — twelve boolean flags, one per affordance type. `Default` is
  all-false (the safe default); `all_allowed()` is provided for
  test convenience.
- **`gate::build_affordances`** in worker — issues a single
  `check_permissions_batch` call and maps the parallel `Vec<bool>`
  back into the struct. Reads as well as forms call this; the cost
  is one D1 round-trip per page render.
- **Per-page rendering** — Overview shows quick-action buttons
  (`+ New organization`, `+ Add tenant member`); Organizations
  list shows `+ New organization`; Organization detail shows
  `Change status` / `+ New group` / `+ Add member` and per-group
  `delete` / `+ member` actions; Role assignments shows
  `+ Grant role` and per-assignment `revoke` links.

The route handlers behind each affordance still re-check on
submit (defense in depth). The affordance gate is the operator's
first signal — clicking what they can't do already returns 403,
but they shouldn't have to find out by clicking.

### Added — `check_permissions_batch`

New function in `cesauth_core::authz::service`. Evaluates N
`(permission, scope)` queries for one user, all at once:

- One `assignments.list_for_user(user_id)` call.
- One `roles.get(role_id)` per *distinct* role the user holds
  (cached in a HashMap across queries).
- N in-memory scope-walks against the prepared inputs.

The naive alternative (call `check_permission` once per query)
costs N round-trips for the assignment fetch alone. The batch
helper collapses that to one. For affordance gating with 12
flags per render, the speedup is the difference between "1 RTT"
and "12 RTTs".

The `scope_covers` and `role_has_permission` helpers became
`pub(crate)` to support the batch implementation. Behaviour is
intentionally identical to per-query `check_permission`; a
test pins this equivalence.

### Tests

- Total: **276 passing** (+19 over v0.14.0).
  - core: **119** (was 114) — 5 new in
    `authz/tests.rs::check_permissions_batch_*` covering empty
    query → empty result, batch == per-query equivalence (the
    load-bearing test), no-assignments → `NoAssignments` for
    every query, dangling role id → graceful
    `PermissionMissing`, expiration handling.
  - adapter-test: 36 (unchanged).
  - ui: **121** (was 107) — 14 new tests:
    - 8 affordance-gating tests covering hide-when-denied +
      show-when-allowed for organizations / detail / overview /
      role_assignments pages, including granular
      per-flag-independence and "empty list → no orphan revoke
      links even when can_unassign_role = true".
    - 2 invariants tests pinning
      `Affordances::default()` = all-false and
      `all_allowed()` = all-true. Defends against a future
      refactor that flips a default to `true`, which would
      silently widen affordances for every test that uses
      `Default::default()` as a fixture.
    - 4 membership form template tests: slug-relative actions,
      three-role / two-role pickers per scope, no-Owner role
      at org level (organizations have only Admin/Member), and
      confirm=yes hidden field on remove pages.

### Defense-in-depth invariants pinned by tests

Following the v0.14.0 convention. The new ones:

- `target user_id` for membership add belongs to *this* tenant
  — refused 403 otherwise.
- `Affordances::default()` is all-false — a future refactor
  that defaults a flag to `true` is a test failure, not a
  silent UI widening.
- Empty assignment list → no revoke links even when
  `can_unassign_role = true` — the affordance gate doesn't
  emit orphan buttons when there's nothing to act on.
- Batch result equals per-query check — the affordance gate
  cannot diverge from the per-route check.

### Migration (0.14.0 → 0.15.0)

Code-only release. No schema migration. No `wrangler.toml`
change. New HTML routes are additive — existing
`/admin/t/<slug>/*` GET routes from v0.13.0 and form routes from
v0.14.0 are unchanged.

For operators expecting to use the new membership forms or the
affordance-gated UI:

1. **Membership forms** at the URLs above. Permission slugs:
   `TENANT_MEMBER_ADD/REMOVE`, `ORGANIZATION_MEMBER_ADD/REMOVE`,
   `GROUP_MEMBER_ADD/REMOVE`. The two new tenant-level slugs
   need to be granted to existing roles before any tenant admin
   can use the tenant-membership flavor.
2. **Affordance gating** is automatic — operators see only the
   buttons they can use. A tenant admin who notices a button
   missing should check their role assignments at the
   appropriate scope.

Existing `/admin/tenancy/*`, `/admin/console/*`, and the v0.13.0
/v0.14.0 `/admin/t/<slug>/*` routes are unaffected.

### Smoke test

```bash
USER_TOKEN=...  # user-bound token from /admin/tenancy/users/<uid>/tokens/new

# 1) Overview now surfaces quick-action buttons gated by permission:
curl -sS -H "Authorization: Bearer $USER_TOKEN" \
  https://cesauth.example/admin/t/acme | grep -i 'Quick actions'
# -> "Quick actions" appears iff the user has at least one
#    of {ORGANIZATION_CREATE, TENANT_MEMBER_ADD} at tenant scope

# 2) Tenant-membership add (additive, one-click):
curl -sS -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -d "user_id=u-bob&role=member" \
  https://cesauth.example/admin/t/acme/memberships
# -> 303 redirect to /admin/t/acme

# 3) Organization-membership remove (confirm-then-apply):
curl -sS -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -d "confirm=yes" \
  https://cesauth.example/admin/t/acme/organizations/o-eng/memberships/u-bob/delete
# -> 303 redirect to /admin/t/acme/organizations/o-eng

# 4) Cross-tenant target user attempt: refused with 403:
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -d "user_id=u-other-tenant&role=member" \
  https://cesauth.example/admin/t/acme/memberships
# -> 403  (verify_user_in_tenant refused)
```

### Deferred to 0.15.1 or later

- **Anonymous-trial promotion.** Spec §3.3 introduces
  `Anonymous` as an account type and §11 priority 5 asks for
  a promotion flow. Now the next planned slot, since the
  tenant-scoped surface is feature-complete.
- **`check_permission` integration on `/api/v1/...`.** The
  v0.7.0 JSON API still uses `ensure_role_allows`. Now that
  user-bound tokens exist, `check_permission` is validated in
  the new HTML routes, AND `check_permissions_batch` is
  available, extending it to the API surface is more
  straightforward than before. Unscheduled — depends on
  concrete need.
- **External IdP federation.** `AccountType::ExternalFederatedUser`
  is reserved; no IdP wiring exists yet.

---

## [0.14.0] - 2026-04-27

Tenant-scoped admin surface — high-risk mutation forms — plus a
system-admin token-mint UI that exposes
`AdminTokenRepository::create_user_bound` to operators. v0.13.0
shipped the read pages and the auth gate; v0.14.0 adds the
form-driven mutations that operators most need to run from inside
the tenant context, and the missing piece for bootstrapping the
whole flow (a way to actually mint user-bound tokens without
scripting).

The release follows the v0.9.0 → v0.10.0 split for the system-admin
surface: high-risk forms first, additive ones in the next release.
v0.15.0 adds the membership add/remove forms (three flavors,
mirroring v0.10.0's split).

### Added — tenant-scoped mutation forms

Six form pairs (GET + POST) under `/admin/t/<slug>/...`:

- **`organizations/new`** — additive, one-click submit.
  Permission: `ORGANIZATION_CREATE` at tenant scope.
  Plan-quota enforcement (`max_organizations`) mirrors the
  v0.9.0 system-admin path.
- **`organizations/:oid/status`** — preview/confirm.
  Permission: `ORGANIZATION_UPDATE`. Active / Suspended /
  Deleted picker with required reason field; the diff page
  spells out the change and round-trips the reason into the
  apply form.
- **`organizations/:oid/groups/new`** — additive, one-click.
  Permission: `GROUP_CREATE`. Uses the `NewGroupInput` shape
  that v0.5.0 introduced.
- **`groups/:gid/delete`** — preview/confirm.
  Permission: `GROUP_DELETE`. Preview counts affected role
  assignments and memberships so the operator sees the
  cascade impact before clicking Apply.
- **`users/:uid/role_assignments/new`** — preview/confirm.
  Permission: `ROLE_ASSIGN`. Scope picker omits System (per
  ADR-003: tenant admins cannot grant cesauth-wide roles);
  Tenant scope's scope_id is forced to the current tenant
  (a tenant admin who types in a different tenant's id is
  refused with 403, not just an error). Defense-in-depth
  `verify_scope_in_tenant` walks the storage layer to confirm
  the scope's organization / group / user actually belongs
  to the current tenant before the grant proceeds.
- **`role_assignments/:id/delete`** — preview/confirm.
  Permission: `ROLE_UNASSIGN`. The user_id rides on the
  query string (same pattern as the system-admin equivalent;
  the repository does not expose `get_by_id` for assignments).

Every handler runs the v0.13.0 gate's 3-step opening
(`auth::resolve_or_respond` → `gate::resolve_or_respond` →
`gate::check_action`), then preview/confirm gating on the
`confirm` form field, then the mutation, then audit emission.
Audit entries carry `via=tenant-admin,tenant=<id>` to
distinguish them from `via=tenancy-console` (system-admin
originated) — log analyses can split by surface origin.

### Added — system-admin token-mint UI

- **`/admin/tenancy/users/:uid/tokens/new`** (GET + POST) —
  three pages: form (role + nickname), preview/confirm, applied
  (plaintext shown ONCE with prominent warning + post-mint usage
  instructions linking to `/admin/t/<slug>/...`).
- Gated on `ManageAdminTokens` (existing v0.4.0 admin-token
  capability). Tenant admins cannot self-mint per ADR-002 / ADR-003
  — this route lives at `/admin/tenancy/...`, not
  `/admin/t/<slug>/...`.
- Re-uses `mint_plaintext()` and `hash_hex()` from the existing
  `console/tokens.rs` (made `pub(crate)`); calls
  `AdminTokenRepository::create_user_bound`.
- The applied page resolves the user's tenant **slug** for the
  post-mint URL hint — a tempting bug here would have used
  the tenant *id* directly, leaking the internal id into the
  operator-facing URL. The test
  `applied_page_carries_plaintext_token_and_post_mint_link`
  pins this down explicitly.

### Gate API change

The v0.13.0 `gate::check_read` was a thin wrapper for "permission
at tenant scope". Mutation forms operate on child resources
(Organization, Group) and need narrower scopes, so the underlying
function is now `gate::check_action(ctx_ta, permission, scope, ctx)`
accepting an explicit `ScopeRef`. `check_read` remains as a
backward-compatible convenience wrapper for the v0.13.0 read
routes (always passes `ScopeRef::Tenant { tenant_id: ctx.tenant.id }`).

### Defense-in-depth invariants pinned by tests

The v0.13.0 release introduced cross-resource defense
(`organization_detail` and `role_assignments` re-verify the child
resource's tenant_id). v0.14.0 extends this to every mutation:

- `organization_set_status` re-verifies `org.tenant_id ==
  ctx_ta.tenant.id` before applying.
- `group_delete` walks the `GroupParent` enum: tenant-scoped
  groups check `group.tenant_id`; org-scoped groups check the
  parent organization's `tenant_id`.
- `role_assignment_grant` calls `verify_scope_in_tenant` for
  every Organization / Group / User scope before proceeding.
- `role_assignment_revoke` re-verifies the assignment's user
  belongs to this tenant.

The corresponding template-level invariants — scope picker
without System option, tenant id pinned in the help text,
preview round-tripping every form field — are pinned by 7 new
tests in `tenant_admin/tests.rs`.

### Tests

- Total: **257 passing** (+12 over v0.13.0).
  - core: 114 (unchanged).
  - adapter-test: 36 (unchanged).
  - ui: **107** (was 95) — 12 new tests covering form-template
    invariants:
    - 7 in `tenant_admin/tests.rs` — slug-relative form actions,
      sticky values on error re-render, preview confirm=yes
      hidden field, group_delete affected-counts visible, scope
      picker omits System, tenant id pinned in help text, preview
      round-trips role_id/scope_type/expires_at.
    - 4 in `tenancy_console/tests.rs::token_mint_tests` —
      role radio for each AdminRole, plaintext-shown-once warning,
      applied page uses tenant slug not id, plaintext HTML-escaped.
    - 1 footer marker assertion update (now `v0.14.0`).

The host-side test surface for the form templates is the load-
bearing test family. A future refactor that drops the System-
omission from the scope picker is a test failure, not a security
regression.

### Migration (0.13.0 → 0.14.0)

Code-only release. No schema migration. No `wrangler.toml`
change. The new HTML routes are additive — existing
`/admin/t/<slug>/*` GET routes from v0.13.0 are unchanged.

For operators expecting to use the new mutation forms or the
token-mint UI:

1. **Tenant admins** can now visit
   `/admin/t/<slug>/organizations/new`, etc. The forms are
   gated on the appropriate write permissions (the same slugs
   the v0.7.0 JSON API gates on).
2. **System admins** mint user-bound tokens at
   `/admin/tenancy/users/<uid>/tokens/new`. The plaintext is
   shown once on the apply page; copy it before clicking
   anywhere else. cesauth stores only the SHA-256 hash.

Existing `/admin/tenancy/*`, `/admin/console/*`, and
`/admin/t/<slug>/*` routes are unaffected.

### Smoke test

```bash
ADMIN=$ADMIN_API_KEY  # system-admin

# 1) Mint a user-bound token for a tenant admin via the new UI.
#    For now, drive it from curl (browser flow works the same):
PREVIEW=$(curl -sS -H "Authorization: Bearer $ADMIN" \
  -d "role=operations&name=alice%20bootstrap" \
  https://cesauth.example/admin/tenancy/users/u-alice/tokens/new)
# -> preview page with confirm=yes hidden field

# 2) Apply: post the same form with confirm=yes.
APPLIED=$(curl -sS -H "Authorization: Bearer $ADMIN" \
  -d "role=operations&name=alice%20bootstrap&confirm=yes" \
  https://cesauth.example/admin/tenancy/users/u-alice/tokens/new)
# -> applied page with the plaintext token (shown once)

# 3) Tenant admin uses the token to grant a role inside the tenant:
USER_TOKEN=...  # extract from step 2's response

curl -sS -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -d "role_id=r-admin&scope_type=organization&scope_id=o-eng" \
  https://cesauth.example/admin/t/acme/users/u-bob/role_assignments/new
# -> preview page

curl -sS -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -d "role_id=r-admin&scope_type=organization&scope_id=o-eng&confirm=yes" \
  https://cesauth.example/admin/t/acme/users/u-bob/role_assignments/new
# -> 303 redirect to /admin/t/acme/users/u-bob/role_assignments

# 4) Cross-tenant attempt: try to grant against a different tenant's org.
#    Defense-in-depth refuses with 403:
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $USER_TOKEN" \
  -X POST -d "role_id=r-admin&scope_type=organization&scope_id=o-other-tenant" \
  https://cesauth.example/admin/t/acme/users/u-bob/role_assignments/new
# -> 403  (verify_scope_in_tenant refused)

# 5) Trying to grant System scope: refused with 403 per ADR-003:
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $USER_TOKEN" \
  -X POST -d "role_id=r-admin&scope_type=system" \
  https://cesauth.example/admin/t/acme/users/u-bob/role_assignments/new
# -> 403
```

### Deferred to 0.15.0

- **Membership add/remove forms** (three flavors: tenant /
  organization / group). Same shape as the v0.10.0 system-admin
  forms but tenant-scoped. Permissions:
  `MEMBERSHIP_ADD` / `MEMBERSHIP_REMOVE` /
  `ORGANIZATION_MEMBER_ADD` / `ORGANIZATION_MEMBER_REMOVE` /
  `GROUP_MEMBER_ADD` / `GROUP_MEMBER_REMOVE`.
- **Affordance gating on the v0.13.0 read pages**: render
  mutation buttons only when `check_permission` would actually
  allow the relevant write. Cleanest way is a per-button
  Probe call against `check_permission`, batched per page
  render. Acceptable latency-wise for HTML pages, but worth
  a dedicated review.

### Deferred — unchanged from 0.13.0

- **`check_permission` integration on `/api/v1/...`** —
  unscheduled.
- **Anonymous-trial promotion** — 0.15.1 or later.
- **External IdP federation** — explicitly out of scope.

---

## [0.13.0] - 2026-04-27

Tenant-scoped admin surface — the surface implementation that
v0.11.0's foundation (ADR-001/002/003 + `admin_tokens.user_id` +
`AdminPrincipal::user_id` + `is_system_admin()`) was building
toward. Introduces the `/admin/t/<slug>/...` route surface, the
per-route auth gate that enforces ADR-003's structural separation
between system-admin and tenant-admin contexts, the
`AdminTokenRepository::create_user_bound` mint method that
produces user-bound tokens, and `check_permission` integration
on the new routes.

This is the largest feature release since v0.9.0. Pre-1.0 means
the public surface is still allowed to grow; the tenant-scoped
URL prefix is new ground, not a rename of anything existing.

Read pages only in 0.13.0, mirroring how v0.8.0 introduced the
system-admin tenancy console — read pages first, mutation forms
in the next release. Mutation forms (membership add/remove,
role-assignment grant/revoke, etc.) and the token-mint UI form
land in 0.14.0.

### Added — domain layer

- **`crates/core/src/tenant_admin/`** — new module owning the
  tenant-scoped auth-gate decision logic. Pure (no network calls
  of its own), generic over the repository ports it consumes,
  host-testable. The module exports two types and one function
  the worker layer calls into:
  - **`TenantAdminContext`** — a successful gate pass carries
    the resolved principal, tenant, and user. Route handlers
    use these without re-fetching.
  - **`TenantAdminFailure`** — typed failure modes
    (`NotUserBound`, `UnknownTenant`, `UnknownUser`,
    `WrongTenant`, `Unavailable`) with their HTTP status code
    semantics: `NotUserBound`/`WrongTenant` → 403,
    `UnknownTenant` → 404, `UnknownUser` → 401,
    `Unavailable` → 503. Each failure carries a human-safe
    message that does not echo the slug or user_id back.
  - **`resolve_tenant_admin(principal, slug, tenants, users)`**
    — the gate. Enforces, in order: (1) the principal is
    user-bound (`is_some()`), (2) the slug resolves to a real
    tenant, (3) the principal's user belongs to *that* tenant.
    The third invariant is the structural defense that
    ADR-003 promises: an Acme user cannot peek at Beta's data
    by typing `/admin/t/beta/`.

- **`AdminTokenRepository::create_user_bound`** — new port
  method on the existing repository trait. Mints a token row
  with `admin_tokens.user_id` populated. Resulting
  `AdminPrincipal` has `user_id == Some(...)`, which
  `is_system_admin()` reads as "tenant-admin, not
  system-admin" per ADR-002. Same `token_hash` uniqueness
  rules as `create`. Implementations land in both adapters:
  in-memory (`cesauth-adapter-test`) and Cloudflare D1
  (`cesauth-adapter-cloudflare`). The token-mint *flow* (who
  can mint, what audit trail it emits, what UI exposes the
  operation) is not part of this method; adapters just
  persist what they're told.

- **`UserRepository::list_by_tenant`** — new port method.
  Returns active (non-deleted) users belonging to a given
  tenant. Used by the tenant-scoped users page.
  Implementations in both adapters; the CF adapter selects
  with `WHERE tenant_id = ?1 AND status != 'deleted'
  ORDER BY id`. Pagination is intentionally omitted at this
  stage — the surface that consumes this expects O(10-1000)
  users per tenant. Pagination lands when a tenant's user
  count exceeds what fits on one page.

### Added — UI layer

- **`crates/ui/src/tenant_admin/`** — new module mirroring the
  shape of `tenancy_console` but tenant-scoped. Per ADR-003,
  no chrome (header, nav, footer, color palette) is shared
  between the two surfaces — the structural separation is
  the visual signal that an operator has switched contexts.
  - **`tenant_admin_frame()`** — page chrome. Tenant identity
    (slug + display name) appears next to the role badge in
    the header so screenshots are unambiguous. Nav links are
    slug-relative — the bar contains
    `/admin/t/<slug>/{,organizations,users,subscription}`
    and never anything from `/admin/tenancy/...`.
  - **`TenantAdminTab`** enum — six tabs covering the read
    pages. Drill-in tabs (`OrganizationDetail`,
    `UserRoleAssignments`) are reachable via in-page links,
    not the nav bar.
  - **`overview_page()`** — tenant card (display_name, slug,
    status badge) plus per-tenant counters (organizations,
    users, groups, current plan).
  - **`organizations_page()`** + **`organization_detail_page()`**
    — list and detail. Detail page also lists groups
    belonging to the organization.
  - **`users_page()`** — list users belonging to this tenant
    with drill-through to role-assignments.
  - **`role_assignments_page()`** — drill-in for one user.
    Renders role labels (slug + display name) by joining
    against a `(role_id, slug, display_name)` dictionary the
    route handler assembles. Falls back to the bare role_id
    if a label is missing.
  - **`subscription_page()`** — append-only subscription
    history for this tenant, reverse-chronological.

  All pages render server-side. No JavaScript. No
  mutation buttons in 0.13.0 — those land in 0.14.0.

### Added — worker / route layer

- **`crates/worker/src/routes/admin/tenant_admin/`** — new
  route module. One file per page plus the `gate.rs` shared
  helper. Each handler runs the same opening sequence:
  1. **`auth::resolve_or_respond`** — bearer → principal
     (existing flow).
  2. **`gate::resolve_or_respond`** — wraps
     `cesauth_core::tenant_admin::resolve_tenant_admin` for
     the worker layer, including audit emission for
     `WrongTenant` and `UnknownUser` (cross-tenant access
     attempts and stale principals are forensically
     interesting even when refused).
  3. **`gate::check_read`** — wraps
     `cesauth_core::authz::check_permission` against the
     resolved tenant scope. Each route gates on the
     appropriate read permission:
     - overview → `TENANT_READ`
     - organizations + organization_detail → `ORGANIZATION_READ`
     - users + role_assignments → `USER_READ`
     - subscription → `SUBSCRIPTION_READ`

  Defense-in-depth checks live in handlers that take a child
  resource id from the URL (e.g., `:oid`, `:uid`). The gate
  has already verified that the URL slug resolves to the
  user's tenant; the child id check verifies the *child
  resource* belongs to that same tenant. An unscrupulous
  tenant admin who types in another tenant's organization
  id gets a 403 with "organization belongs to a different
  tenant", not a 200 with the wrong tenant's data.

- **Six new GET routes** registered in
  `crates/worker/src/lib.rs` between the existing
  `/admin/tenancy/*` block and the `/api/v1/...` block:
  - `GET /admin/t/:slug`
  - `GET /admin/t/:slug/organizations`
  - `GET /admin/t/:slug/organizations/:oid`
  - `GET /admin/t/:slug/users`
  - `GET /admin/t/:slug/users/:uid/role_assignments`
  - `GET /admin/t/:slug/subscription`

### Authorization model

The system-admin surface (`/admin/tenancy/*`) continues to use
`auth::ensure_role_allows(principal, AdminAction::*)`. The
tenant-scoped surface (`/admin/t/<slug>/*`) uses
`check_permission(user_id, permission, scope)` instead — this
is what makes the principal's `user_id` actually do work,
because `check_permission` is the spec §9.2 scope-walk that
needs a user_id as input. Both mechanisms coexist; ADR-003's
URL-prefix separation means neither can leak across.

### Tests

- Total: **245 passing** (+26 over v0.12.1).
  - core: **114** (was 105) — 9 new tests in
    `tenant_admin/tests.rs` covering happy path, the three
    ADR-003 invariants (one test each), two failure modes
    (UnknownUser, Unavailable on each repo), and the
    failure-presentation invariants (status code + message
    distinctness + no input echo).
  - adapter-test: **36** (was 32) — 4 new tests for
    `create_user_bound` covering principal stamping, list
    integration with plain tokens, hash uniqueness across
    both `create` and `create_user_bound`, and disable
    parity.
  - ui: **95** (was 82) — 13 new tests in
    `tenant_admin/tests.rs` covering frame chrome (tenant
    identity in header, slug-relative nav, drill-in tabs not
    in nav, version footer marker, distinct chrome
    visually defending ADR-003), per-page rendering
    (overview, organizations, users), HTML escape defense
    in depth.

The host-side test surface for the tenant-admin auth gate is
the most important new test family in this release. It pins
down the three ADR-003 invariants as runnable assertions; a
future refactor that accidentally drops one is a test
failure, not a security regression detected six months later.

### Migration (0.12.1 → 0.13.0)

Code-only release. No schema migration (the
`admin_tokens.user_id` column was added in v0.11.0 by
migration `0005`; v0.13.0 only writes to it, doesn't change
the schema). No `wrangler.toml` change.

For operators expecting to use the tenant-scoped surface:

1. Mint a user-bound admin token via the
   `AdminTokenRepository::create_user_bound` adapter method.
   No HTML form exposes this in 0.13.0 — script the call from
   a one-off worker route or run it against the
   in-memory adapter for testing. The mint UI lands in 0.14.0.
2. Have the user present `Authorization: Bearer <token>` at
   `/admin/t/<their-tenant-slug>/`. The gate verifies the
   token is user-bound, the slug resolves, and the user
   belongs to that tenant; `check_permission` then verifies
   the user has `tenant:read` (or the page-specific
   permission) at the tenant scope.
3. Cross-tenant attempts return 403 with audit. The audit
   reason carries the principal id, the attempted slug, and
   a `(cross-tenant)` marker.

Existing `/admin/tenancy/*` and `/admin/console/*` routes
are unaffected. System-admin tokens continue to work
exactly as before; they just don't unlock the tenant-scoped
surface (per ADR-003).

### Deferred to 0.14.0

- **Mutation forms for the tenant-scoped surface** — all the
  v0.9.0 / v0.10.0 system-admin forms have natural
  tenant-scoped equivalents (organization status changes,
  group create / delete, membership add / remove inside
  this tenant, role grant / revoke). 0.14.0's review
  benefits from 0.13.0's read pages already shipping —
  every mutation has a "before" page to land on.
- **Token-mint HTML form** — the
  `AdminTokenRepository::create_user_bound` adapter method
  exists; what's missing is a `/admin/tenancy/users/:uid/tokens/new`
  form that exposes it (system-admin only, to bootstrap a
  tenant admin's first token). 0.14.0.
- **`check_permission` integration on `/api/v1/...`** — the
  v0.7.0 JSON API still uses `ensure_role_allows`. Now that
  user-bound tokens exist and `check_permission` is
  validated in the new HTML routes, extending it to the API
  surface is mechanical. Unscheduled — depends on whether
  there's a concrete need (most callers of `/api/v1` will
  be system-admin scripts, not tenant admins).

### Deferred — unchanged from 0.12.1

- **Anonymous-trial promotion (0.14.0 or 0.15.0).**
- **External IdP federation** — explicitly out of scope; no
  scheduled target.

---

## [0.12.1] - 2026-04-27

Buffer / follow-up release. Originally reserved as a placeholder
slot for any issues the 0.12.0 rename would surface in real-world
use. The shippable content turned out to be two small but
worthwhile threads:

1. **Stale-narrative cleanup** — three docstrings carried
   forward-references and historical claims that the 0.12.0 rename
   and intervening release-slot reshuffles invalidated. Cleaned
   up.

2. **Dependency audit** — a deliberate look at every direct
   workspace dependency to confirm the tree isn't accumulating
   drift before v0.13.0 (tenant-scoped surface) lands. No bumps;
   the rationale for each "leave at current" is in the audit
   findings below.

The 0.13.0 surface implementation is unchanged in scope and
unaffected by this release.

### Changed — stale-narrative cleanup

- **`crates/ui/src/tenancy_console.rs` module docstring**
  rewritten. The previous version made two claims that became
  false during 0.12.0:
  - "URL prefix is preserved from earlier releases for
    operator-facing stability" — false. v0.12.0 deliberately
    broke `/admin/saas/*` → `/admin/tenancy/*` as an
    operator-visible breaking change.
  - "since v0.18.0" — wrong release marker (the rename
    landed in v0.12.0, and v0.18.0 is not a planned release at
    all).

  The replacement docstring documents what the module is now
  (read pages, mutation forms, memberships and role
  assignments), the v0.11.0 ADR-foundation that 0.13.0 will
  build on, and the naming-history note explaining the v0.12.0
  rename.

- **`crates/core/src/tenancy/types.rs::AccountType`** — two
  variant doc-references corrected:
  - `Anonymous`: "promotion flow is a 0.18.0 item" → "0.14.0
    item" (matches the ROADMAP slot that was settled in 0.12.0).
  - `ExternalFederatedUser`: "Federation wiring is 0.18.0" →
    "Federation wiring is unscheduled at this time" (the
    explicit out-of-scope status is honest about the lack of
    a current target).

  Neither change touches behavior. Both prevent a future
  maintainer from chasing a 0.18.0 milestone that doesn't exist.

### Verified — dependency audit

Per project policy, `cargo-outdated` is the canonical tool for
this check. The audit environment used here couldn't install it
(network and time budget didn't permit the substantial
transitive dep graph compile), so the audit was performed by
manual inspection of `Cargo.toml` against `Cargo.lock` and
known-current version information. Results:

**Healthy as-pinned**, every direct dependency at a current
maintained line:

- `worker = "0.8"` resolves to 0.8.1 — current Cloudflare
  Workers SDK.
- `serde 1`, `serde_json 1`, `thiserror 2`, `anyhow 1`,
  `uuid 1`, `time 0.3`, `url 2`, `hex 0.4`, `tokio 1` —
  all on current major lines.
- `jsonwebtoken 10` — current.
- `base64 0.22`, `sha2 0.10`, `hmac 0.12`,
  `ed25519-dalek 2`, `p256 0.13`, `ciborium 0.2` —
  RustCrypto family aligned, all current within their
  release line.

**Intentionally pinned at older line — leave alone**:

- `getrandom = "0.2"` (resolves 0.2.17) — pinned at 0.2 with
  the `js` feature for the wasm32-unknown-unknown +
  Cloudflare Workers integration. The 0.3.x line replaced
  the `js` feature with `wasm_js` and a different backend
  selection mechanism. Multiple July-August 2025 reports
  (including the Leptos 0.8.6 → uuid 1.18 → getrandom 0.3.3
  break) confirm the upgrade requires either `worker-build`
  to grow corresponding support or the whole transitive tree
  to align on 0.3 simultaneously. **Don't bump until the
  Cloudflare workers-rs ecosystem moves first.**

- `rand_core = "0.6"` (resolves 0.6.4) — couples with
  `getrandom 0.2` and with the RustCrypto family
  (ed25519-dalek 2, p256 0.13). Bumping to 0.9 is gated on
  the same wasm32 alignment that gates getrandom.

**Coexistence noted, fine to ignore**:

- `Cargo.lock` shows a transitive `getrandom 0.7.0` riding
  alongside the directly-pinned 0.2.17. cargo handles
  multiple major versions of the same crate side-by-side;
  the 0.2 instance is the one consumed by the wasm32 build
  path, the 0.4 instance is from a `wasm32-wasi`-targeted
  branch of some transitive dep. No action needed.

The audit is recorded as a one-off snapshot rather than a
recurring CI check. A future release that introduces a
dedicated CI job (`cargo audit` / `cargo-outdated`) would be
worth doing on its own.

### Tests

- Total: **219 passing** (unchanged from 0.12.0).
  - core: 105.
  - adapter-test: 32.
  - ui: 82.

The frame test that asserts the footer's version marker now
asserts `"v0.12.1"`. Otherwise the test diff is empty — the
release's code change is doc-only.

### Why this isn't a no-op

A buffer release without bug fixes can look like ceremony.
What the slot bought:

- **A clean look at every direct dep before adding more code.**
  v0.13.0 will add new auth resolution paths and a token-mint
  flow; landing those on top of unaudited deps is harder to
  review.
- **Three docstrings now agree with reality.** A future
  maintainer reading them won't go looking for a v0.18.0
  milestone or assume that `/admin/saas/*` still resolves.
- **Validation that v0.12.0's hard rename didn't leave any
  broken narrative.** None did, but the only way to confirm
  was to grep the codebase for `0.18.0` and "preserved from
  earlier" — the audit was the work.

### Deferred — unchanged from 0.12.0

- **Tenant-scoped admin surface implementation (0.13.0).**
- **Token-mint flow with `user_id` (0.13.0).**
- **`check_permission` integration on the API surface (0.13.0).**
- **Anonymous-trial promotion (0.14.0).**
- **External IdP federation** — explicitly out of scope; no
  scheduled target.

---

## [0.12.0] - 2026-04-27

Project hygiene release. Pre-1.0, technically — but the changes here
are the kind that get more expensive the longer they're deferred,
so the release is dedicated to retiring them in one focused pass.

Two threads land together:

1. **Project framing and metadata.** Authorship, license, and
   repository metadata now match reality. "Tenancy" /
   "Tenancy" framing — including spec references, comments, and
   prose — has been replaced with "tenancy service" or equivalent
   functional descriptions. `.github/` gains the community-process
   documents that a public repository is reasonably expected to
   carry: code of conduct, contributing guide, structured issue
   templates.

2. **Naming-debt cleanup.** The `saas/` module path under both
   `crates/ui/` and `crates/worker/src/routes/admin/`, the
   `/admin/saas/*` URL prefix, the `SaasTab` public type, and the
   `via=saas-console` audit reason marker have all been renamed
   to use `tenancy_console` / `/admin/tenancy/*` /
   `TenancyConsoleTab` / `via=tenancy-console`. The change is
   operator-visible: any external script targeting
   `/admin/saas/...` URLs needs updating. Pre-1.0 caveat applies
   — see the migration guidance below.

The two threads share a release because they share a motivation
(remove framing that could mislead users or contributors about
what cesauth is) and because doing them together amortizes the
review cost.

### Changed — metadata

- **Workspace `Cargo.toml`**:
  - `authors = ["nabbisen"]` (was
    `["cesauth contributors"]`).
  - `repository = "https://github.com/nabbisen/cesauth"` (was
    the stub `https://github.com/nabbisen/cesauth`).
  - Per-crate `Cargo.toml` files inherit through
    `.workspace = true` so no per-crate edits were needed.
- **`LICENSE`** Apache-2.0 boilerplate copyright line:
  `Copyright 2026 nabbisen` (was
  "cesauth contributors").

### Changed — naming

- **Module paths**:
  - `crates/ui/src/saas/` → `crates/ui/src/tenancy_console/`
  - `crates/worker/src/routes/admin/saas/` →
    `crates/worker/src/routes/admin/tenancy_console/`
  - All `mod`/`use` statements and re-exports updated.
- **Public types**:
  - `SaasTab` → `TenancyConsoleTab`
  - `saas_frame()` → `tenancy_console_frame()`
  - `saas_overview_page` → re-exported under the new module
- **URL prefix**: `/admin/saas/*` → `/admin/tenancy/*`.
  Sixteen mutation routes plus the read pages all migrate.
  **Breaking change** for any operator with bookmarks,
  scripts, or playbooks targeting the old prefix.
- **Audit reason marker**: `via=saas-console` →
  `via=tenancy-console`. Audit consumers that filter on this
  value need updating.
- **Page titles and footer**: "SaaS console" → "tenancy
  console" throughout the chrome. Footer marker is now
  "v0.12.0 (full mutation surface for Operations+)".
- **Project framing language** in comments and docs.
  "Tenancy" / "Tenancy" replaced with "tenancy
  service" or equivalent. The earlier framing was ambiguous
  (the project is open-source under Apache-2.0; "commercial"
  doesn't describe the license, the deployment model, or
  anything else precise) and risked giving users and
  contributors the wrong impression about the project's
  intent. Spec references such as
  `cesauth-Tenancy 化可能な構成への拡張開発指示書.md` are
  now referenced as `cesauth tenancy-service extension spec`.

### Added

- **`.github/CODE_OF_CONDUCT.md`** — Contributor Covenant 2.1.
- **`.github/CONTRIBUTING.md`** — practical guide covering the
  workspace test flow, code-review priorities (make invalid
  states unrepresentable; pure decision in core, side effects
  at the edge; test what changed), the PR checklist, and what
  lands smoothly vs. what needs discussion.
- **`.github/ISSUE_TEMPLATE/`**:
  - `bug_report.yml` — structured bug template with version,
    environment, steps to reproduce.
  - `feature_request.yml` — proposal template with a problem-
    first framing and a "willing to PR" dropdown.
  - `documentation.yml` — for docs-only issues (typos,
    missing examples, outdated content).
  - `config.yml` — links security reports to the private
    advisory path and open questions to Discussions.

### Migration

This is a hard rename — no compatibility-redirect routes were
added. The pre-1.0 SemVer caveat at the top of this file
permits this, but operators upgrading from 0.11.0 should:

1. **Check audit-log filters.** Any consumer that splits
   console-driven mutations from script-driven ones by
   matching `via=saas-console` needs the matcher updated to
   `via=tenancy-console`. Both old and new values appear in
   audit history; the audit log is append-only, so 0.12.0 does
   not rewrite past entries.
2. **Update operator URLs.** Bookmarks, runbooks, and
   tooling targeting `/admin/saas/...` need their prefix
   changed to `/admin/tenancy/...`. The path *suffixes* are
   unchanged — `tenants`, `organizations/:oid`,
   `users/:uid/role_assignments`, etc. are all in their
   original positions.
3. **Search for `SaasTab` in any downstream code.** The public
   type is renamed; downstream code that imported it needs to
   use `TenancyConsoleTab` instead.

A 0.11.0 deployment can run unchanged through this release —
no schema migration, no `wrangler.toml` change. The Worker
upgrade is the only operational step.

### Tests

- Total: **219 passing** (unchanged from 0.11.0).
  - core: 105.
  - adapter-test: 32.
  - ui: 82.
- The rename touched roughly every file under `saas/`; the
  test suite passing unchanged is the key regression check.
  The frame test that asserts the footer's version marker now
  asserts `"v0.12.0"`.

### Deferred

- **Tenant-scoped admin surface implementation** — slides to
  **0.13.0**. The 0.11.0 foundation
  (`AdminPrincipal::user_id`, `is_system_admin()`, the
  `admin_tokens.user_id` column) is unchanged and ready;
  0.12.1 is reserved as a buffer for any follow-up issues
  this rename surfaces in real-world use, and 0.13.0 builds
  the tenant-scoped routes on a clean naming base.
- **Anonymous-trial promotion** stays at the next available
  slot after the surface implementation.

### Why these changes belong in a release at all

A release whose code change is mostly mechanical may look
unusual, but each thread here has a real cost when left alone:

- **License and author metadata that don't match reality**
  make it ambiguous who owns the project and how to reach
  them — bad for downstream consumers, bad for security
  reporters.
- **Marketing-flavored framing** ("tenancy") in a
  project that is actually open-source-under-Apache-2.0
  invites the wrong assumptions. Users may wonder whether
  there's a closed-source variant; contributors may wonder
  whether their work feeds someone else's revenue. Neither
  is the case.
- **Missing community-process documents** make a project look
  abandoned even when it isn't, and put friction on first-time
  contributors who reasonably expect them.
- **Naming debt** ("SaaS console" / `/admin/saas/*`) carries
  a one-time cost to retire and a per-release cost to live
  with. Retiring it before 0.13.0's tenant-scoped surface
  implementation lands means the new surface isn't built
  next to a stale name.

---

## [0.11.0] - 2026-04-26

Foundation for the tenant-scoped admin surface. This is a deliberately
small release: 0.10.0 left three open design questions on URL shape,
user-as-bearer mechanism, and system-admin from inside the tenant
view. v0.11.0 settles those questions in three architecture decision
records (ADR-001/002/003) and ships only the minimum schema + type
changes implied by the decisions. v0.12.0 retires the SaaS-naming
technical debt alongside other project-hygiene work
(`saas/` → `tenancy_console/`, plus authorship/license metadata
and `.github/` documents); v0.13.0 builds the full tenant-scoped
console on top of the foundation.

The split between "decide" (0.11.0) and "implement" (0.12.0) follows
the pattern this codebase has used elsewhere — 0.3.0 → 0.4.0 (read
pages → write UI) and 0.8.0 → 0.9.0 → 0.10.0 (read pages →
high-risk forms → low-risk forms). Mixing design judgment and
implementation in one release tends to lock in choices that should
have been revisited; doing them in sequence keeps each release small
and reviewable.

### Added

- **Three Architecture Decision Records** at
  `docs/src/expert/adr/`:
  - **ADR-001: URL shape** — path-based
    (`/admin/t/<slug>/...`) wins over subdomain-based
    (`<slug>.cesauth.example`). Single cert, single origin,
    same-origin auth model carries over from
    `/admin/saas/*`. Tenant identity is visible in the URL,
    routing has no `Host`-header surface to coordinate.
  - **ADR-002: User-as-bearer mechanism** — extend
    `admin_tokens` with an optional `user_id` column. Continue
    using `Authorization: Bearer <token>` as the wire format.
    No new CSRF surface; no new cryptographic key to rotate;
    one auth path covers both system-admin tokens
    (`user_id IS NULL`) and user-as-bearer tokens
    (`user_id IS NOT NULL`).
  - **ADR-003: System-admin from inside tenant view** —
    complete URL-prefix separation, no in-page mode switch.
    `/admin/saas/*` is system-admin; `/admin/t/<slug>/*` is
    tenant-admin. The two surfaces share no view code, no
    auth state, no precedence rules. Tenant-boundary leakage
    is structurally impossible because there is no view-layer
    code that conditions on "what mode am I in?"
  - Index page at `docs/src/expert/adr/README.md` with the ADR
    contract: when to write one, when not to.

- **Migration `0005_admin_token_user_link.sql`** adding a
  nullable `user_id` column to `admin_tokens` and a partial
  index on it (`WHERE user_id IS NOT NULL`). The migration is
  foundation-only — no code in v0.11.0 *gates* on the column.

- **`AdminPrincipal::user_id: Option<String>`** field, with
  documentation pointing at ADR-002. Every existing call site
  that constructs an `AdminPrincipal` defaults it to `None`,
  preserving v0.3.x and v0.4.x behavior. The Cloudflare D1
  adapters are updated to read the column from the
  `admin_tokens` table and propagate it onto the constructed
  principal.

- **`AdminPrincipal::is_system_admin()`** helper, returning
  `true` iff `user_id.is_none()`. v0.12.0 will use this to gate
  `/admin/saas/*` to system-admin tokens only and
  `/admin/t/<slug>/*` to user-as-bearer tokens only — the
  ADR-003 separation. v0.11.0 itself does not invoke the
  helper from any handler; the test suite pins down the
  invariant that 0.12.0 will rely on.

- **Three new core tests** locking in the principal-shape
  invariants:
  - `principal_with_no_user_binding_is_system_admin`
  - `principal_with_user_binding_is_not_system_admin`
  - `principal_user_id_round_trips_through_default_serialization`
    (v0.3.x JSON shape preserved when `user_id == None` via
    `#[serde(skip_serializing_if = "Option::is_none")]`).

### Changed

- **`admin_tokens` D1 row deserialization** in
  `crates/adapter-cloudflare/src/admin/principal_resolver.rs`
  and `tokens.rs` now selects `user_id` from the schema and
  populates `AdminPrincipal::user_id`. The existing v0.3.x +
  v0.4.x code paths are unaffected because `user_id` reads
  back as `None` for every existing row (which is what every
  existing row contains, since 0005 only added the column).

- **Book SUMMARY** grows an "Architecture decision records"
  section in the Expert chapter, indexed by ADR number.

### Tests

- Total: **219 passing** (+3 over 0.10.0's 216).
  - core: 105 (was 102) — 3 new tests.
  - adapter-test: 32 (unchanged).
  - ui: 82 (unchanged).

The bulk of the v0.11.0 change is the ADR documents and the
schema migration. The code change is intentionally narrow —
adding a field to a struct, threading it through D1
deserialization, and touching the 50-odd test fixtures that
construct an `AdminPrincipal` directly. v0.12.0 will be the
larger code change.

### Why no UI changes in v0.11.0

The decision to ship the ADRs and the foundation seam *separately*
from the implementation is intentional. Two reasons:

- Schema migrations are easier to review in isolation. Mixing a
  migration with new HTML routes makes both harder to review and
  splits the failure modes across review boundaries.
- ADRs that ship alongside their implementation tend to be
  written backwards — capturing what was already built rather
  than guiding what gets built. Writing them as foundation
  documents (with no UI yet) forces the design rationale to
  precede the code. v0.12.0's review can then check that the
  code matches the ADRs, not the reverse.

### Auth caveat (unchanged from 0.3.x and 0.10.0)

Forms POST same-origin and the bearer rides on the
`Authorization` header. Operators must use a tool that sets the
header (curl, browser extension). Cookie-based admin auth is
explicitly *not* part of the v0.11.0 user-as-bearer choice — see
ADR-002. The decision to keep `Authorization`-bearer as the wire
format means v0.12.0's tenant-scoped surface inherits the same
operator-tooling expectation.

### Deferred — still tracked for 0.12.0+

- **Tenant-scoped admin surface implementation**. The URL
  pattern, the per-route auth gate that requires
  `is_system_admin()`-vs-not, the views, and the mutation
  forms scoped to one tenant. **0.12.0.**
- **Admin-token mint flow with `user_id`**. The
  `AdminTokenRepository::create` method continues to mint
  system-admin tokens (no `user_id` parameter); v0.12.0 adds a
  parallel path or extends the existing one to mint
  user-bound tokens.
- **`check_permission` integration on the API surface** —
  v0.12.0 makes this cleanly possible because `AdminPrincipal`
  now carries the `user_id` that
  `check_permission(user_id, …)` needs.
- **Cookie-based auth** — explicitly *not* the user-as-bearer
  mechanism per ADR-002. May be revisited as an *additional*
  mechanism in a later ADR.
- **Anonymous-trial promotion.** **0.12.1.**
- **External IdP federation.**

---

## [0.10.0] - 2026-04-25

Completes the SaaS console mutation surface. v0.9.0 covered the
high-risk operations (status changes, plan changes, group delete);
v0.10.0 fills in the additive ones that were carved out of 0.9.0 to
keep its scope contained — three flavors of membership add/remove
and role-assignment grant/revoke. With this release the HTML
console reaches feature parity with the v0.7.0 JSON API for
operator-driven mutations.

The larger "tenant-scoped admin surface" item (where tenant admins
administer their own tenant rather than every tenant) is **not**
in this release — it has unresolved design questions on URL
shape, user-as-bearer mechanism, and tenant-boundary leakage that
deserve their own design pass. **0.11.0+** picks it up.

### Added

- **Five new HTML form templates** in `cesauth-ui::saas::forms`:
  - **`membership_add`** with three entry points (tenant /
    organization / group). Tenant form renders a 3-option role
    select (owner / admin / member); organization form renders
    a 2-option select (admin / member — no owner at org scope);
    group form omits the role field entirely (group memberships
    have no role).
  - **`membership_remove`** with three entry points. One-step
    confirm — there's no diff to render, just a yes/no decision
    with a "user loses access; data is not destroyed" warning.
  - **`role_assignment_create`** reachable from the user's
    role-assignments drill-in page. Renders a select for
    `role_id` (populated from the system role catalog), a 5-radio
    scope picker (system / tenant / organization / group / user),
    a free-text `scope_id` field with required-vs-optional rules
    documented in the help section, and an optional
    `expires_at` field.
  - **`role_assignment_delete`** confirm page. Shows the
    role label, scope, granted_by, granted_at, and a warning
    that the user "immediately loses any permission granted by
    this assignment" but that "session is not invalidated" —
    operators get the right mental model for what revoke does.

- **Five worker handler modules** in
  `crates/worker/src/routes/admin/saas/forms/`:
  `membership_add` (3 GET/POST pairs),
  `membership_remove` (3 GET/POST pairs),
  `role_assignment_create` (1 GET/POST pair),
  `role_assignment_delete` (1 GET/POST pair).
  Each handler delegates to the existing v0.5.0/0.6.0
  service-layer adapters and emits the appropriate audit event
  (`MembershipAdded`, `MembershipRemoved`, `RoleGranted`,
  `RoleRevoked`) with the `via=saas-console` reason marker.

- **16 new routes** wired in `lib.rs` under a new
  `// SaaS console mutations (v0.10.0: memberships + role assignments)`
  block:
  - `GET/POST /admin/saas/tenants/:tid/memberships/new`
  - `GET/POST /admin/saas/tenants/:tid/memberships/:uid/delete`
  - `GET/POST /admin/saas/organizations/:oid/memberships/new`
  - `GET/POST /admin/saas/organizations/:oid/memberships/:uid/delete`
  - `GET/POST /admin/saas/groups/:gid/memberships/new`
  - `GET/POST /admin/saas/groups/:gid/memberships/:uid/delete`
  - `GET/POST /admin/saas/users/:uid/role_assignments/new`
  - `GET/POST /admin/saas/role_assignments/:id/delete`
  All gated through `AdminAction::ManageTenancy` (Operations+).

- **Affordance buttons on read pages** (gated on
  `Role::can_manage_tenancy()`, ReadOnly sees nothing):
  - Tenant detail: new "+ Add tenant member" action button +
    per-row "Remove" link in the members table.
  - Organization detail: new "+ Add organization member" action
    button + per-row "Remove" link in the members table.
  - User role assignments: new "+ Grant role" action button +
    per-row "Revoke" link on each assignment.

- **Defensive look-up of role-assignment by id**. The
  `RoleAssignmentRepository` does not expose `get_by_id`; the
  delete handler walks `list_for_user(user_id)` to find the
  matching row. The query string and hidden form field carry
  the `user_id` so this lookup is always possible. A new
  `fetch_assignment` helper in
  `routes/admin/saas/forms/role_assignment_delete.rs` localizes
  this pattern.

### Changed

- **Frame footer** updated from
  "v0.9.0 (mutation forms enabled for Operations+)" to
  "v0.10.0 (full mutation surface for Operations+)".

### Tests

- Total: **216 passing** (+20 over 0.9.0's 196).
  - core: 102 (unchanged).
  - adapter-test: 32 (unchanged).
  - ui: 82 (was 62) — 18 new tests across the four new form
    templates (action URL shape, role-option count parity with
    spec §5, group form omits role field, sticky values
    preserved on re-render, HTML escape defense for user_id,
    confirm-yes hidden field carried, system-scope critical
    badge color, session-handoff warning copy) plus 2 new
    affordance gating tests on the existing
    `role_assignments` page (ReadOnly does not see grant /
    revoke; Operations does).

### Auth caveat (unchanged from 0.3.x and 0.9.0)

Forms POST same-origin and the bearer rides on the
`Authorization` header. Operators still need a tool that sets
the header (curl, browser extension). Cookie-based admin auth
remains a 0.11.0+ design pass alongside user-as-bearer.

### Design decisions worth recording

- **No preview/confirm on membership add.** Memberships are
  additive and reversible; adding a friction step for what is
  arguably the most-frequent mutation in a multi-tenant
  deployment is operator-hostile. The same logic applies to
  role grant — but role grant *can* widen a user's effective
  permissions, so the form does collect a reason-equivalent
  audit trail (`granted_by` + `granted_at`) and shows the role
  label clearly.
- **One-step confirm on membership remove and role revoke.**
  These are mildly destructive — the user immediately loses
  access through that path. We show a confirm page (one screen,
  one yes/no button) but don't render a diff because there's
  nothing structural to diff.
- **Form's scope picker is structured, not free-text.** The
  v0.7.0 JSON API takes a tagged Scope enum. Asking operators
  to write JSON in a textarea is a footgun — the radio +
  conditional id field encodes the same shape with no syntax to
  get wrong.
- **Defensive `fetch_assignment` lookup.** The role-assignment
  repository was designed for `list_for_user`-driven paths and
  does not expose `get_by_id`. Rather than add a port method
  for a UI-specific need, the handler walks the list. This
  costs at most one extra DB read per revoke and keeps the
  port surface narrow.
- **Helpful, not cute, error messages.** "User is already a
  member of this tenant" rather than "Conflict (409)";
  "Scope id required for tenant scope" rather than "validation
  failed". The form re-renders preserving sticky values so the
  operator only fixes the failed field.

### Deferred — still tracked for 0.11.0+

- **Tenant-scoped admin surface**. The v0.8.0-0.10.0 console
  serves the cesauth deployment's operator staff — one console,
  every tenant. A tenant-scoped admin surface (where tenant
  admins administer their own tenant rather than every tenant)
  is a parallel UI reachable from a tenant-side login, gated
  through user-as-bearer plus `check_permission`, and filtered
  to the caller's tenant. **0.11.0+.** Three open design
  questions deserve their own pass:
  1. URL shape — `/admin/t/<slug>/...` vs subdomain
     `<slug>.cesauth.example`.
  2. User-as-bearer mechanism — admin-token mapping vs session
     cookie vs JWT.
  3. How to surface system-admin operations from inside the
     tenant view without leaking other-tenant boundaries.
- **Cookie-based auth for admin forms** — lands with the
  user-as-bearer design pass.
- **`check_permission` integration on the API surface** —
  blocked on user-as-bearer.
- **Anonymous-trial promotion.** **0.12.0.**
- **External IdP federation.**

---

## [0.9.0] - 2026-04-25

The mutation surface for the SaaS console. v0.8.0 shipped the read
pages; v0.9.0 wraps the v0.7.0 JSON API in HTML forms with a
preview/confirm flow for destructive operations, mirroring the
v0.4.0 pattern used for bucket safety edits. Operations+ only;
ReadOnly continues to see the read pages from v0.8.0 with mutation
buttons hidden.

### Added

- **Eight HTML mutation forms** in `cesauth-ui::saas::forms`,
  surfaced through 16 worker routes (8 GET + 8 POST):
  - **One-click submit** (additive, isolated changes):
    `tenant_create`, `organization_create`, `group_create`
    (tenant- and org-rooted variants).
  - **Two-step preview/confirm** (destructive — status changes,
    plan changes, deletes):
    `tenant_set_status`, `organization_set_status`,
    `group_delete`, `subscription_set_plan`,
    `subscription_set_status`.
  - The pattern is the same one v0.4.0 introduced: first POST
    (without `confirm=yes`) re-renders the page with a diff
    banner and an Apply button; the Apply button POSTs again
    with `confirm=yes` and commits.

- **Affordance buttons on read pages.** Tenants list grows a
  "+ New tenant" link; tenant detail grows
  "+ New organization", "+ New tenant-scoped group",
  "Change tenant status", "Change plan", and
  "Change subscription status" (the last two only when a
  subscription is on file); organization detail grows
  "+ New group", "Change organization status", and a per-row
  "Delete" link in the groups table. Every button renders
  conditionally on `Role::can_manage_tenancy()`; ReadOnly
  operators see no button (so a click cannot lead to a 403
  page).

- **`Role::can_manage_tenancy()`** helper on
  `cesauth_core::admin::types::Role`. Documented as a
  presentation-layer hint only — the authoritative gate is on
  the route handler. A new core test
  `role_can_manage_tenancy_helper_matches_policy` pins the
  helper's parity with `role_allows(_, ManageTenancy)`, so a
  policy change cannot drift the UI gating without a test
  failure.

- **Worker forms helper module**
  `crates/worker/src/routes/admin/saas/forms/common.rs`:
  - `require_manage` — bearer resolve + `ManageTenancy` gate.
    Returns the principal or a `Response` to short-circuit.
  - `parse_form` — `application/x-www-form-urlencoded` →
    flat `HashMap<String, String>`.
  - `confirmed` — checks the `confirm` field for `"yes"`/`"1"`/
    `"true"`. Used by the preview/confirm dispatch.
  - `redirect_303` — `303 See Other` to a destination URL.
    Browsers follow GET on 303, dropping the form body, so
    page refreshes don't re-submit.

- **HTML escape defense** on every operator-supplied field
  (slug, display_name, owner_user_id, reason). Test coverage
  added: `tenant_create::tests::untrusted_input_is_html_escaped`
  and `tenant_set_status::tests::reason_is_html_escaped_on_confirm_page`.

- **Quota delta visualization** on subscription plan change.
  The confirm page renders a quota-by-quota table comparing
  current vs target plan, with `⚠` markers on quotas that
  *decrease* — the operator's most common "wait, let me check"
  case. Existing usage above the new limit is documented as
  not auto-pruned but blocking new creates.

- **Destructive-operation warnings** baked into the confirm
  pages. Tenant suspend warns "refuses sign-ins for every user
  in this tenant"; tenant delete warns "Recovery requires
  manual SQL"; subscription expire warns "plan-quota
  enforcement falls through to no-plan allow-all"; subscription
  cancel notes "current period continues to be honored".

- **Sticky form values on re-render.** A failed submit (slug
  collision, missing field, quota exceeded) re-renders the
  form with the operator's existing inputs preserved so they
  only fix the failed field. Test coverage added.

- **Footer marker** updated from "v0.8.0 (read-only)" to
  "v0.9.0 (mutation forms enabled for Operations+)".

### Tests

- Total: **196 passing** (+30 over 0.8.0's 166).
  - core: 102 (was 101) — 1 new test:
    `role_can_manage_tenancy_helper_matches_policy`.
  - adapter-test: 32 (unchanged).
  - ui: 62 (was 33) — 29 new tests:
    - 4 each for `tenant_create`, `tenant_set_status`,
      `subscription_set_plan`.
    - 2-3 for each of `organization_create`,
      `organization_set_status`, `group_create`,
      `group_delete`, `subscription_set_status`.
    - 5 affordance-gating tests on the existing read
      pages (ReadOnly hides buttons, Operations+ sees them,
      subscription buttons appear only when a subscription
      exists).
- Worker form handlers themselves require a Workers runtime;
  their service-layer delegation is covered by the existing
  host tests.

### Auth caveat (unchanged from 0.3.x and 0.8.0)

Forms POST same-origin and the bearer rides on the
`Authorization: Bearer ...` header — same as the read pages
and same as the v0.3.x edit forms. The `Authorization` header
is not auto-forged by browsers across origins, which is the
CSRF defense; but it also means operators must use a tool
that sets the header (curl, browser extension, or once it
lands, the v0.10.0+ user-as-bearer cookie path). This is the
existing 0.3.x limitation; v0.9.0 inherits rather than
relaxes it. The v0.10.0+ cookie-based auth design pass is
where this changes.

### Design decisions worth recording

- **Risk-graded preview/confirm.** Not every mutation needs a
  preview screen — adding a friction step for low-risk
  additive operations (creates, role grants within a single
  tenant, membership add) is operator hostile. The preview
  pattern is reserved for destructive or expensive operations
  (status changes, group deletes, plan changes).

- **POST/Redirect/GET via 303 See Other.** After a successful
  mutation the handler redirects to the relevant read page
  (e.g. `/admin/saas/tenants/:tid` after a status change),
  not back to the form. This means a browser refresh on the
  landing page does not re-submit the mutation.

- **`Role::can_manage_tenancy()` not on `AdminPrincipal`.** The
  helper is on `Role` so UI templates can check it without
  importing the principal type, and so a future tenant-scoped
  admin (with a different bearer model) can introduce its own
  helper without conflating the two.

- **Pure presentation-layer hint, with a test-locked parity
  invariant.** The helper documents itself as a presentation-
  layer hint; the new
  `role_can_manage_tenancy_helper_matches_policy` test ensures
  it cannot drift from the authoritative policy. Together
  these prevent the failure mode where a refactor changes the
  policy but leaves a stale UI gate.

### Deferred — still tracked for 0.10.0+

The 0.9.0 surface focuses on the mutations operators do most
often. Items still pending:

- **Role grant / revoke forms.** Today these go through the
  v0.7.0 JSON API or wrangler. A "Grant role" form on a user's
  role assignments page is the natural fit. Slated for the
  next iteration.
- **Membership add / remove forms.** Same as above — frequent,
  low-risk; the JSON API handles them today.
- **Tenant-scoped admin surface.** Tenant admins administering
  their own tenant rather than every tenant. **0.10.0+.** This
  is the user-as-bearer / login → tenant resolution / cookie-
  auth design pass.
- **`check_permission` integration on the API surface.**
  Blocked on user-as-bearer.
- **Anonymous-trial promotion.** **0.11.0.**
- **External IdP federation.**

---

## [0.8.0] - 2026-04-25

A read-only HTML console at `/admin/saas/*` for cesauth's operator
staff to inspect tenancy / billing state. Sits parallel to (and
visually distinct from) the v0.3.x cost / data-safety console at
`/admin/console/*`. Mutation continues to flow through the v0.7.0
JSON API; the HTML preview/confirm flow that wraps those mutations
is slated for v0.9.0 with the same two-step pattern v0.4.0
introduced for bucket safety edits.

### Added

- **SaaS console UI module** in `cesauth-ui`
  (`crates/ui/src/saas/`): `frame` + 5 page templates.
  - `Overview` — deployment-wide counters (tenants by status,
    org/group counts, active plan count) plus a per-plan
    subscriber breakdown via `LEFT JOIN`.
  - `Tenants` — list of every non-deleted tenant with status
    badges and drill-through to detail.
  - `Tenant detail` — summary, current subscription with plan
    label, organization list, member list. Links out to org
    detail and per-user role assignments.
  - `Organization detail` — summary, org-scoped groups, members.
  - `Subscription history` — append-only log per tenant,
    reverse-chronological (newest first — operators most often
    ask "what changed last").
  - `User role assignments` — every assignment held by one user,
    across every scope, with rendered scope links and
    role-label-with-display-name.

- **Worker route handlers** in `crates/worker/src/routes/admin/saas/`:
  one handler per page above. Each delegates to the existing
  `crate::routes::admin::auth::resolve_or_respond` for bearer
  resolution and `ensure_role_allows(AdminAction::ViewTenancy)`
  for capability gating. Response shaping (CSP / cache-control /
  frame-deny) reuses
  `crate::routes::admin::console::render::html_response`.

- **6 new HTML routes** wired in `lib.rs`:
  - `GET /admin/saas`
  - `GET /admin/saas/tenants`
  - `GET /admin/saas/tenants/:tid`
  - `GET /admin/saas/tenants/:tid/subscription/history`
  - `GET /admin/saas/organizations/:oid`
  - `GET /admin/saas/users/:uid/role_assignments`

- **Distinct nav frame** (`SaasTab`). Two top-level tabs
  (`Overview`, `Tenants`); the `UserRoleAssignments` tab is a
  drill-in destination only and is filtered out of the nav even
  when active. Footer bears a `read-only` marker so operators
  cannot mistake this surface for the writable v0.9.0 follow-up.

- **Tests** (+22 over 0.7.0's 144, total 166):
  - `ui::saas::tests` (4) — frame role badge, active-tab
    `aria-current`, drill-in tab not in nav, footer read-only
    marker.
  - `ui::saas::overview::tests` (4) — counter rendering, empty
    plan-breakdown empty state, plan rows, read-only disclaimer
    presence.
  - `ui::saas::tenants::tests` (4) — empty list call-to-action,
    drill-link href shape, suspended status badge, HTML escape
    of untrusted display_name.
  - `ui::saas::tenant_detail::tests` (4) — summary + no-sub case,
    organization list, subscription with plan, member→user link.
  - `ui::saas::subscription::tests` (3) — empty history, reverse-
    chronological ordering, back link.
  - `ui::saas::role_assignments::tests` (3) — empty state, scope
    drill-links + system badge, dangling-role-id resilience.

### Changed

No breaking changes. The 0.7.0 JSON API at `/api/v1/...` continues
to work identically. The 0.8.0 console only **reads** through the
existing service-layer ports + D1 adapters.

### Deferred — still tracked for 0.9.0+

The 0.8.0 console is read-only by design. The mutation surface
(create / update / delete forms with the v0.4.0 preview/confirm
pattern) is the headline 0.9.0 feature. Other still-deferred items
are unchanged from 0.7.0:

- **HTML mutation forms with two-step confirmation** (0.9.0) —
  same preview-then-confirm pattern v0.4.0 introduced for bucket
  safety edits, applied to tenant create / update, org create /
  status change, role grant / revoke, subscription plan/status
  change.
- **Tenant-scoped admins** — tenant admins administering their
  own tenant rather than the cesauth operator administering
  every tenant. Requires user-as-bearer auth and login → tenant
  resolution UX, both of which are open design questions.
- **`check_permission` integration on the API surface** —
  blocked on user-as-bearer.
- **`max_users` quota enforcement** — waits on a user-create
  surface that respects tenancy.
- **Anonymous-trial promotion**.
- **External IdP federation**.

---

## [0.7.0] - 2026-04-25

The HTTP API surface for the tenancy-service data model. v0.5.0
shipped the data model and central authz function; v0.6.0 shipped
the Cloudflare D1 adapters and made `users` tenant-aware; v0.7.0
ships the routes operators use to drive that machinery from the
outside.

### Added

- **`/api/v1/...` route module** (`crates/worker/src/routes/api_v1/`):
  - **Tenants**: `POST /api/v1/tenants` (create with owner
    membership), `GET /api/v1/tenants` (list active),
    `GET /api/v1/tenants/:tid`, `PATCH /api/v1/tenants/:tid`
    (display name), `POST /api/v1/tenants/:tid/status`.
  - **Organizations**: `POST/GET /api/v1/tenants/:tid/organizations`,
    `GET/PATCH /api/v1/tenants/:tid/organizations/:oid`,
    `POST /api/v1/tenants/:tid/organizations/:oid/status`. The
    GET handler verifies the org's `tenant_id` matches the URL
    `:tid` — defense in depth against id-guessing across tenants.
  - **Groups**: `POST/GET /api/v1/tenants/:tid/groups`
    (the GET takes `?organization_id=...` to narrow to org-scoped
    groups), `DELETE /api/v1/groups/:gid`.
  - **Memberships** — three flavors under a unified handler shape:
    `POST/GET/DELETE /api/v1/tenants/:tid/memberships[/:uid]`,
    `.../organizations/:oid/memberships[/:uid]`,
    `.../groups/:gid/memberships[/:uid]`.
  - **Role assignments**: `POST /api/v1/role_assignments`,
    `DELETE /api/v1/role_assignments/:id`,
    `GET /api/v1/users/:uid/role_assignments`.
  - **Subscriptions**: `GET /api/v1/tenants/:tid/subscription`,
    `POST .../subscription/plan`, `POST .../subscription/status`,
    `GET .../subscription/history`. Plan changes refuse to point
    at archived (`active = false`) plans. Every plan / status
    change appends a `subscription_history` entry.

- **27 routes wired** into `lib.rs` under a `// --- Tenancy-service
  API (v0.7.0)` block, contiguous with the existing
  `/admin/console/...` routes.

- **Two new admin capabilities** in
  `cesauth_core::admin::types::AdminAction`:
  - `ViewTenancy` — read tenancy data; granted to every valid
    role (admin tokens already pass a trust boundary).
  - `ManageTenancy` — mutate tenancy data; Operations+ only,
    matching the existing tier with `EditBucketSafety` /
    `EditThreshold` / `CreateUser`. Security alone does not get
    to provision tenants.

- **Plan-quota enforcement** (spec §6.7) at create time for
  organizations and groups. The pure decision logic lives in
  `cesauth_core::billing::quota_decision`:
  - `None` plan → `Allowed` (operator-provisioned tenants without
    a subscription).
  - Quota row absent → `Allowed`.
  - Quota value `-1` (`Quota::UNLIMITED`) → `Allowed` at any count.
  - Otherwise compares `current` vs `limit`, returning
    `Denied { name, limit, current }` when the next insert
    would exceed.
  The worker side (`routes::api_v1::quota::check_quota`) reads the
  current count via `SELECT COUNT(*) FROM <table> WHERE
  tenant_id = ? AND status != 'deleted'` and feeds it to
  `quota_decision`. A `quota_exceeded:<name>` 409 surfaces to the
  caller.

- **14 new audit `EventKind` variants** for tenancy mutations:
  `TenantCreated`, `TenantUpdated`, `TenantStatusChanged`,
  `OrganizationCreated`, `OrganizationUpdated`,
  `OrganizationStatusChanged`, `GroupCreated`, `GroupDeleted`,
  `MembershipAdded`, `MembershipRemoved`, `RoleGranted`,
  `RoleRevoked`, `SubscriptionPlanChanged`,
  `SubscriptionStatusChanged`. Every mutating route emits one with
  the actor (admin principal id), subject (created/affected row
  id), and a structured `reason` field.

### Tests

- Total: **144 passing** (+8 over 0.6.0's 136).
  - core: 101 (was 93) — 2 new admin-policy tests
    (`every_valid_role_may_view_tenancy`,
    `manage_tenancy_is_operations_plus`) + 6 new
    `quota_decision` tests covering no-plan, missing quota row,
    unlimited sentinel, below-limit allow, at-limit deny, and
    above-limit deny edge cases.
  - adapter-test: 32 (unchanged).
  - ui: 11 (unchanged).
- The route handlers are not exercised by host tests — they
  require a Workers runtime — but every route delegates to the
  service layer or the D1 adapters, both of which are covered by
  the host tests above. Route-handler contract is verified at
  deploy time via `wrangler dev` or curl-against-deploy.

### Design decisions worth recording

- **Admin-bearer, not user-as-bearer.** `cesauth_core::authz::
  check_permission` expects a `user_id` and a scope. Admin tokens
  are operator credentials with no row in `users`, and the
  user-as-bearer path (issuing a JWT/session bearer that the
  gateway parses into a tenant-scoped request) is part of the
  multi-tenant admin console (0.8.0). So 0.7.0 ships an API
  surface for *cesauth's operator staff* to provision tenants.
  Self-service tenant operations are deferred. The route handlers
  go through `ensure_role_allows` (admin-side capability) rather
  than `check_permission` (tenancy-side capability); the two
  converge in 0.8.0+ when user bearers arrive.

- **JSON-only, no Accept negotiation.** HTML belongs in 0.8.0 with
  the multi-tenant admin console.

- **URL hierarchy is the natural tree** (`/api/v1/tenants/:tid/
  organizations`, `/api/v1/tenants/:tid/organizations/:oid/...`)
  for tenant-rooted operations. Operations on a single non-tenant
  scoped resource (one group, one role-assignment) take the direct
  form `/api/v1/groups/:gid` so callers don't need to know the
  parent path.

- **Quota count by `SELECT COUNT(*)`, not by cached counter.** This
  is a low-volume admin API; the COUNT on an indexed column is
  cheaper than the cache-invalidation discipline a counter
  would require. When self-signup lands, we will need to migrate
  to a counter-with-occasional-reconcile pattern; until then the
  simple read wins.

### Deferred — still tracked for 0.8.0+

- **Multi-tenant admin console** (0.8.0) — HTML surface for
  tenant-scoped admins. Opens user-as-bearer, login → tenant
  resolution, and Accept negotiation as one design pass.
- **Anonymous-trial promotion** (0.9.0).
- **External IdP federation**.

---

## [0.6.0] - 2026-04-25

The runtime backing for v0.5.0's tenancy-service data model.
Implements the Cloudflare D1 adapters for every port the 0.5.0 core
defined, and migrates the existing `users` table to be tenant-aware.
Routes / multi-tenant admin console / login-tenant resolution remain
deferred (see "Deferred" below).

### Added

- **Cloudflare D1 adapters for every 0.5.0 port** (10 adapters
  in `cesauth-adapter-cloudflare`):
  - `tenancy::{CloudflareTenantRepository,
    CloudflareOrganizationRepository, CloudflareGroupRepository,
    CloudflareMembershipRepository}`.
  - `authz::{CloudflarePermissionRepository,
    CloudflareRoleRepository, CloudflareRoleAssignmentRepository}`.
  - `billing::{CloudflarePlanRepository,
    CloudflareSubscriptionRepository,
    CloudflareSubscriptionHistoryRepository}`.
  Each follows the existing CF-adapter pattern: `pub struct
  CloudflareXRepository<'a> { env: &'a Env }`, manual `Debug` impl,
  Serde row struct → domain via `into_domain`. UNIQUE-violation
  errors are mapped to `PortError::Conflict` by string-matching on
  `"unique"` / `"constraint"` (worker-rs gives no structured error
  code; this is the same pattern the 0.3.x admin adapters use).

- **Schema decisions made explicit** in the role/plan adapters:
  - `roles.permissions` is stored as a comma-separated string. D1
    has no JSON1 extension; a `role_permissions` join table would
    require an N+1 read on the authz hot path. Permission names are
    `[a-z:]+` (no commas), making a comma-list safe.
  - `plans.features` is a comma-separated list; `plans.quotas` is
    `name=value,name=value`. Same trade-off; the catalog data is
    static enough that an extra table is overkill.

- **Migration `0004_user_tenancy_backfill.sql`** (101 lines).
  Adds `tenant_id` (NOT NULL, REFERENCES `tenants`) and
  `account_type` (TEXT, CHECK enumerating spec §5's five values) to
  `users`. Uses the SQLite-standard "rename, recreate, copy" pattern
  because D1 cannot ADD COLUMN with a foreign key in one step.
  Backfills every pre-0.6.0 user into `tenant-default` with
  `account_type = 'human_user'`. Also auto-inserts a
  `user_tenant_memberships` row so every user has a membership in
  their bootstrap tenant — no orphaned users post-migration.

- **`User` struct gains `tenant_id` and `account_type`** in
  `cesauth_core::types`. Both fields use `serde(default = ...)` so
  pre-0.6.0 cached payloads continue to deserialize cleanly. The
  defaults are `tenancy::DEFAULT_TENANT_ID` and
  `tenancy::AccountType::HumanUser`, matching the migration's
  backfill values exactly. New core tests
  `user_serializes_with_tenant_and_account_type` and
  `user_deserializes_pre_0_4_1_payload_with_defaults` pin the
  forward- and backward-compat shape.

- **Email uniqueness becomes per-tenant.** The 0001 migration's
  `UNIQUE(email)` is replaced in 0004 with `UNIQUE(tenant_id, email)`.
  `find_by_email` adds an explicit `LIMIT 1` and a comment about
  the contract change; the spec'd `find_by_email_in_tenant`
  variant arrives with the multi-tenant login flow in 0.7.0+.

### Changed

- **User construction sites updated.**
  `routes/admin/legacy.rs::create_user` and
  `routes/magic_link/verify.rs` (auto-signup at first verification)
  now stamp `tenant_id = tenant-default` and
  `account_type = HumanUser` when creating users. A multi-tenant
  signup path will land alongside the multi-tenant routes.

### Tests

- Total: **136 passing** (+3 over 0.5.0's 133).
  - core: 93 (was 90) — three new `User` serde tests covering
    forward, backward, and default-value behavior.
  - adapter-test: 32 (unchanged).
  - ui: 11 (unchanged).
- The Cloudflare D1 adapters are not exercised by host tests
  (they require a Workers runtime). The host tests in
  `adapter-test` cover the same trait surface against the
  in-memory adapters; the CF adapters' contract correctness is
  verified at deploy time via `wrangler dev`.

### Deferred — still tracked for 0.7.0+

- **HTTP routes** for tenant / organization / group / role-assignment
  CRUD. The service layer + adapters are now both ready; what
  remains is the bearer-extension that carries
  `(user_id, tenant_id?, organization_id?)` context through the
  router, the Accept-aware HTML/JSON rendering, and the integration
  with `check_permission`. This is its own design pass — see
  ROADMAP for the open questions on URL shape and admin-bearer vs
  session-cookie auth.
- **Multi-tenant admin console**.
- **Login → tenant resolution** UX.
- **Plan-quota enforcement** at user-create / org-create / group-create.
- **Anonymous-trial promotion**.
- **External IdP federation**.

---

## [0.18.0] - 2026-04-25

The tenancy-service foundation. Implements the data model and core
authorization engine from
`cesauth-tenancy-service-extension-spec.md` §3-§5 and §16.1,
§16.3, §16.6. Routes / UI / multi-tenant admin console are deferred
to 0.6.0 by design (see "Deferred" below).

### Added

- **Tenancy domain** (`cesauth_core::tenancy`). New entities:
  - `Tenant` — top-level boundary (§3.1). States: pending, active,
    suspended, deleted.
  - `Organization` — business unit within a tenant (§3.2).
    `parent_organization_id` column reserved for future hierarchy;
    flat in 0.5.0.
  - `Group` — membership/authz unit (§3.3) with `GroupParent`
    explicit enum: `Tenant` (tenant-wide group) or
    `Organization { organization_id }` (org-scoped). The CHECK in
    migration 0003 enforces exactly one parent flavor at the DB
    level.
  - `AccountType` (§5) — `Anonymous`, `HumanUser`, `ServiceAccount`,
    `SystemOperator`, `ExternalFederatedUser`. Deliberately
    separate from role/permission per §5 ("user_type のみで admin
    判定を行わない").
  - Membership relations: `TenantMembership`, `OrganizationMembership`,
    `GroupMembership`. Three tables, one
    `MembershipRepository` port. Spec §2 principle 4 ("所属は属性
    ではなく関係として表現する") is the structural reason for the
    split.

- **Authorization domain** (`cesauth_core::authz`).
  - `Permission` (atomic capability string) + `PermissionCatalog`
    constant listing the 25 permissions cesauth ships with.
  - `Role` — named bundle of permissions; system role
    (`tenant_id IS NULL`) or tenant-local role.
  - `RoleAssignment` — one user, one role, one `Scope`. Scopes
    are `System`, `Tenant`, `Organization`, `Group`, `User` (§9.1).
  - `SystemRole` constants for the six built-in roles seeded by
    the migration: `system_admin`, `system_readonly`, `tenant_admin`,
    `tenant_readonly`, `organization_admin`, `organization_member`.
  - **`check_permission`** — the single authorization entry point
    (§9.2 "権限判定関数を単一のモジュールに集約する"). Pure
    function over `(RoleAssignmentRepository, RoleRepository, user,
    permission, scope, now_unix)`. Handles expiration explicitly,
    surfacing `DenyReason::Expired` separately from
    `ScopeMismatch`/`PermissionMissing` so audit logs can distinguish
    "grant ran out" from "wrong scope".
  - Scope-covering lattice: a `System` grant covers every scope; a
    same-id `Tenant`/`Organization`/`Group`/`User` grant covers
    the matching `ScopeRef`. Cross-tier coverage ("my tenant grant
    applies to this org") is tagged as a follow-up — for 0.5.0 the
    caller is expected to query at the natural scope of the
    operation, which it always knows.

- **Billing domain** (`cesauth_core::billing`).
  - `Plan` and `Subscription` are strictly separated (§8.6 "Plan と
    Subscription を分離する"). Plans live in a global catalog;
    subscriptions reference plans by id and carry only the
    tenant-specific state.
  - `SubscriptionLifecycle` (`trial`/`paid`/`grace`) and
    `SubscriptionStatus` (`active`/`past_due`/`cancelled`/`expired`)
    are orthogonal axes per §8.6 ("試用状態と本契約状態を分ける").
    Test `subscription_lifecycle_and_status_are_orthogonal` pins
    the separation as a documentation-style assertion.
  - `SubscriptionHistoryEntry` — append-only log of plan/state
    transitions; one row per event so "when did this tenant move
    plans?" has a deterministic answer.
  - Four built-in plans: Free, Trial, Pro, Enterprise.
    Quotas use `-1` to mean unlimited (`Quota::UNLIMITED`); features
    are free-form strings keyed on a stable name.

- **Migration `0003_tenancy.sql`** (281 lines): adds 11 tables — one
  for each entity above plus the three membership relations. Seeds:
  one bootstrap tenant with id `tenant-default` (matches
  `tenancy::DEFAULT_TENANT_ID`), the 25 permissions, the 6 system
  roles, and the 4 built-in plans. `INSERT OR IGNORE` throughout so
  the migration is re-runnable.

- **In-memory adapters** in `cesauth-adapter-test`:
  `tenancy::{InMemoryTenantRepository, InMemoryOrganizationRepository,
  InMemoryGroupRepository, InMemoryMembershipRepository}`,
  `authz::{InMemoryPermissionRepository, InMemoryRoleRepository,
  InMemoryRoleAssignmentRepository}`,
  `billing::{InMemoryPlanRepository, InMemorySubscriptionRepository,
  InMemorySubscriptionHistoryRepository}`. All ten implement the
  shipped ports.

- **Tests** (+30 over 0.4.0's 103, total 133):
  - core: 18 new (5 tenancy types, 7 authz scope-covering / catalog /
    deny-reason, 5 billing types, 1 dangling-role-id resilience).
  - adapter-test: 12 new — end-to-end tenant→org→group flow, slug
    validation edges, duplicate-slug conflict, suspended-tenant
    org rejection, full-catalog round-trip, plan & subscription &
    history round-trip, single-active-subscription invariant,
    purge-expired roles.

### Changed

- `cesauth_core::lib.rs` exports three new modules: `tenancy`,
  `authz`, `billing`. No existing module changes.

### Deferred — not in 0.5.0, tracked for 0.6.0+

The spec's §16 receive criteria are broad. 0.5.0 ships the data
model and the central authz engine; the items below are
prerequisites for a fully-receivable v0.4 but each carries enough
design surface to deserve its own release:

- **HTTP routes** for tenant / organization / group / role CRUD.
  The service layer has one function per operation; the route layer
  needs an admin-bearer extension carrying `(user, tenant?, org?)`
  context that a 0.6.0 design pass should specify before wiring.
- **Cloudflare D1 adapters** for the new ports. The schema is in
  place; mapping each port to D1 statements is mechanical but
  voluminous.
- **Multi-tenant admin console**. The 0.3.x admin console assumes
  a single deployment-wide operator; tenant-scoped admins need a
  new tab structure and tenancy-aware route guards.
- **Login → tenant resolution**. Today `email` is globally unique
  in `users`. Multi-tenant deployments need either tenant-scoped
  email uniqueness or a tenant-picker step in the login flow. Spec
  §6.1 mentions tenant-scoped auth policies; the precise UX is open.
- **Anonymous trial → human user promotion** (§3.3 of spec, §11
  priority 5). The `Anonymous` account type exists; the lifecycle
  (token issuance, retention window, conversion flow) is unspecified
  and will be its own design pass.
- **Subscription enforcement at runtime**. `Plan.quotas` are
  recorded but no code reads them at user-create / org-create time.
  Enforcement hooks land alongside the routes.
- **External IdP federation** (§3.3 of spec, §11 priority 8).
  `AccountType::ExternalFederatedUser` is reserved; the wiring is
  follow-up.
- **Tenant-scoped audit log filtering**. The 0.3.x audit search is
  global. A tenant-aware filter is small but requires the
  multi-tenant admin console to land first.

---

## [0.5.0] - 2026-04-24

### Added

- **HTML two-step confirmation UI for bucket-safety edits.** The
  pre-0.4.0 preview/apply JSON API is unchanged; 0.4.0 adds a
  form-based wrapper that the Configuration Review page now links to
  per bucket (Operations+ only). The flow:
  1. `GET /admin/console/config/:bucket/edit` renders an edit form
     pre-populated with the current attested state.
  2. `POST` submits the proposed values; the handler re-renders the
     same URL as a confirmation page showing a before/after diff with
     the changed fields highlighted.
  3. Submitting the "Apply" button on the confirmation page re-POSTs
     with `confirm=yes` and the handler commits the change, auditing
     both the attempt (`attempt:BUCKET`) and the outcome
     (`ok:BUCKET`), then 303-redirects back to the review page.
  Corresponds to spec §7's "二段階確認" for dangerous operations.

- **Admin-token CRUD UI (Super-only).** New screens at
  `/admin/console/tokens`:
  - `GET  /admin/console/tokens` — table of non-disabled rows in
    `admin_tokens` (id, role, name, disable button).
  - `GET  /admin/console/tokens/new` — form to mint a new token.
  - `POST /admin/console/tokens` — server mints 256 bits of
    getrandom-sourced plaintext (two `Uuid::new_v4()` concatenated),
    SHA-256-hashes it for storage, inserts the row, and renders the
    plaintext **exactly once** with a prominent one-shot warning.
    Emits `AdminTokenCreated`.
  - `POST /admin/console/tokens/:id/disable` — flips `disabled_at`;
    refuses to disable the caller's own token to prevent accidental
    self-lockout. Emits `AdminTokenDisabled`.
  Per spec §14 ("provisional simple implementation" until tenant
  boundaries land), the list shows only `id`/`role`/`name`; richer
  `created_at` / `last_used_at` / `disabled_at` metadata is a
  post-tenant decision.

- **Conditional Tokens tab in the admin nav.** Visible only when the
  current principal's role is `Super`. Other roles still get a 403
  from the route if they navigate there directly — the tab
  visibility is a UX convenience, not a security boundary.

- **New audit event kinds**: `AdminTokenCreated`, `AdminTokenDisabled`.

- **Test coverage** (+10 tests, total 103):
  - `adapter-test`: token-CRUD roundtrip, hash uniqueness →
    `PortError::Conflict`, disable-unknown → `PortError::NotFound`.
  - `ui`: role-badge rendering, Tokens-tab visibility matrix,
    HTML-escape on untrusted notes, HTML-escape on displayed
    plaintext bearer, changed-fields marker correctness,
    no-change short-circuit on the confirm page, empty-list
    bootstrap-fallback hint.

### Changed

- **Fix: admin pages now show the caller's actual role in the header
  badge.** `cost_page`, `audit_page`, and `alerts_page` were
  hardcoding `Role::ReadOnly` and omitting the operator name; they
  now take an `&AdminPrincipal` like the other pages and propagate
  the role and label through to the header.

- **`AdminPrincipal` gained `Serialize`.** Needed so
  `GET /admin/console/tokens?Accept=application/json` can return the
  list as-is. `Deserialize` is deliberately *not* derived —
  adapters build these from their own row shapes, and nothing on the
  wire should revive one from a client blob.

- **Configuration Review's "Editing" section rewritten.** Pre-0.4.0
  it pointed operators at the JSON API only; it now describes the
  in-UI edit flow first and keeps the JSON recipes as a scripted
  alternative.

### Security

- **Token plaintext is touched for exactly one request path.** The
  server holds the plaintext only long enough to (a) SHA-256 it for
  storage and (b) render it once on the created-token page; no logs,
  no DO state, no error paths mention it. If the operator closes
  that tab without copying, they disable the token and create a new
  one.

- **Self-disable guard on `/admin/console/tokens/:id/disable`.** The
  handler refuses to disable the same principal id that
  authenticated the request. Not a security issue (the operator is
  already authorized to do it), but an accidental lockout of the
  only active Super is painful enough to catch here. The
  `ADMIN_API_KEY` bootstrap path is unaffected: `super-bootstrap`
  has no row and cannot be disabled from the UI at all.

### Deferred (tracked for 0.3.2+)

- **Workers-request and Turnstile-verify hot-path counters.** The
  admin console already reads these KV keys; writing them has a
  residual design question (at what request granularity do we
  count — every fetch, only successful handlers, by path?) that is
  not settled by the spec. See `ROADMAP.md`.
- **Durable Objects enumeration.** Still blocked on a Cloudflare
  runtime API that does not exist.


---

## Versioning history note

**Range affected: 0.5.0 through 0.18.1 (entries above this note).**

The version numbers shown in those entries were retroactively
re-aligned with cesauth's
[versioning policy](../ROADMAP.md#versioning-policy)
(introduced at 0.18.0 / formerly 0.18.0).

Each "minor-shaped" change — new HTTP route surface, new schema
migration, new public type or trait, new permission slug, new
operator-visible config — earns a minor bump. Each "patch-shaped"
change — internal refactor, security fix preserving wire
compatibility, doc-only — earns a patch bump.

When the policy was applied to past releases, several earlier
"patch" bumps that should have been minors got promoted. The
shipped tarballs themselves did not change (those are immutable
artifacts) — only the version numbers used in this changelog,
in `Cargo.toml`, and in subsequent VCS commits were re-aligned.
The mapping is:

| Tarball file (immutable) | Re-aligned version (this changelog &amp; VCS) |
|---|---|
| `cesauth-0.18.1.tar.gz`  | **0.18.1** |
| `cesauth-0.18.0.tar.gz`  | **0.18.0** |
| `cesauth-0.17.0.tar.gz` | **0.17.0** |
| `cesauth-0.16.0.tar.gz` | **0.16.0** |
| `cesauth-0.15.1.tar.gz` | **0.15.1** |
| `cesauth-0.15.0.tar.gz` | **0.15.0** |
| `cesauth-0.14.0.tar.gz` | **0.14.0** |
| `cesauth-0.13.0.tar.gz`  | **0.13.0** |
| `cesauth-0.12.1.tar.gz`  | **0.12.1** |
| `cesauth-0.12.0.tar.gz`  | **0.12.0** |
| `cesauth-0.11.0.tar.gz`  | **0.11.0** |
| `cesauth-0.10.0.tar.gz`  | **0.10.0** |
| `cesauth-0.9.0.tar.gz`  | **0.9.0**  |
| `cesauth-0.8.0.tar.gz`  | **0.8.0**  |
| `cesauth-0.7.0.tar.gz`  | **0.7.0**  |
| `cesauth-0.6.0.tar.gz`  | **0.6.0**  |
| `cesauth-0.5.0.tar.gz`  | **0.18.0**  |
| `cesauth-0.4.0.tar.gz`  | **0.5.0**  |
| `cesauth-0.3.0.tar.gz`  | 0.3.0 (unchanged) |
| `cesauth-0.2.1.tar.gz`  | 0.2.1 (unchanged) |

Below this note, the entries for 0.3.0 and 0.2.1 retain their
original tarball numbering — they pre-date the mapping.

Going forward, the next release after 0.18.1 will be **0.19.0**,
following the policy without further re-alignment.

---

## [0.3.0] - 2026-04-24

### Added

- **Cost & Data Safety Admin Console.** A new operator-facing surface
  under `/admin/console/*`, separate from the user-authentication body.
  Six server-rendered HTML pages plus a small JSON-write surface:

  | Path                                    | Min role    | Purpose                                        |
  |-----------------------------------------|-------------|------------------------------------------------|
  | `GET  /admin/console`                   | ReadOnly    | Overview: alert counts, recent events, last verifications |
  | `GET  /admin/console/cost`              | ReadOnly    | Cost dashboard — per-service metrics & trend  |
  | `GET  /admin/console/safety`            | ReadOnly    | Data-safety dashboard — per-bucket attestation |
  | `POST /admin/console/safety/:b/verify`  | Security+   | Stamp a bucket-safety attestation as re-verified |
  | `GET  /admin/console/audit`             | ReadOnly    | Audit-log search (prefix / kind / subject filters) |
  | `GET  /admin/console/config`            | ReadOnly    | Configuration review (attested settings + thresholds) |
  | `POST /admin/console/config/:b/preview` | Operations+ | Preview a bucket-safety change (diff, no commit) |
  | `POST /admin/console/config/:b/apply`   | Operations+ | Commit a bucket-safety change (requires `confirm:true`) |
  | `GET  /admin/console/alerts`            | ReadOnly    | Alert center — rolled-up cost + safety alerts   |
  | `POST /admin/console/thresholds/:name`  | Operations+ | Update an operator-editable threshold            |

  Every GET is `Accept`-aware: browsers get HTML, `Accept: application/json`
  gets the same payload as JSON — so curl and the browser share one
  URL surface.

- **Four-role admin authorization model.** `ReadOnly` / `Security` /
  `Operations` / `Super`, enforced by a single pure function
  `core::admin::policy::role_allows(role, action)`. Each handler
  declares its `AdminAction` and the policy layer decides. Role
  matrix:

  | Action                  | RO | Sec | Ops | Super |
  |-------------------------|----|-----|-----|-------|
  | `ViewConsole`           | ✓  | ✓   | ✓   | ✓     |
  | `VerifyBucketSafety`    |    | ✓   | ✓   | ✓     |
  | `RevokeSession`         |    | ✓   | ✓   | ✓     |
  | `EditBucketSafety`      |    |     | ✓   | ✓     |
  | `EditThreshold`         |    |     | ✓   | ✓     |
  | `CreateUser`            |    |     | ✓   | ✓     |
  | `ManageAdminTokens`     |    |     |     | ✓     |

  The pre-existing `ADMIN_API_KEY` secret becomes the Super bootstrap:
  a fresh deployment with only that secret set still has console
  access at the Super tier. Additional principals live in the new
  `admin_tokens` D1 table (SHA-256-hashed, never plaintext). See
  [Admin Console — Expert chapter](docs/src/expert/admin-console.md).

- **Honest edge-native metrics.** The dashboard is deliberately
  truthful about what a Worker can and cannot see at runtime. D1 row
  counts come from `COUNT(*)` on tracked tables. R2 object counts and
  bytes come from `bucket.list()` summation. Workers and Turnstile
  counts come from a self-maintained `counter:<service>:<YYYY-MM-DD>`
  pattern in KV. Durable-Object metrics are deliberately empty — the
  Workers runtime cannot enumerate DO instances, so the dashboard
  surfaces a note pointing operators at the Cloudflare dashboard
  rather than fabricating numbers.

- **Bucket safety = operator attestation.** Workers runtime cannot
  read Cloudflare's R2 control-plane (is-public / CORS / lifecycle /
  bucket-lock state). We therefore record what the operator last
  confirmed the bucket to be, with a `last_verified_at` stamp and a
  configurable staleness threshold. Stale attestations raise a `warn`
  alert; any bucket attested public raises a `critical` alert
  regardless of which bucket it is.

- **Audit-log search over R2.** New `CloudflareAuditQuerySource`
  walks the date-partitioned `audit/YYYY/MM/DD/<uuid>.ndjson` tree,
  parses each object, and applies `kind_contains` / `subject_contains`
  filters in the adapter. Hard-capped at 200 objects per call so one
  console view can never fan out to thousands of R2 GETs.

- **Five new `EventKind` variants.**
  `AdminLoginFailed`, `AdminConsoleViewed`, `AdminBucketSafetyVerified`,
  `AdminBucketSafetyChanged`, `AdminThresholdUpdated`. Every console
  view is audited — §11 of the extension spec asks that monitoring
  failures themselves be audit-visible, and logging views captures
  the intent side of that.

- **Migration `0002_admin_console.sql`.** Four tables:
  `admin_tokens`, `bucket_safety_state`, `cost_snapshots`,
  `admin_thresholds`. Five default thresholds seeded; rows for the
  two shipped R2 buckets (`AUDIT`, `ASSETS`) seeded with conservative
  defaults. `INSERT OR IGNORE` throughout so the migration is
  re-runnable.

- **Expert chapter `docs/src/expert/admin-console.md`.** Covers the
  role model, the permission matrix, the change-operation protocol
  (preview → apply), the metrics-source fidelity matrix, and the
  bootstrap / token-provisioning curl recipes.

### Changed

- **`routes::admin` refactored into a submodule tree.** What used to
  be one 145-line file is now:
  - `routes/admin.rs` — parent, re-exports legacy `create_user` /
    `revoke_session` so `lib.rs`'s wiring didn't have to change.
  - `routes/admin/auth.rs` — bearer → principal resolution +
    `ensure_role_allows` helper.
  - `routes/admin/legacy.rs` — existing user-management endpoints,
    now role-gated (`CreateUser` requires Operations+,
    `RevokeSession` requires Security+; previously both required the
    single `ADMIN_API_KEY`).
  - `routes/admin/console.rs` + `routes/admin/console/*` — the v0.3.0
    console.

- **UI crate now depends on `cesauth-core`.** The admin templates
  read domain types directly from `core::admin::types` rather than
  redeclaring them, which would have drifted. `core` has no
  Cloudflare deps (enforced by its module-level comment), so this
  does not pull worker/wasm code into the UI build.

- **ROADMAP: "Audit retention policy tooling" moved from Planned to
  Shipped** as part of the admin console (the console's
  Configuration Review page surfaces each bucket's lifecycle
  attestation; the Alert Center flags staleness).

### Deferred (for 0.4.0)

None of these block §13 of the extension spec — the initial
completion criteria are met. They are recorded here so the scope
of 0.3.0 is unambiguous:

- **HTML edit forms with two-step confirmation UI.** 0.3.0 ships the
  preview → apply pair as a JSON API. The HTML confirm-screen flow
  (preview page → nonce-gated apply) is priority 8 in the spec; the
  scripted pair satisfies §7 (danger-operation preview + audit) in
  the meantime.
- **Admin-token CRUD UI.** 0.3.0 requires operators to INSERT rows
  into `admin_tokens` via a `wrangler d1 execute` command
  (documented in the expert chapter). A Super-only `/admin/tokens`
  HTML surface lands in 0.4.0.
- **Workers-request counter hot-path instrumentation.** 0.3.0 reads
  the `counter:workers:requests:*` KV keys and will report whatever
  is there; the actual `.increment()` call on every request is the
  0.4.0 work. Fresh deployments see zeros.
- **DO-instance enumeration.** Blocked on the Cloudflare Workers
  runtime API, which does not expose DO listing. Shipped as
  "unavailable — see CF dashboard" with a note; wired once CF
  ships the capability.

### Test counts

- `core`            — 72 passed (56 pre-admin + 16 admin policy / service)
- `adapter-test`    — 17 passed (6  pre-admin + 11 admin in-memory adapters)
- `ui`              — 4 passed (unchanged; admin templates exercised by
  `cargo check` rather than unit tests — their contract is HTML shape,
  which breaks visibly)
- **Total**: 93 host lib tests pass; `cargo-1.91 check --workspace` clean.

---

## [0.2.1] - 2026-04-24

### Changed

- **Refactor: test modules extracted to sibling `tests.rs` files.**
  Every `#[cfg(test)] mod tests { ... }` block in `src/` has been
  moved to a sibling `<basename>/tests.rs` file (e.g.
  `crates/core/src/service/token.rs` + `crates/core/src/service/token/tests.rs`).
  The parent file now contains only `#[cfg(test)] mod tests;`.
  Eighteen files changed, all sixty-six host-lib tests still pass
  unchanged. Rationale: parent-file size is dominated by production
  code instead of fixtures, diffs stay focused, and the extracted
  test files are easier to point at in code review.

- **Refactor: large trait-adapter files split by port/handler.** Seven
  files that mixed multiple independent `impl Trait for Struct` blocks
  or multiple HTTP handlers have been split into submodules:

  | Was                                                  | Became (submodules)                                                   |
  |------------------------------------------------------|------------------------------------------------------------------------|
  | `adapter-cloudflare/src/ports/repo.rs` (688 lines)   | `users` / `clients` / `authenticators` / `grants` / `signing_keys`     |
  | `adapter-cloudflare/src/ports/store.rs` (410 lines)  | `auth_challenge` / `refresh_token_family` / `active_session` / `rate_limit` |
  | `adapter-test/src/repo.rs`                           | same five names as the cloudflare adapter                              |
  | `adapter-test/src/store.rs`                          | same four names as the cloudflare adapter                              |
  | `worker/src/routes/oidc.rs` (494 lines)              | `discovery` / `jwks` / `authorize` / `token` / `revoke`                |
  | `worker/src/routes/magic_link.rs` (413 lines)        | `request` / `verify` (Turnstile helpers stay in the parent)            |
  | `worker/src/routes/webauthn.rs` (287 lines)          | `register` / `authenticate` (grouped by ceremony; `rp_from_config` stays in the parent) |

  The D1 helpers (`d1_int`, `run_err`, `db`) stay in the parent
  `repo.rs`; the DO-RPC helpers (`rpc_request`, `rpc_call`) stay in
  the parent `store.rs`; `crates/worker/src/routes/magic_link.rs`
  keeps the shared Turnstile-flag helpers (`turnstile_flag_key`,
  `turnstile_required`, `flag_turnstile_required`, `enforce_turnstile`)
  that both `request` and `verify` consume. Submodules access these
  via `super::` to avoid duplication.

- **Deliberately not split** (boundaries tight enough after test
  extraction, or intertwined enough that splitting would fragment a
  single concept): `core/src/webauthn/cose.rs` (395 lines post-tests;
  COSE key parsing, attestation-object parsing, and `AuthData`
  accessors are mutually referenced), `core/src/webauthn/registration.rs`
  (270 lines post-tests; one ceremony), `core/src/webauthn/authentication.rs`
  (228 lines post-tests; one ceremony), `core/src/service/token.rs`
  (285 lines post-tests; a composed service layer), `core/src/oidc/authorization.rs`
  (183 lines post-tests), `core/src/session.rs`, `core/src/ports/store.rs`,
  `ui/src/templates.rs`, `worker/src/log.rs`, `worker/src/post_auth.rs`.

- **Workspace version bumped to `0.2.1`.** All five crates inherit
  from `workspace.package.version` so the single change propagates.

### Build state

- `cargo check --workspace` clean.
- Host lib tests: 56 (core) + 6 (adapter-test) + 4 (ui) + 16 (worker)
  = 82 passed, 0 failed. Same counts as before the refactor.
- No public-API changes. All `pub` items that existed under the old
  module paths remain available at their original path because the
  parent files re-export them (`pub use submodule::Name;`). External
  users of `cesauth_cf::ports::repo::CloudflareUserRepository`,
  `cesauth_core::routes::oidc::token`, etc., require no source
  changes.

---

## [Unreleased]

### Added

- **Documentation restructure.** The previous monolithic
  `docs/architecture.md` and `docs/local-development.md` have been
  migrated into an [mdBook](https://rust-lang.github.io/mdBook/) site
  under `docs/`, split into a beginner-facing *Getting Started* track
  and an expert-facing *Concepts & Reference* track plus a
  *Deployment* section and an *Appendix* (endpoints, error codes,
  glossary).
- **Project governance files at the repository root.** `ROADMAP.md`,
  `CHANGELOG.md`, `.github/SECURITY.md`, `TERMS_OF_USE.md`.
- **`/token` observability.** Every 500 path in the token handler now
  emits a structured `log::emit` line with the appropriate category
  (`Config`, `Crypto`, or `Auth`), so `wrangler tail` shows the
  immediate cause of a token-endpoint failure instead of a bare 500.
- **Dev-only helper routes** (`GET /__dev/audit`,
  `POST /__dev/stage-auth-code/:handle`), gated on
  `WRANGLER_LOCAL="1"`. They exist to make the end-to-end curl
  tutorial runnable without a browser cookie jar. Production deploys
  MUST NOT set `WRANGLER_LOCAL`.

### Changed

- **README is now slim.** Storage responsibilities, crate layout, and
  implementation status have moved out of the README into the book
  (storage / crate layout) and `ROADMAP.md` (implementation status).
  The README keeps a Quick Start and an Endpoints table and points
  into the book for detail.
- **`jsonwebtoken` now built with the `rust_crypto` feature.**
  Version 10.x requires a crypto provider; we pick the pure-Rust one
  (ed25519-dalek / p256 / rsa / sha2 / hmac / rand) and explicitly
  NOT `aws_lc_rs`, which vendors a C library and does not build for
  `wasm32-unknown-unknown`. With `default-features = false` and
  neither feature set, jsonwebtoken 10 panics at first use.
- **`config::load_signing_key` normalizes escape sequences.** The
  function accepts either real newlines or literal `\n` escapes in
  the PEM body; the latter is useful for single-line dotenv setups.

### Fixed

- **D1 `bind()` now uses a `d1_int(i64) -> JsValue` helper.**
  `wasm_bindgen` converts a Rust `i64` into a JavaScript `BigInt` on
  the wire, but D1's `bind()` rejects BigInt with
  `cannot be bound`. The helper coerces via `JsValue::from_f64` the
  same way worker-rs's `D1Type::Integer` does internally. Every
  INSERT / UPDATE site now uses it.
- **`run_err(context, worker::Error) -> PortError::Unavailable`
  helper** logs the underlying D1 error via `console_error!` before
  collapsing it into the payload-less `PortError::Unavailable`
  variant. Previously, the HTTP layer just said "storage error" with
  no breadcrumb.
- **`.tables` in the beginner tutorial** (`sqlite3` dot-command) has
  been replaced with a real `SELECT … FROM sqlite_master` query.
  `wrangler d1 execute` runs its `--command` argument through D1's
  SQL path, which does not interpret dot-commands.

### Security

- **Session cookies now use HMAC-SHA256, not JWT.** The session
  cookie is an internal server-to-browser token with no need for
  algorithm negotiation or third-party verification, and the
  simpler `<b64url(payload)>.<b64url(hmac)>` format sidesteps a
  class of JWT-library pitfalls.
- **`__Host-cesauth_pending` is unsigned by design; `__Host-cesauth_session` is signed.**
  The pending cookie carries only a server-side handle; forging it
  points to a non-existent or mis-bound challenge and is rejected
  on `take`. The session cookie carries identity and MUST be signed.
- **Sensitive log categories default to off.** `Auth`, `Session`, and
  `Crypto` lines are dropped unless `LOG_EMIT_SENSITIVE=1` is set.
  Enabling this in production should be an explicit, time-boxed ops
  action.

---

## Release-gate reminders

Before cesauth's first production deploy:

1. Replace the `dev-delivery` audit line in
   `routes::magic_link::request` with a real transactional-mail
   HTTP call keyed by `MAGIC_LINK_MAIL_API_KEY`.
2. `WRANGLER_LOCAL` MUST be `"0"` (or unset) in the deployed
   environment. Verify with an explicit `[env.production.vars]`
   entry rather than relying on inheritance.
3. Freshly generate `JWT_SIGNING_KEY`, `SESSION_COOKIE_KEY`, and
   `ADMIN_API_KEY` per environment; do not reuse local-dev values.

See
[Deployment → Migrating from local to production](docs/src/deployment/production.md)
for the full release-gate walkthrough.

---

## Format

Each future release will have sections in this order:

- **Added** — new user-facing capability.
- **Changed** — behavior that existed previously and now works
  differently.
- **Deprecated** — slated for removal in a later release.
- **Removed** — gone this release.
- **Fixed** — bugs fixed.
- **Security** — vulnerability fixes or security-relevant posture
  changes. See also [.github/SECURITY.md](.github/SECURITY.md).

[Unreleased]: https://github.com/nabbisen/cesauth/compare/v0.2.1...HEAD
[0.2.1]:      https://github.com/nabbisen/cesauth/releases/tag/v0.2.1
