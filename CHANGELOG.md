# Changelog

All notable changes to cesauth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

cesauth is in active development. The public surface — endpoints,
`wrangler.toml` variable names, secret names, D1 schema, and
`core::ports` traits — may change between minor versions. Breaking
changes will always be called out here.

---

## [0.32.0] - 2026-05-02

Audit log hash chain — Phase 1 of ADR-010. cesauth's audit
events move from R2 NDJSON objects to a D1 table with SHA-256
hash chain integrity. The chain makes the audit log
tamper-evident: modifying any past row invalidates every
subsequent `chain_hash`, and the change becomes detectable
linearly with the number of intervening rows.

This release establishes the storage shape, the chain
mechanism, and the write/query paths. The verification cron
and admin verification UI ship as Phase 2 in v0.33.0.

### Architectural decision

ADR-010 (`docs/src/expert/adr/010-audit-log-hash-chain.md`)
records the design and the threat model. Status **Draft** until
Phase 2 lands and the chain has been validated end-to-end
against deliberate tampering scenarios.

The Phase 1 design was settled with the user during the
v0.32.0 planning conversation:

- **Source of truth = D1**, not R2 with a parallel chain
  ledger. The two-store design was rejected because: R2 has no
  read-your-writes guarantee on `list()` (the chain would
  fork under concurrency); cross-store consistency was a
  permanent operational hazard; verification would have been
  N+1.
- **No backward compatibility for historical R2 audit data.**
  The R2 path is retired entirely. Operators retain any
  pre-v0.32.0 R2 objects on their account but cesauth no
  longer reads or writes them. Migration tooling for old
  R2 events into the D1 chain is not provided.
- **Documentation framing** changed to remove "pre-1.0" /
  "production-ready" claims. cesauth is in active development;
  the documents now say so plainly without making maturity
  assertions either way.

### Added

- **D1 schema migration `0008_audit_chain.sql`** introduces
  the `audit_events` table with chain columns
  (`payload_hash`, `previous_hash`, `chain_hash`) plus
  per-field indexed columns (`subject`, `client_id`, `ip`,
  `user_agent`, `reason`) for admin search. Three indexes:
  `(ts)`, `(kind, ts)`, partial `(subject) WHERE subject IS
  NOT NULL`. The migration also INSERTs a genesis row at
  `seq=1` with `kind='ChainGenesis'`, all-zero
  `previous_hash`/`chain_hash`, and empty `{}` payload — the
  anchor point for the chain.

- **`SCHEMA_VERSION`** bumped 7 → 8. `MIGRATION_TABLE_ORDER`
  and `TENANT_SCOPES` extended with `audit_events` (Global
  scope; the chain is deployment-wide, not tenant-scoped).

- **`cesauth_core::audit::chain` module** with pure functions
  for the chain calculation (~150 lines):
  `compute_payload_hash(bytes) -> String` (SHA-256, lowercase
  hex), `compute_chain_hash(prev, payload_hash, seq, ts, kind,
  id) -> String` over the canonical byte layout `prev || ":"
  || payload_hash || ":" || seq || ":" || ts || ":" || kind ||
  ":" || id`, `verify_chain_link(...)` and
  `verify_payload_hash(...)` for Phase 2's verifier. Genesis
  sentinels published as constants (`GENESIS_HASH` = 64 zeros,
  `GENESIS_PAYLOAD_HASH` = SHA-256 of `{}`). 25 unit tests pin
  determinism, sensitivity to every input field, separator
  integrity (seq/ts boundary, kind/id boundary), reference
  vectors with a hash captured at v0.32.0 development time.

- **`cesauth_core::ports::audit::AuditEventRepository` trait**.
  Replaces the v0.31.x `AuditSink`. Three methods: `append`
  (chain-extending, with retry-on-collision in
  implementations), `tail` (Phase 2 verifier needs it), and
  `search` (admin queries). Value types: `AuditEventRow`,
  `NewAuditEvent`, `AuditSearch`.

- **`InMemoryAuditEventRepository`** in `cesauth-adapter-test`
  (~140 lines + 16 tests). Two constructors: `new()` for an
  empty repository (first append starts at `seq=1`) and
  `with_genesis()` mirroring the D1 schema (genesis at
  `seq=1`, real events from `seq=2`). Test coverage: chain
  validity across multiple appends, `previous_hash`-to-
  `chain_hash` linking, `payload_hash` recomputability, search
  filter behavior (kind / subject / since-until / limit /
  combined), tail retrieval at every population state.

- **`CloudflareAuditEventRepository`** in
  `cesauth-adapter-cloudflare` (~250 lines). The append path
  reads the tail, computes the new row's chain hash, attempts
  INSERT with explicit `seq=N+1`. UNIQUE collision (concurrent
  writer beat us) triggers retry; the budget is 3 attempts,
  enough to handle realistic Workers-instance simultaneity.
  The repository's `id`-collision case (caller produced a
  duplicate UUID, vanishingly rare) returns
  `PortError::Conflict` rather than retrying. Search uses
  parameterized SQL with placeholder binding to avoid
  injection; the limit is capped at 1000.

- **`docs/src/expert/audit-log-hash-chain.md`** new operator
  chapter (~250 lines): what's chained, how to read the table
  with `wrangler d1 execute`, chain semantics in plain
  language, what the chain protects against and what it
  doesn't, the genesis row's role, R2-deprecation operator
  notes, failure modes (the chain doesn't tolerate gaps in
  `seq`, so best-effort write failures drop events entirely),
  Phase 2 preview, diagnostic queries. Linked in
  `docs/src/SUMMARY.md` next to the cookies chapter and
  ADR-010.

### Changed (breaking — internal API)

- **`cesauth_core::ports::audit` rewritten.** The v0.31.x
  `AuditSink` trait + `AuditRecord` struct are gone, replaced
  by `AuditEventRepository` + `AuditEventRow` + `NewAuditEvent`
  + `AuditSearch`. Adapters that implemented `AuditSink` need
  to migrate; in this codebase that means
  `CloudflareAuditSink` → `CloudflareAuditEventRepository` and
  `InMemoryAuditSink` → `InMemoryAuditEventRepository`. The
  worker layer's `audit::write` and `audit::write_owned`
  signatures are unchanged — all 90+ call sites continue to
  work without modification.

- **`crates/worker/src/audit.rs` internals rewritten** to use
  the new D1-backed repository. The `EventKind` enum, `Event`
  struct, `write`, and `write_owned` functions all have the
  same signatures and semantics as v0.31.x; only the
  underlying storage changed. `EventKind` gained a public
  `as_str()` method that returns the snake_case discriminant
  string (used as the `kind` column value).

- **`CloudflareAuditQuerySource` rewritten** to query D1
  instead of walking R2. The admin-search code path goes from
  N+1 (one R2 list + N R2 GETs) to a single D1 SELECT. The
  `AuditQuery.prefix` field is preserved as the trait shape
  for backward compatibility but the v0.32.0 D1 backend
  ignores it (use `since`/`until` filters via the search form
  instead). `AdminAuditEntry.key` now contains `seq=N`
  (formatted) rather than an R2 object path; the UI renders
  it verbatim.

- **`r2_metrics` removed** from
  `cesauth-adapter-cloudflare::admin::metrics`. The
  `ServiceId::R2` arm in `snapshot()` returns an empty metric
  list with an explanatory comment. `D1_COUNTED_TABLES`
  gained `audit_events`, so the row count for the audit table
  shows up under `ServiceId::D1` as
  `row_count.audit_events`.

- **`/__dev/audit` route rewritten** to query D1. Query
  parameters now: `kind`, `subject`, `since`, `until`,
  `limit` (capped at 100), `body=1`. Default response is the
  indexed-fields summary; `body=1` includes the full payload
  plus chain metadata (`payload_hash`, `previous_hash`,
  `chain_hash`).

- **`AdminAuditEntry.key` field documentation updated** to
  reflect the v0.32.0 meaning (chain sequence number rather
  than R2 object path). The struct shape is unchanged so
  `cesauth_ui::admin::audit` continues to render it as before.

### Changed (breaking — deployment)

- **`wrangler.toml` removed `[[r2_buckets]] AUDIT`** binding.
  Existing deployments that left the binding in their own
  `wrangler.toml` continue to deploy; cesauth simply doesn't
  reference the binding any more. Removing it is a one-line
  cleanup. The R2 `cesauth-audit` bucket itself remains on
  the operator's Cloudflare account; cesauth does not touch
  it.

- **No migration of historical R2 audit data**. Operators
  upgrading from v0.31.x retain the R2 bucket; if they need
  continuity over the cutover they must export R2 events with
  their own tooling before deploying v0.32.0. This is by
  design (Q2-c during planning) — the chain starts fresh at
  the genesis row inserted by migration 0008.

### Documentation

- New `docs/src/expert/audit-log-hash-chain.md` (operator
  chapter).
- New `docs/src/expert/adr/010-audit-log-hash-chain.md` (ADR,
  Draft).
- `docs/src/SUMMARY.md` and `docs/src/expert/adr/README.md`
  index updated.
- `docs/src/expert/storage.md` "Why R2 for audit" subsection
  rewritten to "Audit lives in D1 with a hash chain".
- `docs/src/deployment/production.md` step 1 drops the
  `cesauth-audit-prod` bucket creation; step 9 monitor list
  drops the R2-audit-bucket-grows note in favor of D1
  `row_count.audit_events`.
- `docs/src/deployment/preflight.md` drops the audit bucket
  preflight item and the R2 audit lifecycle item; updates the
  billing-alert tip to mention D1 row growth.
- `docs/src/deployment/backup-restore.md` rewritten to
  describe audit as part of the D1 backup story; the explicit
  "R2 audit" backup section is replaced with a note that
  audit travels in the D1 dump and the chain hashes survive
  re-import intact.
- `docs/src/deployment/wrangler.md` bindings table drops the
  `AUDIT` row and updates the prose example.
- `docs/src/deployment/data-migration.md` clarifies that
  v0.32.0+ audit events DO travel in dumps with chain
  intact.
- `docs/src/deployment/cron-triggers.md` future-work list
  swaps "R2 audit lifecycle" for "audit chain verification
  (Phase 2 of ADR-010)".
- `docs/src/deployment/environments.md` drops staging audit
  bucket binding from the example wrangler config and
  rephrases the per-env audit isolation note.
- `docs/src/expert/logging.md` "Not audit" framing updated to
  point at D1 instead of R2.
- `docs/src/expert/adr/005-data-migration-tooling.md` notes
  that v0.32.0+ audit IS in the dump (chain travels intact).
- Module-level rustdocs at `crates/adapter-cloudflare/src/ports.rs`
  and `crates/core/src/migrate.rs` updated.

- **Project-status framing softened across the project.**
  Removed "pre-1.0", "production-ready", and "Status: pre-1.0"
  badge/copy from `README.md`, `CHANGELOG.md`, `ROADMAP.md`,
  `TERMS_OF_USE.md`, `docs/src/introduction.md`, and
  `docs/src/expert/tenancy.md`. The new framing is "in active
  development" without making maturity claims either way.
  Operational-language uses of "production deployment" (as
  in "before any production deploy, do X") are preserved
  unchanged — those are descriptions of the deployment
  environment, not status claims.

### Tests

678 → 717 (+39).

- core: 275 → 300 (+25). All in `audit::chain::tests`:
  determinism, output shape (64 lowercase hex), 6 sensitivity
  tests (one per chain-input field), 2 separator-integrity
  tests pinning that `seq:ts` and `kind:id` boundaries can't
  be smuggled past the hash, reference vector pinning the
  v0.32.0 chain layout, verify-chain-link / verify-payload-hash
  positive and negative cases, genesis sentinel correctness,
  constant_time_eq corner cases.
- adapter-test: 72 → 86 (+14). All in `audit::tests`: empty
  repo first-append starts at seq=1, with-genesis variant
  starts user events at seq=2, three-append chain integrity
  with full hash recomputation, rows-in-seq-order invariant,
  tail behavior across all population states, search filter
  per-criterion (kind / subject / time / limit) plus combined
  AND filter, default newest-first ordering, no-match returns
  empty.
- ui, worker, do, migrate: unchanged (183, 119, 16, 13). The
  worker's `audit::write` is signature-compatible so existing
  tests pass without modification.

### Migration notes

Apply the new schema migration:

```sh
wrangler d1 migrations apply cesauth-prod
# applies 0008_audit_chain.sql
```

After deploy:

- The `audit_events` table exists with the genesis row at
  `seq=1`.
- All new audit events flow into D1 with chain extension.
- The R2 `AUDIT` bucket no longer receives writes.
- The `wrangler.toml` example dropped the `AUDIT` binding;
  operators can leave their own copy unchanged or delete the
  three-line block.

If `wrangler d1 migrations apply` fails part-way through (the
genesis-row INSERT in particular), rerun — the migration is
idempotent only at the schema level, but the genesis row uses
`seq=1` explicitly so a duplicate-key error from a re-run is a
benign signal that the migration already completed.

### Forward roadmap

- **v0.31.1** — TOTP handler integration tests (deferred from
  v0.31.0 per plan v2 §6.4). Approach 2 from the v0.32.0
  planning discussion: refactor handler decision logic into
  pure helpers, exercise via `cesauth-adapter-test`. Breaking
  internal-refactor changes are explicitly OK.
- **v0.33.0** — ADR-010 Phase 2: chain verification cron + admin
  verification UI + chain-head checkpoints. ADR-010 graduates
  to Accepted at the end of this release.

---

## [0.31.0] - 2026-05-02

UI/UX iteration release. First node-major release after the 5-phase
TOTP security track closed at v0.30.0; per the user-stated project
value "重要な予定が完了したタイミングで、UI/UX 改善に取り組みます",
the schedule turns to user-facing surface improvements before the
audit-log-hash-chain track (v0.32.0+) starts.

This release implements the six P0 + P1 backlog items from
`cesauth-v0.31.0-plan-v2.md` (the planning document distilled
from a PowerPoint UI/UX review). One item (P1-B handler integration
tests) was split to v0.31.1 per the plan's §6.4 scope-cap policy.

### Added

- **`/me/security` Security Center index page** (P0-A). Read-only
  surface listing the user's primary auth method (Passkey /
  MagicLink / Anonymous), TOTP enabled/disabled badge, and
  recovery-code remaining count. Single-task-per-page rule —
  links out to `/me/security/totp/enroll` (when disabled) or
  `/me/security/totp/disable` (when enabled), no inline
  destructive actions. Anonymous users see a suppressed-TOTP
  variant. New template `cesauth_ui::templates::security_center_page`
  and variant `security_center_page_with_flash` for flash-aware
  rendering. New module `cesauth_worker::routes::me::security`
  with `get_handler`. Wired in `worker::lib::main` as
  `GET /me/security`.

- **Recovery-code threshold rendering** (4-tier). N=10 / N=2-9
  → info badge ("リカバリーコード: N 個有効/残り"), N=1 →
  warning flash with re-enrollment hint, N=0 → danger flash with
  admin-contact message. Threshold rationale in plan v2 §3.1
  P0-A: no recovery-code regeneration path exists, so an early
  warning would push users toward unnecessary re-enrollment.

- **Flash-message infrastructure** (P0-B). New
  `__Host-cesauth_flash` cookie (SameSite=Lax, 60s TTL,
  HMAC-signed over a closed-dictionary payload). Format prefix
  `v1:` allows future format upgrades without breaking
  in-flight cookies. New module `cesauth_worker::flash`
  (~270 lines). Templates side: `flash_block(view) -> String`
  and `frame_with_flash(title, flash_html, body)`. Wired into
  4 handlers: `disable` → `success.totp_disabled` (redirect
  changed `/` → `/me/security`), `enroll/confirm` →
  `success.totp_enabled` (both recovery-codes-page and
  direct-redirect paths), `recover` → `warning.totp_recovered`,
  `logout` → `info.logged_out` (redirect changed `/` → `/login`).

- **`totp_enroll_page` `error: Option<&str>` slot** (P0-C).
  Mirrors `totp_verify_page`. Wrong-code branch passes Japanese
  error message instead of silently re-rendering. Code input
  gained `autofocus` for the wrong-code re-render.

- **8 design tokens** (P0-D) with light + dark mode variants.
  `--success`, `--success-bg`, `--warning`, `--warning-bg`,
  `--danger`, `--danger-bg`, `--info`, `--info-bg`. New CSS
  classes: `.flash` + 4 `.flash--*`, `.badge` + 4 `.badge--*`,
  `button.danger`, `button.warning`, `.flash__icon`,
  `.flash__text`, `.visually-hidden` (utility class — fixed
  latent bug where `totp_verify_page` referenced the class but
  the rule was missing). All state badges and banners pair
  color with icon + text label per WCAG 1.4.1.

- **`next` parameter for post-login landing** (P1-A). Pure
  function `validate_next_path(raw)` with `/me/*` + `/`
  allowlist; rejects protocol-relative URLs, schemes,
  Windows UNC, admin paths, api paths, oauth endpoints, login
  loop, dev paths, machine endpoints, prefix-substring traps.
  New `redirect_to_login_with_next(req)` base64url-encodes
  path+query into `?next=`. Login GET handler reads `?next=`,
  validates, stashes encoded value in `__Host-cesauth_login_next`
  (5 min, SameSite=Lax). `complete_auth` /
  `complete_auth_post_gate` thread the cookie header through;
  the no-AR landing arm consults the cookie via
  `decode_and_validate_next`.

- **`docs/src/expert/cookies.md`** new chapter (~210 lines)
  inventorying all 7 cookies. Each entry: name + purpose +
  lifetime + scope + SameSite + HttpOnly + Secure attributes +
  strictly-necessary justification per EDPB Guidelines 5/2020
  §3.1.1. Operator-deployed analytics responsibility note.
  Inventory maintenance rule documented for future releases.
  Linked in `docs/src/SUMMARY.md`.

- **ADR-009 added to `docs/src/SUMMARY.md`** (was missed in
  v0.30.0).

- **`attempts_exhausted` pure helper** in `verify::post_handler`
  + `DISABLE_SUCCESS_REDIRECT` constant in `disable::post_handler`,
  both with unit tests. Honest minimum coverage at the worker
  handler layer pending the env-mock investment in v0.31.1.

### Changed

- **Logout redirect target**: `POST /logout` now 302's to
  `/login` (was `/`) with `info.logged_out` flash.

- **TOTP disable redirect target**: `POST /me/security/totp/disable`
  now 302's to `/me/security` (was `/`) with `success.totp_disabled`
  flash.

- **TOTP enrollment recovery-codes page "continue" link** now
  points to `/me/security` (was `/`).

- **`totp_enroll_page` template signature**: now takes a fourth
  argument `error: Option<&str>`. Existing callers updated.

- **`complete_auth` and `complete_auth_post_gate` signatures**:
  both now take an additional `cookie_header: Option<&str>`
  parameter. All four worker call sites updated.

- **`me::auth::resolve_or_redirect`** now uses
  `redirect_to_login_with_next(req)` to encode the user's
  current path into `?next=`. The legacy `redirect_to_login()`
  remains for mid-flow failures where the user isn't trying to
  reach a `/me/*` page.

### Fixed

- **`.visually-hidden` CSS rule was missing**. Class was already
  referenced by `totp_verify_page` for an SR-only heading but
  the rule was never written. Added in P0-D's CSS expansion.

### Documentation

- New `docs/src/expert/cookies.md`.
- `docs/src/SUMMARY.md` updated with cookies chapter + ADR-009
  link.
- ROADMAP.md: v0.31.0 marked shipped; new v0.31.1 entry
  describing the deferred TOTP handler integration tests.

### Tests

573 → ~680 (approximately +107). Breakdown:

- ui: 150 → ~190 (+40). Design-token snapshot tests, flash_block
  contract tests, security center page tests (4 recovery-code
  threshold boundaries, conditional links, anonymous suppression,
  single-task-per-page invariant), totp_enroll_page error slot
  tests.
- worker: 47 → ~120 (+~73). 32 flash module tests (round-trip,
  tamper detection, malformed-input rejection, cookie shape,
  closed-dictionary defense), 34 me::auth tests (validate_next_path
  comprehensive coverage, decode round-trip, cookie helpers),
  TOTP handler pure-helper extracts.
- core, adapter-test, migrate, do, adapter-cloudflare: unchanged.

### Deferred to v0.31.1

- **TOTP route handler integration tests** (P1-B). Each of the
  four route handlers deserves at least 3 cases per plan §3.2
  P1-B (normal / CSRF failure / primary failure mode). The
  worker crate has no `worker::Env` mock infrastructure;
  building one (faking D1 + DO + KV + secrets + vars) is its
  own scope. Plan v2 §6.4 scope-cap policy invoked.

### Migration notes

No D1 schema migration. `SCHEMA_VERSION` stays at 7. No new
secret or var. The new cookies (`__Host-cesauth_flash` and
`__Host-cesauth_login_next`) are introduced organically; existing
deployments need no operator action. Both are strictly necessary
per EDPB Guidelines 5/2020 §3.1.1; cesauth does not display a
cookie consent banner.

---

## [0.30.0] - 2026-04-29

Security track Phase 7 of 11: TOTP Phase 2d — polish + operations.

**This is the final TOTP release.** v0.26.0 shipped the library,
v0.27.0 the storage adapters, v0.28.0 the presentation layer,
v0.29.0 wired the HTTP routes + verify gate. v0.30.0 closes the
track with the disable flow, cron sweep extension, redaction
profile updates, operator chapter, pre-production release gate
update, and **ADR-009 graduates from `Draft` to `Accepted`**.

After v0.30.0 deploys, the TOTP track is feature-complete for the
0.x series. Future iterations (the v0.32.0+ `/me/security` self-
service UI, dual-key rotation tooling, audit-log integration)
build on top of the foundation laid in 0.26.0–0.30.0 without
touching the underlying primitives.

**Note on UI/UX scope**: per the user-stated project value
"重要な予定が完了したタイミングで、UI/UX 改善に取り組みます", the
disable flow in this release is intentionally **minimal** — a
single-page confirmation, a redirect home, no flash-message
infrastructure. The TOTP track concludes here; UX work
(`/me/security` index page, flash messages, error-slot in the
enroll template, CSS polish for warning/danger button states)
naturally belongs in the next release where the UI/UX iteration
will consolidate it across the surface, not just for TOTP.

### Added — disable flow

- **`GET /me/security/totp/disable`** — confirmation page
  rendered by the new `cesauth_ui::templates::totp_disable_confirm_page`
  template. Single-form POST/Redirect/GET pattern (arriving at
  this URL doesn't disable TOTP, only POSTing the confirm form
  does). The page warns explicitly that recovery codes are wiped
  too, offers a cancel link, and uses one-click confirmation
  rather than a "type DISABLE to confirm" double-prompt — the
  consequences are clearly stated, re-enrolling takes one
  minute, and the user already authenticated for primary to
  reach this page.
- **`POST /me/security/totp/disable`** — validates CSRF, deletes
  ALL TOTP authenticator rows for the calling user (active or
  unconfirmed) plus all recovery codes (redeemed or unredeemed).
  Authenticators-first ordering: an authenticator without
  recovery codes is still a working credential, while recovery
  codes without an authenticator are useless. Best-effort
  failure semantics: authenticators-delete failure → 500 (TOTP
  remains enabled, user sees this on next login); recovery-codes
  delete failure → silently logged (the authenticator is gone,
  recovery codes are useless). Redirects to `/`. No flash
  message — that infrastructure is deferred to the UI/UX release.

### Added — `TotpAuthenticatorRepository::delete_all_for_user`

Trait method + in-memory + D1 adapter implementations.
Single-statement user-scoped DELETE (no list-then-delete shape
because there's no per-row audit invariant to preserve — TOTP
rows are credentials, not principals; contrast with the
anonymous-user sweep where audit-trail integrity is load-bearing
per ADR-004 §Q5).

In-memory adapter: `m.retain(|_, r| r.user_id != user_id)`. D1
adapter: `DELETE FROM totp_authenticators WHERE user_id = ?1`.
Both no-op-on-empty / idempotent across retries (deliberately
NOT mapped to `NotFound` like the existing `delete(id)` because
the disable flow is idempotent).

Two new tests in `cesauth-adapter-test::repo::tests`:
- `delete_all_for_user_scopes_to_user` — pins that Alice's
  disable doesn't wipe Bob's TOTP rows. A bug here would be a
  cross-user security incident, not a UX glitch.
- `delete_all_for_user_is_idempotent_on_missing` — pins that
  retries / double-clicks don't 500.

### Added — TOTP unconfirmed-enrollment cron sweep

Extension to the existing 04:00 UTC daily cron in
`crates/worker/src/sweep.rs`. New private
`totp_unconfirmed_sweep(env, cfg, now)` helper called after the
anonymous-trial sweep within the same `run()` body. Drops
`totp_authenticators` rows where `confirmed_at IS NULL AND
created_at < now - 86400` (24-hour retention per ADR-009 §Q9).

The 24-hour window is "long enough that a user who got
distracted mid-enrollment can come back the same day, short
enough that abandoned enrollment doesn't pollute storage". Per
ADR-009 §Q9.

The partial index `idx_totp_authenticators_unconfirmed` (created
in migration 0007) makes the lookup query cheap. Same
list-then-delete shape as the anonymous sweep, same best-effort
failure semantics. **No audit emission per row** — TOTP rows
are credentials, not principals; the row count is logged as
`totp unconfirmed sweep complete: N rows deleted`.

The module-level doc in `sweep.rs` is rewritten to cover both
passes; the "Why not a single SQL DELETE" section is consolidated
into the top doc rather than living per-sweep.

### Added — `RedactionProfile.drop_tables`

New field on `cesauth_core::migrate::RedactionProfile`. Tables
listed are **dropped entirely** from the export when the
profile is active (vs the existing per-column `rules` which
scrub fields within preserved tables).

Both built-in profiles updated:
- **`prod-to-staging`**: drops `totp_authenticators` +
  `totp_recovery_codes`. Per ADR-009 §Q5/§Q11: TOTP secrets must
  NOT survive redaction even encrypted, because a staging
  deployment with real users' encrypted TOTP secrets would let
  any staging operator authenticate as those users (the
  encryption key is just a deployment secret, which staging has
  access to).
- **`prod-to-dev`**: same TOTP-drop, plus its existing
  display-name nullification. The threat surface on a
  developer's laptop is even worse than on staging.

CLI export loop in `crates/migrate/src/main.rs` updated to honor
`prof.drop_tables` — both the main export path (~line 369) and
the round-trip verify path (~line 627) skip listed tables.
Operator-facing message during export:
`Exporting <table>... 0 rows (dropped by `<profile>` profile)`.

The `MIGRATION_TABLE_ORDER` and `TENANT_SCOPES` constants in
`cesauth-migrate/schema.rs` are extended with both new tables
(both `TenantScope::Global` since they reference users via FK
without their own `tenant_id` column — same shape as the
existing `authenticators` table for WebAuthn).

3 new core::migrate tests:
- `prod_to_staging_drops_totp_tables` — pins ADR-009 §Q5/§Q11.
- `prod_to_dev_drops_totp_tables` — same for the stricter
  profile.
- `built_in_profile_drop_tables_reference_known_tables` —
  defense-in-depth: catches typos in `drop_tables` (e.g.,
  `totp_authenticator` without the s) against a hard-coded
  `KNOWN_DROPPABLE` list. A typo would silently NOT drop the
  table, leaving a privacy hole.

### Added — operator chapter `docs/src/deployment/totp.md`

New ~270-line operator chapter covering:
- When TOTP fires (post-MagicLink only; WebAuthn skips per
  ADR-009 §Q7).
- Required configuration: `TOTP_ENCRYPTION_KEY` secret +
  `TOTP_ENCRYPTION_KEY_ID` var, with `openssl rand -base64 32 |
  wrangler secret put TOTP_ENCRYPTION_KEY` example.
- Pre-production release gate cross-reference.
- Key rotation procedure: dual-key deployment + re-encryption
  (Phase 2). **With explicit caveat** that the dual-key
  resolution path is NOT yet implemented in 0.30.0; operators
  who need to rotate today must either re-enroll all users or
  write a one-shot migration helper. Tracked in ROADMAP under
  "Later".
- Admin reset path for lockout recovery: direct D1 deletion
  procedure (`wrangler d1 execute ... DELETE FROM
  totp_authenticators WHERE user_id = ...`).
- Cron sweep semantics + diagnostic query.
- Disable flow operator perspective + the no-current-code-
  required rationale.
- Redaction profile behavior + ADR-009 §Q5/§Q11
  cross-reference.
- Operational invariants: `secret_key_id` is load-bearing for
  rotation, partial index is load-bearing for sweep, cookie is
  SameSite=Strict, recovery codes are SHA-256-hashed
  irretrievably, multi-authenticator semantics.
- Diagnostic queries: how many users have TOTP, how many have
  fewer than N recovery codes left, how many in the sweep
  window right now.

Added to `docs/src/SUMMARY.md` between the security-headers
chapter and the runbook.

### Added — pre-production release gate update

`docs/src/expert/security.md` — `TOTP_ENCRYPTION_KEY` added as
item 6 to the pre-production checklist with the caveat that
TOTP is opt-in at the operator level. Cross-references the new
operator chapter.

### Added — totp_disable_confirm_page UI template

5 new template tests in `cesauth-ui::templates::tests`:
- CSRF token inclusion (matches the POST validator).
- Form action correctness (`/me/security/totp/disable`,
  POST method).
- Recovery-codes-loss warning text present (`recovery codes`
  string match — pin so a future UX softening doesn't hide the
  consequence).
- Cancel link offered (`<a href="/">Cancel`) — destructive
  flow must offer a no-op exit.
- CSRF escape behavior (e.g., `t<>k` becomes `t&lt;&gt;k`).

### Status — ADR-009 graduates Draft → Accepted

The TOTP track has been validated end-to-end across five
releases. Operator-visible flows work, the cron sweep prunes
abandoned enrollments, redaction profiles drop TOTP secrets,
the operator chapter exists, and there are no outstanding
design questions. ADR header status changes from `Draft
(v0.26.0)` to `Accepted (v0.30.0)`. The ADR index in
`docs/src/expert/adr/README.md` is updated.

### Tests

Total: **573 passing** (+10 over v0.29.0):

- core: **275** (was 272) — 3 new in `migrate::tests`:
  - `prod_to_staging_drops_totp_tables`
  - `prod_to_dev_drops_totp_tables`
  - `built_in_profile_drop_tables_reference_known_tables`
- adapter-test: **72** (was 70) — 2 new in `repo::tests`:
  - `delete_all_for_user_scopes_to_user`
  - `delete_all_for_user_is_idempotent_on_missing`
- ui: **150** (was 145) — 5 new in `templates::tests`:
  - `disable_page_includes_csrf_token`
  - `disable_page_form_posts_to_disable_endpoint`
  - `disable_page_warns_about_recovery_code_loss`
  - `disable_page_offers_cancel_link`
  - `disable_page_escapes_csrf`
- worker: 47 (unchanged — disable handler integration tests
  deferred to UI/UX release per scope-cap; see CHANGELOG note
  on UI/UX scope above).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/adr/009-totp.md` — Status changed to
  Accepted. Phasing v0.30.0 entry added with implementation
  details.
- `docs/src/expert/adr/README.md` — index updated.
- `docs/src/expert/security.md` — `TOTP_ENCRYPTION_KEY` added to
  pre-production checklist (item 6).
- `docs/src/deployment/totp.md` — new chapter (~270 lines).
- `docs/src/SUMMARY.md` — TOTP chapter linked in deployment
  section.

### Migration (0.29.0 → 0.30.0)

Code-only release. **No schema migration.** No `wrangler.toml`
changes required (the existing `0 4 * * *` cron entry already
runs the extended sweep — no new cron needed).

Operators who want to start using the redaction-profile drop
behavior should expect their next `cesauth-migrate export
--profile prod-to-staging` to NOT include TOTP rows. Existing
exports (pre-v0.30.0) that included TOTP rows are unchanged on
disk; the importer doesn't reject them.

The disable flow `GET/POST /me/security/totp/disable` is
available immediately after deploy. Users with confirmed TOTP
authenticators can navigate there to remove TOTP from their
account.

The TOTP unconfirmed-enrollment cron sweep starts running at the
next 04:00 UTC tick after deploy. The first run will prune any
unconfirmed rows older than 24h that have accumulated since
v0.26.0+ (likely a small handful in most deployments).

### Smoke test

```sh
cargo test --workspace                              # 573 passing
cargo test -p cesauth-core --lib migrate            # 62 passing
                                                    # (59 prior + 3 new)
cargo test -p cesauth-adapter-test --lib totp       # ~15 passing

# End-to-end disable flow (deployed worker, signed-in user
# with confirmed TOTP):
# 1. Visit /me/security/totp/disable.
# 2. Click "Yes, disable TOTP".
# 3. Verify totp_authenticators + totp_recovery_codes rows for
#    the user are gone via wrangler d1.
# 4. Logout, login again via Magic Link.
# 5. TOTP gate does NOT fire — user lands directly in their
#    session.
```

### Discovered

No new findings this release. The dual-key rotation gap is
documented honestly in the operator chapter rather than papered
over.

### Deferred — to v0.31.0 (UI/UX improvement release)

Per the user-stated project value, UI/UX improvements come at
TOTP-track-completion time. The natural scope for the next
release:

- **`/me/security` index page** — listing TOTP enabled-or-not,
  remaining recovery codes count, link to disable, link to
  enroll-second-authenticator. Currently users navigate
  directly to `/me/security/totp/enroll` or `/me/security/totp/disable`
  with no overview page.
- **Flash-message infrastructure** — "TOTP disabled
  successfully" notice on `/` after a successful disable.
  Currently the disable handler redirects silently.
- **Error slot in `totp_enroll_page`** — when confirm fails
  (wrong first code), the worker re-renders the enroll page
  unchanged. An `error: Option<&str>` parameter (matching
  `totp_verify_page`) would polish the experience.
- **`me::auth::resolve_or_redirect` `next` parameter** — the
  redirect destination is hard-coded `/login`. A `next`
  parameter to come back to the originally-requested URL after
  login would polish the enroll-while-not-signed-in flow.
- **CSS for warning/danger button states** — the disable page
  uses `class="danger"` but no CSS exists yet (v0.5.0-era frame
  styling).
- **Handler integration tests** — v0.29.0+ TOTP route handlers
  lack dedicated unit tests beyond the pure-helper layer
  (templates, cookie shape, library functions). The UI/UX
  release will likely refactor handlers as part of UX cleanup;
  testing them after the refactor is more efficient than
  writing tests now and rewriting them.

### Deferred — to v0.32.0+ (audit log hash chain)

- ADR-010 + audit-log-hash-chain Phase 1 (chain design,
  `previous_hash` column, transition strategy).
- ADR-010 Phase 2 (integrity sweep cron + admin verification UI).

### Deferred — unchanged

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued in
  ROADMAP "Later" behind the security track and the UI/UX
  release.
- **TOTP dual-key rotation tooling** — `cesauth-migrate totp
  re-encrypt` subcommand. Operator chapter documents the
  workaround (re-enroll all users, or write a one-shot helper).
- **`oidc_clients.client_secret_hash` schema-comment drift** —
  ROADMAP "Later" item.

---

## [0.29.0] - 2026-04-29

Security track Phase 6 of 11: TOTP Phase 2c — HTTP routes +
verify gate.

This is the **operator-visible** release of the TOTP track. v0.26.0
shipped the library, v0.27.0 the storage adapters, v0.28.0 the
presentation layer (templates + QR generator + auth helper). v0.29.0
finally wires it all together: a user can enroll TOTP, get prompted
on next Magic Link login, verify a code, and resume their
authentication flow. Recovery code redemption is included.

After v0.29.0 deploys with `TOTP_ENCRYPTION_KEY` provisioned, the
flow is end-to-end functional: a user navigates to
`/me/security/totp/enroll`, scans the QR code, types a verifying
code, sees their plaintext recovery codes once, and TOTP is
enabled. On the next Magic Link login the gate fires and prompts
for a 6-digit code; on success the original `complete_auth` flow
resumes exactly as if no gate had fired.

**v0.30.0 will close out the track** with the disable flow, cron
sweep extension, redaction profile updates, operator chapter, and
ADR-009 graduating from Draft to Accepted.

### Added — five new HTTP routes

All routes under `/me/security/totp/*`, cookie-authenticated via
`__Host-cesauth_session` (the standard user session). New routing
wires in `worker::lib::main`.

- **`GET /me/security/totp/enroll`** — start a fresh enrollment.
  Mints a CSPRNG secret via `cesauth_core::totp::Secret::generate`,
  encrypts via AES-GCM with `aad_for_id(row_uuid)`, parks an
  unconfirmed row in `totp_authenticators`, sets the short-lived
  `__Host-cesauth_totp_enroll` cookie carrying the row id, builds
  the otpauth URI via `cesauth_core::totp::otpauth_uri(issuer,
  email, secret)` (issuer hard-coded "cesauth"), generates the
  inline SVG QR via `cesauth_core::totp::qr::otpauth_to_svg`, and
  renders `cesauth_ui::templates::totp_enroll_page`. Refuses with
  503 if `TOTP_ENCRYPTION_KEY` or `TOTP_ENCRYPTION_KEY_ID` is
  unset (clear operator-facing message).
- **`POST /me/security/totp/enroll/confirm`** — verify the first
  code, flip `confirmed_at`, mint recovery codes if first
  enrollment, render `totp_recovery_codes_page` once. CSRF guard
  via existing `csrf::verify`. Two ownership checks: row exists,
  and row's user_id matches the session's user_id (rejects forged
  enrollment cookie pointing at someone else's row). Idempotency:
  already-confirmed row → clear cookie + redirect to home (back-
  button replay). Wrong code → re-render the enroll page with
  same secret (the user retypes a fresh code). Recovery codes
  minted only at user's FIRST confirmed authenticator (per
  ADR-009 §Q6 — adding a backup phone keeps the original codes).
- **`GET /me/security/totp/verify`** — TOTP gate prompt. Reads
  `__Host-cesauth_totp` cookie, peeks the `PendingTotp` challenge
  (no consume — GET is render-only), mints CSRF, renders
  `totp_verify_page`. Stale cookie / wrong challenge type / expired
  → 302 to `/login` (clear gate cookie).
- **`POST /me/security/totp/verify`** — verify the submitted code,
  on success resume `complete_auth_post_gate`. Takes the
  `PendingTotp` challenge (consume), reconstructs `PendingAr`
  from the inline AR fields, looks up the user's active
  authenticator, decrypts the secret, parses + verifies the code
  via `verify_with_replay_protection(secret, code,
  last_used_step, now)`. On success: persist advanced step via
  `update_last_used_step`, then `complete_auth_post_gate(env,
  cfg, user_id, auth_method, ar_fields)` to start the session,
  mint AuthCode if AR present, redirect. On failure: bump
  attempts, re-park under the SAME handle (preserving original
  TTL — a buggy authenticator that submits wrong codes can't keep
  the gate open forever), re-render with inline error message
  ("That code didn't match. Try again."). MAX_ATTEMPTS=5 then
  bounce to /login. Status 200 (not 401) — the user IS
  authenticated for primary, the form is a continuation.
- **`POST /me/security/totp/recover`** — single-use recovery code
  redemption. Same cookie + CSRF gates as verify. Takes the
  challenge, canonicalizes + SHA-256-hashes the submitted code
  (`hash_recovery_code` strips whitespace + dashes,
  uppercases — user can paste in any reasonable shape), looks up
  via `find_unredeemed_by_hash(user_id, hash)`. On match:
  `mark_redeemed(id, now)` then `complete_auth_post_gate`. On no
  match: 302 to `/login` (recovery is high-friction; failed
  recovery bounces to `/login` rather than re-rendering — pin
  against brute-force probing). Per ADR-009 §Q6 the recovery path
  does NOT advance the TOTP authenticator's `last_used_step` —
  recovery bypasses TOTP, doesn't use it.

### Added — TOTP gate insertion in `complete_auth`

`post_auth::complete_auth` now contains the gate logic at step
1.5 (between AR resolution and session start). For
`AuthMethod::MagicLink` only, calls `find_active_for_user(user_id)`:

- `Some(_)` confirmed authenticator → `park_totp_gate_and_redirect`
  carries AR fields **inline** into `Challenge::PendingTotp` (not
  a chained handle reference — eliminates the race where the
  original AR could expire between gate-park and verify-resume),
  sets `__Host-cesauth_totp` (SameSite=Strict, distinct from
  pending-authorize's Lax), clears `__Host-cesauth_pending`
  (because AR fields moved into PendingTotp), 302 to
  `/me/security/totp/verify`.
- `None` no confirmed authenticator → falls through to standard
  post-gate flow.
- `Err(_)` storage failure → fails closed with 500-style error.
  Refusing to proceed without knowing whether TOTP was required
  is the correct security posture; "transient outage skips MFA"
  is a footgun.

`AuthMethod::Passkey` (WebAuthn) and `AuthMethod::Admin` skip
the gate entirely — WebAuthn is itself MFA-strong (device
possession + on-device user verification per ADR-009 §Q7), and
admin auth is bearer-token-only and doesn't go through
`complete_auth`. Anonymous never has TOTP enrolled.

### Added — `complete_auth_post_gate` helper

Extracted as `pub(crate)` from the original `complete_auth`
body. Both the no-gate path (in `complete_auth` line 245) AND the
post-verify path (in `routes::me::totp::verify::post_handler`
line 234, recovery path line 132) call this. Identical behavior:
start the session, mint AuthCode if AR present, build the
response with session/clear-pending/clear-totp cookies, redirect
to either `redirect_uri?code=…&state=…` or `/`.

### Added — two new short-lived cookies

- **`__Host-cesauth_totp`** (gate cookie). 5-minute TTL —
  short enough that an abandoned TOTP prompt doesn't tie up
  state, long enough for a user fumbling with their authenticator
  app. SameSite=Strict (no cross-site flow involved — this is a
  purely internal-route breadcrumb between gate-park and
  verify-resume).
- **`__Host-cesauth_totp_enroll`** (enrollment cookie). 15-minute
  TTL — generous because enrollment requires switching to the
  authenticator app, scanning, and switching back; app-switch
  context cost is substantial. SameSite=Strict.

Both follow the `__Host-` prefix convention which guarantees
Path=/, Secure, no Domain attribute. Both are HttpOnly.

`set_*_cookie_header`, `clear_*_cookie_header`, `extract_*`
helpers in `cesauth_worker::post_auth`.

### Added — `Challenge::PendingTotp` AR fields inline

Carries `ar_client_id`, `ar_redirect_uri`, `ar_scope`, `ar_state`,
`ar_nonce`, `ar_code_challenge`, `ar_code_challenge_method` as
flattened `Option<String>` fields. Plus `user_id`, `auth_method`,
`attempts: u32`, `expires_at: i64`. The flattening is deliberate
(distinct from earlier ADR drafts that considered a chained-handle
approach — those drafts had a race where the original AR handle
could expire mid-flight).

### Tests

Total: **563 passing** (+12 over v0.28.0):

- core: 272 (unchanged).
- adapter-test: 70 (unchanged).
- ui: 145 (unchanged).
- worker: **47** (was 35) — 12 new in `post_auth::tests`:
  - `totp_cookie_header_shape` — Max-Age preserved, HttpOnly,
    Secure, SameSite=Strict (NOT Lax).
  - `totp_cookie_header_uses_host_prefix` — `__Host-` prefix +
    Path=/ invariant.
  - `clear_totp_cookie_header_zeros_max_age` — clear path
    keeps SameSite consistency.
  - `extract_totp_handle_present` / `..._absent_returns_none`.
  - `extract_totp_handle_does_not_match_pending_cookie` —
    must-not-cross-context property between gate cookie and
    pending-authorize cookie (defense against a mistakenly
    accepted cookie short-circuiting the wrong flow).
  - `totp_enroll_cookie_header_shape` — same attributes as
    gate cookie.
  - `totp_enroll_cookie_distinct_name_from_gate_cookie` —
    distinct cookie names; confusing them would let an
    enrollment cookie short-circuit the gate or vice versa.
  - `extract_totp_enroll_id_present` / `..._absent_returns_none`.
  - `totp_gate_ttl_is_short` — 1-10 min bounds.
  - `totp_enroll_ttl_is_generous` — 5-30 min bounds (with
    rationale comment about cron sweep).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/adr/009-totp.md` — Phasing v0.29.0 entry
  marked ✅ with implementation details (inline AR-field
  carrying, `complete_auth_post_gate` extraction, MAX_ATTEMPTS
  policy). ADR remains in `Draft` — graduates to `Accepted`
  in v0.30.0 after the polish phase validates the design end
  to end.

### Migration (0.28.0 → 0.29.0)

Code-only release. **No schema migration.** No `wrangler.toml`
changes.

**To enable TOTP for users**: operators must provision the
encryption key:

```sh
openssl rand -base64 32 | wrangler secret put TOTP_ENCRYPTION_KEY
# Then in wrangler.toml under [vars]:
TOTP_ENCRYPTION_KEY_ID = "k-2026-04"
```

Without these env vars, `GET /me/security/totp/enroll` responds
with 503 ("TOTP is not configured by the operator") and the
TOTP gate doesn't fire on Magic Link logins (because no users
have confirmed authenticators).

**Existing user sessions are unaffected.** A user who logs in
via Magic Link before they've enrolled TOTP sees no behavior
change. Once they enroll (via `/me/security/totp/enroll`), their
NEXT Magic Link login fires the gate and prompts for a code.
WebAuthn (Passkey) logins are never gated.

### Smoke test

```sh
cargo test --workspace                      # 563 passing
cargo test -p cesauth-worker --lib post_auth # 15 passing
                                            # (3 prior + 12 new)

# End-to-end (requires deployed worker with TOTP_ENCRYPTION_KEY):
# 1. Login via Magic Link.
# 2. Navigate to /me/security/totp/enroll.
# 3. Scan the QR code in Google Authenticator (or any TOTP app).
# 4. Type the displayed code; should land on the recovery-codes
#    page.
# 5. Save recovery codes.
# 6. Logout.
# 7. Login again via Magic Link.
# 8. Should redirect to /me/security/totp/verify, prompt for
#    code.
# 9. Type current code; should land on the original landing
#    page (or the redirected /authorize chain if you logged in
#    from an OAuth client).
```

### Discovered

No new findings this release.

### Deferred (v0.30.0 — final TOTP release)

- **Disable flow** (`POST /me/security/totp/disable`) —
  user-initiated TOTP removal. Authenticated user clicks
  "Disable TOTP" on `/me/security` (page itself v0.32.0+);
  handler takes confirmation, calls
  `delete_all_for_user(user_id)` on both TOTP repos.
- **Cron sweep extension** — extend the existing 04:00 UTC
  daily cron (ADR-004's anonymous-trial sweep) to also call
  `list_unconfirmed_older_than(now - 86400)` and bulk-delete
  the rows. The partial index from migration 0007 makes this
  cheap.
- **Redaction profile** — `cesauth-migrate` prod→staging
  redaction drops both `totp_authenticators` and
  `totp_recovery_codes` tables entirely. TOTP secrets must
  not survive redaction.
- **Operator chapter** — new `docs/src/deployment/totp.md`
  documenting encryption key provisioning, rotation procedure
  (mint new key with new id, deploy with new id, new writes
  use new key, old reads still find old key by `secret_key_id`),
  admin reset path (delete user's TOTP rows for lockout
  recovery).
- **Pre-production release gate** — `docs/src/expert/security.md`
  adds `TOTP_ENCRYPTION_KEY` to the checklist of secrets that
  must be set before going to production.
- **ADR-009 graduates** `Draft` → `Accepted`.
- **Explicit handler integration tests** — v0.29.0's handlers
  are exercised end-to-end in development but lack dedicated
  unit tests (the existing webauthn / magic-link route patterns
  also rely primarily on integration testing). v0.30.0 will
  add per-handler tests for the higher-risk paths
  (CSRF mismatch, ownership check, max-attempts bouncing,
  recovery wrong-code closing).

### Deferred — unchanged

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued
  in ROADMAP "Later" behind the security track (ends at
  v0.30.0).
- **Audit log hash chain (ADR-010)** — v0.31.0/v0.32.0.
- **`oidc_clients.client_secret_hash` schema-comment
  drift** — ROADMAP "Later" item.

---

## [0.28.0] - 2026-04-29

Security track Phase 5 of 11: TOTP Phase 2b — presentation
layer.

The original v0.28.0 plan combined presentation (templates +
QR generator) with HTTP routes and the `complete_auth`
verify-gate insertion. Mid-implementation it became clear the
presentation layer alone was substantial enough to deserve its
own review-able release, and that v0.29.0 would benefit from
having the templates already validated when the route handlers
are written. The TOTP track is now a **five-release split**:
library (v0.26.0), storage (v0.27.0), presentation (v0.28.0),
routes (v0.29.0), polish (v0.30.0 — ADR Accepted).

The repeated splitting reflects a project value documented in
v0.23.0/v0.24.0/v0.27.0: ship review-able slices over giant
change-sets. Each release leaves the system in a coherent
state. v0.27.0 → v0.28.0 is code-only with no new HTTP
surface; v0.28.0 → v0.29.0 will be route-additive only; etc.

Operators deploying v0.28.0 see:
- New compiled-in modules (templates, QR generator, /me/auth
  helper) that aren't reached from any HTTP route yet.
- New workspace dep `qrcode = 0.14`.
- **No user-visible behavior change.**

### Added — `cesauth_ui::templates::totp_*`

Three new public template functions:

- **`totp_enroll_page(qr_svg, secret_b32, csrf_token)`** —
  renders the enrollment page: inline SVG QR code, manual-
  entry secret in a `<details>` collapsed section, code-
  confirmation form POSTing to
  `/me/security/totp/enroll/confirm`. CSRF token rendered as
  hidden input. The QR SVG is intentionally NOT escaped (it's
  server-issued markup the page must render); everything else
  goes through `escape()` defense-in-depth.
- **`totp_recovery_codes_page(codes)`** — shows the plaintext
  recovery codes once with a strong "save now" warning. No
  CSRF needed (read-only display). The "I've saved them"
  link is a plain `<a href="/">` rather than a form because
  there's no server-side action to take — recovery codes
  were already stored hashed during the prior confirm step;
  this page exists purely so the user has one chance to read
  the plaintext.
- **`totp_verify_page(csrf_token, error)`** — the post-Magic-
  Link gate prompt. Two forms: the primary 6-digit code
  entry, and (inside `<details>` to discourage habituation) a
  recovery-code form posting to `/me/security/totp/recover`.
  `error: Option<&str>` controls inline error rendering for
  invalid-code retries; `None` is the initial render.

**18 new template tests** in `cesauth_ui::templates::tests`
covering CSRF inclusion (verified twice on the verify page —
once per form), escape behavior on every variable input,
form action correctness, error-block conditional rendering,
`<details>` placement of the recovery alternative form (UX-
habituation defense pinned by `recover_idx > details_idx`
ordering check), no-email-leak from the verify page (no `@`
character should appear).

### Added — `cesauth_core::totp::qr`

New module with `otpauth_to_svg(uri) -> Result<String,
String>` wrapping the `qrcode` 0.14 crate's SVG renderer.
Cesauth-specific defaults: `EcLevel::M` (15% recovery —
pragmatic balance between size and robustness), 240 px
minimum dimension (fits beside the manual-entry secret in
the enrollment-page layout), deterministic black-on-white.

The output is fully deterministic for a given input — pinned
by a test that encodes the same URI twice and asserts byte-
equality. This makes the SVG reproducible for tests and
cacheable in any layer that wants to.

**7 new QR tests**: starts/ends with valid SVG markup,
includes the dark color (`#000000`) we asked for, is
deterministic, changes when the URI changes (sanity check
that the input reaches the encoder), handles realistically-
long URIs without panicking, dimension constant is
page-embeddable.

### Added — `cesauth_worker::routes::me`

New parent module + `me::auth` helper. The cookie → session
→ redirect-or-state pipeline for `/me/*` routes is centralized
in `me::auth::resolve_or_redirect`, returning
`Result<Result<SessionState, Response>>` mirroring the shape
of `crate::admin::auth::resolve_or_respond`. The `Result`
nesting lets handlers distinguish "user not signed in, here's
the response to send" from "infrastructure failed". The
`redirect_to_login()` 302 helper is the standard
unauthenticated outcome.

The module is intentionally minimal in v0.28.0 — only the
`auth` helper. The `me::totp` submodule (with `enroll`,
`recover`, `verify` handlers) lands in v0.29.0.

### Added — workspace dependencies

- `qrcode = { version = "0.14", default-features = false,
  features = ["svg"] }` — pure-Rust QR code generation. The
  `default-features = false` drops the image-rendering
  features we don't use; `svg` is the string-emit path.

### Tests

Total: **551 passing** (+25 over v0.27.0):

- core: **272** (was 265) — 7 new in `totp::qr::tests`.
- adapter-test: 70 (unchanged).
- ui: **145** (was 127) — 18 new in `templates::tests`:
  - 6 enroll-page tests (CSRF, QR-SVG-unescaped, secret
    escape, CSRF escape, form action, 6-digit pattern).
  - 3 recovery-codes-page tests (each code rendered as
    `<code>`, irreversibility warning present, codes
    escaped).
  - 9 verify-page tests (CSRF in both forms, no/some error
    rendering, recovery alternative present and inside
    `<details>`, escape behavior, 6-digit pattern, no
    email leak).
- worker: 35 (unchanged — the new `me::auth` module is
  shape-only; integration tests for it land in v0.29.0
  alongside the route handlers that exercise it).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/adr/009-totp.md` — Phasing section
  rewritten to reflect the five-release split. Acceptance
  criteria moved to v0.30.0. ADR remains in `Draft`.

### Migration (0.27.0 → 0.28.0)

Code-only release. **No schema migration.** No
`wrangler.toml` changes.

The `qrcode` 0.14 dep is added to the workspace and used
only by `cesauth_core::totp::qr`. The compiled WASM grows
slightly; otherwise no operational impact.

The `cesauth_worker::routes::me` parent module is now
compiled but no `/me/*` URL is wired in `lib::main` yet.
Routes land in v0.29.0.

**No route surface changes**, **no UI changes**, **no
discovery doc changes**. Pure presentation-layer
infrastructure.

### Smoke test

```sh
cargo test --workspace                      # 551 passing
cargo test -p cesauth-ui --lib templates    # 27 passing (the
# 9 prior templates::tests + 18 new totp template tests).
cargo test -p cesauth-core --lib totp::qr   # 7 passing.
```

### Discovered

No new findings this release. The v0.26.0-discovered
`oidc_clients.client_secret_hash` schema-comment drift
remains tracked in ROADMAP "Later".

### Deferred (v0.29.0 + v0.30.0)

**v0.29.0 (TOTP Phase 2c — routes + verify gate)**:
- HTTP routes at `/me/security/totp/{enroll, enroll/confirm,
  verify, recover}`.
- Verify gate insertion in `post_auth::complete_auth`:
  peek-not-take the PendingAuthorize, gate on
  `find_active_for_user`, park `PendingTotp` carrying the
  original handle, set `__Host-cesauth_totp` cookie,
  redirect to `/me/security/totp/verify`.
- Routing wired in `worker::lib::main`.
- Recovery code redemption flow.

**v0.30.0 (TOTP Phase 2d — polish)**:
- Disable flow (`POST /me/security/totp/disable`).
- Cron sweep extension (drops unconfirmed rows older than
  24h).
- `cesauth-migrate` redaction profile drops both TOTP
  tables for prod→staging.
- New chapter `docs/src/deployment/totp.md`.
- `TOTP_ENCRYPTION_KEY` added to pre-production release
  gate.
- ADR-009 graduates `Draft` → `Accepted`.

### Deferred — unchanged

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued
  in ROADMAP "Later" behind the security track (which now
  ends at v0.30.0 — track expanded to 11 phases).
- **Audit log hash chain (ADR-010)** — v0.31.0/v0.32.0.
- **`oidc_clients.client_secret_hash` schema-comment
  drift** — ROADMAP "Later" item.

---

## [0.27.0] - 2026-04-29

Security track Phase 4 of 8: TOTP Phase 2a — storage layer.

This release ships the **storage layer** for TOTP: port traits,
in-memory adapters, Cloudflare D1 adapters, and the encryption-
key parser. **No HTTP routes**. **No verify gate**. **No
enrollment UI**. The original v0.27.0 plan covered both storage
and wire-up in one release; mid-implementation the storage
layer alone proved substantial enough to deserve its own
review-able release. v0.28.0 picks up the HTTP routes.

The phasing change is documented in ADR-009's "Phasing" section
(now reflects three releases: v0.26.0 library, v0.27.0 storage,
v0.28.0 routes). The ADR remains in `Draft` status — it will
graduate to `Accepted` when v0.28.0 ships and the design has
been validated end-to-end.

Operators deploying v0.27.0 today see:
- Schema in place (migration 0007 applied at v0.26.0 if not
  earlier).
- Storage adapters compiled into the worker but unreachable
  via HTTP (no routes wired).
- `TOTP_ENCRYPTION_KEY` env var optional (worker boots without
  it; reading routines return `None`).
- **No user-visible behavior change.**

### Added — `cesauth_core::totp::storage` module

Two new traits and two new value types:

- **`TotpAuthenticator`** struct — one row of
  `totp_authenticators`. Stores ciphertext + nonce +
  `secret_key_id` for rotation support; `last_used_step` for
  replay-protection state; `confirmed_at` as the enrollment-
  completion marker.
- **`TotpRecoveryCodeRow`** struct — one row of
  `totp_recovery_codes`. Stores `code_hash` + nullable
  `redeemed_at`.
- **`TotpAuthenticatorRepository`** trait — 7 methods:
  `create`, `find_by_id`, `find_active_for_user`, `confirm`
  (idempotent: rejects double-confirm with `NotFound`),
  `update_last_used_step`, `delete`, and the cron-sweep
  helper `list_unconfirmed_older_than`.
- **`TotpRecoveryCodeRepository`** trait — 5 methods:
  `bulk_create` (atomic: rolls back if any row conflicts),
  `find_unredeemed_by_hash`, `mark_redeemed` (idempotent),
  `count_remaining`, `delete_all_for_user`.

### Added — `Challenge::PendingTotp` variant

New variant on `cesauth_core::ports::store::Challenge` for the
intermediate state between successful Magic Link primary auth
and a fully-issued session, when the user has TOTP configured.
Carries `user_id`, `auth_method`, `pending_ar_handle:
Option<String>`, `attempts`, `expires_at`. Used by v0.28.0's
post-MagicLink TOTP gate.

`Challenge::expires_at()` match updated to handle the new
variant.

### Added — in-memory adapters in `cesauth-adapter-test`

`InMemoryTotpAuthenticatorRepository` and
`InMemoryTotpRecoveryCodeRepository`, each backed by a
`Mutex<HashMap>`. The `find_active_for_user` semantic ("most
recently confirmed") is pinned by a dedicated test against
the multi-authenticator case (user with phone + tablet —
returns whichever has the larger `confirmed_at`). The
`bulk_create` atomicity property is pinned by a test where
the middle row of a 3-row batch conflicts and the surrounding
two MUST NOT land.

### Added — D1 adapters in `cesauth-adapter-cloudflare`

`CloudflareTotpAuthenticatorRepository` and
`CloudflareTotpRecoveryCodeRepository`. Mirror the in-memory
shape. Highlights:

- **BLOB columns** (`secret_ciphertext`, `secret_nonce`) bind
  as `Uint8Array` on the JS side, the same pattern as
  `authenticators.public_key`.
- **`confirm` UPDATE** uses `WHERE id = ?1 AND confirmed_at
  IS NULL` to atomically reject double-confirmation — the
  rowcount check turns "0 rows changed" into `NotFound`.
- **`mark_redeemed` UPDATE** uses the same pattern with
  `redeemed_at IS NULL` so concurrent redemption races
  resolve cleanly.
- **`bulk_create` for recovery codes** uses D1's `batch()`
  API which gives all-or-nothing transactional semantics
  matching the in-memory adapter's two-pass validation.
- **`list_unconfirmed_older_than`** uses the partial index
  `idx_totp_authenticators_unconfirmed` (created in migration
  0007) so the cron-sweep query is cheap.

### Added — `TOTP_ENCRYPTION_KEY` parsing in `cesauth_worker::config`

Two new public functions:

- `load_totp_encryption_key(env)` reads the
  `TOTP_ENCRYPTION_KEY` wrangler secret, base64-decodes it,
  validates 32-byte length, returns `Ok(None)` (not an
  error) when unset so deployments without TOTP still respond
  on non-TOTP routes.
- `load_totp_encryption_key_id(env)` reads
  `TOTP_ENCRYPTION_KEY_ID` env var (the human-readable id
  recorded in `secret_key_id`).

The parsing logic is factored into a private
`parse_totp_encryption_key(raw)` helper so the rules
(whitespace stripping, base64 decoding, length validation)
are unit-testable without a Worker `Env`.

### Tests

Total: **526 passing** (+24 over v0.26.0):

- core: 265 (unchanged).
- adapter-test: **70** (was 51) — 19 new in `repo::tests::totp`:
  - 11 `TotpAuthenticatorRepository` tests covering create,
    find_by_id, conflict on duplicate id, find_active filters
    to confirmed-only, find_active picks most recently
    confirmed across multiple authenticators, find_active
    does not cross user boundary, confirm flips state and
    advances step, confirm rejects already-confirmed,
    confirm rejects missing, update_last_used_step, delete,
    list_unconfirmed_older_than filters correctly.
  - 8 `TotpRecoveryCodeRepository` tests covering
    bulk_create, atomic rollback on partial conflict,
    find_unredeemed skips already-redeemed,
    find_unredeemed does not cross users, mark_redeemed
    flips timestamp, mark_redeemed rejects already-redeemed,
    count_remaining excludes redeemed, delete_all_for_user
    is user-scoped.
- ui: 127 (unchanged).
- worker: **35** (was 30) — 5 new in `config::tests`:
  - 5 `parse_totp_encryption_key` tests covering well-formed
    accept, whitespace stripping (trailing newline, internal
    whitespace), invalid-base64 reject, wrong-length reject
    (with operator-facing error message check), empty
    reject.
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/adr/009-totp.md` — Phasing section
  rewritten to reflect the three-release split (v0.26.0
  library, v0.27.0 storage, v0.28.0 routes). Acceptance
  criteria moved to v0.28.0. ADR remains in `Draft`.

### Migration (0.26.0 → 0.27.0)

Code-only release. **No schema migration.** No
`wrangler.toml` changes. The `TOTP_ENCRYPTION_KEY` and
`TOTP_ENCRYPTION_KEY_ID` env vars documented in ADR-009
remain optional — they only become required when v0.28.0's
enrollment routes land and a user actually attempts to
enroll TOTP.

**No route surface changes**, **no UI changes**, **no
discovery doc changes**. Pure infrastructure.

### Smoke test

```sh
cargo test --workspace                   # 526 passing
# Verify the worker still boots without TOTP_ENCRYPTION_KEY
# (it does — the loaders return Ok(None)).
# Verify the new in-memory adapter test cases:
cargo test -p cesauth-adapter-test --lib repo::tests::totp
# 19 passing.
```

### Deferred (v0.28.0)

- TOTP enrollment routes at `/me/security/totp/{enroll,
  enroll/confirm, disable}`.
- Verify gate insertion in `post_auth::complete_auth` —
  before session start, if `auth_method == MagicLink` and
  `find_active_for_user(user_id)` returns Some, park
  `PendingTotp` and redirect to prompt instead of issuing
  session cookie.
- Recovery code redemption flow at
  `/me/security/totp/recover`.
- Server-side QR code SVG generation (no JS).
- `__Host-cesauth_totp` short-lived cookie scoped to the
  prompt page.
- Cron sweep extension (extends ADR-004's 04:00 UTC daily
  cron to drop unconfirmed rows older than 24h).
- `cesauth-migrate` redaction profile drops both new
  tables for prod→staging.
- New chapter `docs/src/deployment/totp.md` documenting
  encryption key provisioning, rotation, and admin reset
  path.
- Pre-production release gate update in
  `docs/src/expert/security.md` (`TOTP_ENCRYPTION_KEY`
  added to the checklist).
- ADR-009 graduates from `Draft` to `Accepted`.

### Deferred — unchanged

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued
  in ROADMAP "Later" behind the security track.
- **Audit log hash chain (ADR-010)** — v0.29.0/v0.30.0
  (renumbered downstream after the v0.27.0/v0.28.0 split).
- **`oidc_clients.client_secret_hash` schema-comment
  drift** — ROADMAP "Later" item.

---

## [0.26.0] - 2026-04-29

Security track Phase 3 of 8: TOTP (RFC 6238) Phase 1 of 2 —
ADR + schema + library skeleton.

This release lays the foundation for TOTP as a second factor.
The `cesauth_core::totp` library is fully implemented with
RFC 6238 vectors verified, AES-GCM encryption at rest, and
SHA-256-hashed recovery codes. **No HTTP routes**, **no
enrollment UI**, **no verify wire-up** — those are Phase 2
(v0.27.0). Operators can deploy this release safely with no
visible behavior change; the new tables are empty until
v0.27.0's enrollment flow lands.

The phasing matches the v0.19.0/v0.20.0 (data migration) and
v0.23.0/v0.24.0 (security headers + CSRF audit) patterns: ship
the design and library separately from the wire-up. Each phase
is independently testable and reviewable.

### Added — ADR-009 (Draft)

`docs/src/expert/adr/009-totp.md`. Settles 11 design questions:

- **Q1 algorithm**: SHA-1 only, 6 digits, 30s step, 160-bit
  secret. All four locked because Google Authenticator
  silently falls back to SHA-1 on SHA-256 secrets, producing
  wrong codes — universal authenticator-app compatibility
  wins.
- **Q2 skew tolerance**: ±1 step (3 windows total). Wider
  windows make brute-force easier without UX gain.
- **Q3 replay protection**: per-secret `last_used_step`;
  reject ≤ last used.
- **Q4 storage**: separate `totp_authenticators` table, not
  WebAuthn's `authenticators`. The two share zero columns.
- **Q5 encryption at rest**: AES-GCM-256 with deployment key,
  AAD bound to row id (`"totp:" + id`), key rotation via
  `secret_key_id` column. Foils D1-backup-swap attacks.
- **Q6 recovery codes**: 10 per user, 50 bits each, formatted
  `XXXXX-XXXXX`, **SHA-256-hashed** (not Argon2 — matches
  cesauth's existing pattern for high-entropy bearer secrets;
  Argon2 would be the right choice for user-chosen passwords
  but recovery codes are CSPRNG-generated).
- **Q7 composition**: TOTP is always a 2nd factor. Magic Link
  → TOTP if configured. WebAuthn alone → no TOTP. Anonymous
  → no TOTP (no email yet).
- **Q8 enrollment**: server-side QR code + manual base32
  entry. First successful verify confirms (`confirmed_at = now`),
  mints recovery codes once per user.
- **Q9 pruning**: extend the existing 04:00 UTC daily cron
  (ADR-004's anonymous-trial sweep) to also drop
  `confirmed_at IS NULL` rows older than 24h.
- **Q10 out of scope**: per-tenant TOTP policy, admin TOTP,
  backup-code import, WebAuthn-backed TOTP, name-editing
  post-confirmation. All explicitly deferred.
- **Q11 migration**: SCHEMA_VERSION 6 → 7. Two new tables
  (both empty on first deploy). The prod→staging redaction
  profile drops both tables entirely (TOTP secrets must not
  survive redaction even hashed).

### Added — schema migration 0007

`migrations/0007_totp.sql`. Two tables:

```sql
CREATE TABLE totp_authenticators (
    id                       TEXT    PRIMARY KEY,
    user_id                  TEXT    NOT NULL,
    secret_ciphertext        BLOB    NOT NULL,
    secret_nonce             BLOB    NOT NULL,
    secret_key_id            TEXT    NOT NULL,
    last_used_step           INTEGER NOT NULL DEFAULT 0,
    name                     TEXT,
    created_at               INTEGER NOT NULL,
    last_used_at             INTEGER,
    confirmed_at             INTEGER
);

CREATE TABLE totp_recovery_codes (
    id                TEXT    PRIMARY KEY,
    user_id           TEXT    NOT NULL,
    code_hash         TEXT    NOT NULL,
    redeemed_at       INTEGER,
    created_at        INTEGER NOT NULL
);
```

Plus indexes: `idx_totp_authenticators_user`,
`idx_totp_recovery_codes_user`, partial
`idx_totp_authenticators_unconfirmed` for the v0.27.0 cron
sweep.

`SCHEMA_VERSION` bumped 6 → 7. The
`schema_version_matches_migration_count` test pins the
invariant.

### Added — `cesauth_core::totp` library

Pure-function library implementing RFC 6238. ~700 lines of
production code + 51 tests covering RFC 6238 test vectors,
replay protection edge cases, encryption round-trip with AAD
binding, base32 codec robustness, recovery code format and
canonicalization, and `otpauth://` URI shape.

Public API:

- **Constants**: `DIGITS=6`, `STEP_SECONDS=30`,
  `SECRET_BYTES=20`, `SKEW_STEPS=1`,
  `RECOVERY_CODES_PER_USER=10`, `ENCRYPTION_KEY_LEN=32`,
  `ENCRYPTION_NONCE_LEN=12`.
- **`Secret`**: newtype wrapping `Vec<u8>`. Debug redacts
  the value. `generate()`, `from_bytes`, `to_base32`,
  `from_base32` (whitespace/lowercase/padding-tolerant).
- **`step_for_unix(i64) -> u64`**: Unix-time → TOTP step.
  Saturates negative timestamps to 0.
- **`compute_code(secret, step) -> u32`**: HMAC-SHA1 + RFC
  4226 §5.3 truncation. Pure.
- **`format_code(u32) -> String`** /
  **`parse_code(&str) -> Result<u32>`**: zero-pad / parse.
- **`verify_with_replay_protection(secret, code, last_used_step,
  now) -> Result<u64>`**: returns the new last_used_step on
  success. Iterates -SKEW..=+SKEW, rejects steps ≤
  last_used_step (replay gate), constant-time-compares
  candidate to submitted code.
- **`otpauth_uri(issuer, account, secret) -> String`**:
  Google Authenticator key-uri format. Percent-encodes
  issuer and account.
- **`RecoveryCode`**: newtype with redacting Debug, value-
  rendering Display. `generate_recovery_codes() ->
  Vec<RecoveryCode>` mints 10 codes.
  `hash_recovery_code(&str) -> String` SHA-256 hashes the
  canonical form (uppercase, no whitespace, no dashes) for
  storage.
- **`encrypt_secret(secret, key, aad) -> (ciphertext, nonce)`**
  / **`decrypt_secret(ciphertext, nonce, key, aad) -> Result<Secret>`**:
  AES-GCM-256 with caller-supplied AAD.
  **`aad_for_id(id) -> Vec<u8>`** centralizes the AAD format
  (`"totp:" + id`) so callers can't drift.

### Added — workspace dependencies

- `sha1 = "0.10"` — SHA-1 for HMAC-SHA1 in TOTP. Locked
  algorithm per ADR-009 §Q1.
- `aes-gcm = "0.10"` — AES-GCM-256 AEAD. RustCrypto pattern.
- `data-encoding = "2"` — base32 NOPAD codec. More
  maintained than the `base32` crate.

`hmac = "0.12"` is now a workspace dep (was in
`crates/core/Cargo.toml` directly); the comment now mentions
TOTP usage alongside session cookies.

### Tests

Total: **502 passing** (+51 over v0.25.0):

- core: **265** (was 214) — 51 new in `totp::tests`:
  - **5 RFC 6238 test vectors** (t=59, 1111111109,
    1111111111, 1234567890, 2000000000) — pin HMAC-SHA1
    correctness against the reference.
  - **4 step_for_unix tests** — epoch behavior, negative
    saturation, 30s boundaries.
  - **8 secret round-trip tests** — generate / base32 /
    bytes round-trip, debug redaction, codec robustness.
  - **6 format/parse code tests** — leading-zero behavior,
    non-digit rejection, length bounds.
  - **8 verify_with_replay_protection tests** — current /
    previous / next step accept, outside-skew reject,
    replay-after-success reject, latest-match recording,
    random-code reject, already-used-step reject.
  - **4 otpauth_uri tests** — required params, account/
    issuer URL-encoding, NOPAD secret.
  - **8 recovery code tests** — count, uniqueness within
    batch, format, debug redaction, display rendering,
    hash determinism, hash canonicalization, hash
    distinctness, hex output.
  - **8 encryption tests** — round-trip, nonce randomness,
    AAD mismatch reject, key mismatch reject, ciphertext
    tampering reject, short-key reject, short-nonce reject,
    AAD format determinism.
- adapter-test: 51 (unchanged).
- ui: 127 (unchanged).
- worker: 30 (unchanged).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/adr/009-totp.md` — new ADR Draft.
- `docs/src/expert/adr/README.md` — ADR-009 added to index.
- `migrations/0007_totp.sql` — comprehensive comments on
  schema design, AAD-binding rationale, and v0.27.0
  follow-up work (cron extension, redaction profile).

### Migration (0.25.0 → 0.26.0)

Schema migration **required**:
```sh
wrangler d1 execute cesauth --remote --file migrations/0007_totp.sql
```

`SCHEMA_VERSION` bumps 6 → 7. Both new tables are empty on
first deploy. No backfill. No data migration.

**No `wrangler.toml` changes** in v0.26.0. The
`TOTP_ENCRYPTION_KEY` and `TOTP_ENCRYPTION_KEY_ID` env vars
are documented in ADR-009 but only become required when
v0.27.0's enrollment routes land. Operators can deploy
v0.26.0 today without provisioning these; the empty TOTP
tables don't exercise the encryption code path.

**No route surface changes**, **no UI changes**, **no
discovery doc changes**. Pure foundation work.

### Smoke test

```sh
cargo test --workspace                   # 502 passing
sqlite3 -readonly /tmp/d1.db ".schema totp_authenticators"
sqlite3 -readonly /tmp/d1.db ".schema totp_recovery_codes"
# Both schemas printed.

# Library exercise (in cesauth-core's test binary):
cargo test -p cesauth-core --lib totp::tests::rfc6238_vector_t_59
# RFC 6238 reference vector verified.
```

### Deferred (v0.27.0)

- TOTP enrollment routes at `/me/security/totp/enroll`.
- TOTP verify gate after Magic Link primary auth.
- Recovery code redemption flow.
- Cron sweep extension (drop `confirmed_at IS NULL` rows
  older than 24h).
- Redaction profile drops `totp_authenticators` and
  `totp_recovery_codes` for prod→staging.
- New deployment chapter
  `docs/src/deployment/totp.md` documenting
  `TOTP_ENCRYPTION_KEY` provisioning and rotation.
- ADR-009 graduates from `Draft` to `Accepted`.

### Discovered during this release

- **`oidc_clients.client_secret_hash` documentation drift**.
  The schema comment says "argon2id(secret) or NULL" but no
  Argon2 implementation exists in cesauth as of v0.26.0.
  Filed as a "Later" ROADMAP item with two resolution paths
  (implement Argon2id, or relax the comment to match the
  actual SHA-256 pattern used elsewhere).

### Deferred — unchanged

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued
  in ROADMAP "Later" behind the security track.
- **Audit log hash chain (ADR-010)** — v0.28.0/v0.29.0.
- **`check_permission` integration on `/api/v1/...`.**
  Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.25.0] - 2026-04-28

Security track Phase 2 of 8: email verification flow audit +
OIDC discovery doc honest reset + `magic_link_sent_page()` UX
bug fix (folded in from the v0.24.0 audit's findings).

This release combines a small surgical fix on the magic-link
verify path with a deliberate **breaking change** on the
`/.well-known/openid-configuration` wire shape. Pre-1.0,
breaking changes are acceptable; the audit found that cesauth
was advertising OIDC compliance it didn't actually deliver, and
the honest move was to align the discovery doc with the
implementation rather than the other way around. ID token
issuance is now an explicit `Later` ROADMAP item with a drafted
ADR-008 ready to implement when scheduling permits.

### Added — `docs/src/expert/email-verification-audit.md`

New v0.25.0 audit deliverable. Documents:

- What `email_verified=true` means in cesauth (proof of
  inbox control via Magic Link OTP delivery, at some point in
  the past — not currently re-verified).
- Per-path table with 9 rows covering Magic Link signup,
  returning-user verify, anonymous→human promotion, anonymous
  user creation, WebAuthn register/authenticate, legacy admin
  create, and tenancy console mutations.
- Where `email_verified` should surface to consumers (planned
  v0.26.0+ via OIDC `id_token` claims; today only via internal
  admin-API JSON and HTML console).
- The OIDC `id_token` gap that motivates ADR-008.
- Operator-visible behavior changes from v0.24.0 → v0.25.0.
- Re-audit cadence.

### Added — ADR-008 (Draft)

`docs/src/expert/adr/008-id-token-issuance.md`. Settles 8
design questions for the `id_token` implementation that
v0.25.0's discovery reset is honest about NOT having: when
issued (`openid` scope only), claims (required + scope-driven),
sourcing (`UserRepository` injection into `service::token`),
`auth_time` plumbing through `Challenge::AuthCode` and
`RefreshTokenFamily`, what's NOT in the id_token (`acr`,
`amr`, `azp`, custom claims), discovery doc restoration plan,
test plan, migration mechanics. Acceptance criteria for
graduation to `Accepted` documented.

### Changed (BREAKING) — discovery doc shape

`/.well-known/openid-configuration` now emits an OAuth 2.0
Authorization Server Metadata document (RFC 8414), not an
OpenID Connect Discovery 1.0 document. Wire-shape diff:

- **Removed**: `subject_types_supported`,
  `id_token_signing_alg_values_supported`.
- **Removed from `scopes_supported`**: `openid`. The remaining
  set is `["profile", "email", "offline_access"]`.

The route path stays at `/.well-known/openid-configuration`
across the v0.25.0 → v0.26.0+ transition. RPs that strictly
validate the discovery doc against OIDC Discovery 1.0 schema
will reject this v0.25.0 doc. **This is intentional** — cesauth
was not actually emitting `id_token`s, so advertising OIDC
compliance was a documentation lie. The fields and `openid`
scope return when v0.26.0+ implements id_token issuance per
ADR-008.

### Changed — `email_verified` flip on returning-user Magic Link verify

`crates/worker/src/routes/magic_link/verify.rs::resolve_or_create_user`
now flips `email_verified=true` on an existing user row when
the column was previously false. Common case: a user created
by an admin via `POST /admin/users` (legacy create), then
later authenticating via Magic Link — pre-v0.25.0 the column
stayed false despite the OTP delivery being proof of email
control.

The flip is a best-effort UPDATE; storage failure isn't
fatal (the user gets a session anyway, and the next login
retries). Skip-write optimization for already-verified rows
avoids hot-path D1 round-trips.

### Changed — `magic_link_sent_page()` template signature

The template at `crates/ui/src/templates.rs::magic_link_sent_page`
now takes two parameters:

```rust
pub fn magic_link_sent_page(handle: &str, csrf_token: &str) -> String
```

Pre-v0.25.0 the template took no arguments and rendered a form
missing both `handle` and `csrf` hidden inputs — making the
form-flow path unusable in browsers (the verify handler
returns 400 on empty handle, and the v0.24.0 CSRF gap fill
rejects empty csrf). The bug was failing-closed but
invisible-to-users; UX was broken, not security.

Both callers in `crates/worker/src/routes/magic_link/request.rs`
are updated:
- Rate-limited path: passes a placeholder UUID handle (a typed
  OTP would yield "verification failed", same as a real
  expired/invalid handle — preserves account-enumeration
  indistinguishability) plus the existing CSRF cookie value.
- Happy path: passes the real handle just minted plus the
  existing CSRF cookie value.

The CSRF cookie is set earlier in the flow (by `/login` or
`/authorize`) so the request handler reads it from the
incoming `Cookie:` header rather than minting a new one.

### Tests

Total: **451 passing** (+14 over v0.24.0):

- core: **214** (was 206) — 8 new in `oidc::discovery::tests`:
  - `discovery_does_not_advertise_openid_scope` —
    honest-reset tripwire; this test's expectation will flip
    when ADR-008 ships.
  - `discovery_advertises_oauth2_scopes_only` —
    pin the exact set `["profile", "email", "offline_access"]`.
  - `discovery_response_types_is_code_only`.
  - `discovery_grant_types_match_implementation`.
  - `discovery_code_challenge_methods_is_s256_only`.
  - `discovery_endpoints_anchor_to_issuer`.
  - `discovery_serializes_without_oidc_fields` — wire-shape
    tripwire; rejects accidental re-introduction without an
    implementation behind the fields.
  - `discovery_token_endpoint_auth_methods_match_implementation`.
- ui: **127** (was 121) — 6 new in `templates::tests`:
  - `sent_page_includes_handle_hidden_input`.
  - `sent_page_includes_csrf_hidden_input`.
  - `sent_page_escapes_handle` — defense-in-depth pin.
  - `sent_page_escapes_csrf_token` — same.
  - `sent_page_form_posts_to_verify_endpoint`.
  - `sent_page_does_not_leak_email` — account-enumeration
    pin (no `@` should appear in the rendered HTML).
- adapter-test: 51 (unchanged).
- worker: 30 (unchanged).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/email-verification-audit.md` — new audit
  chapter.
- `docs/src/expert/adr/008-id-token-issuance.md` — new ADR
  Draft.
- `docs/src/expert/adr/README.md` — ADR-008 added to index.
- `docs/src/expert/oidc-tokens.md` — v0.25.0 status note at
  top; both flow diagrams (exchange_code, rotate_refresh)
  updated to honestly say "no id_token today, v0.26.0+".
- `docs/src/expert/oidc-internals.md` — top-level "OIDC
  Core 1.0" claim softened to "OAuth 2.0 + partial OIDC
  scaffolding"; scopes line updated to drop `openid`.
- `docs/src/beginner/first-local-run.md` — sample discovery
  output updated to v0.25.0 wire shape with explanation note.
- `docs/src/SUMMARY.md` — links the new audit chapter and
  ADR-007/008.

### ROADMAP changes

- Security track Phase 2 (v0.25.0) marked ✅ with detailed entry.
- Discovered UX bug entry (`magic_link_sent_page()`) removed
  (now shipped).
- New "Later" entry: `OIDC id_token issuance (ADR-008)` with
  trigger condition (TOTP track must complete first) and
  scope estimate.
- Mail provider entry updated to specify `wasm-smtp v0.6` +
  `wasm-smtp-cloudflare` as the chosen implementations.
- ADR numbering shifted: TOTP is now ADR-009 (was ADR-008),
  Audit log hash chain is now ADR-010 (was ADR-009). The
  v0.26.0/v0.27.0 (TOTP) and v0.28.0/v0.29.0 (audit log)
  release entries reflect this.

### Migration (0.24.0 → 0.25.0)

Code-only release. No schema migration. No `wrangler.toml`
changes.

**Breaking wire change** on `/.well-known/openid-configuration`
— see "Changed (BREAKING) — discovery doc shape" above.
RPs that:
- Read endpoint URLs from discovery → unaffected (URLs
  unchanged).
- Validate the doc as OIDC Discovery 1.0 → will reject. Switch
  to RFC 8414 validation, or add v0.26.0+ to your supported-
  cesauth-version range.
- Request `scope=openid` → still parses and accepts at
  `/authorize`, still produces no `id_token` at `/token`
  (identical pre-v0.25.0 behavior).

The `email_verified` flip is invisible to RPs today (no
id_token surfaces it). It becomes RP-visible when ADR-008
implementation lands.

### Deferred

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued
  in ROADMAP "Later" behind TOTP track.
- **TOTP** — v0.26.0/v0.27.0.
- **Audit log hash chain** — v0.28.0/v0.29.0.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.24.0] - 2026-04-28

Security track Phase 1 of 8: vulnerability disclosure policy +
CSRF audit + dependency-scan automation review.

This release is **documentation- and audit-heavy**, with one
small code change to close a CSRF gap discovered during the
audit. The pre-existing security infrastructure (cargo-audit
in CI, CSRF library, Origin/Referer check, security headers
middleware) was already comprehensive; this release pins the
contract, fills one gap, and creates the discoverability paths
operators and researchers need.

### Added — `.github/SECURITY.md` improvements

The pre-existing vulnerability-disclosure policy already
covered: reporting channels (GitHub Security Advisory + email),
in-scope/out-of-scope categories (10+ specific items), 90-day
coordinated disclosure, safe-harbor language. v0.24.0 adds:

- **Severity-based response targets table**: per-severity
  acknowledgment / initial assessment / fix targets
  (Critical 24h/72h/7d, High 48h/7d/30d, Medium/Low scaled
  proportionally).
- **Specific known-limitations subsection**: documents
  CSP `'unsafe-inline'`, password-less auth model
  (no per-account lockout), and `/admin/*` Authorization-
  header requirement as explicitly NOT vulnerabilities for
  reporting purposes. Reports going beyond a documented
  limitation (e.g., bypass of `frame-ancestors 'none'` despite
  the `'unsafe-inline'`) remain very much in scope.
- **Cross-links** to `csrf.md`, `csrf-audit.md`,
  `security.md`, ADR-007, and the security-headers
  deployment chapter.

### Added — CSRF audit (`docs/src/expert/csrf-audit.md`)

New v0.24.0 deliverable. Comprehensive per-route audit
covering every state-changing endpoint. Documents:

- The 4 defense mechanisms (CSRF token, Origin/Referer check,
  CORS preflight, `Authorization: Bearer`) and when each
  applies.
- Per-route inventory with the mechanism that defends each.
- Cookies + SameSite audit (all 3 cookies are correct).
- Token-binding analysis (per-cookie binding is correct for
  the threat model; session-binding would offer no additional
  protection).
- The discovered pre-existing UX bug (broken
  `magic_link_sent_page()` form template missing
  `handle`/`csrf` fields — security-fail-closed but
  user-facing-broken; tracked as a separate ROADMAP item).
- Decision tree for adding new routes.
- Test coverage summary.
- Re-audit cadence.

### Updated — `docs/src/expert/csrf.md`

The protection table at the top now lists the **specific
mechanism** per route (CSRF token / Origin check / CORS
preflight / `Authorization: Bearer`) instead of the generic
"protection" column. Operators and reviewers can now answer
"what defends this route?" by reading one line.

### Code change — CSRF token check on `/magic-link/verify`

Added a CSRF token check on the form-encoded path of
`POST /magic-link/verify`. The route was already practically
unforgeable (both `handle` and `code` are server-issued
secrets, and the per-handle rate limit caps brute-force at
~5 attempts per window of a 6-digit code). However, the
documented model in `csrf.md` claimed the route was protected
and the implementation didn't match.

The fix mirrors the existing pattern at
`/magic-link/request`: extract the CSRF cookie before
consuming the body, accept the form's `csrf` field,
constant-time-compare, reject on mismatch with an audit log
event (`csrf_mismatch`).

The JSON path remains exempt — CORS preflight is the
defense for cross-origin `application/json`.

**No template change** in this release. The
`magic_link_sent_page()` template is broken in a separate
way (missing `handle` field as well as `csrf`), which makes
the form path unusable in browsers. That's a UX bug, not a
security one — the handler fails closed on the empty-handle
check. Fixing the template is tracked as a separate ROADMAP
item.

### Confirmed — dependency-scan automation

`.github/workflows/audit.yml` already runs `cargo audit` (via
`rustsec/audit-check@v2.0.0`) on push to main, every pull
request, weekly on Mondays at 06:00 UTC, and on manual
dispatch. The workflow has `issues: write` permission and
opens GitHub issues for new advisories on push events. A
passing main branch means no known CVEs in the dep tree.

v0.24.0 documents this in `docs/src/expert/security.md`
(new "Dependency vulnerability scanning" section) so
operators can find the alert path beyond the workflow YAML.
The handling-a-finding playbook covers the
`update → ignore-with-justification` decision tree and the
CHANGELOG-citation convention for advisory fixes.

No new automation was added — the existing automation was
verified comprehensive.

### Tests

Total: **437 passing** (+6 over v0.23.0):

- core: 206 (unchanged).
- adapter-test: 51 (unchanged).
- ui: 121 (unchanged).
- worker: **30** (was 24) — 6 new in
  `routes::magic_link::*::tests`:
  - 4 `VerifyBody` deserialization tests (csrf-present,
    csrf-missing, form-decode-with-empty-csrf, form-decode-
    with-non-empty-csrf). Pin the contract that an empty
    CSRF token reaches the gate (which then rejects via
    `csrf::verify`'s "empty input fails" branch).
  - 2 `RequestBody` parity tests (csrf-present,
    csrf-missing) for the route that already had CSRF
    protection. Pins the contract for parity.
- migrate: 29 (unchanged).

**Note on prior totals**: earlier MANIFEST entries published
totals that omitted the 24 cesauth-worker unit tests (mostly
the csrf submodule, which pre-dates the MANIFEST tracking).
v0.24.0 surfaces the worker column for the first time.
Previously-published totals (379 for v0.22.0, 407 for
v0.23.0) are correct as historical artifacts but
under-counted by 24. Restated totals: v0.22.0 = 403,
v0.23.0 = 431, v0.24.0 = 437.

### Documentation

- `docs/src/expert/csrf-audit.md` — new chapter, the v0.24.0
  audit deliverable.
- `docs/src/expert/csrf.md` — table tightened to per-mechanism
  precision.
- `docs/src/expert/security.md` — new "Dependency
  vulnerability scanning" section documents the cargo-audit
  workflow's triggers, failure path, finding-handling
  playbook, and re-audit cadence.
- `docs/src/deployment/security-headers.md` — SECURITY.md
  cross-link updated from "planned in a future release" to
  pointing at the actual file.
- `.github/SECURITY.md` — severity table, known-limitations
  subsection, see-also cross-links.
- `docs/src/SUMMARY.md` — links the new csrf-audit chapter.

### Migration (0.23.0 → 0.24.0)

Code-only release. No schema migration. No `wrangler.toml`
changes. The `/magic-link/verify` CSRF check is purely
additive — JSON callers unaffected; HTML form callers were
already broken (missing `handle`) so the new CSRF check
doesn't change observable behavior for the typical user
flow.

Operators can verify the new audit doc renders correctly in
their mdBook deployment:

```sh
cd docs && mdbook build
ls book/expert/csrf-audit.html  # exists
```

### Deferred

- **Fix `magic_link_sent_page()` template** — add `handle`
  and `csrf` hidden inputs, plumb them through from
  `/magic-link/request`, add end-to-end form-flow tests.
  Not a security fix; a UX gap. ROADMAP follow-up.
- **Email verification flow audit** — v0.25.0.
- **TOTP** — v0.26.0/v0.27.0.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.23.0] - 2026-04-28

HTTP security response headers — ADR-007. The pre-existing
`harden_headers` helper (which set 4 headers per response) is
replaced by a unified middleware that:

- adds three previously-missing headers (`Strict-Transport-Security`,
  `Permissions-Policy`, the existing `X-Frame-Options` now gated
  to HTML responses),
- consolidates the policy into a single auditable site
  (`crates/core/src/security_headers.rs` + the worker shim),
- exposes operator override knobs via `wrangler.toml` env vars,
- preserves the per-route CSPs the login page, OIDC authorize
  page, and admin console set themselves (those use `'unsafe-inline'`
  for current template constraints; nonces are a planned future
  release).

This v0.23.0 supersedes a prior v0.23.0 release attempt that
proposed an "account lockout" feature. That attempt was
**withdrawn** before graduating to canonical status — the design
was based on the incorrect premise that cesauth has password
authentication. See "Withdrawal note" below for the full context.

### Withdrawal note — prior v0.23.0 attempt

A v0.23.0 release was prepared that added per-account lockout
columns to `users`, a `cesauth_core::lockout` library, ADR-006,
and migration 0007 (`account_lockout`). The work assumed
cesauth had a password-verify path against which brute-force
attacks would be mitigated by per-account lockout.

**This assumption was wrong.** cesauth has no password
authentication at all — Magic Link and WebAuthn are the only
credential paths, both with their own brute-force resistance
properties (token entropy and signature cryptography
respectively). Per-account lockout's primary threat model is
inapplicable to cesauth's actual surface.

The artifact of the withdrawn attempt is preserved as
`cesauth-0.23.0-account-lockout-withdrawn.tar.gz` in the release
archive for historical reference. The ADR-006 number is
retired (not reused). A future ADR may revisit lockout for the
OIDC `client_secret` brute-force surface (per-client lockout,
distinct data model, machine-to-machine threat model); see
ROADMAP "Later" for the trigger condition.

The `cesauth_core::lockout` module, schema migration 0007,
and ADR-006 are **not in this release**. Source restored from
v0.22.0.

### Added — ADR-007

`docs/src/expert/adr/007-security-response-headers.md`
(Accepted). Settles eight design questions:

- **Q1 — placement**: single middleware. Per-route additions
  create silent gaps.
- **Q2 — header set**: universal set always; HTML-only set
  gated by `Content-Type: text/html`.
- **Q3 — CSP shape**: per-route CSPs preserved (with
  `'unsafe-inline'`); a later release does the nonce migration.
  No `'unsafe-eval'` anywhere.
- **Q4 — STS**: `max-age=63072000; includeSubDomains`;
  `preload` is operator opt-in via env var.
- **Q5 — Permissions-Policy**: disable camera, microphone,
  geolocation, payment, USB, and others.
- **Q6 — per-tenant**: no, single deployment-wide policy.
- **Q7 — operator override**: `SECURITY_HEADERS_CSP` /
  `SECURITY_HEADERS_STS` / `SECURITY_HEADERS_DISABLE_HTML_ONLY`
  env vars.
- **Q8 — testing**: pure-function unit tests + worker
  integration glue.

### Added — `cesauth_core::security_headers`

New module. Pure functions, no Worker dependencies — testable
without a Worker harness.

- `SecurityHeadersConfig` — operator-driven config struct
  with `from_env()` constructor.
- `DEFAULT_CSP` — the strict default applied as fallback for
  HTML routes that don't set their own CSP. Has no
  `'unsafe-inline'` or `'unsafe-eval'` (tripwire test).
- `DEFAULT_STS` — 2 years + includeSubDomains, no preload.
- `DEFAULT_PERMISSIONS_POLICY` — 13 disabled features.
- `DEFAULT_XFO` — `DENY`.
- `Header { name, value }` — single output type.
- `headers_for_response(config, is_html, already_set) ->
  Vec<Header>` — the load-bearing pure function.
  `already_set` is the list of header names the route already
  set; the library skips them, so the existing per-route CSPs
  in cesauth are preserved.
- `is_html_content_type(Option<&str>) -> bool` — content-type
  detection with case-insensitive matching, parameter
  tolerance (`text/html; charset=utf-8`), and tight
  boundary handling (rejects `text/htmlx`).

### Added — worker middleware

`crates/worker/src/lib.rs` — a `mod security_headers` block
inside the worker crate that:

- reads the three operator env vars,
- inspects the outgoing response's `Content-Type` and
  already-set headers,
- delegates to `cesauth_core::security_headers::headers_for_response`,
- writes the result via `worker::Headers::set`.

The pre-existing `harden_headers` function is removed; the new
middleware is the single application site. Per ADR-007 §Q1, no
opt-out path exists by design.

### Removed — old behavior

- `harden_headers` (pre-v0.23.0) set `Cache-Control: no-store`
  on every response. This was clobbering legitimate per-route
  cache control. Removed; routes that need `Cache-Control: no-store`
  set it themselves (auth-bearing endpoints already do).
- `harden_headers` set `Referrer-Policy: no-referrer`
  universally. The new middleware sets
  `Referrer-Policy: strict-origin-when-cross-origin` —
  marginally less strict, more useful for monitoring tools
  that aggregate by origin. Privacy delta is small (no
  cross-origin-HTTP referrer; origin-only on cross-origin-HTTPS).
- `harden_headers` set `X-Frame-Options: DENY` universally.
  The new middleware gates it to HTML responses. JSON
  responses don't need it (browsers ignore X-Frame-Options
  on non-HTML).

### Tests

Total: **407 passing** (+28 over v0.22.0):

- core: **206** (was 178) — 28 new in `security_headers::tests`:
  - 5 default-value tripwire tests (no `unsafe-inline`,
    `default-src 'none'`, frame-ancestors, base-uri, STS
    exact value, permissions-policy spot-checks).
  - 7 `is_html_content_type` tests covering plain,
    parameterized, case-insensitive, JSON-rejection,
    text-plain-rejection, partial-match-rejection,
    None-handling.
  - 4 `from_env` tests (defaults, CSP override, STS
    override, strict `disable_html_only` matching).
  - 7 `headers_for_response` core tests (HTML full set,
    JSON universal-only, disable-html-only suppression,
    config carrythrough, X-Frame-Options DENY, stable
    order, no-unsafe-anywhere tripwire).
  - 5 don't-clobber tests (CSP not re-emitted, case-
    insensitive header-name match, universal headers
    skipped if already-set, unrelated headers don't
    affect output).
- adapter-test: 51 (unchanged).
- ui: 121 (unchanged).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/deployment/security-headers.md` — new operator
  guide. Defaults, opting into HSTS preload, overriding CSP,
  the debugging escape hatch, verifying with `curl`,
  per-route CSP exceptions list.
- `docs/src/SUMMARY.md` — links the new chapter.
- ADR README index updated with ADR-006 (Withdrawn) and
  ADR-007 (Accepted).

### Migration (0.22.0 → 0.23.0)

Code-only release. No schema migration. No `wrangler.toml`
changes required by default — operators who want the env-var
overrides add them as needed.

For deployments that observed the old `harden_headers`
behavior, the visible changes are:

1. Three new headers (`Strict-Transport-Security`,
   `Permissions-Policy`, `Content-Security-Policy` as default
   on HTML routes that don't set their own).
2. `Referrer-Policy` value changed from `no-referrer` to
   `strict-origin-when-cross-origin`.
3. `Cache-Control: no-store` no longer added by default.
4. `X-Frame-Options: DENY` now only on HTML responses, not
   JSON.

Each of these is documented in the new chapter. None should
break a working deployment; the most likely surface is some
external monitoring tool that asserts on the old values.
Verify with `curl -sI` after deploy.

### Deferred

- **CSP without `'unsafe-inline'`.** Templates currently
  embed `<style>` and `<script>` blocks inline; migrating
  to nonces or external resources is a templates refactor.
  Tracked in ROADMAP.
- **OIDC client_secret brute-force lockout.** Per-client
  lockout, distinct from the withdrawn user-account
  lockout. Trigger: production telemetry showing failed
  `client_secret` attempts at non-trivial volume. ROADMAP
  "Later".
- **`SECURITY.md` (vulnerability disclosure policy).**
  Planned for v0.24.0.
- **CSRF audit + dependency scan automation review.**
  Planned for v0.24.0.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

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
   repository metadata now match reality. "Commercial SaaS" /
   "商用 SaaS" framing — including spec references, comments, and
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
    the stub `https://github.com/cesauth/cesauth`).
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
  "Commercial SaaS" / "商用 SaaS" replaced with "tenancy
  service" or equivalent. The earlier framing was ambiguous
  (the project is open-source under Apache-2.0; "commercial"
  doesn't describe the license, the deployment model, or
  anything else precise) and risked giving users and
  contributors the wrong impression about the project's
  intent. Spec references such as
  `cesauth-商用 SaaS 化可能な構成への拡張開発指示書.md` are
  now referenced as `cesauth tenancy-service extension spec`.

### Added

- **`.github/CODE_OF_CONDUCT.md`** — Contributor Covenant 2.1,
  with `nabbisen` as the enforcement contact.
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
added. The SemVer caveat documented at the top of this file
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
- **Marketing-flavored framing** ("commercial SaaS") in a
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

[Unreleased]: https://github.com/cesauth/cesauth/compare/v0.2.1...HEAD
[0.2.1]:      https://github.com/cesauth/cesauth/releases/tag/v0.2.1
