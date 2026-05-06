# Roadmap

cesauth is in active development. This file tracks what ships today,
what is planned, and what is deliberately out of scope.

Format inspired by [Keep a Changelog](https://keepachangelog.com/) and
the [Semantic Versioning](https://semver.org/) naming for priorities.

---

## Versioning policy

cesauth follows SemVer. The major number stays at `0` while the
public surface continues to evolve. Within `0.x.y`:

- **Bump the minor (`0.x → 0.x+1`) when** a release introduces a new
  HTTP route surface, a new schema migration, a new public type or
  trait in `cesauth-core`, a new permission slug, a new operator-visible
  configuration knob (`wrangler.toml` `[triggers]`, new env var),
  or a renamed/removed URL. Anything an integrator or operator could
  observe by reading the release notes and going "I need to do
  something" earns a minor bump.
- **Bump the patch (`0.x.y → 0.x.y+1`) when** the change is
  internal-only: bug fixes that preserve existing behavior, doc
  updates, dependency upgrades that don't shift any visible
  behavior, refactors. Security fixes that preserve wire compatibility
  also count as patch (the v0.15.1 RUSTSEC fix is the canonical
  example — `Cargo.toml` features narrowed, no surface change).

A few historical 0.4.x releases (notably 0.6.0 through 0.11.0 and
0.13.0-0.15.0, 0.16.0-0.17.0) by this rubric should arguably have
been minor bumps rather than patches. We accept that as historical
debt rather than rewriting bundles already shipped — those releases
are immutable artifacts. Going forward (from 0.18.0 onward) the rule
above is the policy.

A future `1.0` will be cut when the public surface settles. There
is no fixed timeline; the bar is "what shipped is what we want"
across the OIDC, tenancy, and operator surfaces.

---

## Shipped

The following subsystems are implemented end-to-end and covered by
host tests. "Initial" here means the happy path and the documented
failure modes are in place; it does not assert any particular
maturity level beyond what each release's CHANGELOG entry says.

| Area                                   | Status   | Where                                             |
|----------------------------------------|----------|---------------------------------------------------|
| Five-crate workspace + ports/adapters  | ✅       | `crates/core`, `crates/adapter-*`, `crates/worker` |
| D1 schema                              | ✅       | `migrations/0001_initial.sql`                      |
| Durable Objects: 4 classes             | ✅       | `crates/adapter-cloudflare/src/objects/*`          |
| OIDC discovery document                | ✅       | `/.well-known/openid-configuration`                |
| JWKS endpoint                          | ✅       | `/jwks.json`                                       |
| `/authorize` with PKCE S256, `prompt`, `max_age` | ✅ | `crates/worker/src/routes/oidc.rs`             |
| `/token` code exchange + refresh rotation | ✅    | Reuse-burns-family rule enforced                   |
| `/revoke` (RFC 7009)                   | ✅       |                                                   |
| WebAuthn EdDSA + ES256, `none` attestation | ✅   | Pure-Rust via `core::webauthn::cose`               |
| Magic Link (dev delivery; see caveat)  | ✅       | `routes::magic_link::*`                            |
| Post-auth code minting                 | ✅       | `post_auth::complete_auth` across all auth paths    |
| Signed session cookies (`__Host-cesauth_session`) | ✅ | HMAC-SHA256 with `SESSION_COOKIE_KEY`        |
| Session revocation (`ActiveSessionStore`) | ✅    | Admin + user-initiated (`/logout`)                 |
| CSRF protection (double-submit cookie) | ✅       | Form POSTs; JSON bypasses                          |
| Operational logger (JSON Lines)        | ✅       | Categorized, level-gated, sensitivity-gated         |
| Turnstile integration (flag-based)     | ✅       | Fires on `RateLimitDecision.escalate`              |
| Admin API (`POST /admin/users`, `DELETE /admin/sessions/:id`) | ✅ | Role-gated (0.3.0), bearer auth             |
| Audit log (R2, NDJSON per event)       | ✅       | Covered by `/__dev/audit` browser + searchable via admin console (0.3.0) |
| **Cost &amp; Data Safety Admin Console** | ✅     | `/admin/console/*` — Overview, Cost, Safety, Audit, Config, Alerts (0.3.0); HTML two-step edit UI for bucket-safety + admin-token CRUD (0.4.0) |
| Dev-only routes (`/__dev/*`)           | ✅       | Gated on `WRANGLER_LOCAL="1"`                      |
| **Tenancy-service data model + authz** | ✅       | Tenants, organizations, groups, memberships, role/permission engine, plans, subscriptions (0.18.0). Cloudflare D1 adapters for every port + `users` table tenant-aware (0.6.0). `/api/v1/...` HTTP routes for tenant / org / group / membership / role-assignment / subscription CRUD with plan-quota enforcement (0.7.0). Read-only HTML console at `/admin/tenancy/*` (0.8.0, originally `/admin/saas/*`). Mutation forms with preview/confirm pattern (0.9.0) for tenant / organization / group / subscription. Membership add/remove + role grant/revoke forms (0.10.0) bring the HTML console to feature parity with the v0.7.0 JSON API. ADR-001/002/003 settle the tenant-scoped admin surface design (0.11.0) and ship the schema + type foundation (`admin_tokens.user_id`, `AdminPrincipal::user_id`, `is_system_admin()`). Project-hygiene release with naming-debt cleanup (0.12.0) — `saas/` → `tenancy_console/`, `/admin/saas/*` → `/admin/tenancy/*`, plus author/license metadata and `.github/` community documents. Buffer/follow-up release with stale-narrative cleanup + dependency audit (0.12.1). Tenant-scoped admin surface read pages shipped at `/admin/t/<slug>/*` with auth gate + `check_permission` integration (0.13.0). High-risk mutation forms plus a system-admin token-mint UI shipped (0.14.0). Additive membership forms (× 3 flavors) plus affordance gating shipped (0.15.0) — the tenant-scoped surface reaches feature parity with the system-admin tenancy console. Security-fix and audit-infrastructure release (0.15.1): RUSTSEC-2023-0071 in transitive `rsa` removed via `jsonwebtoken` feature narrowing, `cargo audit` integrated via initial sweep + GitHub Actions workflow + operator docs. Anonymous-trial promotion design (ADR-004) plus foundation (migration `0006_anonymous.sql`, `AnonymousSession` type + repository, in-memory + D1 adapters, 3 new audit event kinds) shipped (0.16.0). Anonymous-trial HTTP routes (`POST /api/v1/anonymous/begin` and `/promote`) shipped (0.17.0); ADR-004 graduates to `Accepted`. Anonymous-trial daily retention sweep (Cloudflare Workers Cron Trigger, `[triggers]` block in `wrangler.toml`, sweep handler with audit-before-delete ordering, operator runbook diagnostic) shipped (0.18.0); ADR-004 feature-complete. **Note: versioning was retroactively re-aligned with the [versioning policy](#versioning-policy) at 0.18.0; the version numbers shown for 0.5.0 through 0.18.0 in this row are the re-aligned values, not the original tarball numbers — see the [Versioning history note](../CHANGELOG.md#versioning-history-note) section in CHANGELOG for the full mapping.** Deployment guide build-out shipped (0.18.1) — eight new operator-facing chapters (pre-flight, cron, custom domains, multi-environment, backup/restore, observability, day-2 runbook, disaster recovery) covering the operational surface previously held in tribal knowledge. |
| **Data migration tooling**             | ✅       | ADR-005 + foundation shipped (0.19.0): `cesauth_core::migrate` library value types (`Manifest`, `TableSummary`, `PayloadLine`), redaction profile registry with two built-ins, `FORMAT_VERSION` + `SCHEMA_VERSION` constants, CLI skeleton with `list-profiles` implemented. Real export + verify shipped (0.20.0): typed `MigrateError` (8 kinds), `Exporter<W>` with single-use `ExportSigner` (per-export Ed25519 keypair, fingerprint handshake), streaming `verify` with per-table + whole-payload SHA-256 checks, `apply_redaction` with deterministic `HashedEmail` (preserves UNIQUE invariant). CLI's `export` subcommand wires `WranglerD1Source` → `Exporter` (refuses to clobber, prints fingerprint to stderr at start, walks `MIGRATION_TABLE_ORDER` of 18 tables in topological order, prints secrets-coordination checklist at end). CLI's `verify` subcommand has no D1 dependency. Real import shipped (0.21.0): `Violation` + `ViolationReport`, `InvariantCheckFn` + `SeenSnapshot` + four default checks (user→tenant, membership→user, membership→container, role_assignment→role+user), `ImportSink` trait with `WranglerD1Sink` impl (batched-INSERT-per-table commits, full rollback on decline). CLI's `import` subcommand walks five gates (verify → fingerprint handshake → `JWT_SIGNING_KEY` pre-flight → invariant checks → final commit confirmation) — destination D1 untouched until final yes. **ADR-005 graduated to Accepted (0.21.0)**. New deployment chapter `data-migration.md` makes the legacy `sed`-script prod→staging refresh pattern obsolete; new runbook section "Operation: cross-account data migration"; disaster-recovery Scenario 4 (account compromise) rewritten with concrete `cesauth-migrate` invocations. Polish phase shipped (0.22.0): `--tenant <id>` filter on `export` (with manifest scope record + `TenantScope::Global` vs `OwnColumn` per-table classification), `cesauth-migrate refresh-staging` single-command combinator (export + redaction + import in one invocation, opinionated for single-operator runs, `--yes` for unattended use), email-uniqueness-within-tenant invariant check (redaction-aware, case-insensitive), per-row import progress via `ProgressSink` decorator. **Feature-complete for ADR-005's scope as of 0.22.0.** Deferred items (resume support, native Cloudflare HTTP API client, custom invariant registration via CLI) are tracked as post-1.0 polish — they don't change the design and don't have known operator demand. |
| **HTTP security response headers**     | ✅       | ADR-007 (`Accepted`, 0.23.0): unified middleware replaces ad-hoc per-response `harden_headers`. Adds three previously-missing headers (`Strict-Transport-Security`, `Permissions-Policy`, plus `X-Frame-Options` now gated to HTML responses). Pure-function library `cesauth_core::security_headers` produces header lists; worker shim reads operator env (`SECURITY_HEADERS_CSP`/`STS`/`DISABLE_HTML_ONLY`) and applies via `worker::Headers::set`. Library tracks `already_set` so per-route CSPs (login, OIDC authorize, admin console — all use `'unsafe-inline'` for current template constraints) are preserved; "don't clobber" is a library responsibility with case-insensitive header-name matching. 28 new tests cover defaults pinning, content-type detection (rejects `text/htmlx` partial-match), env override parsing (strict `"true"` matching for the disable knob), don't-clobber semantics. New operator chapter `docs/src/deployment/security-headers.md`. **Note (v0.23.0 supersedes a withdrawn release)**: a prior v0.23.0 attempt added per-account lockout based on the incorrect premise that cesauth has password authentication; withdrawn before canonical, artifact preserved as `cesauth-0.23.0-account-lockout-withdrawn.tar.gz`. CSP without `'unsafe-inline'` (nonces or template extraction) tracked as future work in the security track. |
| **Security track Phase 1: SECURITY.md + CSRF audit + dep scan automation review** | ✅       | Shipped 0.24.0. Documentation- and audit-heavy with one small CSRF gap fill. **`.github/SECURITY.md` improvements**: severity-based response-target table (Critical 24h/72h/7d, scaled), known-limitations subsection (CSP `'unsafe-inline'`, no per-account lockout, `/admin/*` Authorization-only), see-also cross-links. **CSRF audit** (`docs/src/expert/csrf-audit.md`) per-route inventory with mechanism per route (4 mechanisms: token, Origin/Referer check, CORS preflight, `Authorization: Bearer`), cookies+SameSite audit, token-binding analysis, decision tree for new routes, test coverage summary, re-audit cadence. **CSRF gap fill on `/magic-link/verify`**: form-encoded path now validates the CSRF token (mirrors `/magic-link/request`); JSON path remains exempt (CORS preflight); `csrf_mismatch` audit event. **Dep scan automation review**: verified `.github/workflows/audit.yml` is comprehensive (push to main + every PR + weekly cron + manual dispatch; `rustsec/audit-check@v2.0.0`; opens GitHub issues automatically); documented the alert path in new "Dependency vulnerability scanning" section in `docs/src/expert/security.md`. **Discovered UX bug**: `magic_link_sent_page()` template missing `handle`/`csrf` hidden inputs — fixed in v0.25.0. 6 new tests pin the CSRF field contract on `VerifyBody` and `RequestBody`. Total 437 passing (worker tests now broken out — see CHANGELOG note on the historical undercount). |
| **Security track Phase 2: email verification audit + OIDC discovery honest reset** | ✅       | Shipped 0.25.0. Audit deliverable (`docs/src/expert/email-verification-audit.md`) per-path table with 9 rows + meaning of `email_verified=true` + the discovered OIDC `id_token` issuance gap. **Concern 2 fix**: returning-user Magic Link verify flips `email_verified=true` when previously false (best-effort UPDATE, skip-write optimization for already-verified rows). **Discovery doc honest reset** (breaking wire change): `id_token_signing_alg_values_supported` and `subject_types_supported` removed from struct + JSON output; `openid` removed from `scopes_supported` (now `["profile", "email", "offline_access"]`); discovery is now RFC 8414 OAuth 2.0 metadata, not OIDC Discovery 1.0 — accurate to what the implementation delivers. **`magic_link_sent_page()` UX bug fix** (folded in from v0.24.0 audit): template takes `handle: &str, csrf_token: &str` parameters, both render as escaped hidden inputs; both callers in `/magic-link/request` updated. **ADR-008 drafted**: `id_token` issuance design queued for "Later" — TOTP track (v0.26.0/v0.27.0) goes first per security-track sequencing. 14 new tests (8 discovery shape, 6 templates). Total 451 passing. |
| **Security track Phase 3: TOTP Phase 1 (ADR + schema + library)** | ✅       | Shipped 0.26.0. Foundation work for TOTP as a 2nd factor (RFC 6238). **ADR-009 Draft** (`docs/src/expert/adr/009-totp.md`) settles 11 design questions: SHA-1/6/30/160 algorithm parameters locked (Q1, universal authenticator-app compatibility); ±1 step skew tolerance (Q2); per-secret `last_used_step` replay protection (Q3); separate `totp_authenticators` table not WebAuthn's (Q4 — they share zero columns); AES-GCM-256 encryption at rest with AAD bound to row id (Q5); 10 SHA-256-hashed recovery codes per user matching cesauth's existing high-entropy bearer pattern (Q6); always-2nd-factor composition (Q7 — Magic Link → TOTP if configured, WebAuthn → no TOTP, Anonymous → no TOTP); QR code + manual base32 enrollment (Q8); cron sweep extension for unconfirmed pruning (Q9, lands in v0.27.0); per-tenant policy / admin TOTP / backup-code import / WebAuthn-backed TOTP / name-editing all out of scope (Q10); SCHEMA_VERSION 6 → 7 with prod→staging redaction dropping both new tables (Q11). **Migration 0007** adds `totp_authenticators` and `totp_recovery_codes` tables with full comments. **`cesauth_core::totp` library** ~700 lines: `Secret` newtype with debug redaction, `compute_code` with HMAC-SHA1 + RFC 4226 §5.3 truncation, `verify_with_replay_protection` with constant-time-eq and replay gate, `RecoveryCode` newtype with redacting Debug, `encrypt_secret`/`decrypt_secret` with AAD binding, `otpauth_uri` builder. Workspace deps added: `sha1`, `aes-gcm`, `data-encoding`. **No HTTP routes, no UI, no verify wire-up** — Phase 2 (v0.27.0). Discovered: `oidc_clients.client_secret_hash` schema comment claims Argon2 but no Argon2 implementation exists; ROADMAP "Later" item tracks resolution. 51 new tests (5 RFC 6238 reference vectors, 8 verify replay/skew, 8 encryption with AAD, 8 recovery codes, etc.). Total **502 passing**. |
| **Security track Phase 4: TOTP Phase 2a — storage layer** | ✅       | Shipped 0.27.0. Storage adapters between v0.26.0's pure-function library and v0.28.0's HTTP routes. The original v0.27.0 plan combined storage and routes; mid-implementation the storage layer alone proved substantial enough to deserve its own review-able release. **`cesauth_core::totp::storage`** submodule with `TotpAuthenticator` and `TotpRecoveryCodeRow` value types and `TotpAuthenticatorRepository` (7 methods: create, find_by_id, find_active_for_user, confirm — idempotent via `WHERE confirmed_at IS NULL`, update_last_used_step, delete, list_unconfirmed_older_than for the cron sweep) and `TotpRecoveryCodeRepository` (5 methods: bulk_create — atomic, find_unredeemed_by_hash, mark_redeemed — idempotent, count_remaining, delete_all_for_user). **`Challenge::PendingTotp`** variant for the post-MagicLink intermediate state. **In-memory adapters** in `cesauth-adapter-test` with 19 tests pinning `find_active`-picks-most-recently-confirmed semantic, atomic `bulk_create` rollback, idempotency, user-scoped delete. **D1 adapters** in `cesauth-adapter-cloudflare` mirroring in-memory shape; BLOB columns bind via `Uint8Array`; recovery code `bulk_create` uses D1's `batch()` for transactional atomicity; unconfirmed-row sweep query uses partial index from migration 0007. **`load_totp_encryption_key()` and `load_totp_encryption_key_id()`** in worker config, with pure helper `parse_totp_encryption_key` factored out for testability + 5 unit tests covering whitespace stripping, base64 errors, length validation. **No HTTP routes, no verify gate, no UI** — Phase 2b (v0.28.0). ADR-009 remains Draft pending end-to-end validation. 24 new tests. Total **526 passing**. |
| **Security track Phase 5: TOTP Phase 2b — presentation layer** | ✅       | Shipped 0.28.0. Templates + QR generator + `/me/*` auth helper between v0.27.0's storage layer and v0.29.0's HTTP routes. The v0.28.0 plan originally combined presentation + routes; mid-implementation the presentation layer alone proved review-able as its own slice. The TOTP track is now a **five-release split**: library (0.26), storage (0.27), presentation (0.28), routes (0.29), polish (0.30 — ADR Accepted). **Three new UI templates**: `totp_enroll_page(qr_svg, secret_b32, csrf)` renders the QR + manual-entry secret + confirmation form; `totp_recovery_codes_page(codes)` shows the plaintext codes once with strong "save now" warning; `totp_verify_page(csrf, error)` is the post-MagicLink prompt with a `<details>`-collapsed recovery alternative form. **18 template tests** pinning CSRF inclusion across both forms, escape behavior on every variable input, error-block conditional rendering, `<details>` placement of the recovery alternative (UX-habituation defense), no-email-leak from the verify page. **`cesauth_core::totp::qr` module** with `otpauth_to_svg(uri) -> Result<String>` using the `qrcode` 0.14 crate at `EcLevel::M` (15% recovery — pragmatic balance), 240 px min-dimension, deterministic black-on-white SVG. **7 QR tests** pinning determinism, color emission, long-URI handling, output structure. **`cesauth_worker::routes::me`** parent module with `me::auth::resolve_or_redirect` centralizing the cookie → `SessionCookie::verify` → `ActiveSessionStore::status` → 302-to-/login pipeline; `redirect_to_login()` 302 helper. **Workspace dep added**: `qrcode = { version = "0.14", default-features = false, features = ["svg"] }`. **No HTTP routes still** — the presentation layer renders in unit tests and the QR generator runs pure-function; the wire-up is v0.29.0. 25 new tests. Total **551 passing**. |
| **Security track Phase 6: TOTP Phase 2c — HTTP routes + verify gate** | ✅       | Shipped 0.29.0. Wires v0.26.0–v0.28.0's library + storage + presentation into operator-visible behavior at last. **Five new routes** in `cesauth_worker::routes::me::totp`: `GET /me/security/totp/enroll` mints a fresh secret with CSPRNG, encrypts via `aad_for_id(row_uuid)`-bound AES-GCM, parks an unconfirmed `totp_authenticators` row, sets `__Host-cesauth_totp_enroll` short-lived (15 min) cookie, builds the otpauth URI via `cesauth_core::totp::otpauth_uri`, generates QR via `cesauth_core::totp::qr::otpauth_to_svg`, renders `totp_enroll_page`. `POST /me/security/totp/enroll/confirm` validates CSRF, looks up the unconfirmed row + verifies user_id ownership, decrypts the secret, verifies the submitted code via `verify_with_replay_protection`, on success calls `confirm()` (idempotent flip + step advance + last_used_at), then iff this is the user's first confirmed authenticator (recovery_repo.count_remaining=0) mints 10 recovery codes, hashes each via `hash_recovery_code`, bulk-creates the rows, renders `totp_recovery_codes_page` with plaintexts. `GET /me/security/totp/verify` peeks `Challenge::PendingTotp`, mints CSRF, renders `totp_verify_page`. `POST /me/security/totp/verify` takes the challenge (consume), decrypts the user's authenticator secret, verifies code with replay protection, on success persists advanced `last_used_step` then calls `complete_auth_post_gate` to resume the original session-start + AuthCode-mint + redirect. On failure: re-parks with bumped attempts (MAX_ATTEMPTS=5 then bounces to /login), preserves original deadline rather than refreshing TTL, generic error message. `POST /me/security/totp/recover` canonicalizes + SHA-256-hashes the submitted recovery code, looks up via `find_unredeemed_by_hash`, marks redeemed, resumes via `complete_auth_post_gate`. **TOTP gate insertion** in `post_auth::complete_auth`: for `AuthMethod::MagicLink` only, after step 1 (AR taken), checks `find_active_for_user`; on Some(confirmed) calls `park_totp_gate_and_redirect` which carries AR fields **inline** into PendingTotp (eliminates race where the original AR handle could expire between gate-park and verify-resume — distinct improvement over the chained-handle approach considered in earlier ADR drafts), sets `__Host-cesauth_totp` (SameSite=Strict, distinct from pending-authorize's Lax), clears `__Host-cesauth_pending`, 302 to verify page. WebAuthn paths (Passkey AuthMethod) bypass the gate — WebAuthn is itself MFA-strong per ADR-009 §Q7. Storage failure on TOTP lookup fails closed with 500 rather than silently bypassing. **`complete_auth_post_gate` extracted** as `pub(crate)` from the original `complete_auth` body so both no-gate and post-TOTP-verify paths share session-start/AuthCode-mint/redirect logic. **`__Host-cesauth_totp_enroll`** (15 min TTL, generous for app-context-switch cost during enrollment scan) and **`__Host-cesauth_totp`** (5 min TTL, short to avoid abandoned prompts tying up state) cookies introduced; both SameSite=Strict (no cross-site flow involved); helpers `set_*_cookie_header`, `clear_*_cookie_header`, `extract_*` follow the same pattern as `__Host-cesauth_pending`. Routing wired in `worker::lib::main` (5 new routes). 12 new tests in `post_auth::tests` pinning cookie shape (Max-Age preserved, HttpOnly + Secure + SameSite=Strict, `__Host-` prefix), TTL bounds (gate 1-10 min, enroll 5-30 min), distinct-cookie-name property between gate and enroll (must-not-cross-context defense). The route handlers themselves (~800 lines across 3 files) are integration-tested via the existing webauthn / magic-link patterns; v0.30.0 will add explicit handler tests after the disable + cron + redaction work consolidates the test fixture surface. 12 new tests. Total **563 passing**. |
| **Security track Phase 7: TOTP Phase 2d — polish + ADR Accepted** | ✅       | Shipped 0.30.0. **Final TOTP release** — closes the 5-release track started at v0.26.0. **Disable flow**: `GET /me/security/totp/disable` shows confirmation page (POST/Redirect/GET pattern; warns recovery codes are wiped, offers cancel link, single-click confirm); `POST` validates CSRF and does authenticators-first then recovery-codes deletion (rationale: an authenticator without recovery codes is still a working credential, while recovery codes alone are useless). Best-effort failure semantics — authenticators-delete failure 500s, recovery-codes-delete failure logged-and-swallowed. Redirects home with no flash message (deferred to UI/UX release). **`TotpAuthenticatorRepository::delete_all_for_user`** trait + in-memory + D1 adapters (single-statement user-scoped DELETE, no list-then-delete because there's no per-row audit invariant on credentials, contrast anonymous-user sweep's audit-trail integrity). Both adapters no-op-on-empty / idempotent across retries. **TOTP unconfirmed-enrollment cron sweep** extension to the existing 04:00 UTC daily cron in `crates/worker/src/sweep.rs`: new `totp_unconfirmed_sweep` helper drops `confirmed_at IS NULL AND created_at < now - 86400` rows. The 24-hour window is per ADR-009 §Q9. Same best-effort failure semantics, no audit per row. The partial index `idx_totp_authenticators_unconfirmed` from migration 0007 keeps the lookup cheap. **`RedactionProfile.drop_tables` field** added; both built-in profiles (`prod-to-staging`, `prod-to-dev`) drop both TOTP tables entirely — TOTP secrets must NOT survive redaction even encrypted because a staging operator with the deployment's encryption key could authenticate as real users (ADR-009 §Q5/§Q11). CLI export loop in both main and round-trip-verify paths honor `drop_tables`. `MIGRATION_TABLE_ORDER` + `TENANT_SCOPES` extended for both new tables (Global scope, FK-through-users like the existing WebAuthn `authenticators` table). **Operator chapter** new file `docs/src/deployment/totp.md` (~270 lines): when TOTP fires, encryption key provisioning, key rotation procedure with explicit caveat that dual-key resolution is not yet implemented (workaround: re-enroll users or one-shot helper), admin reset path for lockout recovery via direct D1 deletion, cron sweep semantics, disable-flow operator perspective with no-current-code-required rationale, redaction profile cross-reference, operational invariants (`secret_key_id` load-bearing, partial index load-bearing, cookie SameSite=Strict, recovery codes irretrievable, multi-authenticator semantics), diagnostic queries. Linked in `docs/src/SUMMARY.md`. **Pre-production release gate** — `TOTP_ENCRYPTION_KEY` added to `docs/src/expert/security.md` checklist as item 6, with caveat that TOTP is opt-in at operator level (single-factor magic-link or passkey-only deployments don't need it). **ADR-009 graduates `Draft` → `Accepted`** — the design has been validated end-to-end across 5 releases, no outstanding design questions. ADR header status updated, ADR index updated, Phasing v0.30.0 entry added with implementation details. **10 new tests**: 3 in core (redaction profile drop_tables semantics + defense-in-depth typo guard), 5 in ui (disable template), 2 in adapter-test (delete_all_for_user user-scoping + idempotency). **Note on UI/UX scope**: per the user-stated project value "重要な予定が完了したタイミングで、UI/UX 改善に取り組みます", the disable flow is intentionally minimal — single-page confirm, silent redirect, no flash messages. The `/me/security` index page, flash-message infrastructure, error-slot for the enroll template, CSS for warning/danger button states, and handler integration tests all naturally consolidate in the next release where the UI/UX iteration will tackle them across the surface, not just for TOTP. **TOTP track is now feature-complete for the 0.x series.** Total **573 passing**. |
| **UI/UX iteration release v0.31.0** | ✅       | Shipped 0.31.0. UI/UX improvements at TOTP-track-completion boundary — first node-major release after the security track closed. Per plan v2 (`cesauth-v0.31.0-plan-v2.md`) all six P0/P1 backlog items shipped, P1-B split to v0.31.1 per the §6.4 scope-cap policy. **P0-A `/me/security` Security Center**: read-only index showing primary auth method (Passkey / MagicLink / Anonymous), TOTP enabled/disabled badge, recovery code remaining count with 4-tier rendering (N=10 → info, N=2-9 → info, N=1 → warning + re-enroll hint, N=0 → danger + admin-contact message). Anonymous-suppression variant (匿名トライアルでは TOTP を有効化できません). Single-task-per-page rule: links to `/me/security/totp/enroll` (when disabled) or `/me/security/totp/disable` (when enabled) — no inline destructive forms. **P0-B flash-message infrastructure**: new `__Host-cesauth_flash` cookie, SameSite=Lax (survives OAuth redirect chain), HttpOnly, 60s TTL. Cookie value is `v1:{b64url(payload)}.{b64url(hmac_sha256(payload))}` with HMAC key derived from `SESSION_COOKIE_KEY` via inline HKDF (`HMAC(session_key, "cesauth flash v1 hmac")`). Payload is `{level_code}.{key}` over a closed dictionary (4 levels × 4 keys); attempting to forge an unknown level or key fails decoding even with valid MAC (defense-in-depth). Set / take / clear API in `cesauth_worker::flash` (~270 lines). 32 unit tests pin the round-trip, tamper detection (payload mutation, tag mutation, wrong key), malformed-input rejection (missing prefix, `v9:` version, multiple separators, non-base64), cookie attribute shape, and the closed-dictionary contract. Templates side: `flash_block(Option<FlashView>) -> String` returns empty for None, otherwise renders `<div class="flash flash--*" role="alert|status" aria-live="assertive|polite">` with icon (✓ ⚠ ⛔ ℹ) + text. `frame_with_flash` splices the banner above body content. Wired into 4 handlers: `disable` → `success.totp_disabled` + redirect to `/me/security`; `enroll/confirm` → `success.totp_enabled` (both first-enrollment recovery-codes-page path and backup-enrollment direct-redirect path); `recover` → `warning.totp_recovered` (consumed code is worth flagging); `logout` → `info.logged_out` + redirect to `/login` (changed from previous `/`). **P0-C `totp_enroll_page` error slot**: signature changed to `totp_enroll_page(qr, secret, csrf, error: Option<&str>)` matching `totp_verify_page`. Error message rendered as `role="alert" aria-live="assertive"` div above the form. Code input gained `autofocus` so the user lands on the input after a wrong-code re-render — they have the authenticator app open, the next 6-digit code is what they want to type. The wrong-code branch in `enroll::post_confirm_handler` passes the Japanese error message; previously this branch silently re-rendered the same secret with no feedback. **P0-D 8 new design tokens**: `--success` `#1f9d55`, `--success-bg` `#e8f5e9`, `--warning` `#b76e00`, `--warning-bg` `#fff7e6`, `--danger` `#c92a2a`, `--danger-bg` `#fdecea`, `--info` `#1864ab`, `--info-bg` `#e7f5ff` (light mode; dark mode `@media (prefers-color-scheme: dark)` overrides shift to deep-tinted variants). New CSS classes: `.flash` + 4 `.flash--*` modifiers, `.badge` + 4 `.badge--*` modifiers, `button.danger` (red bg + white fg + red focus ring), `button.warning` (warning-color outline), `.flash__icon` and `.flash__text` for the icon-plus-text composition, and a `.visually-hidden` utility (this fixed a latent bug — the class was already referenced by `totp_verify_page` for an SR-only heading but the rule was missing from BASE_CSS). All state badges/banners pair color with icon + text label per WCAG 1.4.1. Legacy tokens (`--accent`, `--err`, `--muted`, `--bg`, `--fg`) preserved unchanged. **P1-A `next` parameter**: new pure function `validate_next_path(raw) -> Option<&str>` with allowlist policy `/` and `/me*` only. Rejects: protocol-relative (`//evil.com`), Windows UNC (`\\evil`), any scheme (`https:`, `javascript:`, `data:`, `mailto:`), `/admin/*` (cookie-vs-bearer auth-context mixing), `/api/v1/*` (JSON, not browser landing), `/login` and `/logout` (loop), `/__dev/*`, `/.well-known/*`, machine endpoints, POST-only auth handlers, prefix-substring traps like `/menu`. New `redirect_to_login_with_next(req)` encodes path+query as base64url into `?next=...`, used by `resolve_or_redirect`. Login GET handler reads `?next=`, validates, stashes the encoded value in `__Host-cesauth_login_next` (5 min TTL, SameSite=Lax). `complete_auth` and `complete_auth_post_gate` thread the cookie header through; the no-AR landing arm consults it via `decode_and_validate_next` and 302's there with a clear-cookie header (one-shot). All four entry points (WebAuthn register, WebAuthn authenticate, Magic Link verify, TOTP verify, recovery code redeem) updated to forward the cookie header. 34 new auth-helper tests pin the allowlist + rejection list comprehensively. **`docs/src/expert/cookies.md`** new chapter (~210 lines) inventorying all 7 cookies (`_session`, `_pending`, `-csrf`, `_totp`, `_totp_enroll`, `_flash`, `_login_next`), each with name / purpose / lifetime / scope / SameSite / HttpOnly / Secure attributes and a strictly-necessary justification per EDPB Guidelines 5/2020 §3.1.1. Operator-deployed analytics responsibility note clarifies that cesauth library does not provide a consent-management hook; operators adding analytics cookies own that obligation. Linked in `docs/src/SUMMARY.md` next to security-headers chapter. **Cookie audit added to security pre-production checklist**. Plan v2 §6.4 split policy: P1-B (TOTP route handler integration tests) was deferred to v0.31.1 — the worker crate has no `worker::Env` mock infrastructure, and standing one up would have inflated this release past the review-able slice. Pure-helper extracts shipped here as honest minimum coverage at this layer (`attempts_exhausted` boundary in `verify`, `DISABLE_SUCCESS_REDIRECT` constant in `disable`, both with tests pinning the contract). The full integration suite arrives in v0.31.1 once the env-mock investment lands. Total **~680 passing** (+~107 from v0.30.0). |
| **Per-client audience scoping for /introspect v0.50.0** | ✅       | Shipped 0.50.0. ADR-014 §Q1 marked **Resolved**. First release after the six-item operator-requested batch (v0.44–v0.49) completed. Picked from the four open security-track items the v0.49.0 changelog flagged as the only candidate that's both ready-to-ship AND security-meaningful (the other three: ADR-012 §Q2 idle-timeout notification needs email pipeline cesauth doesn't have; §Q3 geo/device columns needs GeoIP infrastructure cesauth has none of; §Q5 orphan DOs is structurally blocked by Cloudflare not supporting DO namespace iteration). **Why this matters**: v0.38.0 shipped /introspect with a global trust model — any authenticated confidential client could introspect any token. ADR-014 §Q1 paragraph flagged this as privilege-escalation concern for multi-tenant deployments where one cesauth issues tokens for many resource servers. Pre-v0.50.0, an RS_A holding valid introspection credentials could ask cesauth about RS_B's tokens — and learn whether they were active, what scopes they carried, which user owned them. Cross-RS visibility, unintended. v0.50.0 closes this with per-client audience scope that's **off by default** (existing deployments upgrade unchanged) and **opt-in per client** (no deployment-wide flag — operators enable it for clients that need it). **Schema migration** `migrations/0010_introspection_audience.sql` adds `audience TEXT` (nullable) to `oidc_clients`. **SCHEMA_VERSION 9 → 10** — first schema bump since v0.35.0. NULL means "unscoped — pre-v0.50.0 behavior"; non-NULL value means "this client may introspect ONLY tokens whose `aud` claim matches verbatim". Single string column not JSON array — RFC 7662 doesn't model multi-audience introspecters; if demand surfaces for clients needing multiple allowed audiences, future migration can broaden. No CHECK constraint on the value (audiences are operator-controlled identifiers; truth check is runtime comparison not schema constraint). **Pure gate function** `cesauth_core::service::introspect::apply_introspection_audience_gate(response, requesting_client_audience) -> IntrospectionGateOutcome::{PassedThrough(IntrospectionResponse) \| AudienceDenied { response, requesting_client_audience, token_audience }}`. The orchestrator (`introspect_token`) stays pure — produces a response based purely on token validity; the gate runs separately, in the worker handler, applied after `introspect_token` returns. This keeps orchestrator testable without touching audit infrastructure AND surfaces gate-fired signal to handler for distinct audit emission. Gate is no-op when `requesting_client_audience` is None (client is unscoped — the default), or `response.active` is false (already inactive — gate has nothing to add), or `response.aud` is None (refresh-token responses; documented out-of-scope). **Privacy invariant on denial**: gate replaces response with `IntrospectionResponse::inactive()` — wire form `{"active":false}`, byte-identical to v0.38.0's privacy-preserving inactive shape. Returning 403 would let attacker probe whether tokens exist for other audiences by trying their own credentials (same enumeration-side-channel concern v0.38.0 documented for unknown-client vs wrong-secret). Test pin `mismatch_response_serializes_to_bare_inactive` asserts wire form byte-exact — defense in depth against future change adding field to IntrospectionResponse that gate forgets to clear. **`IntrospectionResponse.aud` field added**: RFC 7662 §2.2 lists aud as optional response field; v0.38.0 deliberately omitted because no resource servers cesauth supported needed it. v0.50.0 surfaces it because (a) gate reads it internally so we may as well expose on wire, and (b) standard introspection libraries expect it. Active access responses populate aud from JWT's aud claim; active refresh responses leave None; inactive responses (including audience-denied) leave None. `#[serde(skip_serializing_if = "Option::is_none")]` — clients consuming only fields they need are unaffected. **`active_access` constructor signature change**: now takes final `aud: Option<String>` parameter; `active_refresh` and `active_refresh_with_ext` unchanged (refresh responses always have aud=None). External code constructing IntrospectionResponse directly will need one-line update; in-tree call sites updated alongside. **Refresh-token introspection out of v0.50.0 scope**: FamilyState doesn't record audience (audience is determined per access-token mint, not per family); refresh introspection therefore returns aud=None and gate falls through. Audience scoping for refresh introspection is architecturally distinct (family doesn't bind to a single audience; tokens minted from refresh inherit aud from request) and is left to a future iteration if operator demand surfaces. **`EventKind::IntrospectionAudienceMismatch`**: new audit kind, snake_case `introspection_audience_mismatch`. Payload `{requesting_client_id, requesting_client_audience, token_audience}`. Both audiences are operator-controlled identifiers not secret material — their presence in audit doesn't reveal token contents. Introspected token itself is NOT in payload (same privacy invariant as TokenIntrospected). Distinct from IntrospectionRateLimited (fires before any token check) and TokenIntrospected (fires on any authenticated request that proceeded to checks). Spike of these events likely indicates misconfigured resource server (its audience doesn't match what its tokens carry) or legitimate-but-unintended cross-RS introspection probe. **Worker handler integration**: `POST /introspect` now (1) authenticates client, (2) rate-limit gate, (3) **NEW** fetches authenticated client row to read audience (storage outage on this lookup treats client as unscoped letting request proceed under pre-v0.50.0 behavior rather than fail-closing on transient hiccup; errors log warning), (4) introspect_token, (5) **NEW** apply_introspection_audience_gate (on AudienceDenied: emit IntrospectionAudienceMismatch audit event with operator-controlled identifiers; replace response with bare inactive()), (6) audit TokenIntrospected, (7) render JSON. **Tests**: 986 → **996** lib (+10). With migrate integration: 1015 → **1025**. core: 443 → 453 (+10) all in `service::introspect::tests::audience_gate`: unscoped_client_passes_through_active_response (NULL client.audience = legacy), matching_audience_passes_through (happy path), mismatched_audience_returns_inactive_no_leak (critical privacy pin: response on denial has zero leaked claims), mismatch_response_serializes_to_bare_inactive (wire-form byte-exact `{"active":false}`), already_inactive_response_passes_through_unchanged (gate doesn't double-wrap), refresh_token_response_with_no_aud_passes_through (documented v0.50.0 scope), empty_string_audiences_compared_byte_exact ("" matches "" only — legitimate edge), case_sensitive_audience_comparison (RFC 7519 §4.1.3 case-sensitivity preserved), substring_match_does_not_satisfy_gate (defensive: "rs" must NOT match "rs.example.com" nor vice versa), mismatched_audience_audit_payload_contains_both_values (audit payload contract). UI test count unchanged at 244; worker test count unchanged at 182 (handler wiring; testable transformation is in pure core). **Schema migration** runs (SCHEMA_VERSION 9 → 10) — single ALTER TABLE, ~milliseconds for any realistic deployment size. **Wire format additive only**: aud added to IntrospectionResponse, spec-conformant clients ignore unknown fields; existing inactive-response byte-form unchanged; audience-denied responses byte-equal to legacy inactive responses. **DO state unchanged** (refresh families don't store audience). **No new dependencies**. **Operator note**: no production behavior change until operator sets `oidc_clients.audience` to non-NULL for at least one client; default behavior unchanged. Recommended deployment progression for multi-RS deployments: (1) upgrade to v0.50.0 no clients have audience set behavior unchanged; (2) identify which resource-server clients should be scoped, decide each one's allowed audience (typically RS's stable hostname or identifier); (3) set `oidc_clients.audience` via direct D1 statement `UPDATE oidc_clients SET audience = ? WHERE id = ?` (admin console UI for this is out of v0.50.0 scope); (4) watch audit logs for introspection_audience_mismatch events — spike right after enabling typically indicates misconfiguration (audience value doesn't match what tokens actually carry) or discovered cross-RS introspection that motivated scoping in first place. No `wrangler.toml` change. No new bindings. No new env vars. **Open security-track items remaining**: ADR-012 §Q2 (idle-timeout user notification — needs email pipeline, defer); §Q3 (geo/device-fingerprint columns — needs GeoIP infrastructure, defer); §Q5 (orphan DOs — structurally blocked by Cloudflare DO namespace iteration limitation, no good resolution with current platform primitives). |
| **D1 session-index repair tool v0.49.0** | ✅       | Shipped 0.49.0. ADR-012 §Q1.5 marked **Resolved**. Per-operator-request order: tech-debt sweep first (v0.44.0), bulk-revoke second (v0.45.0), refresh-introspection third (v0.46.0), i18n-2 fourth (v0.47.0), audit retention fifth (v0.48.0), D1 repair sixth. **All six items shipped**. v0.40.0 introduced session_index_audit cron pass walking D1 outward to per-session DOs, classifying drift via `session_index::classify`, emitting `SessionIndexDrift` audit events; **emitted but did not repair**. ADR-012 §Q1.5 paragraph deferred repair half pending observation of clean drift events; operators have now surfaced demand. **`cesauth_core::ports::session_index::SessionIndexRepo`** new trait: `list_active(limit)` + `delete_row(sid)` + `mark_revoked(sid, revoked_at)`. Both write methods idempotent: `delete_row` on non-existent sid is `Ok(())`; `mark_revoked` uses `WHERE revoked_at IS NULL` SQL guard to refuse to overwrite already-set revoked_at (history preserved — port contract says repair must not rewrite history). CF D1 adapter at `crates/adapter-cloudflare/src/ports/session_index.rs` implements both with explicit comments on guard SQL. **Pure repair service** `cesauth_core::session_index::repair::run_repair_pass(index, store, cfg, now) -> RepairOutcome`: composes existing classify logic with new port. Per-row decision tree — InSync → no-op; DoVanished → `index.delete_row(sid)`; DoNewerRevoke → `index.mark_revoked(sid, do_revoked_at)`; AnomalousD1RevokedDoActive → **never auto-repaired** (automated repair would mask whatever upstream bug produced it — D1 says revoked, DO says active means revoke write landed in D1 but not DO, that's regression not drift to silently fix). **Best-effort failure containment**: per-row failures increment `errors` and continue batch; alternative (abort on first error) would leave bulk of drifts unrepaired forever if first row hits transient failure. **`RepairConfig` opt-in**: `auto_repair_enabled: bool` (default false), `batch_limit: u32`. When false (cesauth default), pass classifies + counts but emits no D1 writes; `RepairOutcome::dry_run = true`. When true, pass writes repairs. **Default-off because**: trust gradient (deployment without track record of clean drift events shouldn't have automated D1 mutation pointed at it; first cron pass after upstream regression could mass-delete real rows; default-off gives operators time to watch session_index_drift event stream from v0.40.0 detection pass and decide "yes upstream paths stable, turn repair on"); reversibility (v0.40.0 detection trail of one SessionIndexDrift event per drift is operator's "what got changed and why" record if repair later turns out wrong; auto-repair without prior detection period collapses that trail). **Fifth cron pass** `session_index_repair_cron::run` runs after sweep → audit_chain_cron → session_index_audit → audit_retention_cron on daily 04:00 UTC schedule; independent (failure logs but doesn't block others). **Env vars**: `SESSION_INDEX_AUTO_REPAIR` (default false; "true" enables D1 mutations), `SESSION_INDEX_REPAIR_BATCH_LIMIT` (default 1000). **Tests**: 973 → **986** lib (+13). With migrate integration: 1002 → **1015**. core: 430 → 443 (+13) all in `session_index::repair::tests`: in_sync_rows_count_no_writes, do_vanished_drift_is_repaired_when_enabled, do_newer_revoke_drift_is_repaired_with_do_timestamp, anomalous_alert_only_is_never_repaired (also documents list_active-filter-excludes-anomalous edge), dry_run_classifies_but_writes_nothing (critical opt-in contract pin), list_failure_propagates_as_internal, per_row_status_failure_increments_errors_does_not_abort, per_row_repair_failure_increments_errors_does_not_abort (best-effort failure containment), walked_count_equals_listed_rows, idempotent_second_repair_pass_is_no_op, mark_revoked_idempotent_at_repo_level (WHERE-revoked_at-IS-NULL guard pin), default_config_is_dry_run (opt-in contract pin), outcome_default_zero_counts. UI test count unchanged at 244; worker test count unchanged at 182 (cron handler is glue; testable transformation is in pure core). **Schema unchanged** from v0.48.0 (still SCHEMA_VERSION 9); repair operates on existing user_sessions table, no migration. **Wire format unchanged**. **DO state unchanged** (repair pass reads DO state via ActiveSessionStore::status, never mutates it). **No new dependencies**. **Operator note**: new cron pass runs daily after existing four; **default behavior is dry-run** classifying but not mutating; two new optional env vars; operators opt in to repairs by setting SESSION_INDEX_AUTO_REPAIR=true. **Recommended deployment progression**: (1) upgrade to v0.49.0; dry-run pass starts emitting log lines showing would-repair counts; (2) watch for at least one week ideally a month — if dry-run counts stable (small numbers no spikes) upstream paths are healthy and repair is safe; (3) set SESSION_INDEX_AUTO_REPAIR=true and redeploy; subsequent cron passes write repairs. No `wrangler.toml` change (cron schedule unchanged). No new bindings. No schema migration. **Q5 limitation acknowledged**: orphan DOs with no D1 row remain undetectable (Cloudflare does not support DO namespace iteration); pre-v0.35.0 sessions and start-time-mirror-failures stay invisible. |
| **Audit retention policy v0.48.0** | ✅       | Shipped 0.48.0. ADR-014 §Q3 marked **Resolved**. Per-operator-request order: tech-debt sweep first (v0.44.0), bulk-revoke second (v0.45.0), refresh-introspection third (v0.46.0), i18n-2 fourth (v0.47.0), audit retention fifth. **Why now**: v0.38.0 added /introspect emitting one audit row per call; chatty resource server can produce ~1 introspection/sec/user, ~86k events per day per active user, 1k-active-user deployment hits ~86M rows per day. D1 is row-priced; retention without pruning means cost scales linearly with deployment age. ADR-014 §Q3 deferred at v0.38.0 because steady-state cost wasn't observable; v0.48.0 ships now that operators have surfaced demand. **The challenge**: cesauth's audit log is a hash-chained ledger (ADR-010, migrations/0008); naively deleting old rows would break the chain. v0.48.0 prunes safely by anchoring on the verifier's checkpoint. **Pure service in core** (`cesauth_core::audit::retention::run_retention_pass`): reads verifier checkpoint, computes safe `floor_seq = max(checkpoint.last_verified_seq - 100, 2)`, runs two passes (per-kind for `TokenIntrospected`, then global for everything else), returns `RetentionOutcome { deleted_token_introspected, deleted_global, checkpoint_seq, floor_seq, skipped_no_checkpoint }`. **Hash-chain preservation strategy**: verifier resumes from `last_verified_seq + 1` and never re-walks rows below checkpoint, so pruning those rows is integrity-safe; cross-check anchor row at `last_verified_seq` itself preserved by 100-row safety margin (`CHECKPOINT_SAFETY_MARGIN`); margin well above per-cron-pass write rate in any deployment (cron daily; even at peak introspection rate verifier walks far more than 100 rows per pass). **Genesis row (seq=1) is sacred** — both in-memory test adapter and Cloudflare D1 adapter explicitly exclude `seq <= 1` from the prune predicate; an aggressive 0-day retention config still leaves the chain anchor intact for any future re-walk. **Refuses to prune without a checkpoint** — fresh deployments where audit_chain_cron hasn't yet run produce `Ok(skipped_no_checkpoint=true)`; pruning without a chain anchor opens forensics-vs-tampering ambiguity that the safety margin is meant to prevent. **Two-knob retention**: global window (default 365 days, env `AUDIT_RETENTION_DAYS`) + per-kind for `TokenIntrospected` (default 30 days, env `AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS`). Shorter `TokenIntrospected` window reflects high volume + low post-30-day forensic value (resource-server caching pathology surfaces within hours). Setting either knob to 0 disables that pass; both 0 = legitimate "unbounded retention" config. **Two-pass execution**: per-kind first (when `ti_days > 0` AND (`global_days == 0` OR `ti_days < global_days`)) deletes TokenIntrospected rows older than per-kind window; global next (when `global_days > 0`) deletes rows of any kind older than global window with TokenIntrospected excluded when per-kind was active (preventing double-counting). **`AuditEventRepository::delete_below_seq(floor_seq, older_than, kind_filter)` trait method** added — non-default, so adding to 3rd-party implementors requires update; cesauth's two in-tree adapters updated. Implementations MUST observe all three gates conjunctively (seq < floor, ts < cutoff, kind matches filter) AND preserve genesis row. **`AuditRetentionKindFilter` enum**: `OnlyKinds(Vec<String>)` (delete iff in list, empty list = delete-zero shortcut), `ExcludeKinds(Vec<String>)` (delete iff NOT in list); D1 adapter translates filter variants into parameterized SQL (kind values bound as `?n`, never concatenated). **Fourth cron pass**: `audit_retention_cron::run` runs after sweep → audit_chain_cron → session_index_audit on daily 04:00 UTC schedule; independent (retention failure logs but doesn't block other passes). **Tests**: 957 → **973** lib (+16). With migrate integration: 986 → **1002**. core: 414 → 430 (+16) all in `audit::retention::tests`: no_checkpoint_skips_pass, checkpoint_present_but_below_safety_margin_is_no_op (floor_seq lower-bound protects fresh deployments), token_introspected_pass_prunes_old_rows_only, global_pass_prunes_only_above_global_window, global_pass_excludes_token_introspected_when_per_kind_active (critical no-double-prune pin), global_includes_token_introspected_when_per_kind_disabled, global_includes_token_introspected_when_per_kind_geq_global, global_zero_disables_global_pass, floor_seq_protects_recent_rows_even_when_old_by_ts (chain-walker safety pin), checkpoint_at_genesis_keeps_genesis_safe, delete_failure_propagates_as_internal, checkpoint_read_failure_propagates_as_internal, idempotent_second_call_is_zero_count, default_config_matches_published_defaults (pin 365/30), safety_margin_is_one_hundred (pin 100 matches ADR), kind_token_introspected_constant_matches_event_kind (drift detector). UI test count unchanged at 244; worker test count unchanged at 182 (cron handler is glue; testable transformation is in pure core service). **Schema unchanged** from v0.47.0 (still SCHEMA_VERSION 9); retention DELETE statements operate on existing audit_events table, no migration. **Wire format unchanged**. **No new dependencies**. **Operator note**: new cron pass runs daily after existing three; default behavior with unset env vars is 365-day global window + 30-day TokenIntrospected. New env vars both optional. No production behavior change until next cron tick; after that audit rows past retention windows start disappearing on each daily run. Storage cost reduction scales with difference between previous unbounded retention and new windows; deployments several years old should expect one-time large prune followed by steady-state. Audit dashboards counting token_introspected events more than 30 days back will see counts decline; dashboards relying on chain_length from verifier still get full count (chain_length is MAX(seq), unaffected by deletes — seq is AUTOINCREMENT and never reused). No `wrangler.toml` change (cron schedule unchanged). No new bindings. No schema migration. |
| **i18n-2 continuation v0.47.0** | ✅       | Shipped 0.47.0. Per-operator-request order: tech-debt sweep first (v0.44.0), bulk-revoke second (v0.45.0), refresh-introspection third (v0.46.0), i18n-2 continuation fourth. **No new ADR** — v0.47.0 closes out the i18n-2 thread opened in v0.39.0 using the established design pattern (catalog + `_for` variants + default shorthand routing). v0.39.0 migrated LOGIN / TOTP enroll / TOTP verify / Security Center; v0.47.0 closes the remaining four user-facing templates: Magic Link "Check your inbox", TOTP recovery codes display, TOTP disable confirm, generic error page. Plus PrimaryAuthMethod label (used by Security Center to render "how you sign in") which was still hard-coded JA pre-v0.47.0 — a v0.39.0 limitation noted in that release. **22 new MessageKey variants** (catalog total 76 → **98**): 3 PrimaryAuthMethod labels (PrimaryAuthMethodPasskey/MagicLink/Anonymous), 5 Magic Link sent (Title/Heading/Intro/OtpHeading/CodeLabel — submit reuses existing TotpVerifyContinueButton), 6 TOTP recovery codes (Title/Heading/AlertStrong/AlertBody/Body/Continue), 7 TOTP disable confirm (Title/Heading/AlertStrong/AlertBody/RecoveryHint/ConfirmHeading/Submit — cancel reuses existing TotpEnrollCancelLink), 1 ErrorPageBackLink. JA + EN translations for every new key. **The catalog uniqueness invariant** (no two MessageKey variants resolve to the same string within a locale) caught two well-intentioned duplicates during development: MagicLinkSentSubmit ("Continue"/"続ける") would have collided with TotpVerifyContinueButton; TotpDisableCancel ("Cancel and go back"/"キャンセルして戻る") would have collided with TotpEnrollCancelLink. Both new variants dropped in favor of reusing existing keys — strictly better outcome (one source of truth per string). **Privacy-preserving phrasing pinned**: MagicLinkSentIntro translates the v0.27.0 privacy phrasing ("if that address is registered, we've just sent...") into JA preserving the same non-confirmation: "このメールアドレスが登録されている場合、ワンタイムコードを送信しました。". User-enumeration prevention is part of the contract; test `magic_link_sent_page_for_renders_japanese_default` pins JA carries the "登録されている場合" conditional. **`PrimaryAuthMethod::label_for(locale)`** new public method on the public enum; legacy `label()` getter preserved as default-locale shorthand delegating to `label_for(Locale::default())`. `security_center_page_for` now calls `label_for(locale)`, so Security Center renders primary-method label in negotiated locale (fixing v0.39.0 limitation). **Four templates gain `_for(.., locale)` variants**: `magic_link_sent_page` / `error_page` / `totp_recovery_codes_page` / `totp_disable_confirm_page`. Pre-v0.47.0 these were EN-only despite cesauth's "default JA" pattern; v0.47.0 brings them in line with the rest of the user-facing surfaces. Shorthand wraps `_for` with `Locale::default()` (Ja). **Behavior change for legacy shorthand callers**: previously rendered EN; v0.47.0 routes through Locale::default()=Ja. Pin `magic_link_sent_legacy_shorthand_now_renders_ja_default` documents this. **Production handlers were already on negotiated locales since v0.39.0 and pass through `_for`, so the production path is unaffected**. External code calling shorthand directly may see the change; updating to `_for(.., Locale::En)` restores pre-v0.47.0 behavior explicitly. **Worker handlers thread locale**: four call sites updated (totp/disable.rs, totp/enroll.rs for recovery codes after enrollment, magic_link/request.rs at both render sites — rate-limit fallback + success path). `error_page` has no in-tree worker call sites; it's a public template helper retained for external consumers. **Tests**: 948 → **957** lib (+9). With migrate integration: 977 → **986**. core: 414 → 414 (catalog-only changes; existing i18n test suite covers new keys via exhaustiveness + uniqueness invariants). ui: 235 → 244 (+9 locale-aware tests across the 5 new template/method surfaces). worker: 182 → 182. **3 pre-v0.47.0 UI tests migrated** (recovery_codes_page_includes_irreversibility_warning, disable_page_warns_about_recovery_code_loss, disable_page_offers_cancel_link) to assert via `_for(.., Locale::En)` since they pinned EN-substring assertions and the default shorthand now returns JA. **Schema unchanged** from v0.46.0 (still SCHEMA_VERSION 9). **Wire format unchanged**. **No new dependencies**. **Operator note**: JA renders for the four migrated pages when user's Accept-Language negotiates Ja (or unset, since cesauth defaults to Ja); EN preserved for Accept-Language: en. **i18n-2 fully closed** with v0.47.0 — every user-facing template now flows through the catalog with locale negotiation. Admin/tenancy console templates remain JA-only (separable thread). |
| **Refresh-token introspection enhancements v0.46.0** | ✅       | Shipped 0.46.0. Per-operator-request order: tech-debt sweep first (v0.44.0), bulk-revoke second (v0.45.0), refresh-introspection enhancements third. **No new ADR** — v0.46.0 is an additive extension under RFC 7662 §2.2's allowance for service-specific response names. **Why this matters**: pre-v0.46.0 every "inactive" path (revoked / jti-mismatched / never-existed) collapsed to a bare `{"active": false}` — spec-compliant but operationally opaque. RS dashboards couldn't distinguish "stale due to rotation; user has fresher token" from "killed by reuse-defense; alert security"; audit couldn't break down inactive events by reason without external correlation; stale-token-due-to-rotation looked identical to forged-token, masking attacker probing in noise of legitimate rotations. **`cesauth_core::oidc::introspect::CesauthIntrospectionExt`** new struct serializing under the `x_cesauth` key (RFC 7662 §2.2 namespacing); all fields Option-typed with skip_serializing_if so absent fields don't render. **`FamilyClassification` enum** (snake_case serde): `Current` (jti matches family.current_jti AND not revoked), `Retired` (jti in family.retired_jtis — surfaces `current_jti` as stale-token hint), `Revoked` (family.revoked_at.is_some — surfaces `revoked_at` + `revoke_reason`), `Unknown` (family doesn't exist OR jti mismatch with no retired-membership — privacy-conflated). **`RevokeReason` enum** (snake_case): `ReuseDetected` (family killed by ADR-011 §Q1 reuse defense, distinguished by family.reused_jti.is_some), `Explicit` (`/revoke` endpoint, admin revocation, or v0.45.0 bulk-revoke; future could split User vs Admin). **Privacy invariant — `Unknown` is the conflation point**: distinct underlying states (no-family vs forged-jti-against-real-family) map to it; surfacing `Retired` for a forged jti would let an attacker confirm guessed family_id existence by response shape. v0.46.0 explicitly maps no-retired-membership case to `Unknown` to prevent this — pinned by `jti_mismatch_without_retired_membership_is_unknown_not_retired` test. `current_jti` surfaced ONLY on Retired path — introspecter has proven possession of a once-valid jti so revealing current jti is no fresh information leak; lets RS dashboards recognize "stale due to rotation; user has newer token" without trying to refresh. **`service::introspect::introspect_refresh` rewrite**: five-line decision tree (no-decode, no-family, revoked, jti-mismatch, current) now produces five distinct response shapes. Pre-v0.46.0 fall-through-to-access on revoked/mismatched is removed (was already a no-op in practice — JWTs fail refresh decode at `exp.parse::<i64>()` step; v0.46.0 makes this explicit by returning `Some(inactive_with_ext)` instead of `None`). **Worker audit-payload extension**: `EventKind::TokenIntrospected` payload gains optional `family_state` + `revoke_reason` fields when x_cesauth is present; access-token paths set neither (compact rows for high-volume happy path); refresh-token paths set family_state always, revoke_reason only when family_state=revoked. Unlocks operator-side breakdowns: spike in family_state=unknown → forged family_id probing (scanner OR targeted recon); spike in revoke_reason=reuse_detected → token-leak event affecting multiple users (security alert); steady-state retired → legitimate background level of stale-RS-cache introspection (expected). **Tests**: 937 → **948** lib (+11). With migrate integration: 966 → **977**. core: 403 → 414 (+11) all in `service::introspect::tests::refresh_ext` (active_refresh_response_carries_x_cesauth_current, revoked_family_returns_inactive_with_explicit_reason, reuse_detected_family_returns_inactive_with_reuse_reason, retired_jti_returns_inactive_with_current_jti_hint, unknown_family_returns_unknown_classification, jti_mismatch_without_retired_membership_is_unknown_not_retired — privacy invariant pin, truly_malformed_token_falls_through_no_ext — preserves pre-v0.46.0 access-fallback for non-refresh-shape tokens, access_token_path_does_not_set_x_cesauth, x_cesauth_field_serializes_under_correct_key, x_cesauth_omitted_when_none, revoke_reason_serializes_as_snake_case). UI test count unchanged at 235; worker test count unchanged at 182 (handler payload extended, no new tests — testable transformation is in pure core service). **Schema unchanged** from v0.45.0 (still SCHEMA_VERSION 9). **Wire format additive only** — introspection response gains optional `x_cesauth` envelope (spec-conformant clients consuming only RFC 7662 fields ignore unknown top-level keys per spec); audit payload gains optional `family_state` + `revoke_reason` fields when present. **No new dependencies**. **Operator note**: resource servers reading `x_cesauth` can now distinguish four families of inactive responses; recommend updating dashboard queries to break out by family_state / revoke_reason. Audit dashboards should add panels grouping token_introspected events by family_state and revoke_reason — steady-state baseline: current+retired normal, unknown should be near-zero unless scanner traffic, reuse_detected should be near-zero (non-zero warrants security investigation). |
| **Bulk "revoke all other sessions" v0.45.0** | ✅       | Shipped 0.45.0. ADR-012 §Q4 marked **Resolved**. Per-operator-request order: tech-debt sweep first (v0.44.0), bulk-revoke second. **No new ADR** — implementation maps directly to the §Q4 deferred-paragraph. **`cesauth_core::service::sessions::revoke_all_other_sessions`** new pure orchestration: `(store, user_id, current_session_id, now) -> BulkRevokeOutcome { revoked, errors, skipped_current }`. **Best-effort semantics** (cesauth failure-isolation pattern): per-row revoke failure increments `errors` and continues — does NOT abort the batch (alternative: user sees error, has no idea which sessions were revoked vs left alone — strictly worse than "most got revoked, retry the button for the rest"). Per-row `Ok(SessionStatus::NotStarted)` (race with sweep) counts as `revoked` (matches user mental model — row is gone, what they wanted). Per-row `Ok(SessionStatus::Active)` (shouldn't happen — `revoke` is supposed to be terminal) counts as `errors` to surface store bugs in audit counter. Per-user cap of 50 (matches `/me/security/sessions` page display limit). **`POST /me/security/sessions/revoke-others`** worker handler in `crates/worker/src/routes/me/sessions.rs`: CSRF-protected with same form-token-vs-cookie check as per-row endpoint. Pure-service does heavy lifting; handler picks one of three flashes by outcome and 302-redirects back to list. **Audit emits ONE `SessionRevokedByUser` event with `bulk: true` payload** — operators distinguish bulk from per-row via payload field; per-row approach would require capturing each session_id mid-loop, which the pure service doesn't surface (return type is counts not row metadata). **Flash codec extended**: `Flash` struct gains optional `count: Option<u32>` parameter for `{n}` substitution; wire format `<key>:<N>` notation in cookie payload (e.g., `success.other_sessions_revoked:3`); `:` delimiter verified by test to not appear in any existing FlashKey::as_str(); pre-v0.45.0 cookies (no `:`) decode as `count=None` — fully backward-compatible (cookies in flight at upgrade still display correctly); strict parsing rejects multi-`:`, non-numeric, u32 overflow; no FORMAT_PREFIX bump needed (additive within v1 format). **`FlashView::text` migrated** from `&'static str` to `Cow<'static, str>` — borrowed variant zero-alloc for v0.31-v0.44 parameter-free flashes; owned variant for runtime-substituted strings. `FlashView` lost `Copy` (Cow isn't Copy) but kept `Clone`. **`render_view_for` does `{n}` → decimal substitution** at projection time; catalog strings without `{n}` unaffected. **UI button on `/me/security/sessions`**: `sessions_page_for` adds `<section class="bulk-revoke">` above back link with inline confirmation copy + form posting to `/me/security/sessions/revoke-others` + submit button. **Conditional on `items.iter().any(|s| !s.is_current)`** — empty session list / only-current-session pages omit the button (showing it would be no-op or accidental self-revoke); current-session-not-listed (§Q5 D1 mirror drift) shows it (every listed item is "other" by definition). **i18n catalog** gains 5 MessageKey variants: `SessionsRevokeOthersButton`, `SessionsRevokeOthersConfirm`, `FlashOtherSessionsRevoked` (with `{n}`), `FlashOtherSessionsRevokeFailed` (with `{n}`), `FlashNoOtherSessions`. JA + EN translations; pluralization explicitly deferred to ADR-013 §Q4 (consistent with v0.39.0 deferral) — JA forms count-agnostic ("件"), EN forms use "device(s)" as defensive fallback. MessageKey total: 71 → 76. **Tests**: 911 → **937** lib (+26). With migrate integration: 940 → **966**. core: 393 → 403 (+10) all in `service::sessions::tests` (revokes_all_other_active_sessions_keeps_current, no_other_active_sessions_is_zero_count_no_calls, user_with_no_sessions_is_zero_count_zero_skipped, current_session_not_in_user_list_revokes_all_listed — the §Q5 drift edge, does_not_touch_other_users_sessions — multi-tenant isolation, already_revoked_sessions_are_filtered_by_list, per_row_failure_increments_errors_does_not_abort — best-effort failure containment, list_failure_propagates_as_internal_error, revoke_returning_notstarted_counts_as_revoked — race-with-sweep mental-model match, second_call_after_first_is_zero_count — idempotence). ui: 230 → 235 (+5) bulk button presence in EN + JA, hidden when empty / only-current, shown-when-current-not-listed. worker: 171 → 182 (+11) 8 in flash::tests for count codec round-trip + boundary cases (count=0, u32::MAX, multi-`:`, non-numeric, overflow, no-FlashKey-has-colon defensive pin) + 3 for render_view_for substitution. **Schema unchanged** from v0.44.0 (still SCHEMA_VERSION 9). **Wire format** additive only — flash cookie `key:N` notation backward-compatible; one new endpoint mounted. **No new dependencies**. **Operator note**: audit dashboards should distinguish `SessionRevokedByUser` events with payload `bulk: true` (bulk action) from `bulk: false`/absent (per-row clicks); a spike of bulk events is legitimate user behavior — responding to an alert by signing out everywhere is exactly the workflow this release enables. No `wrangler.toml` change. No new bindings. No schema migration. |
| **Tech-debt sweep: drop jsonwebtoken v0.44.0** | ✅       | Shipped 0.44.0. **No new ADR** — the v0.41.0 CHANGELOG already tracked the swap as planned tech-debt; v0.44.0 delivers it. Resolves the v0.41.0 trade-off that accepted transitive `rsa` v0.9 (RUSTSEC-2023-0071) as dead-code-but-linked. **`crates/core/src/jwt/signer.rs` rewrite**: the whole module — `JwtSigner::from_pem`, `JwtSigner::sign`, `verify<C>`, `extract_kid` — rewritten using `ed25519-dalek` 2.x directly + manual JWS Compact Serialization (RFC 7515 §3.1). `JwtSigner::from_pem` uses `ed25519-dalek`'s `pkcs8` feature plus the upstream `pkcs8` crate with the `pem` feature for `from_pkcs8_pem(&str)`. `JwtSigner::sign<C>` hand-builds the JWS: header JSON `{"alg":"EdDSA","typ":"JWT","kid":"..."}` with kid properly JSON-string-escaped via `serde_json::to_string`; `b64url_no_padding(header) + "." + b64url_no_padding(payload)` is the signing input per RFC 7515 §5.1; `ed25519_dalek::Signer::sign(signing_input.as_bytes())` produces the 64-byte signature; final compact form is `signing_input + "." + b64url(sig.to_bytes())`. `verify<C>` is the inverse: split on `.` (reject if not exactly three segments), decode header and check `alg=EdDSA` strictly (reject `alg=none` and any other algorithm by default per RFC 8725 §3.1), decode signature and verify with the supplied 32-byte public key against the original signing input bytes (RFC 7515 §5.2 — **cryptographic gate first**, before any claim parsing, preserves the v0.41.0 discipline), decode payload and validate `iss`/`aud` (string form only — cesauth never emits the array form from RFC 7519 §4.1.3, accepting it would be a footgun for operators copy-pasting tokens between deployments)/`exp` (with `leeway_secs`)/`nbf` (optional, with leeway), then second-pass deserialize into the caller's `C` shape (both decodes operate on the same in-memory bytes — no extra allocation cost). `extract_kid` decodes only the header (no signature work) and returns `header.kid` if present; same untrusted-hint contract as v0.41.0. **Same wire format**: tokens produced by v0.44.0's signer are byte-identical to what jsonwebtoken produced for the same inputs (RFC 7515 §3.1 deterministic encoding). Field ordering inside the header JSON differs (cesauth: `alg, typ, kid`; jsonwebtoken: `typ, alg, kid`) but verifiers parse JSON and don't care about order. **Tokens produced by v0.43.0 verify under v0.44.0 without re-issuance** — no forced rotation. **Dependency tree changes**: removed from `cargo tree -p cesauth-core` — `jsonwebtoken` 10.x (root), `rsa` 0.9 (the RUSTSEC-2023-0071 dep), `pkcs1`, `num-bigint-dig`, `num-iter`, `num-integer`, `num-traits`, `simple_asn1` (RSA's multi-precision arithmetic stack), `signature` 2.x (jsonwebtoken's algorithm trait). Retained — `hmac` (TOTP), `p256` (WebAuthn ES256), `signature 1.x` (transitive of p256), `sha2` (KDF / TOTP / refresh token hash) — these were always direct deps unrelated to jsonwebtoken. Added — `pkcs8` 0.10 with `pem` feature (the `DecodePrivateKey::from_pkcs8_pem` method requires it; `ed25519-dalek`'s `pkcs8` feature alone does not enable it). Workspace `time` dep gains the `formatting` feature explicitly — pre-v0.44.0 `formatting` was being unified in via jsonwebtoken's transitive `time` with that feature enabled; removing jsonwebtoken broke the unification, so we declare the requirement explicitly (purely a correctness fix for the now-unification-free state). **Tests**: 911 lib tests still pass — zero test count change. core: 393 → 393. The signer rewrite is a pure refactor; existing tests through `service::introspect` exercise the verify path with real Ed25519 JWTs (v0.41.0's multi_key tests already used `ed25519-dalek::Signer` directly), and existing tests via `service::token` exercise the sign path via real `JwtSigner::sign` calls. Coverage is preserved by the existing test suite already exercising both the new and old implementations through identical entry points. Total still 940 with migrate integration tests. **Schema unchanged** from v0.43.0 (still SCHEMA_VERSION 9). **DO state unchanged**. **Operator note**: bundle size goes DOWN (rsa family removed; WASM bundle should shrink ~5-10% based on similar swaps in other ed25519-only projects). `cargo audit` runs cleaner (no more RUSTSEC-2023-0071 acknowledgment needed). Supply-chain audit trail simpler — cesauth-core's direct deps are now exactly the crypto primitives cesauth actually exercises. No production behavior change — wire format byte-identical; tokens issued before the upgrade verify under the new code; no forced rotation. No `wrangler.toml` change. No new bindings. |
| **Introspection rate limit v0.43.0** | ✅       | Shipped 0.43.0. ADR-014 §Q2 marked **Resolved**. **No new ADR** — implementation mirrors v0.37.0's `/token` per-family rate limit pattern (ADR-011 §Q1) but with a different bucket-key namespace and at a different abstraction layer. Closes the second of ADR-014's three remaining open questions on the introspection endpoint (§Q4 was resolved in v0.41.0; §Q1 + §Q3 remain). **Why this matters**: v0.38.0 shipped `/introspect` with no rate limit. The endpoint requires client authentication, but a compromised confidential client (or a malicious resource server with valid creds) had unbounded ability to (1) probe token existence — each call reveals whether a token is currently active; (2) DoS-amplify — each call hits the `RefreshTokenFamily` DO; (3) starve other RSes' cron-tick budgets. v0.43.0 caps per-client introspection rate. **`cesauth_core::service::introspect::check_introspection_rate_limit`** new pure helper: `(rates, authenticated_client_id, now_unix, window_secs, threshold) -> IntrospectionRateLimitDecision::{Allowed | Denied { retry_after_secs }}`. **Bucket key shape `introspect:<client_id>`** — the authenticated client_id is the natural rate-limit unit. Per-family (v0.37.0 pattern) wouldn't apply because introspection consumes tokens across many families; per-token-jti would let an attacker probing many distinct tokens never hit any single bucket; per-user-id would be wrong because introspection responses don't reveal the user for inactive tokens; per-client-id is correct because RFC 7662 requires authentication so we always have a stable identifier, chatty RS_A doesn't affect RS_B, and legitimate per-RS quotas are operator-configurable. **threshold = 0 disables the gate** (operator opt-out for deployments with upstream rate limits or RSes that legitimately need extreme rates). **`Config` additions**: `introspection_rate_limit_threshold: u32` (env `INTROSPECTION_RATE_LIMIT_THRESHOLD`, default **600**), `introspection_rate_limit_window_secs: i64` (env `INTROSPECTION_RATE_LIMIT_WINDOW_SECS`, default **60**). Default 600/min = 10/sec is sized for resource servers that may introspect on every incoming request — substantially more permissive than v0.37.0's `/token` default of 5/min (which fires specifically on token-replay probing patterns where 5 attempts is already pathological). **Worker handler `crates/worker/src/routes/oidc/introspect.rs`** rate-limit check fires AFTER client authentication (need authenticated client_id as bucket key; unauthenticated attacker shouldn't be able to burn the rate limit on behalf of a victim client_id) and BEFORE any DO lookup or JWT verify (a tripped limit doesn't even reach the family store or signing-key consultation, so DoS amplification is contained). **Wire response on rate limit denial**: HTTP **429 Too Many Requests** with `Retry-After: <secs>` header (RFC 7231 §6.6 + §7.1.3); body code `invalid_request` (RFC 6749 §5.2 catch-all since neither RFC 7662 nor RFC 7009 define a rate-limit error code; matches v0.37.0's `/token` rate-limit precedent and v0.42.0's `/revoke` 429 plumbing). Resource-server clients already handling 429s on `/token` (which they should be) handle `/introspect` 429s identically. **`EventKind::IntrospectionRateLimited`** new audit kind (snake_case `introspection_rate_limited`), payload `{client_id, threshold, window_secs, retry_after_secs}` — distinct from v0.37.0's `RefreshRateLimited` because they're different surfaces with different operational semantics: a spike in `introspection_rate_limited` indicates resource-server polling pathology OR a compromised confidential client used for mass token probing; a spike in `refresh_rate_limited` indicates token-replay probing patterns on `/token`. Operators alert on each independently. **Tests**: 902 → **911** lib (+9). With migrate integration: 934 → **940**. 6 in `service::introspect::tests::rate_limit` (threshold_zero_always_allows, first_n_within_window_allowed_then_n_plus_one_denied, denied_decision_carries_retry_after_secs, rate_limit_is_isolated_per_client_id — the headline per-RS isolation property, rate_limit_resets_after_window_rolls, threshold_one_denies_immediately_after_first_hit). Plus 3 from earlier session work (extract_kid + introspect_token sanity expansions). UI test count unchanged at 230; worker test count unchanged at 171 (handler edits, no new tests; all testable logic in pure core service). **Schema unchanged** from v0.42.0 (still SCHEMA_VERSION 9). **Wire format unchanged** for happy-path introspection — rate-limit denial returns 429 + `Retry-After` (same shape v0.37.0 `/token` established). **No new dependencies**. **Operator note**: two new env vars for tuning (`INTROSPECTION_RATE_LIMIT_THRESHOLD`, `INTROSPECTION_RATE_LIMIT_WINDOW_SECS`); steady-state baseline for `introspection_rate_limited` audit events is **0/day**; non-zero indicates misconfigured RS in tight poll loop (investigate RS-side caching — introspection responses are cacheable for the access token's `exp` window) or compromised client_secret (rotate immediately if no legitimate cause identified). Reuses the existing `CACHE` KV binding for rate-limit buckets — no new bindings required. |
| **RFC 7009 token revocation conformance v0.42.0** | ✅       | Shipped 0.42.0. **No new ADR** — implementation maps directly to RFC 7009; no cesauth-specific decision points beyond spec. Closes a **silent security gap** in v0.27.0's `/revoke`: pre-v0.42.0 the endpoint was fully public — any actor with a refresh token (e.g., obtained from a leaky client) could revoke the underlying family without authenticating, AND could attribute their own `client_id` form field to arbitrarily-issued tokens (cross-client revoke). Per RFC 7009 §2.1 confidential clients MUST authenticate, and §2 says "the authorization server first validates the client credentials and then verifies whether the token was issued to the client making the revocation request" — v0.27.0 did neither. **`cesauth_core::service::client_auth::verify_client_credentials_optional`** new companion to v0.38.0's `verify_client_credentials` — takes `presented_secret: Option<&str>` and returns three-variant `ClientAuthOutcome` (`PublicOrUnknown` / `Authenticated` / `AuthenticationFailed`). The `PublicOrUnknown` conflation preserves the v0.38.0 enumeration-side-channel defense: caller can't tell "unknown client" from "public client" by outcome alone. **`cesauth_core::service::revoke`** new module with pure RFC 7009 logic: `revoke_refresh_token(families, clients, input)` returns four-variant `RevokeOutcome` — `Revoked { family_id, client_id, auth_mode }` (success), `NotRevocable` (token decode failed — malformed input or JWT access token; cesauth doesn't support access-token revocation per RFC 7009 §2's "AS MAY refuse"), `UnknownFamily` (token decoded but family already swept / never existed; idempotent no-op), `Unauthorized { reason }` (auth or cid-binding failed). `RevokeAuthMode` (`PublicClient` / `ConfidentialClient`) distinguishes how an authorized revoke succeeded; `UnauthorizedReason` (`ConfidentialAuthFailed` / `ClientIdCidMismatch`) attributes denials. **RFC 7009 §2 ordering**: authenticate first against the request's `client_id`, then check the cid binding (request's claimed client_id vs token's actual cid). Auth target picked as `input.client_id.unwrap_or(token_cid.as_str())` so: public client with no `client_id` form field passes cid binding trivially (auth target IS the cid); public client with wrong `client_id` form field gets cid mismatch (closes cross-client revoke vector); confidential client with creds authenticates against own client_id, cid binding still enforced (can't revoke another client's token even after authenticating). **Cross-client revoke prevention** is the headline **security improvement**, not just spec conformance — pre-v0.42.0 an attacker who obtained a refresh token belonging to ClientA could submit it with `client_id=AttackerControlledApp` and the endpoint would happily revoke it. v0.42.0's cid-binding gate rejects this with silent 200. **Worker handler `crates/worker/src/routes/oidc/revoke.rs`** rewritten: parses form body via `req.form_data()` (matches v0.38.0 introspection pattern); reuses v0.38.0's `client_auth::extract` for `Authorization: Basic` + form-body credential extraction (Basic precedence per RFC 6749 §2.3.1); resolves requestor's claimed client_id (Basic-creds first, form `client_id` second); calls `revoke_refresh_token`; maps outcome to per-outcome audit-event JSON payload + log line. **Wire response always 200 OK with empty body** per RFC 7009 §2.2 — including `Unauthorized` cases. Returning 401 there would let an attacker probe whether a refresh token belongs to a confidential vs public client by response shape. **`NotRevocable` cases NOT audited** — scanner traffic; would just bloat the audit chain. The other three outcomes emit `EventKind::RevocationRequested` (existing v0.27.0 audit kind, payload extended) with `{outcome, ...}` JSON. **Discovery doc gains `revocation_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"]`** per RFC 8414 §2. The `none` entry is the spec-mandated difference vs `introspection_endpoint_auth_methods_supported`: RFC 7009 §2.1 explicitly allows public-client revocation, RFC 7662 §2.1 doesn't. Spec-conformant clients (`oauth-discovery`-style libraries) auto-pick-up the new field. **`token_type_hint` form param** now parsed (RFC 7009 §2.1) but currently advisory-only — cesauth's revoke implementation always treats input as refresh token; a future release may use the hint to short-circuit refresh decode for `access_token`-hinted tokens. **Tests**: 882 → **902** lib (+20). With migrate integration: 911 → **934**. 6 in `client_auth::tests` for the optional helper (public, unknown, no creds, correct creds, wrong creds, empty secret as defensive). 14 in `service::revoke::tests` (public-no-client_id revokes by token possession, public-client_id-mismatch returns unauthorized — the cross-client revoke prevention pin, confidential correct creds revokes, confidential no-creds returns unauthorized, confidential wrong-secret returns unauthorized, confidential cannot-revoke-other-clients-token — the multi-tenant cross-cid pin, malformed token returns NotRevocable, empty token returns NotRevocable, unknown family returns UnknownFamily, JWT access token returns NotRevocable, token_type_hint parses recognized values, returns None for unknown, repeat-revoke idempotence). 3 in `oidc::discovery::tests` (revocation_endpoint_auth_methods_advertised, includes_none — pins the RFC 7009 §2.1 vs RFC 7662 §2.1 spec difference, in_wire_form). UI test count unchanged at 230; worker test count unchanged at 171 (handler edits, no new tests; testable logic lives in pure core service). **Schema unchanged** from v0.41.0 (still SCHEMA_VERSION 9). **Wire format additive only** — discovery doc gains one field, spec-conformant parsers tolerate. **No new dependencies**. **Operator note**: pre-v0.42.0 `/revoke` was a known security gap (cross-client revoke; no confidential-client auth). v0.42.0 fixes it. Add an audit-dashboard panel breaking down `revocation_requested` events by `outcome` field — the new four-way attribution lets operators distinguish steady-state revoked / cross-client-revoke probing / wrong-creds investigation / stale-client noise. For confidential-client integrations: ensure `client_secret_basic` or `client_secret_post` credentials are sent on `/revoke`; without them revocation silently no-ops. For public-client integrations (mobile apps, SPAs): no action required IF you weren't sending a wrong `client_id` form field. |
| **Multi-key access-token introspection v0.41.0** | ✅       | Shipped 0.41.0. ADR-014 §Q4 marked **Resolved**. **No new ADR** — design choices recorded inline in ADR-014 §Q4's resolved-paragraph. **Two issues, one release**: (1) signing-key rotation correctness — pre-v0.41.0 introspection tried only `keys.first()` (most-recently-added active key), so during a rotation grace period an access token signed with an older but still-active `kid` would falsely report `active=false`. (2) **A P0 latent bug from v0.38.0**: the workspace's `jsonwebtoken-10` was configured with `features = ["use_pem", "ed25519-dalek", "rand"]` deliberately omitting `rust_crypto` to avoid the transitive `rsa` dep flagged by RUSTSEC-2023-0071 (Marvin Attack — sound threat-model call given cesauth never uses RSA). But jsonwebtoken-10 wired the EdDSA verify path through `CryptoProvider::install_default`, which the bare `ed25519-dalek` opt-dep doesn't satisfy. The first real introspection request with a real access token in production would have panicked the worker. Bug existed since v0.38.0 (introspection's introduction) but no CI test exercised the real-JWT verify path until v0.41.0's multi-key work tried to. **`cesauth_core::oidc::introspect::IntrospectionKey<'a>`** new type with `{kid, public_key_raw}` borrowed-by-reference (lifetime ties to the worker's request-scoped signing-key buffer). **`cesauth_core::jwt::signer::extract_kid(token: &str) -> Option<String>`** new helper extracts the JWT header's `kid` member without verifying the signature; `None` on malformed input or kid-less header; the kid is **untrusted at this point** — used only as a hint for key selection, the cryptographic verify still runs against the chosen key. **`introspect_token` signature change**: `public_key_raw: &[u8]` → `keys: &[IntrospectionKey<'_>]`. v0.38.0's behavior is the special case `keys.len() == 1`. **`introspect_access` multi-key strategy**: empty keys → return inactive (deployment misconfigured); else try kid-directed lookup first (fast path: one crypto verify call), fall through to try-each if no kid present / no match in active set / kid-matched key fails verify (defensive); return active on first success, inactive if all fail. **Worker handler update** at `crates/worker/src/routes/oidc/introspect.rs`: builds `Vec<IntrospectionKey>` from `key_repo.list_active()` result; malformed `public_key_b64` entries (b64 decode fails) filtered out with `console_warn!` rather than aborting the whole request — defensive against a single bad key shadowing the whole active set. **CryptoProvider fix in workspace `Cargo.toml`**: enabled `rust_crypto` feature. Trade-off accepted: brings transitive `rsa` v0.9 back in (plus `pkcs1`, `pkcs8`, `num-bigint-dig`, `num-iter`, `num-traits`, `signature` 2.x, `p256`, `p384`, `hmac` — all unused by cesauth). **The dep is dead code from cesauth's perspective**: cesauth has no code path calling `Algorithm::RS{256,384,512}` or `Algorithm::PS{256,384,512}`. Marvin Attack is a side-channel against RSA decryption / signing, not against unused-but-linked code; a linked-but-unreachable `rsa::PrivateKey` does not exercise the vulnerable path. Alternative (a panicking production binary on the first real introspection request) is strictly worse. Future tech-debt sweep should swap to `josekit` + `ed25519-dalek` direct, dropping `rsa` entirely (the v0.4 "WASM caveat" comment in `signer.rs` already anticipates this). **Tests**: 871 → **882** (+11 lib tests, total 911 with migrate integration). 7 new in `service::introspect::tests::multi_key` requiring real Ed25519 verify (single_key_match_verifies_active, multi_key_kid_directed_lookup_picks_correct_key — the headline rotation-grace-period scenario, multi_key_try_each_fallback_when_kid_unknown, forged_kid_with_unknown_signature_rejected, token_signed_by_retired_key_reports_inactive, empty_keys_returns_inactive, refresh_path_isolated_from_empty_access_keys). 4 new in `service::introspect::tests::extract_kid_tests` (extracts_kid_when_present, returns_none_when_kid_absent, returns_none_on_garbage_input, does_not_verify_signature). Tests build JWTs directly via base64url + `ed25519_dalek::Signer` rather than through `jsonwebtoken::EncodingKey` (which expects PKCS#8 DER rather than the raw 32-byte seed; production stores raw 32-byte public keys b64-encoded in `jwt_signing_keys.public_key_b64`, also published as RFC 8037 JWK `x` field via `/jwks.json`). Public-key path uses `DecodingKey::from_ed_der` with the 32 raw bytes, which `jsonwebtoken-10` accepts (inner storage is `SecretOrDer(raw_bytes)` regardless of constructor). The 13 baseline introspect tests still pass; their call sites were migrated from `&FAKE_PUBKEY` to `&fake_keys()` (a one-element slice). UI test count unchanged at 230; worker test count unchanged at 171. **Schema unchanged** from v0.40.0 (still SCHEMA_VERSION 9). **Wire format unchanged**. **Cookies unchanged** (still 7). **Operator note**: resource servers that previously saw spurious `active=false` from `/introspect` (or any case where the worker died on real-token introspection — looked like a 500 / connection drop) now get correct results. No `wrangler.toml` change. No new bindings. **WASM bundle size goes up modestly** due to the unused `rsa` family of deps; if your deployment has tight Worker bundle-size budgets, audit before deploying. |
| **Session-index drift detection v0.40.0** | ✅       | Shipped 0.40.0. ADR-012 §Q1 marked **partially Resolved** (detection shipped, repair deferred to new §Q1.5); §Q5 added documenting the orphan-DO limitation that's structurally unresolvable without Cloudflare DO namespace iteration. **No new ADR** — design choices recorded inline in ADR-012 §Q1's resolved-paragraph, this is a follow-on to ADR-012 not a separate decision tree. Closes half of the operator-visibility gap that v0.35.0 left behind: the daily 04:00 UTC scheduled handler now runs a third pass after `sweep::run` and `audit_chain_cron::run` — `session_index_audit::run` walks the first 1000 active rows of `user_sessions` (oldest-first so long-living drift surfaces even on tables with many newer rows), peeks the corresponding `ActiveSession` DO via `ActiveSessionStore::status`, classifies via the new pure `cesauth_core::session_index::classify` function into one of four `ReconcileOutcome` variants (`InSync`, `DoVanished`, `DoNewerRevoke { do_revoked_at }`, `AnomalousD1RevokedDoActive`), and emits one `EventKind::SessionIndexDrift` audit event per drift detected. **Detection-only, NOT auto-repair**: operational visibility comes before automated D1 mutations — until we have data on drift volume and pattern, we don't know whether automated repair is the right response or whether the appropriate response is "alert a human and let them decide". A high rate of `anomalous_d1_revoked_do_active` would indicate a structural bug in the mirror write paths and the right move is fixing the root cause, not auto-rewriting D1. **`SessionIndexDrift` audit payload**: `{session_id, user_id, drift_kind, do_revoked_at?}` where `drift_kind` is the snake_case discriminator (`do_vanished` / `do_newer_revoke` / `anomalous_d1_revoked_do_active`) and `do_revoked_at` is included only for `do_newer_revoke` so operators can see how stale the D1 mirror was. **Failure semantics**: best-effort, non-transactional. Per-row DO query failures count as a separate `errors` counter (distinguishes "drift" correctness signal from "cron is unhealthy" operational signal); D1 read failure aborts the cron with an error log and re-tries the next day; audit-write failure is silently dropped (drift is real but unsignalled this run, next day's cron will surface it again). **Scope cap of 1000 rows** sized for known cesauth deployments; larger populations need cursor pagination across cron ticks tracked under §Q1.5 follow-up. **Pure classification logic**: `cesauth_core::session_index::classify(d1, do_status) -> ReconcileOutcome` has no I/O — trivially testable. Treats `IdleExpired` and `AbsoluteExpired` DO terminal states the same as `Revoked` from reconcile's perspective (different audit events from v0.35.0 sessions work, but identical "DO is in a terminal state" signal for drift detection). Two defensive arms: (a) `Active` variant whose inner `state.revoked_at.is_some()` (store bug — variant promises active) → treated as `DoNewerRevoke`, closing the drift window rather than panicking; (b) `Revoked` variant whose `state.revoked_at.is_none()` (store bug) → falls back to `created_at` so the outcome carries a usable timestamp and the row still gets classified as drift. **Tests**: 889 → **900** (+11). All 11 in `cesauth_core::session_index::tests`: in_sync_when_both_active, in_sync_when_both_revoked_with_matching_timestamp, do_vanished_when_d1_active_do_notstarted (the classic "phantom row"), do_vanished_when_d1_revoked_do_notstarted (terminal-on-both-sides but DO truly gone), do_newer_revoke_when_d1_still_thinks_active, idle_expired_classifies_as_do_newer_revoke, absolute_expired_classifies_as_do_newer_revoke, do_newer_revoke_when_d1_has_stale_timestamp, anomalous_when_d1_revoked_do_active, plus 2 defensive arms above. Worker cron orchestrator is glue with full coverage delegated to the pure core function — D1-query / DO-peek / audit-write integration tests deferred to a future operational-test PR (workers-rs harness territory). **Schema unchanged** from v0.39.0 (still SCHEMA_VERSION 9). **Cookies unchanged** (still 7). **Wire format unchanged**. **No new dependencies**. **Cron schedule unchanged** (`0 4 * * *` daily — three independent passes now: sweep, audit_chain_cron, session_index_audit; each failure-isolated from the others). **Operator note**: add a dashboard panel for the new `session_index_drift` audit kind. Steady-state baseline is **0 events per day**; non-zero indicates either recent D1 outage (transient, expect spike-then-settle), sweep cascade lag (will self-clear once §Q1.5 ships), or — for `anomalous_d1_revoked_do_active` only — a structural bug worth investigating immediately. **Q1.5 (NEW)**: D1 repair tool. Once we observe a few weeks of `session_index_drift` events in production, ship the repair half: D1 delete for `do_vanished` rows, D1 update for `do_newer_revoke` rows. `anomalous_d1_revoked_do_active` remains alert-only — automated repair would mask whatever upstream bug produced it. Likely shape: worker admin endpoint (auth-gated) plus a `cesauth-migrate sessions repair` CLI wrapper, OR a separate cron switch (`SESSION_INDEX_AUTO_REPAIR=true`) for trusted deployments. Decision blocked on observed data. **Q5 (NEW)**: orphan DOs. Cloudflare doesn't support DO namespace iteration, so a session whose D1 mirror write failed at start time exists in the DO with no D1 row — invisible to v0.40.0's D1-outward reconcile approach. Pre-v0.35.0 sessions are also invisible (no mirror existed when they started). v0.40.0 documents the limitation; resolution path TBD. |
| **i18n-2 continued v0.39.0** | ✅       | Shipped 0.39.0. **No new ADR** — anticipated in ADR-013 ("subsequent releases migrate the rest of the end-user surfaces"). Continues v0.36.0's i18n-2 by migrating the four largest user-facing surfaces from locale-hardcoded prose to catalog-managed bilingual rendering: **login page** (10 keys), **TOTP enroll page** (11 keys), **TOTP verify gate** (11 keys + 1 new `TotpVerifyWrongCode` for the post-handler error re-render — distinct from `TotpEnrollWrongCode` because enroll says "enter LATEST 6-digit code" as a setup hint about TOTP rotation, while verify just says "try again"), **Security Center index** (13 keys, disabled-state TOTP rendering only — enabled-state + recovery-codes status row stays JA-hardcoded pending v0.39.1+ pluralization work tracked under ADR-013 §Q4). MessageKey total: **22 → 70** (+48). All 48 new variants resolve in both Ja and En, statically guaranteed by the lookup match's exhaustiveness. **JA disambiguation for `LoginTitle`**: changed from "サインイン" to "サインインする" to differentiate from `SessionsLabelSignIn` ("サインイン" as session-card sign-in-timestamp label) — verb form is the natural action-prompt rendering anyway. **Catalog completeness tests refactored**: v0.36.0's hardcoded `all_keys` arrays (22 elements) replaced with `for_each_key(closure)` that pins exhaustiveness via a compile-time match. Adding a new variant without adding it to the iterator is now a build error. Bonus: the test grew an `is_legitimate_duplicate` allowlist for shared brand strings + concept-reuse — `"Magic Link"` (brand, identical in both locales), `"Passkey"` / `"パスキー"` (term-of-art shared between session row's `SessionsAuthMethodPasskey` + login's `LoginPasskeyHeading`), `"Active sessions"` / `"アクティブなセッション"` (canonical translation reused between `SessionsPageTitle` + `SecuritySessionsHeading`). **`cesauth_ui::js_string_literal` helper** new in v0.39.0: encodes a `&str` as a double-quoted JavaScript string literal suitable for inlining into `<script>` blocks. Adopted because the migrated login page interpolates the catalog's passkey-failed error message into inline JS, and the naive concatenation would have broken on translations containing quotes, backslashes, newlines, or `</script>` patterns. Specifically escapes `\\` / `"` / `\n\r\t` (named), `0x00..=0x1f` controls (`\uXXXX`), `</` (becomes `<\/` to defeat `</script>` element-end), `<!--` (becomes `<\!--`, defensive). UTF-8 multi-byte sequences pass through unchanged — JS source files are UTF-8; iterates by `char` not byte so JA codepoints never split. **Page migration pattern** matches v0.36.0: each page gets a `_for(.., locale)` variant; the plain function becomes a default-locale shorthand returning Ja. Out-of-tree callers using locale-less shorthands see a behavior change for `login_page` / `totp_enroll_page` / `totp_verify_page` (these were EN-hardcoded pre-v0.39.0; the no-locale shim now returns JA per Default = Ja convention). Worker handlers all use the negotiated `_for` form, so production traffic with normal `Accept-Language` is unaffected. **Worker handler wire-up**: 5 handlers now resolve locale via `crate::i18n::resolve_locale(&req)` once at the top + thread through to `_for` calls — `GET /login` (`routes/ui.rs::login`), `GET /authorize` login fork (`routes/oidc/authorize.rs`), `GET /me/security` (`routes/me/security.rs`, also threads to `flash::display_text_for`), `GET /me/security/totp/enroll` + `POST /me/security/totp/enroll/confirm` wrong-code re-render, `GET /me/security/totp/verify` + `POST /me/security/totp/verify` wrong-code re-render. **Tests**: 867 → **889** (+22). 8 new in `cesauth_ui::tests` for `js_string_literal` (double-quote + backslash, newlines/tabs/CR, multi-byte UTF-8 passthrough with JA payload, `</script>` neutralization, `<!--` neutralization, lone-`<` passthrough, `\uXXXX` control fallback). 14 new in `cesauth_ui::templates::tests` (login EN + JA chrome + JS-literal interpolation EN + JA + default-shorthand-returns-JA, totp_enroll EN + JA chrome + aria-label translation EN + JA, totp_verify EN + JA chrome, security_center EN + JA chrome + EN anonymous-notice translated). core test count unchanged at 342 — the closure-based exhaustive iterator means the same two completeness tests cover all 48 new variants without new test functions. worker test count unchanged at 171 — handler edits, no new tests; existing handler tests assert on structural properties (CSRF, redirects, status codes) not page-text. **Schema unchanged** from v0.38.0 (still SCHEMA_VERSION 9). **Cookies unchanged** (still 7). **Wire format unchanged**. **No new dependencies**. **Deferred to v0.39.1+**: TOTP recovery codes display (`totp_recovery_codes_page` JA-hardcoded), TOTP disable confirm (`totp_disable_confirm_page` JA-hardcoded), magic link request + sent (`magic_link_sent_page` JA-hardcoded), error pages (`error_page` JA-hardcoded), `PrimaryAuthMethod::label()` migration (separable thread — touches admin console too), Security Center enabled-state TOTP + recovery-codes status row (blocked on pluralization work — count-aware "リカバリーコード残 N 個" / "Recovery codes: N remaining" needs CLDR plural rules per ADR-013 §Q4). |
| **RFC 7662 Token Introspection v0.38.0** | ✅       | Shipped 0.38.0. ADR-014 Accepted. First feature-track release after the security-track sprint (v0.34-v0.37) and i18n track (v0.36). Adds the standard server-side "is this token currently active?" endpoint resource servers consult, closing the long-standing gap where refresh tokens were entirely opaque to bearers (v0.4-v0.37 had `/jwks.json` for local access-token JWT verification but no introspection). **`POST /introspect` endpoint**: parses RFC 7662 §2.1 form body (`token`, optional `token_type_hint`), authenticates via `client_secret_basic` (preferred) or `client_secret_post` (fallback), dispatches to access-token JWT verify or refresh-token family DO peek depending on hint+fallback order, returns RFC 7662 §2.2 response shape. **Authentication required**: `none` (PKCE-only) is rejected at this endpoint per RFC 7662 §2.1 — discovery advertises only `client_secret_basic` + `client_secret_post`. **Privacy invariant at the type level**: `IntrospectionResponse::inactive()` is the only public constructor producing `active=false` and accepts no claim arguments — the handler literally cannot accidentally leak. `serde` `skip_serializing_if = "Option::is_none"` on every claim field means inactive wire form is exactly `{"active":false}` (test `inactive_response_serializes_with_only_active_field` pins byte-exact). **Read-only by design**: introspection NEVER triggers reuse detection; a retired jti is reported `active=false` without consuming the family. A malicious resource server with valid introspection credentials must NOT be able to revoke families on demand. **Hint advisory per RFC 7662 §2.1**: cesauth tries the hinted type first, falls through to the other on failure. No-hint or `access_token` hint = access-first (cheaper, no DO round-trip on negative path); `refresh_token` hint = refresh-first. Test `hint_access_with_actually_refresh_token_falls_through_to_refresh_check` pins fall-through correctness. **`cesauth_core::service::client_auth::verify_client_credentials`** new helper: looks up `client_secret_hash` via `ClientRepository`, does constant-time SHA-256-hex compare, conflates "unknown client" / "wrong secret" / "no secret on file" all to `CoreError::InvalidClient` to avoid the enumeration side-channel. SHA-256-of-secret (not Argon2) because `client_secret` is server-minted high-entropy (32+ bytes) — for high-entropy secrets, salted password hashes provide no additional protection. **`cesauth_worker::client_auth`** new module: `extract_from_basic` parses `Authorization: Basic` with full RFC 6749 §2.3.1 percent-decoding semantics (`%XX` and `+`-to-space), `extract_from_form` reads form-body credentials, `extract` dispatches Basic-or-form. **Form fallback ONLY when no Authorization header is present at all** — a malformed Basic does NOT fall through to form (would be a probing surface). **Discovery document gains two fields**: `introspection_endpoint` + `introspection_endpoint_auth_methods_supported` (excludes `none`). Test `discovery_introspection_endpoint_requires_authentication` pins both invariants. **New audit kind `EventKind::TokenIntrospected`** (snake_case `token_introspected`). Payload `{introspecter_client_id, token_type, active}`. The token itself is **deliberately not in the payload** — including it would defeat the inactive-privacy invariant (an audit row with the token would let anyone with audit access deduce whether the token was valid at the time, which is exactly what the inactive response is supposed to hide). `token_type` is `"none"` when `active=false` (another privacy property: an attacker with audit access can't distinguish "JWT signature mismatch" from "retired refresh jti"). **Tests**: 839 → **867** (+28). 8 in `service::client_auth::tests` (correct/wrong secret, unknown client, public client no secret, empty secret, SHA-256 known vectors per RFC 6234, constant-time helper). 13 in `service::introspect::tests` (active refresh full claims, retired-jti privacy invariant verifying ALL claim fields are None, revoked family inactive, unknown family inactive, malformed token MUST be inactive not 400, empty token, hint fallback both directions, hint parser registered values + ignores unknown, type-level invariants for ctor + byte-exact wire form + Bearer access + non-Bearer refresh). 6 in `cesauth_worker::client_auth::tests` (percent-decode passthrough, escape, plus-to-space, truncated returns None, invalid hex returns None, hex-digit lookup table). 1 in `oidc::discovery::tests` (`discovery_introspection_endpoint_requires_authentication`). **Schema unchanged** from v0.37.0 (still SCHEMA_VERSION 9). **Cookies unchanged** (still 7). **Wire format**: adds **`POST /introspect`** as new endpoint; discovery document gains two additive fields (spec-conformant parsers tolerate). **No new dependencies** — sha2 + base64 already in tree. **Operator note**: provision a confidential client per resource server via admin console (32-byte URL-safe random secret, SHA-256 hash stored, plaintext shown once and never recoverable); audit dashboards should add a panel for `token_introspected`; resource servers using `oauth-discovery`-style libs auto-pick-up the new endpoint URL. **Latent issue surfaced + partially addressed**: `ClientRepository::client_secret_hash` was added in v0.4 but never consulted — `/token` endpoint accepts public clients only and didn't verify confidential-client secrets. v0.38.0 adds the verification helper that introspection uses; future work may extend it to `/token` for confidential-client paths. **Open questions Q1-Q4** in ADR-014 for future scheduling: resource-server-typed clients (today any registered confidential client can introspect any token — multi-tenant deployments need audience scoping), per-resource-server rate limit, audit retention policy for chatty introspecters, multi-key access-token verification during signing-key rotation grace period (today tries only most-recently-added active key; refresh-introspection fallback covers most cases). |
| **Per-family rate limit on /token v0.37.0** | ✅       | Shipped 0.37.0. ADR-011 §Q1 marked **Resolved**. Closes the rate-limiting gap deferred from v0.34.0's refresh-token-reuse hardening: v0.34.x atomically revoked a family on first reuse detection (BCP-correct), but until-the-first-reuse an attacker with a leaked-but-current refresh token could blast the rotation endpoint in tight loop and either win a race against the legitimate party or exhaust the family's `retired_jtis` ring (size 16). v0.37.0 bounds rapid retry with a per-family rate gate that fires *before* the family DO is consulted. **`Config::refresh_rate_limit_threshold`** (default 5, `REFRESH_RATE_LIMIT_THRESHOLD` env, 0 disables) + **`refresh_rate_limit_window_secs`** (default 60, `REFRESH_RATE_LIMIT_WINDOW_SECS` env). **`CoreError::RateLimited { retry_after_secs }`** new variant — distinct from `RefreshTokenReuse` because rate limit fires before family DO consultation; the two are separable signals. `retry_after_secs` sourced from existing `RateLimitDecision::resets_in`. **`rotate_refresh` signature change**: now takes a `RateLimitStore` generic + threshold + window in the input. Check happens after `decode_refresh` (we need `family_id` for the bucket key) but before `families.rotate(...)` so a tripped limit doesn't even touch the family DO. **Bucket key shape `refresh:<family_id>`** — `family_id` is the right namespace: per-jti would not catch leaked-token replay (each attempt may carry a different stale jti); per-user_id would have unrelated apps interfere; per-family_id catches "rapid attempts against one logical session" exactly. **Wire response**: HTTP **429 Too Many Requests** with `Retry-After: <secs>` header (RFC 7231 §6.6 + §7.1.3); body code `invalid_request` (RFC 6749 §5.2 catch-all since RFC 6749 doesn't define a rate-limit code). `Retry-After` clamped to a minimum of 1 second so the header is always actionable. **New audit kind `EventKind::RefreshRateLimited`** (snake_case `refresh_rate_limited`). Payload `{family_id, client_id, threshold, window_secs, retry_after_secs}`. `family_id` decoded via the existing v0.34.0 `decode_family_id_lossy` audit-only decoder so a malformed token doesn't fail-close the audit write. **Independence from reuse detection**: a client that hits the rate limit gets `RateLimited`; the same client subsequently presenting a stale jti once the gate clears would see `RefreshTokenReuse`. The two audit kinds are independently alertable — a high rate of `refresh_rate_limited` without matching `refresh_token_reuse_detected` indicates someone is probing without (yet) having a valid jti. **Tests**: 833 → **839** (+6). 3 in `cesauth-adapter-test::store::tests` pinning the bucket-key pattern (`refresh_rate_limit_first_5_within_window_allowed_6th_denied`, `refresh_rate_limit_isolated_per_family_id` — fam_A's saturated bucket must NOT affect fam_B, `refresh_rate_limit_resets_after_window_rolls`). 3 in `cesauth_worker::error::tests` (`rate_limited_maps_to_http_429`, `rate_limited_status_is_independent_of_retry_after` for stable wire status across `retry_after_secs` values, `rate_limited_status_distinct_from_other_4xx_oauth_errors` to catch accidental table-mapping changes). **Schema unchanged** from v0.36.0 (still SCHEMA_VERSION 9). **Cookies unchanged** (still 7). **No new dependencies**. **Existing `RateLimitStore` reused** — the in-memory + Cloudflare KV adapters in v0.31.x already had the right surface (`hit(bucket_key, now, window, limit, escalate_after) -> RateLimitDecision`); v0.37.0 just calls them with a new bucket-key namespace. **No new ADR** — design choices (bucket key namespace, threshold default, RFC 7231 status selection) recorded inline in ADR-011 §Q1's resolved-paragraph; this is a follow-on to ADR-011 not a separate decision tree. **Operator note**: audit dashboards should add a panel for `refresh_rate_limited` to monitor for brute-force / scanning attacks. **Forward**: feature track candidate next = RFC 7662 Token Introspection; i18n-2 continued (login + TOTP page chrome migration); future security-track items still open are ADR-012's Q1-Q3 (D1-DO reconciliation tool, user notification on session timeout, device fingerprint columns) and ADR-013's Q2 (tenant-default locale). |
| **i18n track infrastructure v0.36.0** | ✅       | Shipped 0.36.0. ADR-013 Accepted. Pays the i18n debt from `crates/worker/src/flash.rs:215`'s v0.31.0 TODO ("Translations are out of scope for v0.31.0; future i18n would replace this lookup with one keyed by Accept-Language"). Ships **i18n-1 + partial i18n-2** in the ROADMAP phasing. Pre-v0.36.0 baseline: end-user UI was language-mixed without negotiation — TOTP / Security Center / login / sessions surfaces hardcoded JA, admin console hardcoded EN, machine error bodies EN, no `Accept-Language` handling, no message catalog. **`cesauth_core::i18n` module**: closed `Locale` enum (Ja, En; `Default = Ja` to preserve existing behavior for users without `Accept-Language`), closed `MessageKey` enum (22 variants for v0.36.0: 5 flash banners + 1 TOTP wrong-code + 16 sessions-page chrome), `lookup(MessageKey, Locale) -> &'static str` with compile-time exhaustive coverage of both axes (adding a key without a translation in every locale is a build error). **`parse_accept_language` RFC 7231 §5.3.5 q-value-aware parser**: handles empty header, single tag, q-value priority, `q=0` drop per RFC, wildcard `*` mapping to default, missing or malformed q value treated as 1.0 (lenient), region subtag stripping (`ja-JP` → `ja`, `en-US` → `en` — full RFC 5646 region/script awareness is i18n-4, deferred until real demand surfaces), tie-breaking in document order. **`cesauth_worker::i18n::resolve_locale(&Request) -> Locale`**: per-request negotiation entrypoint reading `Accept-Language`. The resolved locale is **stable for the request duration** (re-resolving per template would risk a single response with mixed locales). Future iterations may layer on user-pref cookie + tenant default (cookie → tenant → header → default). **Backward-compatible migration pattern**: each migrating call site adds a `_for(..., locale)` variant; the plain function becomes a default-locale shorthand. So `sessions_page(items, csrf, flash) -> sessions_page_for(items, csrf, flash, Locale::default())`. Existing callers and tests continue to work unchanged; new call sites adopt locale-awareness incrementally. **Migrated surfaces in v0.36.0**: (1) **flash banners** — `FlashKey::display_text_for(locale)` routes through `lookup`; `FlashKey::message_key()` exposes the catalog key for direct use; legacy `display_text()` is the default-locale shim. (2) **`flash::render_view_for(flash, locale)`** — locale-aware Flash → FlashView projection. (3) **`/me/security/sessions` chrome** — page title, intro, empty state, back link, current-device badge, current-device disabled button + title, revoke button, four auth-method labels (passkey, magic_link, admin, unknown), four session-meta labels (sign-in, last-seen, client, session-id). (4) **TOTP enroll wrong-code error** — `TotpEnrollWrongCode` key. (5) **`/me/security/sessions` handler** wired up — `resolve_locale(&req)` at the top, threads through to `sessions_page_for` and `render_view_for`. **Tests**: 808 → **833** (+25). 20 in `cesauth_core::i18n::tests`: locale parsing (`from_primary_subtag` case-insensitive + region-stripping + unknown returns None), Accept-Language edge cases (empty, single supported, region subtag, q-value priority both directions, q-value default 1.0, typical browser header for both ja and en, q=0 dropped, wildcard, all-unsupported falls through, malformed q lenient, whitespace-tolerant, tie-break in document order), catalog completeness (`every_message_key_resolves_in_every_locale_to_nonempty`, `no_two_keys_share_text_within_a_locale`). 5 in `cesauth_ui::templates::tests` for `sessions_page_for` English rendering (chrome strings, method labels, revoke button, current-device badge, default shorthand still produces JA). **Schema unchanged** from v0.35.0 (still SCHEMA_VERSION 9). **Cookies unchanged** (still 7). **Wire format unchanged** for OAuth/OIDC clients. **No new dependencies**. **Why-not-runtime-catalogs**: `fluent-rs` / `gettext-rs` would bring runtime parsing of `.ftl` / `.po` / `.mo` files and the surface area that comes with that; cesauth has 22 keys at v0.36.0 — a closed Rust enum is the right tool for this size. Reconsider when key count exceeds ~200, where the recompile-to-add-a-string friction starts to matter. **Macro-generated lookup** also rejected for v0.36.0: the long-form match is greppable, reviewable, IDE-jumpable; reconsider when catalog grows past 100 keys. **Open questions Q1-Q4** in ADR-013 for future scheduling: user-pref cookie at `/me/preferences` to override Accept-Language, tenant-default locale, date/time format localization (needs timezone awareness which cesauth has none of yet), pluralization (CLDR rules differ by language — v0.36.0 has zero strings needing it; if one is added, the locale-aware integer-substitution facility comes with it). |
| **Session hardening v0.35.0** | ✅       | Shipped 0.35.0. ADR-012 Accepted. Closes the v0.4 — v0.34.0 session-management gaps surfaced by an audit against NIST 800-63B §4.1.3 + OWASP ASVS V3.3.4. **Five gaps closed**: (1) idle timeout enforcement, (2) per-user session enumeration, (3) `/me/security/sessions` user-facing page with per-row revoke buttons, (4) `me::auth::resolve_or_redirect` switched from `status()` to `touch()` (load-bearing fix — without this the timeout config would be dormant, AND `last_seen_at` was never advancing past `created_at` in v0.34.x, a pre-existing structural bug), (5) audit event split. **Idle timeout** via `Config::session_idle_timeout_secs` (default 30 min, env `SESSION_IDLE_TIMEOUT_SECS`, 0 disables); check happens **inside the DO `Touch` command** atomic with the touch update — peek-then-decide in the worker would open a small race window. **`SessionStatus`** gains `IdleExpired(SessionState)` + `AbsoluteExpired(SessionState)` variants populated atomically with the DO state mutation. **`ActiveSessionStore::touch` signature change** now takes `(session_id, now_unix, idle_timeout_secs, absolute_ttl_secs)` — keeps the store transport-agnostic (in-memory adapter doesn't have a Config). **Order of timeout checks**: absolute first, then idle. A session past both gates reports `AbsoluteExpired` (the deeper cause); pinned by `session_touch_absolute_takes_priority_over_idle`. **Per-user session enumeration**: `ActiveSessionStore::list_for_user(user_id, include_revoked, limit)` port method. **DO + D1 hybrid** for the index — three alternatives considered (second `UserSessionIndex` DO, namespace iteration, D1 secondary index), chose D1 as the lightest. `ActiveSession` DO remains source of truth for individual session state; `user_sessions` D1 table provides per-user enumeration. Adds migration **0009_user_session_index.sql** (SCHEMA_VERSION 8 → 9). Mirror columns: `session_id PRIMARY KEY`, `user_id INDEX`, `created_at`, `revoked_at`, `auth_method`, `client_id`. **`last_seen_at` deliberately NOT mirrored** — hot-path mutable in the DO; mirroring would multiply D1 write load by request volume. User-facing list shows `created_at` as approximate "last activity"; if a future UI iteration needs precise rendering it can peek the DO per-row. Two stores eventually consistent for index columns; DO is always the authoritative "newer". **Best-effort D1 mirror** on every DO write — a D1 hiccup must not unwind a successful DO operation. **`/me/security/sessions` page**: lists active sessions newest-first, each row shows auth method (passkey / magic link / admin), client id, sign-in time, approximate last activity, shortened session id (first 8 chars), revoke button. **Current session's button disabled** with a "この端末" badge — revoking the session you're currently using should go through the regular logout flow, not surprise the user via this list. **`POST /me/security/sessions/:session_id/revoke`**: CSRF-guarded, refuses self-revoke, ownership check via `store.status()` (defensive 403 if target's user_id doesn't match requester's; depth-of-defense for the unlikely UUIDv4-forge case), already-revoked / never-started returns silent success (no session-id existence leak), audit emits `session_revoked_by_user` with `{session_id, revoked_by, actor_user_id}` payload, redirect with `SessionRevoked` flash. **Audit event split**: `SessionRevokedByUser`, `SessionRevokedByAdmin`, `SessionIdleTimeout`, `SessionAbsoluteTimeout`. Legacy `SessionRevoked` retained for backward compat with v0.4 — v0.34.x audit chain rows. Operator-facing dashboards monitoring for "someone is forcibly logging users out" can now distinguish admin-action from auto-expiry. **`me::auth::resolve_or_redirect`** dispatches the new audit kinds on touch outcome (`IdleExpired` → `session_idle_timeout`, `AbsoluteExpired` → `session_absolute_timeout`); both best-effort writes so a downstream audit-store outage doesn't leave the user stuck on an error page. **New `flash::render_view` helper** centralizing `Flash → FlashView` projection. **New `FlashKey::SessionRevoked`** (level Success). **Cross-link from Security Center** — `/me/security` now has an アクティブなセッション section linking to the new page. **Tests**: 783 → **808** (+25). 11 in `adapter-test::store::tests` (touch-bumps-last-seen, idle-fires-when-stale, idle-disabled-with-zero, absolute-fires, absolute-priority-over-idle, idempotent-on-revoked, unknown-id-NotStarted, list-returns-only-user-newest-first, list-excludes-revoked-by-default, list-includes-revoked-with-flag, list-respects-limit, list-empty-on-unknown-user — minus 1 = 11). 7 in `cesauth_ui::templates::tests` for `sessions_page` (empty state, listing, current-device disable, revoke-form rendering, CSRF escaping, flash splice, back-link). **Schema**: SCHEMA_VERSION 8 → 9; one D1 migration. **Wire format unchanged** for OAuth/OIDC clients. **Existing sessions don't appear in `user_sessions`** — index populated on `start`, sessions started before v0.35.0 deploy aren't backfilled (DO namespace iteration isn't possible). Users see only post-upgrade sessions in their list page; pre-existing sessions remain authoritative-but-invisible until they expire. Documented in upgrade notes. **`session-id rotation on login`** was already correct in v0.34.x via `complete_auth_post_gate` minting `Uuid::new_v4` per successful auth — preserved verbatim, no v0.35.0 change. **Open questions Q1-Q4** in ADR-012 for future scheduling: D1-DO reconciliation tool for index drift, user notification on idle/absolute timeout, geographic / device-fingerprint columns, bulk "revoke all other sessions" button. |
| **Refresh token reuse hardening v0.34.0** | ✅       | Shipped 0.34.0. ADR-011 Accepted. Closes the **observability** gaps an audit of v0.33.0 against RFC 9700 §4.14.2 / OAuth 2.0 Security BCP §4.13 surfaced. Family-based rotation invariant ("first reuse atomically revokes the family") was already implemented and atomic since v0.4 — single-writer `RefreshTokenFamily` DO with `current_jti` + `retired_jtis` ring (size 16), `fam.revoked_at` set in same `storage.put` as the rest of the rejection path. v0.33.0 baseline COULD detect reuse but COLLAPSED reuse with routine refresh failures into one audit event (`token_refresh_rejected`) and one error (`InvalidGrant("refresh token revoked")`). v0.34.0 splits both. **`FamilyState` gains `reused_jti` / `reused_at` / `reuse_was_retired`** — all `#[serde(default)]` so existing DO storage records deserialize unchanged (no migration). The `was_retired` distinction is the v0.34.0 forensic gain: `Some(true)` = real-but-rotated-out token replayed (= classic leaked-session case), `Some(false)` = wholly unknown jti (= forged or shotgun attempt). Operators prioritize alerts on the higher-signal subcase. **Admin-initiated `revoke()` does NOT populate reuse fields** (those are reserved for actual reuse detection — admin revoke must not look like reuse). **Once a family is revoked, subsequent rotation attempts do NOT overwrite recorded forensics** (first reuse is the investigation anchor; later attacker pokes are recorded only as `AlreadyRevoked` outcomes). Both invariants tested: `admin_revoke_does_not_populate_reuse_forensics`, `refresh_reuse_then_more_attempts_preserve_first_forensics`. **`RotateOutcome::ReusedAndRevoked` carries `{ reused_jti, was_retired }` payload** so the service layer doesn't need to peek the family again. **New `CoreError::RefreshTokenReuse { reused_jti, was_retired }`** distinct from `InvalidGrant`; service layer `rotate_refresh` dispatches by outcome. **Same wire response for both error variants** (`error: "invalid_grant"`, HTTP 400) — distinguishing externally would let attackers probe whether a presented jti is currently in the retired ring (= a real-but-rotated-out token) vs wholly unknown — the BCP §4.13 / spec §10.3 internal/external separation. The `(code, status)` decision is extracted as `pub(crate) fn oauth_error_code_status(&CoreError) -> (&'static str, u16)` so wire-equivalence properties can be unit-tested without constructing a wasm-backed `worker::Response` (which panics on the host test target — same constraint v0.32.1 hit and worked around). **New audit event `EventKind::RefreshTokenReuseDetected`** (snake-case `refresh_token_reuse_detected`); emitted ONLY on `CoreError::RefreshTokenReuse`; payload JSON `{family_id, client_id, presented_jti, was_retired}`. `family_id` decoded via `decode_family_id_lossy` — audit-only lossy decoder that returns `"<malformed>"` rather than fail-closing on a malformed token (losing the audit signal is worse than recording an empty family_id; the authoritative decoder used by the rotation path stays in core where its errors propagate normally). **Tests**: 777 → **783** (+6). 3 forensic-field tests in `cesauth-adapter-test::store::tests`: strengthened `refresh_reuse_burns_family` (now pins `reused_jti`, `was_retired`, `reused_at`, plus the post-revoke peek invariants), `refresh_reuse_with_unknown_jti_marks_was_retired_false` (the BCP signal that distinguishes 'real token leaked' from 'attacker guessing'), `refresh_reuse_then_more_attempts_preserve_first_forensics`, `admin_revoke_does_not_populate_reuse_forensics`. 3 error-mapper wire-equivalence tests in `cesauth_worker::error::tests`: `refresh_token_reuse_maps_to_same_wire_code_and_status_as_invalid_grant`, `refresh_token_reuse_same_response_regardless_of_was_retired`, `refresh_token_reuse_uses_invalid_grant_per_rfc_6749`. **Schema unchanged** from v0.33.0 (SCHEMA_VERSION still 8); no migration. **Cookies unchanged** (still 7). **Wire format unchanged** for OAuth clients — refresh-token reuse produces byte-identical HTTP response to legitimate revocation. **mdBook ADR section** updated: ADR-010 `(Draft)` annotation removed (it graduated to Accepted in v0.33.0), ADR-011 added to `SUMMARY.md` and the ADR README index. **Operator dashboards may need a panel update** to alert on the new `refresh_token_reuse_detected` kind specifically; the generic `token_refresh_rejected` no longer fires for reuse. **Open questions Q1-Q3** documented in ADR-011 for future scheduling: per-family rate limiting on `/token` refresh attempts, user-facing notification on reuse detection, tenant admin aggregate view of recent reuse events. |
| **Audit log hash chain Phase 2 v0.33.0** | ✅       | Shipped 0.33.0. ADR-010 Draft → **Accepted**. Active verification + tamper detection + checkpoint defense ship on top of the v0.32.0 chain mechanism. **Pure-ish verifier in core**: `cesauth_core::audit::verifier::verify_chain` (incremental, resumes from a checkpoint) + `verify_chain_full` (operator-triggered, ignores checkpoint). Both functions take trait-bounded `AuditEventRepository` + `AuditChainCheckpointStore` references — same Approach 2 pattern as v0.32.1 TOTP handlers (port-level IO in scope, Env touching not). **New port `AuditChainCheckpointStore`** with two records: `AuditChainCheckpoint` (`last_verified_seq`, `chain_hash`, `verified_at`) for resume + cross-check, and `AuditVerificationResult` (`run_at`, `chain_length`, `valid`, `first_mismatch_seq`, `checkpoint_consistent`, `rows_walked`) for admin UI. **In-memory adapter** in `cesauth-adapter-test` (with `with_checkpoint` pre-seed helper for wholesale-rewrite test scenarios). **Cloudflare KV adapter** (`CloudflareAuditChainCheckpointStore`) in `cesauth-adapter-cloudflare`: per-key layout under reserved `chain:` prefix in the existing `CACHE` namespace (`chain:checkpoint`, `chain:last_result`); no TTL on either (operational records, not cache values); no new wrangler binding. **Dual-store design** is the wholesale-rewrite defense: an attacker who compromises D1 still has to compromise KV synchronously to evade detection. Asymmetric difficulty is the value. **New repository method `fetch_after_seq(from, limit)`** on `AuditEventRepository`: returns rows with `seq > from` in ascending order, hard-cap 1000. Verifier uses paged walks (page size = 200) so memory stays bounded regardless of chain length. **Daily cron** at 04:00 UTC piggybacks on existing sweep schedule — `scheduled` event handler invokes both `sweep::run` and `audit_chain_cron::run` independently, failure in one doesn't block the other. **Admin verification UI** at `/admin/console/audit/chain`: status badge (✓ valid / ⛔ tamper-at-seq-N / ⛔ chain history mismatch / no runs yet), checkpoint metadata (seq + chain_hash + when), growth-since-checkpoint hint, CSRF-guarded "Verify chain now (full re-walk)" POST form. Cross-linked from the existing audit search page. Stale "R2 prefix" copy on the audit search form removed (carried over from pre-v0.32.0 R2 backend). **Failure semantics**: tamper detection persists failing result to KV (admin UI surfaces alarm) + logs at `console_error!` + does NOT advance checkpoint (next cron retries from same point — investigation gate). cesauth KEEPS WRITING audit events on tamper detection (chain is forensic, not runtime gating; refusing to write would let an attacker who forged a mismatch take audit log offline; ADR-010 §Q3). Storage outage during verification propagates as PortError so operator sees "verifier couldn't run" distinctly from "verifier ran and found tamper". **Tests**: 757 → **777** (+20). 4 fetch_after_seq pagination tests in adapter-test in-memory audit. 10 end-to-end verifier integration tests covering payload edits, chain_hash edits, intermediate row deletion, wholesale rewrite (the case the chain alone can't catch — caught here via checkpoint cross-check), tampered genesis row sentinel, idempotent re-runs, full re-verify resets the cross-check. 6 UI rendering tests for the chain status template (empty / valid / tamper-at-seq / wholesale-rewrite / growth-since-checkpoint / CSRF token wiring). **Rust dev-dep cycle workaround** surfaced and documented: `cesauth-core` dev-depending on `cesauth-adapter-test` produces duplicate trait artifacts (each compilation unit ends up with its own version of the port traits, breaking the impl resolution). Workaround: verifier integration tests live in `cesauth-adapter-test::audit_chain::tests` instead of `cesauth-core`. Documented in the verifier module's closing comment for future similar abstractions. **Open Questions** Q1 (checkpoint location) and Q3 (in-flight write behavior on tamper) closed in this release. Q2 (input format rotation), Q4 (per-tenant retention), Q5 (user-facing audit view) remain open. **Schema unchanged** from v0.32.0 (SCHEMA_VERSION still 8); no migration. **Cookies unchanged** from v0.32.0 (still 7). **Operator runbook** added to `docs/src/expert/audit-log-hash-chain.md`: what runs and when, what verification checks, where the checkpoint lives, how to read the status page, how to trigger full re-verify, what to do when a tamper alarm fires (investigation recipe + KV inspection commands). |
| **Audit log hash chain Phase 1 v0.32.0** | ✅       | Shipped 0.32.0. ADR-010 Draft establishes a SHA-256 hash chain over audit events. **Source of truth = D1**, not R2. Case C chosen during planning over case B (R2 + parallel chain ledger) because two-store design would fork the chain under concurrency, expose cross-store consistency hazards permanently, and force N+1 reads. The R2 `AUDIT` bucket binding is removed from `wrangler.toml` entirely; no maintenance code left for the deprecated path. **D1 schema migration `0008_audit_chain.sql`** introduces `audit_events` (seq AUTOINCREMENT, id UNIQUE, ts, kind, indexed metadata fields, payload, payload_hash, previous_hash, chain_hash, created_at) plus three indexes ((ts), (kind, ts), partial (subject) WHERE NOT NULL) and a genesis row at seq=1. SCHEMA_VERSION 7→8. **`cesauth_core::audit::chain`** new pure-function module (~150 lines) with `compute_payload_hash`, `compute_chain_hash` over canonical byte layout `prev || ":" || payload_hash || ":" || seq || ":" || ts || ":" || kind || ":" || id`, plus verify functions for Phase 2 + genesis sentinels. **`cesauth_core::ports::audit::AuditEventRepository`** trait replaces v0.31.x AuditSink. **In-memory + D1 adapters** implement it; the D1 adapter handles concurrent writers via UNIQUE-collision retry (budget 3). **Worker `audit::write` rewritten internally** — signature compatible (90 call sites unchanged); internals serialize once and hand to repo.append. **`CloudflareAuditQuerySource` rewritten** D1 SELECT instead of R2 list+fetch (N+1 → one query). **Admin metrics**: audit_events added to `D1_COUNTED_TABLES`, `r2_metrics` removed. **`/__dev/audit` route** rewritten. **`docs/src/expert/audit-log-hash-chain.md`** new operator chapter (~250 lines). **R2 audit references purged** across deployment docs (production, preflight, backup-restore, wrangler, data-migration, cron-triggers, environments, storage, logging, ADR-005). **Project-status framing softened across the project** per user instruction: removed "pre-1.0" and "production-ready" claims/badges from README, CHANGELOG, ROADMAP, TERMS_OF_USE, introduction.md, tenancy.md; "production deployment" as deployment-environment label preserved. ADR-010 graduates to Accepted at v0.33.0 after Phase 2 ships. Total **717 passing** (+39 from v0.31.0: 25 chain-hash tests in core, 14 in-memory repository tests in adapter-test). |
| **TOTP handler integration tests v0.32.1** | ✅       | Shipped 0.32.1 (deferred P1-B from v0.31.0). Internal-only refactor release: zero wire-surface change, zero schema change, zero deployment-affecting change. Six TOTP handlers (`disable::post_handler`, `recover::post_handler`, `verify::get_handler`, `verify::post_handler`, `enroll::get_handler`, `enroll::post_confirm_handler`) refactored into pure-ish `decide_X` functions plus thin Env-touching handler wrappers — Approach 2 from the v0.32.0 planning discussion. Each decision function takes trait-bounded `&impl Repo` references, returns an enum capturing the outcome plus any data the handler needs (`user_id`/`auth_method`/`ar_fields` for `complete_auth_post_gate`, `secret_b32` for re-render, `plaintext_codes` for the recovery page). Tests construct in-memory adapters from `cesauth-adapter-test` and exercise the full branch table per handler. **Decision-extraction pattern**: decisions DO perform port-level IO (`take`/`put` on challenge store, `find_active_for_user`, `update_last_used_step`, `confirm`, `bulk_create`) — these are part of the domain semantics, not response-building concerns, and they go through trait references that tests can satisfy with in-memory adapters. **`unimplemented!()` stub repos** used to pin port-surface regressions: stub methods that the decision under test should NOT call panic if invoked, so a passing test is evidence the decision didn't widen its port contract. **Test infrastructure**: `crates/worker/Cargo.toml` gained a `[dev-dependencies]` block adding `tokio` (workspace) for `#[tokio::test]` async runtime + `cesauth-adapter-test` (workspace) for the in-memory port impls. No production dependencies changed. **Coverage breakdown**: disable +5, recover +10, verify::get +4, verify::post +9, enroll::get +4, enroll::post_confirm +8 = 40 new integration tests. Plus 5 pre-existing `attempts_exhausted` boundary tests and 2 `DISABLE_SUCCESS_REDIRECT` constant pins preserved verbatim from v0.31.0. **Release decision**: shipped as v0.32.1 (option α from the planning discussion) on top of v0.32.0 rather than as a separate v0.31.x branch — main moves forward with the audit-chain release, the deferred test work lands as a patch on the current line. CHANGELOG and ROADMAP both frame this clearly. 717 → **757** total tests (+40). User explicitly authorized "保守性向上、拡張性向上を考慮した上で、コード変更を惜しまず、必要であれば破壊的な変更も許容する" during the v0.32.0 planning conversation; this release exercises that latitude with the handler-signature-compatible refactor. |
| mdBook documentation                   | ✅       | `docs/`                                            |

---

## Planned (0.x)

Approximate priority order. Items near the top are closer to being
started.

> **Engineering specs**: as of v0.50.1, items in this section that
> are ready to be implemented have a corresponding RFC under
> [`rfcs/`](../rfcs/). RFCs are the implementation handover spec
> (what to build, how to test it); this ROADMAP tracks the theme;
> ADRs in `docs/src/expert/adr/` track the design decisions.

### Next minor releases

- ✅ **v0.51.2 — RFC 005 (`cargo fuzz` for JWT parser).**
  Patch release. `fuzz/` crate (NOT workspace member) + one fuzz target
  (`jwt_parse`) exercising `verify` and `verify_for_introspect` under
  libFuzzer. 10-file seed corpus. GH Actions one-shot job (60 s) on PRs
  touching JWT or fuzz code. `.gitignore` and workspace comment updated.
  Zero production code change.

- ✅ **v0.51.1 — RFC 004 + RFC 003 (WebAuthn typed errors + proptest).**
  Patch release. Additive wire change (`kind` field on WebAuthn errors)
  + dev-dep addition only.

  **RFC 004**: `cesauth_core::webauthn::error` — `WebAuthnErrorKind` enum
  with six variants and `classify(detail) -> WebAuthnErrorKind`. Worker
  `oauth_error_response` surfaces `kind` in the JSON body for WebAuthn
  failures only; diagnostic detail stays server-side (audit + logs).
  10 unit tests + 3 worker error-shape pins.
  **RFC 003**: `proptest = "1"` as workspace dev-dep. Two new property-based
  test modules: `jwt/proptests.rs` (5 properties — sign/verify round-trip,
  single-byte tamper, wrong-key rejection, magic-link round-trip, tamper
  rejection) and `oidc/authorization/redirect_uri_proptests.rs` (7 properties
  — exact-match, no-trailing-slash, no-suffix, port-explicit-vs-default,
  http-vs-https, case-sensitive). 481 core tests pass (was 459).

- ✅ **v0.51.0 — RFC 010 + RFC 002 (MagicLinkMailer port + schema drift fix).**
  Minor bump because RFC 010 introduces operator-visible configuration knobs
  (three optional env vars for the HTTPS provider adapter).

  **RFC 010**: `MagicLinkMailer` trait (`cesauth-core::magic_link::mailer`)
  with `MagicLinkPayload`, `MagicLinkReason`, `DeliveryReceipt`, `MailerError`.
  Four reference adapters in `cesauth-adapter-cloudflare::mailer`:
  `DevConsoleMailer` (local dev only, never logs OTP), `UnconfiguredMailer`
  (default fallback, audits misconfig), `ServiceBindingMailer` (CF service
  binding to operator mail worker — preferred), `HttpsProviderMailer`
  (SendGrid v3-compatible POST). Worker factory `crate::adapter::mailer::from_env`
  selects the adapter from env. Both Magic Link issuance routes
  (`routes::magic_link::request`, `routes::api_v1::anonymous` promote path)
  now call the mailer port instead of writing to the audit log. Two new audit
  kinds: `MagicLinkDelivered`, `MagicLinkDeliveryFailed` (keyed on `kind`
  field: `transient` / `permanent` / `not_configured`). ADR-015 Accepted.
  New operator chapter `docs/src/deployment/email-delivery.md`.
  **RFC 002**: `migrations/0001_initial.sql` column comment corrected from
  `argon2id(secret)` to `sha256_hex(secret)`. `service::client_auth` module
  doc updated with RFC 002 resolution rationale. 820 tests pass (was 817).
  No schema migration; new env vars are all optional; existing behavior
  unchanged for deployments that don't configure a provider.

- ✅ **v0.50.3 — RFC 008 + RFC 009 + RFC 011 (security hardening patch).**
  Ships the Tier-0 production-blocker and Tier-1 hardening items from the
  external codebase review that do not require new operator-visible
  configuration knobs.

  **RFC 008 (P0)**: OTP plaintext removed from audit log on every Magic
  Link issuance. `code_plaintext` renamed to `delivery_payload`. Static-
  grep pin test prevents reintroduction. Operator runbook for purging
  already-persisted rows and re-baselining the hash chain added to
  `docs/src/deployment/runbook.md`. **RFC 009 (P0)**: `introspect_token`
  no longer takes `expected_aud` — access tokens carry `aud = client.id`
  not `aud = issuer`; the pre-v0.50.3 verifier rejected every valid
  production access token. New `verify_for_introspect()` in jwt/signer
  is the introspect-only relaxed path. Audience-gate client lookup is now
  fail-closed: `Ok(None)` → HTTP 401 + `IntrospectionRowMissing` audit
  event; `Err(_)` → HTTP 503. Test fixture corrected to `AUD = "client_X"`.
  Three regression tests added. **RFC 011 (P1)**: `csrf::mint()` → `Result`,
  fail HTTP 500 on CSPRNG failure; `var_u32_bounded` helper rejects negative
  rate-limit env values (previously silently disabled limits via `as u32`
  wrap); duplicate session-route block removed from `lib.rs`;
  `no_duplicate_route_registrations` test added; `012-session-hardening.md`
  marked Superseded. 817 tests pass (was 814). No schema/wire/DO changes;
  `/introspect` behavior change: now returns correct `active: true` for
  valid access tokens.

- **v0.50.2 production-blocker sweep — external review remediation.**
  An external Rust + Cloudflare codebase review of v0.50.1
  surfaced three production blockers, three security
  hardening items, and four quality-and-operations items.
  Independently verified against the source tree. Triaged
  into RFCs 008-014 in [`rfcs/`](../rfcs/) for handover to
  implementer.

  **Production blockers (Tier 0, ship in v0.50.2)**:

  - ✅ **RFC 008 — Eliminate plaintext OTP in audit log
    [P0]** — shipped in v0.50.3. `worker/src/routes/magic_link/request.rs:170-178`
    and `worker/src/routes/api_v1/anonymous.rs:254-264`
    write the Magic Link OTP plaintext into
    `EventKind::MagicLinkIssued` audit `reason` on every
    issuance, violating the project's own self-declared
    "No token material ever" invariant from
    `worker/src/audit.rs`. Anyone with audit-read access
    (operator D1 read role, Logpush forwarder, SIEM
    operator, anyone running `cesauth-migrate export`,
    backup restorer) can log in as any user who used Magic
    Link or anonymous-promote during the retention
    window. Fix: drop `code_plaintext` from both audit
    sites; add static-grep pin test to prevent
    reintroduction; rename `code_plaintext` →
    `delivery_payload` to signal intent; ship operator
    runbook for purging already-leaked rows + chain
    re-baseline. RFC 008 details all 6 implementation
    steps.

  - ✅ **RFC 009 — Introspection access-token `aud`
    correctness + audience-gate fail-closed [P0 + P1]** — shipped in v0.50.3.
    Tokens minted with `aud = client.id`
    (`core/src/service/token.rs:115,277`); verifier uses
    `expected_aud = issuer`
    (`worker/src/routes/oidc/introspect.rs:202-208`).
    **Tests pass because fixture sets `ISS == AUD` (line
    78-79 of `service/introspect/tests.rs`)**, masking
    the production bug. Result: `/introspect` returns
    `{"active":false}` for every valid access token in
    production. ADR-014 §Q1's audience gate
    consequently never fires (it gates on active
    responses that never come back). Companion P1: the
    audience-gate's client lookup
    (`introspect.rs:97-117`) silently fails open on D1
    storage error, defeating the security boundary
    operators opted into. Fix: remove `expected_aud`
    from `introspect_token` (audience gate becomes
    canonical aud check); update test fixture to
    `AUD = "client_X"`; harden gate to fail-closed (HTTP
    503 on storage error, HTTP 401 on row missing with
    new audit kind `IntrospectionRowMissing`); amend
    ADR-014 §Q1 with v0.50.2 tightening note. RFC 009
    details all 9 implementation steps.

  - ✅ **RFC 010 — Magic Link real delivery (mailer port +
    provider adapters) [P0]** — shipped in v0.51.0. The development
    directive declares a `MagicLinkMailer` trait that
    operators implement; **workspace-wide grep returns
    zero hits** — no such trait exists. The audit log
    IS the OTP delivery mechanism in cesauth today
    (which is why RFC 008's plaintext-leak exists at
    all). Without a real mailer contract, RFC 008's fix
    will not stay fixed: the next operator under
    deadline pressure reintroduces the audit-as-delivery
    hack. Fix: build the trait the directive claims
    exists (`MagicLinkMailer` in `cesauth-core` with
    audit-disjoint crate boundary); ship 4 reference
    adapters (Cloudflare service binding, HTTPS
    provider, dev console with `WRANGLER_LOCAL=1` gate,
    `UnconfiguredMailer` fallback that surfaces misconfig
    via audit); new audit kinds `MagicLinkDelivered` /
    `MagicLinkDeliveryFailed`; new operator chapter
    `docs/src/deployment/email-delivery.md`; ADR-015
    drafted alongside graduating to Accepted on ship.
    RFC 010 details all 6 implementation PRs.

  - ✅ **RFC 011 — Worker-layer hardening [P1 + P2]** — shipped in v0.50.3. Bundle
    of four mechanical fixes:
    (1) `csrf::mint()` swallows `getrandom` error with
    `let _ =` — RNG failure produces a constant predictable
    token. Fix: `Result`-ize, audit `CsrfRngFailure`
    kind, fail HTTP 500.
    (2) `var_parsed_default(...)? as u32` in `config.rs:126,134`
    silently wraps negative values to huge u32, disabling
    rate limits. Fix: `var_parsed_u32_bounded` with
    explicit non-negative + sane upper bound check.
    (3) `worker/src/lib.rs:161-168` and `:193-200`
    register the same three `/me/security/sessions` routes
    twice (merge-conflict residue from v0.35.0). Fix:
    delete second block; uniqueness pin test.
    (4) `docs/src/expert/adr/012-session-hardening.md`
    (older draft) and `012-sessions.md` (canonical) both
    exist. Fix: header `012-session-hardening.md` as
    Superseded. May ride along v0.50.2 or land in
    v0.50.3 depending on PR review bandwidth.

  **Quality / scaling work (Tier 3, defer behind v0.50.2)**:

  - **RFC 012 — Doc and repo hygiene**. README claims
    "No management GUI" (false — admin console since
    v0.3.0) and "land in R2" (false — R2 audit removed
    v0.32.0); `crates/core/src/migrate.rs` is 2568
    lines (development directive's 800-line cap);
    development directive itself describes rate-limit as
    KV (actually DO); inline comments reference removed
    R2 audit subsystem. Fix: README rewrite, mechanical
    `migrate.rs` split into 9 submodules under 500 lines
    each, dev directive corrections + move into
    `docs/src/expert/development.md`, drift-scan CI
    workflow with stale-phrase pattern list.

  - **RFC 013 — Operational envelope**. Cesauth has
    implicit Cloudflare plan assumptions never
    documented: cron passes walk 1000 rows × DO call
    each (Free plan subrequest cliff at 50);
    `/introspect` hot path issues multiple D1 reads +
    DO calls (Free plan D1 query cliff at 50);
    monolithic worker bundle never measured against
    Free 3 MB / Paid 10 MB ceiling; `nodejs_compat`
    enabled despite no Node API runtime use. Fix:
    ADR-016 declares Paid plan as floor; bundle-size CI
    gate at 7 MB gzipped (70% of Paid ceiling);
    configurable cron batch sizes for each pass;
    `nodejs_compat` removal or in-tree justification;
    new `docs/src/deployment/operational-envelope.md`
    chapter with per-request budget tables; new
    `docs/src/deployment/bundle-history.md` trend
    record.

  - **RFC 014 — Audit append performance**. D1
    contention concern under high-rate audit events
    (`/introspect`-heavy deployments). Path A
    (acceptance + telemetry): instrument
    `audit::append` with latency / retry warnings,
    document ~100/s sustained ceiling, ship operator
    runbook. Path B (DO-serialized append, ADR-017):
    deferred until Path A telemetry triggers — single
    new DO class + adapter + migration; chain integrity
    preserved.

  - **RFC 015 — Request traceability**. Operator
    follow-up question on logging completeness: log
    framework is well-designed (categorized,
    level-gated, sensitivity-gated) but no
    correlation across log lines from the same
    request, no cross-link between log and audit, no
    consistent HTTP request lifecycle log. Adds:
    `cf-ray`-derived `request_id` threaded through
    `LogConfig` and `NewAuditEvent`; one HTTP
    lifecycle log per request as middleware
    (replaces ad-hoc per-handler `Category::Http`
    emissions, net log volume same or fewer); new
    nullable `audit_events.request_id` column
    (SCHEMA_VERSION 10 → 11; non-chained, additive).
    **Deliberately documents the absence of a
    file-writing logger** as ADR-018: Cloudflare
    Workers has no filesystem; persisting per-line
    to KV/R2/D1 contradicts the security posture and
    duplicates audit/log governance — operator
    question on this is answered by ADR-018, not by
    implementation. Coordinates with RFC 013
    (operational envelope) since both touch
    observability.

  **Tier 4 — Admin UX hardening (defer behind P0
  sweep + Tier 3)**: a third source — an external
  UI/UX design update reviewing v0.50.1 — surfaced
  three admin-surface gaps not covered by the
  external code review or operator logging
  follow-up. Triaged into RFCs 016-018:

  - **RFC 016 — Admin scope badge standardization**.
    Currently the three admin frames
    (`/admin/console/*` system, `/admin/tenancy/*`
    tenancy, `/admin/t/<slug>/*` tenant) have
    visually distinct chrome but no semantic "you
    are operating in scope X" badge consistent
    across all three. Adds `ScopeBadge` enum
    (System/Tenancy/Tenant(slug)) + 3 colour tokens
    (purple/blue/green, deliberately distinct from
    semantic success/warning/danger/info) + 3
    MessageKey variants. Single-place chrome change
    that lets operator + screenshot-reviewer read
    scope as a first-class element rather than
    incidental styling.

  - **RFC 017 — OIDC client audience-scoping admin
    editor**. v0.50.0 shipped the audience-scoping
    schema + gate but explicitly deferred the
    admin UI ("Admin console UI for this is out
    of v0.50.0 scope"). Operators currently must
    run `wrangler d1 execute "UPDATE oidc_clients
    SET audience = ? WHERE id = ?"` against
    production. RFC 017 adds the tenant admin
    editor surface with explicit 3-state form
    (Unscoped/Scoped+empty/Scoped+value)
    distinguishing NULL vs `""` vs `"value"`
    semantics, per-tenant uniqueness check with
    `?force=1` override, new audit kind
    `OidcClientAudienceChanged` with before/after
    payload, audit-trail section showing recent
    changes for the client.

  - **RFC 018 — Preview-and-apply pattern for
    destructive admin operations**. The deck's
    "状態 → 影響 → 実行 → 監査" framing; current
    admin console largely lacks the explicit
    impact step (config_edit, token rotation, etc.
    apply directly on submit). Establishes
    reusable infrastructure (`ImpactStatement`,
    HMAC-signed `PreviewToken` with 5-min TTL,
    paired `OperationPreviewed`/
    `OperationApplied` audit events). First
    adopters: LOG_LEVEL change, token rotation,
    audience editor (RFC 017 ideally rides on
    this). ADR-019 establishes the convention.

  All three Tier 4 RFCs ship after Tiers 0-3
  (production blockers + worker hardening +
  quality + operations). Recommended placement:
  v0.52.x or 0.53.0 in the order RFC 016 (chrome,
  ships anywhere) → RFC 018 (pattern infra) → RFC
  017 (rides on the pattern).

- **Security track — phased rollout.** Eleven releases of focused
  security work, ordered by impact-vs-effort. Each is small
  enough to ship cleanly without overlap. Originally framed as
  eight phases; v0.27.0 split into 2a (storage) + 2b (routes)
  mid-implementation, then v0.28.0 split again into 2b
  (presentation) + 2c (routes) + 2d (polish) — adding three
  phases total. Each split keeps releases review-able rather
  than shipping a giant change-set.

  - **0.24.0** ✅ — `SECURITY.md` improvements (severity table,
    known-limitations subsection, see-also cross-links;
    pre-existing policy was already comprehensive) + CSRF
    audit deliverable (`docs/src/expert/csrf-audit.md`,
    per-route inventory with mechanism per route, test
    coverage, re-audit cadence) + CSRF gap fill on
    `/magic-link/verify` (token check, JSON-path exempt) +
    dependency-scan automation review (verified the existing
    `.github/workflows/audit.yml` is comprehensive, documented
    the alert path in `docs/src/expert/security.md`'s new
    "Dependency vulnerability scanning" section). 6 new tests
    pinning the CSRF field contract on `VerifyBody` and
    `RequestBody`. Total 413 passing.
  - **0.25.0** ✅ — Email verification flow audit + gap fill +
    OIDC discovery doc honest reset. Audit deliverable
    (`docs/src/expert/email-verification-audit.md`) documents the
    9-row per-path table, the meaning of `email_verified=true`,
    and the discovered OIDC `id_token` issuance gap. **Concern 2
    fix**: returning-user Magic Link verify now flips
    `email_verified=true` when previously false (best-effort
    UPDATE; skip-write optimization for already-verified rows).
    **Discovery doc honest reset**: `id_token_signing_alg_values_supported`
    and `subject_types_supported` fields removed from wire output,
    `openid` removed from `scopes_supported` (now
    `["profile", "email", "offline_access"]`). Discovery is now
    RFC 8414 (OAuth 2.0 metadata), not OIDC Discovery 1.0 —
    accurate to what the implementation actually delivers.
    **`magic_link_sent_page()` UX bug fix** (folded in from
    v0.24.0 audit): template now takes `handle` and `csrf_token`
    parameters, both rendered as escaped hidden inputs; both
    callers in `/magic-link/request` (rate-limited path with
    placeholder UUID handle, happy path with real handle)
    updated. **ADR-008 drafted**: `id_token` issuance design,
    queued for implementation when scheduling permits (currently
    deferred behind TOTP track per security-track sequencing —
    see below). 14 new tests (8 discovery shape, 6 templates).
    Total 451 passing.
  - **0.26.0** ✅ — TOTP Phase 1: ADR-009 Draft + schema
    migration 0007 + `cesauth_core::totp` library skeleton
    (RFC 6238 generator and verifier with skew tolerance,
    recovery code generator, AES-GCM encryption helpers).
    SCHEMA_VERSION bumped 6 → 7. No HTTP routes, no
    enrollment UI, no verify wire-up — those are Phase 2.
    51 new tests including 5 RFC 6238 reference vectors.
    Total **502 passing**.
  - **0.27.0** ✅ — TOTP Phase 2a: storage layer.
    `cesauth_core::totp::storage` port traits, in-memory
    adapters, D1 adapters, `Challenge::PendingTotp` variant,
    `TOTP_ENCRYPTION_KEY`/`TOTP_ENCRYPTION_KEY_ID` env-var
    parsing in worker config. The original v0.27.0 plan
    bundled storage + routes; mid-implementation the
    storage layer alone proved review-able as its own
    release. 24 new tests. Total **526 passing**.
  - **0.28.0** ✅ — TOTP Phase 2b: presentation layer.
    Three new `cesauth_ui::templates` (enroll page,
    recovery-codes page, verify page) with 18 tests pinning
    CSRF inclusion / escape behavior / `<details>` placement
    of the recovery alternative form / no-email-leak from
    the verify page. New `cesauth_core::totp::qr` module
    with `otpauth_to_svg` using `qrcode` 0.14 at EcLevel::M,
    240 px, deterministic black-on-white. New
    `cesauth_worker::routes::me::auth::resolve_or_redirect`
    centralizing the cookie → session → 302-to-/login
    pipeline for `/me/*` routes. Workspace dep added:
    `qrcode = 0.14`. The original v0.28.0 plan bundled
    presentation + routes; mid-implementation the
    presentation layer alone proved review-able. 25 new
    tests. Total **551 passing**.
  - **0.29.0** ✅ — TOTP Phase 2c: HTTP routes + verify gate.
    Five new routes wired in `worker::lib::main`: `GET` and
    `POST` enroll, `GET` and `POST` verify, `POST` recover.
    Verify gate insertion in `post_auth::complete_auth` —
    for `AuthMethod::MagicLink` after step 1 (AR taken),
    checks `find_active_for_user`, on Some carries AR
    fields inline into `Challenge::PendingTotp` (no chained
    handle) and 302s to verify page. WebAuthn paths bypass.
    `complete_auth_post_gate` extracted from the original
    `complete_auth` body so both no-gate and post-verify
    paths share the same session-start/AuthCode-mint logic.
    Two new short-lived cookies introduced: `__Host-cesauth_totp`
    (5 min, SameSite=Strict, gate handle) and
    `__Host-cesauth_totp_enroll` (15 min, SameSite=Strict,
    enrollment row id). 12 new cookie-shape tests pinning
    Max-Age preservation, prefix integrity, TTL bounds, and
    distinct-cookie-name property. ~800 lines of route
    handlers covering enroll / verify / recover. 12 new
    tests. Total **563 passing**.
  - **0.30.0** ✅ — TOTP Phase 2d: polish + ADR Accepted.
    Disable flow (`GET/POST /me/security/totp/disable`) with
    minimal single-page confirmation. Cron sweep extension —
    drops `confirmed_at IS NULL AND created_at < now - 24h`
    rows after the existing anonymous-trial sweep on the same
    cron tick. `RedactionProfile.drop_tables` field; both
    built-in profiles (`prod-to-staging`, `prod-to-dev`) drop
    both TOTP tables (ADR-009 §Q5/§Q11). New
    `TotpAuthenticatorRepository::delete_all_for_user` trait
    method + adapters. New chapter
    `docs/src/deployment/totp.md` (~270 lines) covering
    encryption key provisioning, key rotation procedure with
    explicit caveat that dual-key resolution is not yet
    implemented (workaround: re-enroll users), admin reset
    path for lockout recovery, cron sweep semantics,
    operational invariants, diagnostic queries. Pre-prod
    release gate updated. **ADR-009 graduates `Draft` →
    `Accepted`** — design validated end-to-end across 5
    releases. 10 new tests (3 redaction + 5 disable template
    + 2 adapter delete_all_for_user). Disable flow is
    intentionally minimal — single-page confirm, silent
    redirect, no flash messages. The UX work (flash
    infrastructure, `/me/security` index, error-slot in
    enroll template, CSS for warning/danger states, handler
    integration tests) consolidates in the next release per
    the user-stated project value. **TOTP track
    feature-complete for the 0.x series.** Total **573
    passing**.

  After this track completes (now 11 phases instead of the
  original 8 — the v0.27.0 split added one and the v0.28.0
  split added two more), the schedule reverts to the
  feature track AFTER one UI/UX-focused release per the
  user-stated project value:

- **UI/UX iteration release.**
  - **0.31.0** ✅ — UI/UX improvements at TOTP-track-completion
    boundary, per user-stated project value "重要な予定が完了
    したタイミングで、UI/UX 改善に取り組みます". Shipped:
    P0-A `/me/security` Security Center index page (primary
    auth method label, TOTP enabled/disabled badge, recovery
    code remaining count with 4-tier rendering N=10/2-9/1/0,
    conditional enroll/disable link, anonymous-suppression
    variant); P0-B flash-message infrastructure
    (`__Host-cesauth_flash` cookie with HMAC + closed token
    table, `flash_block` template, all 4 success/info/warning
    paths wired: TOTP enabled/disabled/recovered + logged-out);
    P0-C `error: Option<&str>` slot on `totp_enroll_page` with
    autofocus on the code input; P0-D 8 design tokens
    (`--success`, `--success-bg`, `--warning`, `--warning-bg`,
    `--danger`, `--danger-bg`, `--info`, `--info-bg`) + dark-mode
    `@media` overrides + `.flash--*` and `.badge--*` modifier
    classes + `button.danger` / `button.warning` rules +
    `.visually-hidden` utility (this fixed a latent bug — the
    class was already referenced but the rule was missing);
    P1-A `validate_next_path` allowlist (`/me/*` + `/`)
    + `__Host-cesauth_login_next` cookie + threading through
    `complete_auth` → `complete_auth_post_gate`; new
    `docs/src/expert/cookies.md` (privacy notice covering all
    7 cookies, EDPB Guidelines 5/2020 rationale for "strictly
    necessary"). 614 → ~680 tests. Plan v2 §6.4 split policy
    invoked: P1-B (TOTP handler integration tests) deferred to
    v0.31.1 — see entry below. The pure-helper extracts
    (`attempts_exhausted`, `DISABLE_SUCCESS_REDIRECT`) shipped
    here as honest minimum coverage at this layer.

  - **0.31.1** ✅ shipped as **v0.32.1** — TOTP handler
    integration tests (P1-B split from v0.31.0) landed via
    Approach 2 (decision-extraction refactor) on top of the
    v0.32.0 audit-log hash-chain release rather than as a
    separate v0.31.x branch. Six handlers were refactored into
    pure-ish `decide_*` functions plus thin Env-touching
    wrappers: `disable::post_handler`, `recover::post_handler`,
    `verify::get_handler`, `verify::post_handler`,
    `enroll::get_handler`, `enroll::post_confirm_handler`.
    Each `decide_X` takes trait-bounded `&impl AuthChallengeStore`
    / `&impl TotpAuthenticatorRepository` /
    `&impl TotpRecoveryCodeRepository` references, returns an
    enum capturing the decision outcome plus any data the
    handler needs to build the response. Tests construct
    in-memory adapters from `cesauth-adapter-test` and exercise
    the full branch table per handler (3-10 tests each, 40
    total). Production wiring unchanged — handler signatures
    are signature-compatible. `unimplemented!()` stub repos
    used to pin port-surface regressions: a passing test
    confirms the decision didn't widen its port contract.
    Released as v0.32.1 because the user explicitly authorized
    "(α) v0.32.0 の上に v0.32.1 として出す" during the
    planning conversation; CHANGELOG entry frames it as
    "deferred from v0.31.0, landing on v0.32.x line". 717 →
    757 tests (+40).

- **Audit log integrity track.**
  - **0.32.0** ✅ — Audit log hash chain Phase 1 (ADR-010 Draft).
    Audit events moved from R2 NDJSON objects to a D1 table
    `audit_events` with SHA-256 hash chain over rows; case C
    (D1 source-of-truth) chosen during planning over case B
    (R2 + parallel D1 chain ledger) because the two-store
    design would have forked the chain under concurrency,
    permanently exposed cross-store consistency hazards, and
    forced N+1 reads on every verifier and admin search. R2
    `AUDIT` binding removed entirely from `wrangler.toml`; no
    backward-compat code left in the repo. New schema
    migration `0008_audit_chain.sql` introduces the table,
    three indexes (`(ts)`, `(kind, ts)`, partial
    `(subject) WHERE NOT NULL`), and a genesis row at `seq=1`.
    `cesauth_core::audit::chain` provides pure hash
    calculation; `cesauth_core::ports::audit::AuditEventRepository`
    is the trait; in-memory adapter and D1 adapter implement
    it. Worker `audit::write` rewritten internally (signature
    unchanged, all 90 call sites work). Admin search rewritten
    to D1 SELECT; `r2_metrics` removed in favor of
    `row_count.audit_events`. `/__dev/audit` rewritten.
    Documentation: ADR-010 Draft, new operator chapter
    `audit-log-hash-chain.md`, R2 audit references purged
    across deployment docs. Project-status framing softened
    across all docs (removed "pre-1.0" / "production-ready"
    claims) per user instruction during planning. 678 → 717
    tests (+39: 25 chain-hash tests in core, 14 in-memory
    repository tests in adapter-test). No verification cron
    yet — that is Phase 2.
  - **0.33.0** ✅ — Audit log hash chain Phase 2 shipped
    (ADR-010 Draft → **Accepted**). Daily cron at 04:00 UTC
    (piggybacked on the existing sweep schedule) walks the
    chain incrementally, resuming from the last checkpoint
    via the new `AuditEventRepository::fetch_after_seq`
    method (page size = 200) and verifying every link's
    payload_hash, chain_hash, and previous_hash linkage.
    New port `AuditChainCheckpointStore` with two records:
    `AuditChainCheckpoint` (resume + cross-check) and
    `AuditVerificationResult` (admin UI surface). KV adapter
    in `cesauth-adapter-cloudflare` stores them under the
    reserved `chain:` prefix in the existing `CACHE`
    namespace — no new wrangler binding, no schema migration.
    The dual-store design is the wholesale-rewrite defense:
    an attacker who compromises D1 still has to compromise
    KV synchronously to evade detection. Pure-ish verifier
    in core (`cesauth_core::audit::verifier::verify_chain`
    incremental + `verify_chain_full` operator-triggered);
    same Approach 2 pattern as v0.32.1 TOTP handlers
    (port-bound IO in scope, Env touching not). Admin UI at
    `/admin/console/audit/chain` renders status badge +
    checkpoint metadata + CSRF-guarded "verify now" button;
    cross-linked from the existing audit search page;
    six rendering tests pin status / tamper / wholesale-
    rewrite / growth-since-checkpoint / CSRF wiring. Tamper
    detection persists the failing result to KV (admin UI
    surfaces the alarm), logs at `console_error!` level, and
    does NOT advance the checkpoint — investigation gate
    before the chain advances past suspect rows. cesauth
    keeps writing audit events on tamper detection (chain is
    forensic, not runtime gating; ADR-010 §Q3). 757 → **777**
    tests (+20: 4 fetch_after_seq + 10 verifier tamper-
    detection scenarios + 6 UI rendering). Open Questions
    Q1 (checkpoint location) and Q3 (in-flight write
    behavior on tamper) closed in this release; Q2/Q4/Q5
    remain open. Rust dev-dep cycle workaround surfaced and
    documented: verifier integration tests live in
    `cesauth-adapter-test::audit_chain::tests` rather than
    `cesauth-core` itself, because dev-depending core on
    adapter-test would produce duplicate trait artifacts.
  - **0.34.0** ✅ — Refresh token reuse hardening shipped
    (ADR-011 Accepted). The structural rotation invariant
    from RFC 9700 §4.14.2 was already implemented and atomic
    since v0.4 (single-writer `RefreshTokenFamily` DO with
    a current_jti + retired_jtis ring; first reuse atomically
    revokes the family). v0.34.0 closes the **observability**
    gaps surfaced by an audit of the v0.33.0 baseline against
    the BCP §4.13 monitoring expectations. **`FamilyState`
    gains** `reused_jti` / `reused_at` / `reuse_was_retired`
    — all `#[serde(default)]` so existing DO storage records
    deserialize unchanged (no migration). **`RotateOutcome::
    ReusedAndRevoked` carries forensic payload** so the
    service layer doesn't need to peek the family again.
    **New `CoreError::RefreshTokenReuse` variant** distinct
    from `InvalidGrant`; service layer `rotate_refresh`
    dispatches by outcome. **Same wire response** for both
    error variants (`error: "invalid_grant"`, HTTP 400) —
    distinguishing externally would let attackers probe
    family state via error-code differentiation, the BCP-
    flagged side channel. The `(code, status)` decision is
    extracted as `oauth_error_code_status` so wire-equivalence
    can be unit-tested without constructing a wasm-backed
    `worker::Response`. **New audit event
    `EventKind::RefreshTokenReuseDetected`** with JSON payload
    `{family_id, client_id, presented_jti, was_retired}`;
    family_id decoded via audit-only lossy decoder so audit
    writes don't fail-close on malformed tokens.
    **`reuse_was_retired`** distinguishes recognized-retired
    jti (= real leaked token, classic case) from unknown jti
    (= forged or shotgun); operators can prioritize alerts on
    the higher-signal subcase. **Schema unchanged** from
    v0.33.0 (still SCHEMA_VERSION 8). **No DO migration.**
    **Wire format unchanged** for OAuth clients. 777 → **783**
    tests (+6: 3 forensic-field tests in adapter-test, 3
    error-mapper wire-equivalence tests in worker). ADR-011
    documents the audit findings + design + 3 deferred items
    (per-family rate limiting at `/token` — **resolved in
    v0.37.0**, user notification on reuse, tenant admin
    aggregate view).
  - **0.35.0** ✅ — Session management hardening shipped
    (ADR-012 Accepted). v0.34.x baseline audited against
    BCP guidance; five gaps closed: idle timeout enforcement
    (default 30 min, `SESSION_IDLE_TIMEOUT_SECS` env, 0
    disables), `me::auth::resolve_or_redirect` switched
    from `status()` to `touch()` (the load-bearing change —
    without it the new gates would be dormant; this also
    fixes a structural bug where `last_seen_at` was never
    advancing past `created_at` in v0.34.x), `SessionStatus`
    gains `IdleExpired` / `AbsoluteExpired` variants
    populated atomically with the DO state mutation,
    `ActiveSessionStore::list_for_user` port method backed
    by a new D1 `user_sessions` index (SCHEMA_VERSION 8 →
    9, migration 0009; per-session DO remains source of
    truth, D1 row is denormalized index for the user-facing
    list page), `/me/security/sessions` page renders one
    card per active session with auth method label /
    timestamps / client_id / shortened session id and a
    "取り消す" button per non-current row, current session
    shows "この端末" badge with disabled button (revoking
    your own session would surprise the user — the explicit
    logout flow is the right path), `POST /me/security/
    sessions/:session_id/revoke` handler with CSRF guard +
    ownership check (refuses revoke of another user's
    session via 403, defense in depth), four new audit
    event kinds: `SessionRevokedByUser`,
    `SessionRevokedByAdmin`, `SessionIdleTimeout`,
    `SessionAbsoluteTimeout`. Legacy `SessionRevoked` kind
    retained for backward-compatibility with v0.4-v0.34.x
    audit chain rows. **Session-id rotation on login** was
    already correct in v0.34.x via `complete_auth_post_gate`
    minting `Uuid::new_v4` per successful auth — preserved
    unchanged. **"New device" notification deferred** —
    requires general transactional email infrastructure
    cesauth doesn't yet have; would entangle two changes;
    documented in ADR-012 §"Considered alternatives". 783 →
    **801** tests (+18: 11 timeout/list tests in adapter-test,
    7 sessions_page rendering tests in ui). **Schema
    migration required**: operators must run `wrangler d1
    migrations apply` before serving v0.35.0 traffic.
    Without the migration `start()` fails on D1 INSERT and
    new sessions can't be created (existing sessions
    continue working through touch/revoke).

  After all of this — security track complete plus the
  UX iteration — the schedule reverts to the feature
  track (RFC 7662 Token Introspection, etc.).

- **Internationalization (i18n) track.** **Status:
  infrastructure shipped in v0.36.0 (ADR-013); migration
  partial.** cesauth's user-facing UI was language-mixed
  without negotiation pre-v0.36.0: the end-user TOTP /
  Security Center / login surfaces carried hardcoded Japanese
  strings (e.g., "TOTP を有効にしました。", "二段階認証 (TOTP)",
  the wrong-code re-render error
  "入力されたコードが一致しませんでした。…"), the admin console
  carried hardcoded English, and machine-emitted error bodies
  were English. There was no `Accept-Language` handling, no
  locale negotiation, no message catalog, no fallback chain.
  The v0.31.0 flash module carried a TODO at
  `crates/worker/src/flash.rs:215` ("Translations are out of
  scope for v0.31.0; future i18n would replace this lookup
  with one keyed by Accept-Language") — this track is the
  payment of that debt.

  Phasing is open; the track may run in parallel with feature
  work because the surface area is small and discrete:

  - **i18n-1** ✅ — message-catalog infrastructure shipped
    in v0.36.0 (ADR-013 Accepted). `cesauth_core::i18n`
    module: closed `Locale` enum (Ja, En), closed
    `MessageKey` enum (22 variants in v0.36.0), `lookup`
    function with compile-time exhaustive coverage of both
    axes (adding a key without a translation in every locale
    is a build error), RFC 7231 §5.3.5 q-value-aware
    `parse_accept_language` parser. `cesauth_worker::i18n::
    resolve_locale(&Request)` is the per-request
    negotiation entrypoint. Migration pattern: each call
    site adds a `_for(..., locale)` variant alongside the
    existing function; the plain function becomes a
    default-locale shorthand so existing callers continue
    to work unchanged. **20 unit tests** in
    `cesauth_core::i18n::tests`: locale parsing
    (case-insensitive, region-stripping, unknown returns
    None), Accept-Language parsing edge cases (empty,
    q-value priority, q=0 dropped per RFC 7231, wildcard,
    malformed q treated as 1.0 lenient, all-unsupported
    falls through, tie-breaking in document order,
    browser-typical headers), catalog completeness (every
    key resolves to nonempty in every locale, no two keys
    share text within a locale).
  - **i18n-2** 🚧 partial through v0.39.0 — surfaces migrated
    to date: flash banners (5 keys, v0.36.0),
    `/me/security/sessions` chrome (16 keys, v0.36.0), TOTP
    enroll wrong-code error (1 key, v0.36.0), **login page**
    (10 keys, v0.39.0), **TOTP enroll page** (11 keys,
    v0.39.0), **TOTP verify page** (12 keys including new
    `TotpVerifyWrongCode`, v0.39.0), **Security Center
    index** (13 keys, v0.39.0). MessageKey total 22 → 70.
    Catalog completeness tests refactored from hardcoded
    `all_keys` arrays to `for_each_key(closure)` — adding a
    new variant without adding it to the iterator is now a
    build error, not a missed-test silent gap. New
    `cesauth_ui::js_string_literal` helper introduced for
    safe interpolation of catalog strings into inline
    `<script>` blocks (login page passkey-failed JS error
    message); 8 dedicated tests for the helper covering
    UTF-8 multi-byte passthrough, `</script>` defense,
    control-char `\uXXXX` fallback. Disabled-state
    Security Center TOTP rendering goes through the
    catalog; **enabled-state + recovery-codes status row
    intentionally still hardcoded JA** pending v0.39.1+
    (recovery messages need pluralization — ADR-013 §Q4).
    `PrimaryAuthMethod::label()` independently localized
    (used by admin console too) — separable thread, not
    in v0.39.0 scope. Remaining for v0.39.1+: TOTP
    recovery codes display, TOTP disable confirm, magic
    link request + sent, error pages,
    `PrimaryAuthMethod::label`, Security Center
    enabled-state recovery-codes row.

  - **i18n-3** — additional locales added on demand. Pull
    requests welcome.

  - **i18n-4** — RFC 5646 / IETF-BCP-47 language tag
    parsing edge cases (script subtags like `zh-Hant`,
    region subtags like `pt-BR`). Defer until i18n-2 ships
    and real demand surfaces.

  Acceptance for i18n-1 + i18n-2 (the MVP): every
  user-visible string in the v0.33.0+ end-user surfaces
  comes through a `MessageKey` lookup; tests pin the table
  shape; both `ja` and `en` resolve every key. No
  template-side hardcoded prose surviving in the
  end-user templates after the migration.

- **Real mail provider for Magic Link delivery.** The current
  `dev-delivery` audit line containing the plaintext OTP must be
  replaced with a transactional mail HTTP call keyed by
  `MAGIC_LINK_MAIL_API_KEY` before any production deployment.
  (Release gate — see [Security → Pre-production release gates](docs/src/expert/security.md).)

  **Implementation choice (chosen 2026-04)**: use `wasm-smtp v0.6`
  with the `wasm-smtp-cloudflare` adapter. Both crates released
  in 2026-04. The integration point is
  `cesauth-worker/src/routes/magic_link/request.rs` (the
  `dev-delivery` line at line ~157 — the audit-write that today
  carries the plaintext OTP must split into (a) an audit-write
  with handle only, and (b) a `wasm-smtp` send call). Operator
  config flows through `wrangler.toml` `[vars]` for the SMTP
  endpoint + `[secrets]` for credentials. Scope: ~1 release,
  most of it operator-doc work in `docs/src/deployment/`.

- **Discoverable-credential (resident-key) WebAuthn flows.**
  Currently cesauth requires the user to start from an identifier;
  resident keys would allow true username-less login.

- **`prompt=consent` with a real consent screen.** Requires a
  consent-record table, consent-screen UI template, and handler
  wiring. Until then the value is rejected with `invalid_request`.

- **Conditional UI for WebAuthn** (`mediation: "conditional"`) —
  autofill-assisted sign-in.

- **Admin Console hot-path counters (0.3.2).** The Cost Dashboard
  reads `counter:workers:requests:YYYY-MM-DD` and
  `counter:turnstile:{verified,rejected}:YYYY-MM-DD` but nothing
  writes them yet, so fresh deployments report zero for Workers and
  Turnstile. The missing piece is a per-request KV increment, and the
  open design question is at what granularity to count:
    - every fetch (including 404s and preflight)?
    - only requests that land on a real handler?
    - by HTTP method / response class?
  The answer shapes what operators see in the dashboard, and the
  spec is silent on it — defer until the counting policy is settled.
  A related open question: how to handle the read-modify-write race
  (KV has no atomic increment; concurrent requests will lose
  increments). Likely acceptable for a "proxy" metric, but worth
  recording explicitly.

- **Tenancy-service HTTP routes (shipped in 0.7.0).** The
  `/api/v1/...` surface ships JSON CRUD for tenants, organizations,
  groups, memberships, role assignments, and subscriptions. Plan-
  quota enforcement (max_users / max_organizations / max_groups)
  runs on org-create and group-create paths. The remaining design
  question — admin bearer vs session cookie for the tenant-scoped
  console — is now scoped to the v0.8.0 admin console, since the
  0.7.0 surface uses the existing 0.3.x admin-bearer model
  exclusively. The `check_permission` integration is also still
  pending: 0.7.0 routes go through `ensure_role_allows` (admin-side
  capability) because admin tokens have no `users` row to feed into
  `check_permission`. The two converge in 0.8.0+ when user-as-bearer
  arrives.

- **Read-only SaaS console (shipped in 0.8.0).** The
  `/admin/saas/*` HTML surface gives cesauth's operator staff a
  navigable view of tenancy state — tenants, organizations,
  members, subscriptions, role assignments — without having to
  curl the JSON API. Five pages, all read-only by design;
  mutations remain on `/api/v1/...`. The footer carries an
  explicit "read-only" marker so operators don't mistake this
  surface for the writable v0.9.0 follow-up.

- **SaaS console mutation forms (shipped in 0.9.0).** Wraps the
  v0.7.0 JSON API in HTML forms following a risk-graded preview/
  confirm pattern: one-click submit for additive operations
  (creates), v0.4.0-style preview/confirm for destructive ones
  (status changes, group deletes, plan changes). Eight forms ship:
  tenant create / set-status, organization create / set-status,
  group create / delete, subscription set-plan / set-status.
  Affordance buttons gate on `Role::can_manage_tenancy()` so
  ReadOnly operators don't see broken-link buttons. Auth caveat:
  forms POST same-origin and the bearer rides on the
  `Authorization` header — operators must use a tool that sets
  the header (curl, browser extension, or the future cookie-auth
  path).

- **Membership / role-assignment forms (shipped in 0.10.0).** The
  HTML console reaches feature parity with the v0.7.0 JSON API:
  three flavors of membership add (one-click submit) and remove
  (one-step confirm), plus role-assignment grant (full Scope
  picker) and revoke (one-step confirm). Reachable from the
  affordance buttons on tenant detail, organization detail, and
  user role-assignments pages. Operations+ only — ReadOnly
  continues to see the read pages with no mutation buttons.

- **Tenant-scoped admin surface — design settled (0.11.0).** The
  three open design questions from the v0.10.0 deferred list have
  been answered as ADRs at `docs/src/expert/adr/`:
  - **ADR-001**: path-based URLs (`/admin/t/<slug>/...`).
    Single cert, single origin, tenant identity visible.
  - **ADR-002**: user-as-bearer extends `admin_tokens` with an
    optional `user_id` column. `Authorization: Bearer` stays as
    the wire format. No new CSRF surface; no new cryptographic
    key.
  - **ADR-003**: complete URL-prefix separation between
    `/admin/saas/*` (system-admin) and `/admin/t/<slug>/*`
    (tenant-admin). No mode switch. Tenant-boundary leakage is
    structurally impossible.

  The 0.11.0 release shipped the foundation reflecting these
  decisions: migration `0005`, the `AdminPrincipal::user_id`
  field, the `is_system_admin()` helper, and Cloudflare D1
  adapters that read the new column. No UI yet — the surface
  implementation lands in 0.13.0.

- **Project-hygiene release with naming-debt cleanup (shipped in
  0.12.0).** Two threads landed together:
  - **Metadata** — author / license / repository now match
    reality (`nabbisen`,
    `https://github.com/nabbisen/cesauth`). Project framing
    language tightened: "Commercial SaaS" / "商用 SaaS" replaced
    with "tenancy service" or equivalent functional
    descriptions across docs and comments. `.github/` gains
    `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1),
    `CONTRIBUTING.md`, and four `ISSUE_TEMPLATE/*` files.
  - **Naming-debt cleanup** — the `saas/` module path under
    both `crates/ui/` and `crates/worker/src/routes/admin/`,
    the `/admin/saas/*` URL prefix, the `SaasTab` public type,
    and the `via=saas-console` audit reason marker have all
    been renamed to `tenancy_console` / `/admin/tenancy/*` /
    `TenancyConsoleTab` / `via=tenancy-console`. Operator-
    visible — bookmarks and scripts targeting the old prefix
    need updating. No compatibility-redirect routes were
    added; the SemVer caveat documented in the policy section
    permits the hard rename.

- **Buffer / follow-up release (shipped in 0.12.1).** Reserved
  as a placeholder slot for any issues the 0.12.0 rename would
  surface in real-world use. The shippable content turned out
  to be two small but worthwhile threads:
  - **Stale-narrative cleanup** — three docstrings carried
    forward-references and historical claims that the 0.12.0
    rename and intervening release-slot reshuffles
    invalidated. Fixed in `crates/ui/src/tenancy_console.rs`
    (the false "URL prefix preserved" claim and the wrong
    "since v0.18.0" marker) and
    `crates/core/src/tenancy/types.rs` (`AccountType::Anonymous`
    forward-ref to 0.18.0 → 0.14.0; `ExternalFederatedUser`
    forward-ref to 0.18.0 → unscheduled).
  - **Dependency audit** — manual review of every direct
    workspace dependency. No bumps. `getrandom 0.2` and
    `rand_core 0.6` are intentionally pinned at the older
    line for wasm32-unknown-unknown + Cloudflare Workers
    integration; bumping is gated on the workers-rs
    ecosystem aligning on the corresponding 0.3 / 0.9 lines.
    Every other direct dep is current.

- **Tenant-scoped admin surface — read pages shipped (0.13.0).**
  The 0.11.0 foundation lands as a working surface. Six read
  pages under `/admin/t/<slug>/...` (overview, organizations,
  organization detail, users, role assignments, subscription),
  a per-route auth gate that enforces ADR-003's three
  invariants (principal is user-bound, slug resolves, user
  belongs to the slug's tenant), and `check_permission`
  integration via a new `gate::check_read` helper that wraps
  the spec §9.2 scope-walk for the worker layer. New port
  methods: `AdminTokenRepository::create_user_bound` (mints
  tokens with `admin_tokens.user_id` populated) and
  `UserRepository::list_by_tenant` (powering the tenant-scoped
  users page). 245 tests passing (+26): 9 in
  `core::tenant_admin::tests` for the gate, 4 in
  `adapter-test` for `create_user_bound`, 13 in
  `ui::tenant_admin::tests` for chrome and per-page rendering.
  Read pages only — mutation forms in 0.14.0 mirror the
  v0.8.0 → v0.9.0 split for the system-admin surface.

- **Tenant-scoped high-risk mutations + token-mint UI
  (shipped in 0.14.0).** Six tenant-scoped form pairs at
  `/admin/t/<slug>/...` (organization create + status,
  group create + delete, role-assignment grant + revoke), plus
  one system-admin form pair at
  `/admin/tenancy/users/:uid/tokens/new` exposing
  `AdminTokenRepository::create_user_bound`. Each handler
  composes the v0.13.0 gate (`auth::resolve_or_respond` →
  `gate::resolve_or_respond` → `gate::check_action`) with the
  appropriate write permission slug; preview/confirm gating on
  the `confirm` form field; audit emission with
  `via=tenant-admin,tenant=<id>` to distinguish from
  `via=tenancy-console`. Defense-in-depth invariants enforced
  per-handler:
  - `organization_set_status`: re-verifies
    `org.tenant_id == ctx_ta.tenant.id`.
  - `group_delete`: walks `GroupParent` to verify either
    `group.tenant_id` or the parent organization's tenant_id.
  - `role_assignment_grant`: rejects `Scope::System` outright
    (per ADR-003), forces tenant scope's scope_id to the
    current tenant, and `verify_scope_in_tenant` walks
    storage to confirm Organization / Group / User scopes
    belong to this tenant before granting.
  - `role_assignment_revoke`: re-verifies the assignment's
    user belongs to this tenant.

  The `gate::check_read` from 0.13.0 is now a thin wrapper
  around a more general `gate::check_action(permission, scope, ctx)`
  that accepts an explicit `ScopeRef` (mutations need narrower
  scopes than reads). 257 tests pass (+12), zero warnings.

- **Tenant-scoped additive mutations + affordance gating
  (shipped in 0.15.0).** Six membership form pairs at
  `/admin/t/<slug>/...` (`memberships/`,
  `organizations/<oid>/memberships/`, `groups/<gid>/memberships/`
  — each with new + delete flavors). Two new permission slugs
  added to fill the symmetry gap: `TENANT_MEMBER_ADD` and
  `TENANT_MEMBER_REMOVE`. Defense-in-depth: target user_id is
  verified to belong to the current tenant before any add
  proceeds.

  Affordance gating: every read page and form page now renders
  mutation links/buttons only when the current user holds the
  relevant permission at tenant scope. Implementation:
  - **`check_permissions_batch`** new in
    `cesauth_core::authz::service` — evaluates N (permission,
    scope) queries with one `list_for_user` call + cached role
    lookups. The scope-walk is in-memory; the cost is one D1
    round-trip total, not N.
  - **`Affordances` struct** in `cesauth_ui::tenant_admin` —
    twelve boolean flags. `Default` is all-false (the safe
    default); `all_allowed()` is provided for tests.
  - **`gate::build_affordances`** in worker — issues the batch
    check and maps results to the struct.
  - Each read/form template now takes `&Affordances` and emits
    HTML conditionally for "+ New organization", "Change
    status", "+ New group", "delete", "+ Add member",
    "+ Grant role", "revoke", etc.

  The route handlers behind each affordance still re-check on
  submit (defense in depth). The affordance gate is the
  operator's first signal — clicking what they can't do already
  returned 403 since v0.13.0, but they shouldn't have to find out
  by clicking. 276 tests pass (+19), zero warnings.

  This release brings the tenant-scoped surface to feature
  parity with what the system-admin tenancy console reached at
  v0.10.0.

- **Anonymous trial → human user promotion — design + foundation
  (shipped in 0.16.0).** ADR-004 settles the five design
  questions (provenance / token issuance / retention / conversion
  ceremony / audit trail). Foundation in this release:
  - **Migration `0006_anonymous.sql`** — `anonymous_sessions`
    table with `token_hash` PK, FK CASCADEs to `users` and
    `tenants`, indexes for the retention sweep and per-user
    revocation paths.
  - **`cesauth_core::anonymous`** — `AnonymousSession` value
    type with `is_expired()` (boundary inclusive — pinned by
    test), `AnonymousSessionRepository` port (4 methods),
    `ANONYMOUS_TOKEN_TTL_SECONDS` (24h) and
    `ANONYMOUS_USER_RETENTION_SECONDS` (7d) constants.
  - **In-memory adapter** in `cesauth-adapter-test`, **D1
    adapter** in `cesauth-adapter-cloudflare` — both behind
    the same trait; the adapter test that runs both will
    catch divergence early in 0.17.0.
  - **`EventKind`** gains `AnonymousCreated`,
    `AnonymousExpired`, `AnonymousPromoted` so v0.17.0's
    emit calls don't force an audit-schema bump on the
    downstream side.

  286 tests pass (+10 over v0.15.1); zero warnings. The
  HTTP surface and existing audit kinds are untouched —
  this is a pure additive release. ADR-004 is in `Draft`
  status until v0.17.0 ships the routes that exercise it.

- **Anonymous trial — HTTP routes (shipped in 0.17.0).**
  ADR-004 graduates from `Draft` to `Accepted`. Two routes
  land:
  - `POST /api/v1/anonymous/begin` — unauthenticated (per-IP
    rate limit only). Mints fresh `users` row +
    `anonymous_sessions` row, returns plaintext bearer once.
    Strict rate limit: 20 over 5 minutes per IP, with
    Turnstile-style escalation at 10. The 7-day daily
    retention sweep (0.6.05) is the second line of defense.
  - `POST /api/v1/anonymous/promote` — anonymous-bearer
    authenticated. Two-step body shape (no `code` =
    issue-OTP step; with `code` = verify-OTP+apply step)
    distinguishes phases under one URL. Magic Link
    infrastructure reused unchanged. UPDATEs the user row
    in place (preserving `User.id`); revokes the anonymous
    bearer at promotion time. Email collisions return a
    distinguishable error (`email_already_registered`) so
    the client can render the right guidance vs OTP-failure.

  Defense-in-depth invariants pinned by adapter-level tests:
  revoke-before-update fail-safe ordering, per-user revoke
  isolation, idempotent double-promote (the racy second
  submit's revoke returns `Ok(0)`, then the route's
  `account_type == Anonymous` re-check refuses with
  `not_anonymous`). 289 tests pass (+3 over v0.16.0);
  zero warnings.

- **Anonymous trial — daily retention sweep (shipped in 0.18.0).**
  ADR-004 Phase 3, the final piece. The flow is now
  feature-complete. New `[triggers]` block in `wrangler.toml`
  (operator-visible config change — first cron trigger in
  cesauth) fires the new `#[event(scheduled)]` handler at
  04:00 UTC daily. The sweep handler runs:
  ```sql
  SELECT id, ... FROM users
   WHERE account_type='anonymous' AND email IS NULL
     AND created_at < ?  -- now - 7d
  ```
  emits one `AnonymousExpired` audit event per row, then
  deletes the row (FK CASCADEs clean up
  `anonymous_sessions`, memberships, role assignments).
  Best-effort failure semantics: per-row failures log `Warn`
  and continue; the next day's sweep retries the survivors.

  **Operator-visible**: cron invocation history in the
  Cloudflare dashboard, `wrangler tail` for live streaming,
  one `Info` summary line per sweep:
  `"anonymous sweep complete: X/Y rows deleted"`. Operator
  runbook gains "Verifying the anonymous-trial retention sweep
  ran" with a residual-count diagnostic query.

  Schema additions: `UserRepository::list_anonymous_expired`
  and `delete_by_id` port methods; in-memory + D1 adapters;
  `EventKind::AnonymousExpired` was pre-added in 0.16.0. 294
  tests pass (+5 over v0.17.0); zero warnings.

- **Data migration tooling (server-to-server moves) — Phase 4:
  polish (shipped in 0.22.0).** All four phases of ADR-005 are
  now shipped; the data-migration tooling is feature-complete
  for the design's scope. Phasing summary:

  - **0.19.0** — design + foundation (ADR-005, library value
    types, CLI skeleton).
  - **0.20.0** — real export + verify, the source side.
  - **0.21.0** — real import, the destination side; ADR-005
    graduated to Accepted.
  - **0.22.0** (this release) — polish: `--tenant <id>`
    filter on `export` (with `TenantScope::Global` vs
    `OwnColumn` per-table classification + manifest scope
    record), `cesauth-migrate refresh-staging` single-command
    combinator (export + redaction + import in one
    invocation, opinionated for single-operator runs, `--yes`
    for unattended use), email-uniqueness-within-tenant
    invariant check (redaction-aware, case-insensitive,
    `users.email` `COLLATE NOCASE`-matching), per-row import
    progress via `ProgressSink` decorator. 379 tests pass
    (+21 over v0.21.0).

  **Deferred to post-1.0 polish** — these were originally on
  the v0.22.0 list but are reclassified because they don't
  change the design and don't have known operator demand:

  - **Resume on interruption** — checkpoint-file format is
    real new design surface. The current Ctrl-C-then-restart-
    from-zero workflow is acceptable for the dump sizes the
    tool targets.
  - **Native Cloudflare HTTP API client** — wrangler shell-out
    works. A native client would avoid subprocess spawn costs
    and the wrangler dependency, but it adds a non-trivial
    HTTP auth surface to the binary.
  - **Custom invariant registration via CLI** — the library
    accepts a slice of `InvariantCheckFn` already; the CLI
    just hardcodes `default_invariant_checks()`. When an
    operator hits a case the defaults miss, the surface to
    expose this is straightforward.

- **OAuth 2.0 Token Introspection (RFC 7662).** `POST /introspect`.
  RFC 7009 (`/revoke`) shipped with the OIDC core; the
  introspection counterpart is the gap. RPs that want to
  validate opaque access tokens stateful-style (instead of
  parsing JWTs themselves) need this. Implementation lifts
  the existing `ActiveSessionStore::status` lookup and wraps
  it in the RFC 7662 response shape (`active`, `client_id`,
  `username`, `exp`, etc.) gated on client authentication.
  The discovery doc gains an `introspection_endpoint`
  declaration. Estimated scope: ~150 lines + tests.

- ✅ **Property-based tests (`proptest`)** — shipped in v0.51.1 (RFC 003). ~~for round-trip and
  matcher invariants.** Two surfaces benefit most:
  1. **Crypto round-trips**: `EncodingKey::from_ed_pem` →
     `DecodingKey::from_ed_der` → JWT sign → JWT verify →
     equal claims; magic-link token gen → verify →
     equal subject. Pure-deterministic, well-defined
     invariants — proptest catches the pathological inputs
     that example-based tests don't reach.
  2. **`redirect_uri` matcher**: OAuth's redirect-URI
     matching is historically the most bug-prone piece of
     a provider (open-redirect via prefix-match, port
     stripping, percent-encoding, IDN). proptest can
     generate adversarial URI pairs and assert the match
     decision matches the spec.

  Modest dep cost (proptest is dev-dep only). Target slot:
  any maintenance window.

- ✅ **`cargo fuzz` for the JWT parser surface** — shipped in v0.51.2 (RFC 005). cesauth
  receives potentially adversarial JWTs on every
  `Authorization: Bearer ...` request. The `jsonwebtoken`
  crate itself is upstream-fuzzed, but cesauth's wrappers
  (`jwt::signer.rs` PEM/DER parsing, claim extraction
  helpers) are independent code paths. Fuzz them for panics,
  OOM, and DoS. Layer-1 setup (single fuzz target,
  GitHub Actions one-shot run) is cheap; long-term continuous
  fuzzing is parked under "Later" for now. Note: CIDR
  parser is **not** a fuzz target — cesauth has no IP
  allowlist code path (Cloudflare dashboard handles
  IP-level controls). Config parser is `Config::from_env`
  reading discrete env vars, surface too small to fuzz
  productively.

- ✅ **WebAuthn error → typed client responses** — shipped in v0.51.1 (RFC 004). ~~The current
  `CoreError::WebAuthn(&'static str)` carries diagnostic
  strings (`"rpIdHash mismatch"`, `"signature invalid"`,
  etc.) that surface only in server-side logs. The HTTP
  response shape collapses them into a generic 400. Client
  UX would benefit from a small `WebAuthnErrorKind` enum
  exposed in the JSON body — distinguishing "wrong
  authenticator", "user cancelled", "credential not
  registered", "RP id mismatch (likely subdomain
  misconfiguration)" so RPs can render specific guidance.
  Server-side strings stay as today (the typed variant is
  the *category*, the string is the *detail*).

- **Domain-metric observability.** Cloudflare Analytics
  already covers HTTP-level metrics (request rate, error
  rate, p50/p95/p99 latency). The gap is **domain-specific**
  counters: `auth_attempts_total{result, method}`,
  `tokens_issued_total{kind}`, `webauthn_ceremony_failures_total{stage}`.
  Architecturally, Prometheus pull is a poor fit for
  Workers (stateless, horizontally scaled — `/metrics` would
  return single-instance values). The native path is to
  emit metric events through the existing `log.rs`
  channel and aggregate downstream via Logpush →
  ClickHouse / BigQuery / Datadog, **or** use the
  Cloudflare `cloudflare:analytics-engine` binding which
  is purpose-built for this. Target slot: any maintenance
  window once the operator-facing dashboarding requirement
  becomes concrete.

- **`cargo audit` integration (shipped in 0.15.1).** Three
  layers landed at once:
  1. **Initial sweep**: ran against the rustsec/advisory-db
     `main` checkout on 2026-04-28. One finding —
     RUSTSEC-2023-0071 in `rsa 0.9.10` (Marvin Attack timing
     side-channel), pulled in transitively by `jsonwebtoken`'s
     `rust_crypto` feature. cesauth never exercised the RSA
     path (EdDSA-only), but the dep would have shipped in the
     workspace lock anyway. Fixed by narrowing `jsonwebtoken`
     features from blanket `rust_crypto` to explicit
     `ed25519-dalek` + `rand`. Post-fix sweep clean; dep count
     186 → 176.
  2. **`.github/workflows/audit.yml`** using
     `rustsec/audit-check@v2.0.0`. Triggers: push, PR,
     weekly cron (Mondays 06:00 UTC), manual dispatch.
     New advisories fail the workflow.
  3. **Operator documentation**: `docs/src/deployment/production.md`
     gains a "Step 7 — Verify dependencies" pre-deploy
     check; the operator runbook in
     `docs/src/expert/tenancy.md` documents the same command
     under "Verifying dependencies before an upgrade".

  Layer 4 (Makefile / xtask wrapper) is **not planned** —
  the cost-vs-value isn't there for a workspace with no
  Makefile today.

- **Login → tenant resolution.** Today `users.email` is globally
  unique. Multi-tenant login flows need either
  tenant-scoped email uniqueness (schema change) or a tenant-picker
  step in the login flow. Spec §6.1 mentions tenant-scoped auth
  policies; the precise UX is open. Tracked here so the change is
  not made silently.

- **External IdP federation.** `AccountType::ExternalFederatedUser`
  is reserved in 0.5.0 but no IdP wiring exists. SAML / OIDC
  federation surface; specific protocols TBD.

### Later

- ✅ **`oidc_clients.client_secret_hash` documentation drift** — resolved in v0.51.0 (RFC 002).
  ~~The schema comment in `migrations/0001_initial.sql` describes
  `client_secret_hash` as "argon2id(secret) or NULL", but no
  Argon2 implementation exists~~ in cesauth as of v0.26.0 — the
  hashing path for client_secret falls back to whatever the
  adapter does, which currently is plaintext comparison or
  unimplemented. (Discovered during the v0.26.0 TOTP work.)
  Two paths to resolve: either implement Argon2id hashing of
  client_secret on write + verify on read (matches the schema
  comment, adds a real password-stretching dependency for the
  one input type that's user-chosen), OR relax the schema
  comment to "SHA-256(secret) or NULL" and route client_secret
  through the same hashing path as admin_tokens (matches what
  cesauth actually does for similar bearer secrets). The
  former is more rigorous; the latter is more honest. Either
  is fine; the current state — schema lying — is not.

- **OIDC `id_token` issuance.** Drafted as ADR-008 in v0.25.0.
  Closes the OIDC compliance gap surfaced by the v0.25.0 email
  verification audit: `exchange_code` and `rotate_refresh`
  currently return `id_token: null`, and the discovery doc was
  honestly reset to RFC 8414 OAuth 2.0 metadata until id_token
  ships. Implementation requires:
  - `UserRepository` injected into `cesauth_core::service::token`
    (generic-parameter addition).
  - `auth_time` plumbed through `Challenge::AuthCode` and
    `RefreshTokenFamily` DO state.
  - `build_id_token_claims` pure function with scope-driven
    population (`email`/`email_verified` iff `email` scope;
    `name` iff `profile` scope).
  - Discovery doc restored to OIDC Discovery 1.0 shape with
    `claims_supported` field added.
  - End-to-end test: authorize → token exchange → id_token
    decoded and claims verified.
  - 8 v0.25.0 discovery shape tests inverted/extended to OIDC
    posture.

  **Scheduled when**: TOTP track (v0.26.0 - v0.30.0) is now
  complete. The schedule continues with the UI/UX iteration
  (v0.31.0) and the audit-log-hash-chain track (v0.32.0+)
  before the feature track resumes. Likely v0.36.0 or later.
  Not blocking 1.0 unless a deployment requires OIDC compliance
  for an identity-federation integration. The audit doc and
  ADR-008 keep the design ready for whoever picks it up.

- **`prompt=select_account`.** Requires multi-session / account-picker
  UX. Rejected today.

- **Full FIDO attestation verification** (`packed`, `tpm`,
  `android-key`, `android-safetynet`, `fido-u2f`, `apple`).
  Requires a FIDO Metadata Service (MDS) implementation and a CA
  trust store. Useful if a deployment needs AAGUID-gated access
  control.

- **Device Authorization Grant** (RFC 8628) for CLI / smart-TV
  clients.

- **Dynamic Client Registration** (RFC 7591 / 7592) if multi-tenant
  deployments become a target.

- **Request Objects** (`request` / `request_uri` parameters, JAR).

- **Pushed Authorization Requests** (RFC 9126 PAR).

- **Rate-limit bucket tuning** based on production telemetry.

- **FIDO Alliance conformance certification.** Costs real money and
  assumes full attestation support is already in.

- **OIDC `client_secret` brute-force lockout (per-client).**
  Per-client failure tracking on `oidc_clients` for
  `client_secret_basic` / `client_secret_post` authentication
  failures at `/oauth/token`. **Trigger condition for adoption**:
  production telemetry shows non-trivial volume of failed
  `client_secret` attempts against existing clients. As of
  v0.23.0 (the canonical release), the prior v0.23.0-withdrawn
  attempt assumed user-account lockout, which is inapplicable
  to cesauth's password-less authentication model — Magic Link
  and WebAuthn are the only credential paths and both have
  cryptographic brute-force resistance. Per-client lockout
  would have a different data model (lockout state on
  `oidc_clients`, no per-tenant policy override since clients
  are tenant-scoped, no Magic Link/WebAuthn interaction). A
  future ADR (probably -010) would re-design from the
  per-client angle if the threat materializes. The withdrawn
  artifact (`cesauth-0.23.0-account-lockout-withdrawn.tar.gz`)
  is preserved for reference; ADR-006 number is not reused.

- **CSP without `'unsafe-inline'` (nonces or template
  refactor).** ADR-007 §Q3 documents the v0.23.0 limitation:
  cesauth's HTML templates embed `<style>` and `<script>`
  inline, requiring per-route CSPs to use `'unsafe-inline'`.
  Two paths to remove this: extract inline content to
  same-origin files, or generate per-request nonces and
  attach them to every inline block. The latter is the
  modern best practice. Either path is real refactor work
  (templates module + every render path); track separately
  from the security headers shipped in v0.23.0.

- **Cesauth-specific attack surface review.** A periodic
  audit (ideally before each major milestone, and at minimum
  before any 1.0 release) of cesauth-specific attack
  surfaces. Initial 2026 review identified the following as
  worth examining; this list is not exhaustive and the
  reviewer should look broader:
  - **Open redirect via OAuth `redirect_uri` matcher**: the
    matcher implementation should be exercised with proptest-
    generated adversarial URI pairs. (Already on roadmap as
    "Property-based tests".)
  - **JWT alg confusion attack**: confirm the verifier
    rejects `alg: none`, and never verifies `alg: HS256`
    against a public key.
  - **Confused deputy in tenant scoping**: tenant A's admin
    operating tenant B's resources via global `/api/v1/...`
    routes. (Already on roadmap as "`check_permission`
    integration".)
  - **Subdomain takeover**: if a deployment surfaces
    tenants on `<slug>.example.com`, retired tenants must
    have DNS reclaimed.
  - **PKCE enforcement**: confirm public clients are
    rejected without PKCE.
  - **Cookie security**: SameSite, Secure, HttpOnly attrs
    on every cookie; Path scope; rotation on session id.
  - **Timing side-channels** in token comparison and
    secret verification (constant-time comparison
    everywhere).
  - **Open registration paths**: anonymous trial creation
    rate limit, abuse vectors.

  **Maintainer TODO**: schedule the next review by 2026-Q4
  or before v0.30.0, whichever is sooner. Outcomes either
  feed into the security-track minor releases or become
  individual hardening releases.

---

## Explicitly out of scope

The following are not planned for any future release. If a deployment
needs one of these, cesauth is the wrong choice.

- **Password-based authentication.** No password-hash table, no
  "forgot password" flow, no password reset endpoint. Magic Link
  and passkey cover the equivalent UX without the password's
  problems.

- **SAML 2.0**, **WS-Federation**, **OAuth 1.0**. Out of scope in
  both directions (not as IdP, not as consumer).

- **LDAP directory integration.** Not blocked on LDAP specifically;
  blocked on the entire concept of federating identity from an
  external directory. cesauth is a primary identity source.

- **Management GUI.** The admin surface is an API (`/admin/*`). If
  you need a dashboard, build one on top.

- **Implicit flow** / **hybrid flow**. Deprecated by OAuth 2.1 for
  good reasons.

- **Docker / container-based production deployment.** cesauth
  targets the Cloudflare Workers runtime (V8 isolate, wasm32
  + the `cf::*` API surface, Durable Objects, R2, D1). None of
  these are available inside a generic container. Production
  deployment is `wrangler deploy`; local development is
  `wrangler dev`. A "build environment" container (containing
  `cargo-1.91`, `wrangler`, `node`) for developer onboarding
  would be a pure ergonomics win, but is not on the roadmap —
  the supported install paths in `docs/src/beginner/prerequisites.md`
  cover the same ground.

- **Prometheus `/metrics` endpoint.** Architecturally a poor
  fit for Workers' stateless / horizontally-scaled execution
  model — a scrape would return single-instance values that
  don't aggregate. See "Domain-metric observability" in
  Planned for the alternative path (Logpush + downstream
  aggregation, or `cloudflare:analytics-engine`).

- **A generic `KeyValueStore` trait.** See [Storage responsibilities](docs/src/expert/storage.md)
  for the reasoning.

- **`mod.rs` module files.** See [Crate layout](docs/src/expert/crate-layout.md).

---

## How to propose changes

Open an issue describing the use case. If it aligns with cesauth's
scope, we'll discuss the design tradeoffs before code. A formal
`CONTRIBUTING.md` is planned but not yet written.
