# Changelog

All notable changes to cesauth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

cesauth is in active development. The public surface — endpoints,
`wrangler.toml` variable names, secret names, D1 schema, and
`core::ports` traits — may change between minor versions. Breaking
changes will always be called out here.

---

---

## Older releases

Entries for v0.49.0 and earlier are in
[`docs/changelog-archive/`](docs/changelog-archive/README.md),
split by minor-version range:

- v0.41–v0.49 → [`CHANGELOG-0.41-to-0.49.md`](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md)
- v0.31–v0.40 → [`CHANGELOG-0.31-to-0.40.md`](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md)
- v0.1–v0.30  → [`CHANGELOG-0.1-to-0.30.md`](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md)

---

## [0.56.0] - 2026-05-12

Implements RFC 040-044: OIDC compliance completion, technical debt clearance,
and the first two SaaS-required features from the commercial extension guide.

### OIDC compliance (RFC 040)

- **`GET /userinfo` + `POST /userinfo`** — OIDC Core §5.3.  Accepts a Bearer
  access token; returns claims gated by granted scopes (`email`, `profile`).
- `build_userinfo_claims(sub, user, scopes)` pure function in
  `cesauth_core::oidc::userinfo` (10 unit tests).
- `DiscoveryDocument.userinfo_endpoint` field added — discovery doc now
  complete per OIDC Discovery 1.0.

### Technical debt — token service (RFC 041)

- `TokenDeps<CR,AS,FS,GR,UR,RL>` struct replaces 5-parameter generic lists on
  `exchange_code` and `rotate_refresh`.  Call sites construct `TokenDeps` once
  per request.
- `TokenConfig { access_ttl_secs, refresh_ttl_secs, iss }` bundles static
  config; no more repeating TTLs at every call site.
- Zero wire change.  Test stubs updated.

### Preview-and-apply: first adopter (RFC 042)

- `POST /admin/console/config/log_level/preview` — RFC 018 infrastructure
  first live use.  Renders an impact statement + HMAC-signed preview token.
- `POST /admin/console/config/log_level/apply` — verifies preview token
  (TTL 5 min, CSRF-bound), persists new level to `CONFIG_KV`, emits
  `OperationApplied` audit event.
- Routes added to route-contracts.md.

### SaaS features (RFC 043 / RFC 044)

**RFC 043 — Invitation tokens** (`crates/core/src/invitation.rs`)

- `invitation_tokens` table (migration 0018): unique pending invite per
  `(tenant_id, email)`, 72-hour TTL, full accept/revoke lifecycle.
- `issue_invitation`, `verify_invitation`, `accept_invitation`,
  `revoke_invitation` pure service functions.
- `InvitationVerifyOutcome`: `Valid | Expired | Revoked | AlreadyAccepted | NotFound`.
- `InvitationRepository` port trait.
- 11 unit tests covering conflict, expiry, email case-insensitivity, etc.

**RFC 044 — Deletion requests / GDPR Article 17** (`crates/core/src/deletion.rs`)

- `deletion_requests` table (migration 0019): one pending request per user,
  configurable grace period (default 30 days), request row retained post-delete.
- `schedule_deletion`, `execute_deletion` (calls `UserRepository::delete_by_id`
  + ON DELETE CASCADE), `cancel_deletion` service functions.
- `DeletionRequestRepository` port trait.
- `DeletionRequest.is_due(now)` helper for cron sweep.
- 8 unit tests covering conflict, execution, cancellation, grace period boundary.

**New `CoreError::Conflict`** variant — reusable for both invitation and deletion
uniqueness violations.

### Schema

SCHEMA_VERSION: 17 → **19** (migrations 0018–0019)

### Test counts

| Crate | v0.55.0 | v0.56.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 559 | **588** | +29 |
| `cesauth-adapter-test` | 117 | **117** | ±0 |
| `cesauth-ui` | 270 | **270** | ±0 |
| `cesauth-migrate-test` | 17 | **21** | +4 |
| **Total** | **963** | **996** | **+33** |

### Remaining work for RFC 043/044

Both `invitation` and `deletion` cores are complete with tests.  Worker
routes (HTTP handlers, Cloudflare D1 adapters) are the next step:

- `POST /admin/t/:slug/invitations`, `GET/POST /accept-invite`
- `POST /me/security/delete-account`, admin deletion queue routes
- Cron: `sweep_pending_deletions`
- Audit `EventKind`: `InvitationIssued`, `InvitationAccepted`, `InvitationRevoked`,
  `DeletionRequested`, `DeletionExecuted`, `DeletionCancelled`

---

## [0.55.0] - 2026-05-09

Addresses all P0/P1 findings from the v0.54.0 external code review
(RFC 030–039).

### Security / correctness

- **RFC 033**: OIDC nonce now reflected in `id_token` at authorization-code
  exchange (OIDC Core §3.1.3.6). Previously `None` was passed, causing strict
  RPs to reject the token.
- **RFC 030**: `Category::Magic` added to log.rs as a sensitive category.
  Provider response bodies removed from `MailerError` — eliminates the path
  where external mail providers echoing back request bodies could expose OTP
  codes in Cloudflare log drains.
- **RFC 031**: `MagicLinkMailer` `Box<dyn>` factory replaced with
  `CloudflareMagicLinkMailer` enum dispatcher. Resolves the dyn-compatibility
  build blocker (`async fn` in trait is not object-safe).
- **RFC 034**: `/introspect` handler connected to `find_auth_view` (RFC 026
  infrastructure). Single D1 read instead of two; TOCTOU window closed.
- **RFC 037**: `groups` composite FK changed from `ON DELETE SET NULL` to
  `ON DELETE RESTRICT`. The previous `SET NULL` would attempt to null `tenant_id`
  (NOT NULL column) causing a constraint error on any org hard-delete.

### Database / schema

- **RFC 032**: Forward repair migration `0016_repair_legacy_0004_fk_and_collation.sql`.
  Repairs existing DBs where the original broken `0004` was applied: rebuilds
  `users` with `COLLATE NOCASE` + rebuilds `authenticators`/`consent`/`grants`
  with FK pointing at `users` (not `users_pre_0004`). Idempotent — clean installs
  (with fixed 0004) pass through without data change. Includes `PRAGMA foreign_key_check`.
- **RFC 037**: `0017_groups_fk_restrict.sql` — see above.
- SCHEMA_VERSION: 15 → **17**

### Audit traceability (RFC 036)

- `NewAuditEvent` gains `request_id: Option<&str>` field.
- `AuditEventRow` gains `request_id: Option<String>` field.
- `worker::audit::Event` gains `request_id` + `with_request_id()` builder method.
- D1 INSERT and SELECT updated to include `request_id` column (migration 0015 added the column).
- In-memory adapter and Cloudflare D1 adapter thread the field through.
- `write_owned` (cron paths) passes `request_id: None`.

### CI gates (RFC 035)

- `.github/workflows/test.yml` — `cargo-1.91 test` on host crates on every PR
- `.github/workflows/clippy.yml` — `cargo-1.91 clippy -D warnings` on host crates
- `.github/workflows/deny.yml` — `cargo deny check` with `deny.toml` (licenses + advisories)
- `bundle-size.yml` updated from `stable` to `1.91` toolchain
- `deny.toml` added to workspace root

### Housekeeping

- **RFC 038**: `nodejs_compat` removed from `wrangler.toml` (RFC 029 measurement: 0 diff)
- **RFC 039**: `docs/src/beginner/first-oidc-flow.md` and `production.md` updated
  to remove stale "OTP in audit log" instructions; `preflight.md` updated.
  Three new drift-scan patterns added: `dev-delivery handle=`, `-> Box<dyn MagicLinkMailer>`,
  and nodejs_compat return-type patterns.

### Test counts

| Crate | v0.54.0 | v0.55.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 557 | **559** | +2 (RFC 033 nonce tests) |
| `cesauth-adapter-test` | 117 | **117** | ±0 |
| `cesauth-ui` | 270 | **270** | ±0 |
| `cesauth-migrate-test` | 14 | **17** | +3 (RFC 032/037) |
| **Total** | **958** | **963** | **+5** |

### Wire compatibility

Additive only. `id_token.nonce` appears for new flows where the authorize
request included `nonce=...`; absent otherwise. `audit_events.request_id`
is nullable — existing rows read back as `None`.

---

## [0.54.0] - 2026-05-09

Implements RFC 001 (OIDC `id_token` issuance), closing the compliance gap
documented in ADR-008. cesauth now issues fully-spec-compliant id_tokens on
`authorization_code` exchange and `refresh_token` rotation when the `openid`
scope is present.

### What shipped

**OIDC `id_token` issuance (RFC 001)**

- `crates/core/src/oidc/id_token.rs` — pure module with:
  - `build_id_token_claims(iss, user, client_id, scopes, nonce, auth_time, iat, ttl)`
    — scope-driven claim population per ADR-008 §Q2.
  - `sign_id_token(claims, signer)` — thin wrapper over the existing Ed25519
    JWS Compact serializer; `kid` header set identically to access tokens.
- `Challenge::AuthCode.auth_time: i64` — unix timestamp of the authentication
  event; `#[serde(default)]` for migration compatibility (pre-RFC 001 challenges
  deserialize with 0 and fall back to `issued_at`).
- `FamilyState.auth_time: i64` + `FamilyInit.auth_time: i64` — same pattern;
  refresh-path id_token preserves the **original** auth_time, not the rotation
  moment (ADR-008 §Q10).
- `service::token::exchange_code` — new `users: &UR` and `iss: &str` generic
  parameters; issues id_token when `openid` ∈ scopes.
- `service::token::rotate_refresh` — same signature extension.
- `post_auth::complete_auth_post_gate` — writes `auth_time: now` to AuthCode
  at the moment the credential step completes.
- Worker `/token` handler — creates `CloudflareUserRepository` and forwards
  `iss` from config to both token service functions.

**Discovery doc restored to OIDC posture**

- `DiscoveryDocument` gains `id_token_signing_alg_values_supported: ["EdDSA"]`,
  `subject_types_supported: ["public"]`, `claims_supported: [...]` (10 fields).
- `scopes_supported` restored to `["openid", "profile", "email", "offline_access"]`.
- 8 v0.25.0 "honest-reset" tests inverted to assert OIDC posture.

### Test counts

| Crate | v0.53.0 | v0.54.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 532 | 557 | +25 |
| `cesauth-adapter-test` | 117 | 117 | ±0 |
| `cesauth-ui` | 270 | 270 | ±0 |
| `cesauth-migrate-test` | 14 | 14 | ±0 |
| **Total** | **933** | **958** | **+25** |

New tests:
- 12 `oidc::id_token::tests::*` — unit tests for claim assembly and JWT signing
- 8 `service::token::tests::id_token_tests::*` — integration tests against
  inline stubs covering exchange + rotate id_token issuance, auth_time
  preservation, and no-openid-scope suppression
- 5 `oidc::discovery::*` — new OIDC-posture assertions (8 old tests inverted)

### Wire changes

**Additive only.** Existing `TokenResponse.id_token` was already present as
`Option<String>` (serialized as `null` pre-RFC 001); it now carries a real
value when `openid` ∈ scopes.  Clients that do not request `openid` see no
change.

**Discovery doc** field additions are additive; JSON parsers that ignore
unknown fields see no change.

### Breaking changes

None.

---

## [0.53.0] - 2026-05-09

Implements RFC 020 (migration chain hygiene), RFC 021 (user FK cascade
alignment), RFC 022 (permission catalog seed sync), RFC 023 (tenant boundary
integrity), RFC 024 (D1 index restoration), RFC 025 (Workers operational
readiness), RFC 026 (introspect hot-path consolidation), RFC 027
(accessibility and route contracts), RFC 028 (CHANGELOG/ROADMAP volume
policy), RFC 029 (rustfmt.toml review), RFC 013 (operational envelope),
RFC 014 (audit append performance), RFC 015 (request traceability), RFC 016
(admin scope badge), RFC 017 (OIDC audience admin editor), RFC 018
(preview-and-apply pattern). See the linked RFCs for design detail.

### What shipped (summary)

- **Migration chain** (`rfcs/done/020`): `schema_meta` table, `0004` rebuilt
  with FK cascade + COLLATE NOCASE restored, `0009` schema_meta write fixed,
  all migrations now write version. `cesauth-migrate-test` integration crate
  (14 tests).
- **User FK cascades** (`rfcs/done/021`): 7 tables gain `ON DELETE CASCADE`
  to `users(id)` — TOTP secrets, sessions, memberships, and role assignments
  are cleaned up when a user is deleted.
- **Permission catalog sync** (`rfcs/done/022`): `tenant:member:add` and
  `tenant:member:remove` added to the `permissions` seed and granted to
  `tenant_admin` / `system_admin` roles. Previously tenant admins received 403
  when attempting member management despite it being documented as supported.
- **Tenant boundary integrity** (`rfcs/done/023`): composite FKs on `groups`
  enforce cross-tenant isolation at the schema layer.
  `CoreError::CrossTenantReference` + service-layer validator.
- **D1 index restoration** (`rfcs/done/024`): restores `idx_users_status`,
  `idx_users_created_at` lost at the 0004 rebuild; adds partial indexes for
  anonymous-user sweep and session-index cron scan.
- **SCHEMA_VERSION** 10 → 15.
- **Workers operational readiness** (`rfcs/done/025`): bundle-size CI gate
  (2.5 MiB), plan-tier declaration in preflight doc.
- **`/introspect` hot path** (`rfcs/done/026`): `ClientAuthView` +
  `find_auth_view()` port method consolidates two D1 reads into one per
  request, closing a TOCTOU window.
- **Route contracts** (`rfcs/done/027`): `docs/src/expert/route-contracts.md`
  (149 routes), CI enforcement script, 3 flash accessibility tests.
- **CHANGELOG/ROADMAP volume** (`rfcs/done/028`): CHANGELOG 511KB → 62KB,
  ROADMAP 211KB → 79KB; archive files in `docs/changelog-archive/`.
- **`rustfmt.toml` removed** (`rfcs/done/029`): measurement confirmed zero
  diff; `cargo fmt --check` CI added.
- **ADR-016** (`rfcs/done/013`): Paid plan as operational baseline; bundle
  budget 2.5 MiB; cron batch-size env vars documented.
- **ADR-017** (`rfcs/done/014`): audit append telemetry (100ms threshold
  warning); Path B redesign deferred pending telemetry data.
- **RFC 015**: `request_id` (cf-ray) threaded through `LogConfig` and
  `audit_events`; ADR-018 documents deliberate absence of file-writing logger.
- **Scope badge** (`rfcs/done/016`): all 3 admin frames carry a scope badge
  (System/Tenancy/Tenant) with distinct color tokens; JA+EN i18n.
- **OIDC audience editor** (`rfcs/done/017`): `AudienceTarget` type,
  `resolve_audience_target` helper, tenant-admin editor form;
  `OidcClientAudienceChanged` + `OperationPreviewed` + `OperationApplied`
  audit event kinds.
- **Preview-and-apply** (`rfcs/done/018`): `ImpactStatement`, `ImpactSeverity`,
  `PreviewToken` infrastructure; `preview_body` template helper; first adopter
  impact functions for LOG_LEVEL change and admin token rotation.

### Test counts

| Crate | v0.52.1 | v0.53.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 493 | 532 | +39 |
| `cesauth-adapter-test` | 117 | 117 | +0 |
| `cesauth-ui` | 249 | 270 | +21 |
| `cesauth-migrate-test` | 0 (new crate) | 14 | +14 |
| **Total** | **859** | **933** | **+74** |

### Schema

SCHEMA_VERSION 10 → 15 (migrations 0011–0015). New migrations:
- 0011: permission catalog sync (RFC 022)
- 0012: user FK cascades (RFC 021)
- 0013: tenant composite FK keys (RFC 023)
- 0014: D1 index restoration (RFC 024)
- 0015: `audit_events.request_id` column (RFC 015)

### New CI workflows

- `.github/workflows/bundle-size.yml` — gzip budget gate
- `.github/workflows/route-contracts.yml` — route documentation enforcement
- `.github/workflows/fmt.yml` — `cargo fmt --check`

### Breaking changes

None. All changes are additive at the wire layer. Existing audit rows
deserialize cleanly (`request_id` is nullable). Existing D1 schema upgrades
via the migration chain.

---

## [0.52.1] - 2026-05-06

Patch release. Implements RFC 012 (documentation and repo hygiene) and
RFC 007 (attack surface review cadence). No production behavior change;
no schema migration; no new env vars.

### Why this release

**RFC 012**: Four documentation quality items identified in the external
v0.50.1 codebase review. Two claims in README and `docs/src/introduction.md`
were factually wrong (admin console existence, audit storage). `migrate.rs`
at 2568 lines exceeded the 800-line soft cap. Inline comments referenced
the removed `jsonwebtoken` and R2 audit subsystems. No drift-detection
automation existed to catch future drift.

**RFC 007**: The attack surface review cadence process was defined in the
2026 initial review but never written into the codebase. This release
adds the written policy and creates the framework for per-quarter review
deliverables.

### What shipped

**RFC 012 — Documentation and repo hygiene**

- **README rewrite** (PR 1): "No management GUI" → "No SAML/LDAP/password
  login; admin console and tenant-scoped admin surface ship for operator
  use". "All land in R2" → "All land in D1's hash-chained `audit_events`
  table (ADR-010)". `Quick Start` code block removed spurious `R2` from
  the D1/KV/DOs description.
- **Inline comment cleanup** (PR 2): `routes/dev.rs` route comment updated
  from R2 bucket to D1 table; `config.rs` doc comment simplified (dropped
  `jsonwebtoken::EncodingKey::from_ed_pem` historical ref); `routes/oidc/token.rs`
  PKCS8 parser comment updated from `jsonwebtoken` to `pkcs8` crate.
- **`docs/src/introduction.md`** (PR 2): "No management GUI" claim corrected
  to match README.
- **`scripts/drift-scan.sh`** (new, PR 3): 60-line bash script that grep-scans
  the workspace for stale narrative phrases. Current pattern list:
  `"all land in R2"`, `"R2_AUDIT"`, `"pub code_plaintext"`,
  `"No management GUI"`. Passes cleanly on current codebase.
- **`.github/workflows/drift-scan.yml`** (new, PR 3): runs drift-scan on
  every PR and main-branch push. No Rust toolchain required; < 10 seconds.
- **`wrangler.toml`** (PR 4): added clarifying comment to `[[durable_objects]]`
  block noting RATE_LIMIT = Durable Object (not KV); KV holds only
  long-lived caches.
- **`crates/core/src/migrate.rs` split** (PR 5): 2568-line monolith → facade
  of ~35 lines + 7 focused submodules. Public API unchanged; all items
  re-exported from facade. Submodule sizes: `error.rs` (75 lines),
  `types.rs` (165 lines), `redaction.rs` (200 lines), `export.rs` (265 lines),
  `verify.rs` (135 lines), `invariants.rs` (425 lines), `import.rs` (20 lines).
  All 29 migrate tests pass unchanged.

**RFC 007 — Attack surface review cadence**

- `docs/src/expert/attack-surface-review-cadence.md` (new): process document
  defining when reviews run (pre-major, pre-cross-cutting-refactor,
  when new threat classes surface), the per-review deliverable shape
  (structured Markdown in `docs/src/expert/security-review-<year>-<quarter>.md`),
  the 8 starting surface categories from the 2026 initial review, and the
  link to `drift-scan.sh` as the continuous inter-review gate.
- `docs/src/SUMMARY.md`: entry added under Expert section.
- `rfcs/done/007-attack-surface-review-cadence.md`: RFC status → Implemented.

### RFC lifecycle

- `rfcs/done/007-attack-surface-review-cadence.md`: moved from proposed.
- `rfcs/done/012-doc-and-repo-hygiene.md`: moved from proposed.
- `rfcs/README.md`: Done table updated.

### Tests

859 lib + 29 migrate = 888 total, all pass. No new tests needed (RFC 012
is documentation; RFC 007 is process; migrate split is a mechanical refactor
gated by the existing 29-test suite).

### Schema / wire / DO changes

None. Patch-only release.

### Upgrade procedure

```
1. Deploy v0.52.1 (drop-in; no action required).
2. Run scripts/drift-scan.sh in your pipeline to catch future drift.
```

## [0.52.0] - 2026-05-06

Minor release. Implements RFC 006 (CSP without `'unsafe-inline'`) and
RFC 019 (RFC lifecycle policy adoption). RFC 006 earns the minor bump:
it changes the observable `Content-Security-Policy` HTTP header for all
HTML responses, which is an operator-visible behavior change.

### Why this release

**RFC 006**: ADR-007 (v0.23.0) noted `'unsafe-inline'` as a known
limitation; CSP Level 2 nonces were the intended fix. This release closes
that gap. Every inline `<style>` and `<script defer>` tag in cesauth's
rendered HTML now carries a per-request CSPRNG nonce. The
`Content-Security-Policy` header for HTML responses drops `'unsafe-inline'`
from `script-src` and `style-src` and adds `'nonce-<value>'` instead.
A CSP Level 2-aware browser will ignore any injected `<script>` or
`<style>` without the matching nonce, eliminating the XSS amplification
class that `'unsafe-inline'` would otherwise allow.

**RFC 019**: The `rfcs/` directory was a flat list of 18 files with all
statuses hardcoded to `Ready`. This release restructures it to a 4-folder
lifecycle (`proposed/`, `done/`, `archive/`) governed by a written policy
(RFC 019 itself, `rfcs/done/019-rfc-lifecycle-policy.md`).

### What shipped

**RFC 006 — CSP without `'unsafe-inline'`**

- `cesauth_core::security_headers::CspNonce` (new type): generates a
  cryptographically unguessable 16-byte base64url nonce per-request.
  Methods: `generate() -> Result<Self, getrandom::Error>`,
  `from_str(s: &str) -> Self`, `as_str() -> &str`,
  `csp_expression() -> String` (returns `'nonce-<value>'`).
- `build_csp_with_nonce(csp: &str, nonce: Option<&CspNonce>) -> String`
  (internal helper): injects `'nonce-<value>'` into `script-src` and
  `style-src` directives; removes `'unsafe-inline'`; supports `{nonce}`
  placeholder in operator-supplied `SECURITY_HEADERS_CSP` override.
- `headers_for_response` gains `nonce: Option<&CspNonce>` parameter.
  All existing call sites pass `None`; HTML render paths pass the
  per-request nonce.
- `cesauth_ui::set_render_nonce(nonce: &str)` / `render_nonce() -> String`:
  thread-local nonce store for the Cloudflare Workers per-Isolate model.
  Worker handlers call `set_render_nonce` before rendering HTML; template
  functions read it via `crate::render_nonce()` without parameter changes
  to the public API.
- `crates/ui/src/admin/frame.rs`, `tenant_admin/frame.rs`,
  `tenancy_console/frame.rs`: `<style nonce="{nonce}">` — frame-level
  inline CSS now carries the nonce attribute.
- `crates/ui/src/templates.rs` (`frame_with_flash`, `login_page_for`):
  `<style nonce="{nonce}">` and `<script defer nonce="{nonce}">`.
- Worker route handlers (`routes/ui.rs`, `routes/oidc/authorize.rs`,
  `routes/admin/console/render.rs`, `routes/me/*`, `routes/magic_link/*`):
  each HTML-returning handler now calls `CspNonce::generate()` +
  `cesauth_ui::set_render_nonce()` before rendering. On CSPRNG failure:
  audit `CsrfRngFailure`, return HTTP 500 (fail-closed).
- Per-route CSP strings: `'unsafe-inline'` replaced by `format!("...
  'nonce-{n}'...", n = csp_nonce.as_str())`. The login-page Turnstile
  variant and the non-Turnstile variant are both updated.
- `security_headers::apply` (worker middleware): reads `render_nonce()` 
  after the handler runs and passes `Some(CspNonce::from_str(&nonce_str))`
  to `headers_for_response`, so the global security-headers middleware
  also injects the nonce into its CSP output.
- `crates/ui/src/templates/tests.rs`: `strip_inline_style` updated to
  match `<style nonce="...">` tags. Five new nonce-injection tests added.
- 15 new tests in `security_headers::nonce_tests` covering RFC 006
  §Test plan items 1–5, 7–8, 12–13 (uniqueness, base64url format,
  ≥128-bit entropy, CSP expression format, `{nonce}` placeholder,
  `unsafe-inline` removal, HTML/non-HTML CSP presence).

**RFC 019 — RFC lifecycle policy**

- `rfcs/` restructured: `proposed/` (10 open RFCs), `done/` (8 shipped
  RFCs + RFC 019 itself), `archive/` (empty).
- All existing RFC Status fields updated to match their folder.
- `rfcs/README.md` rewritten as a state-grouped index.
- `rfcs/done/019-rfc-lifecycle-policy.md` (new): the lifecycle policy
  document itself, implementing the policy it describes.

### Tests

859 lib tests pass (was 842 in v0.51.2).

| Crate | Before | After | Delta |
|---|---|---|---|
| `cesauth-core` | 481 | 493 | +12 (RFC 006 nonce + CSP tests) |
| `cesauth-adapter-test` | 117 | 117 | — |
| `cesauth-ui` | 244 | 249 | +5 (RFC 006 nonce injection tests) |

### Wire / operator changes

- `Content-Security-Policy` header for HTML responses: `'unsafe-inline'`
  removed from `script-src` and `style-src`; `'nonce-<per-request-value>'`
  added instead. **This is a behavior change.** Browsers that support
  CSP Level 2 (all current browsers) will block scripts and styles that
  don't carry the matching nonce attribute. Verify that no inline event
  handlers (`onclick=`, `onload=`, etc.) exist in operator-customised
  templates before upgrading. cesauth's own templates carry no inline
  event handlers (pinned by test).
- `SECURITY_HEADERS_CSP` operator override: now supports `{nonce}`
  placeholder. `"...'nonce-{nonce}'..."` will be substituted with the
  actual per-request nonce value. Operators who override CSP and want
  nonce support must add this placeholder.
- No new env vars. No schema changes. No DO state changes.

### Upgrade procedure

```
1. Deploy v0.52.0.
2. Verify HTML pages render correctly in a staging browser.
   Open DevTools → Console: look for CSP violations.
3. If using SECURITY_HEADERS_CSP override and want nonce support,
   add 'nonce-{nonce}' to your script-src and style-src directives.
4. Deploy production.
```

### ADR changes

- ADR-007 §Q3: `'unsafe-inline'` limitation closed in v0.52.0.
  The two paths listed (extract to same-origin files / per-request
  nonces) were resolved via the nonce path, as specified in RFC 006.

## [0.51.2] - 2026-05-06

Patch release. Implements RFC 005 (`cargo fuzz` for the JWT parser
surface). No production code change, no schema change, no new env vars.

### Why this release

cesauth's JWS Compact deserializer (`cesauth_core::jwt::signer::verify`
and `verify_for_introspect`) processes potentially adversarial tokens on
every protected request. The code is hand-rolled since v0.44.0 (replacing
`jsonwebtoken`). Example-based tests verify correctness for known inputs;
libFuzzer finds panics, OOM, and DoS-via-super-linear-parsing on the vast
adversarial input space that tests can't realistically enumerate.

This is **layer-1** fuzzing: a 60-second one-shot in CI. Continuous fuzzing
(OSS-Fuzz, ClusterFuzzLite) is a `Later` item.

### What shipped

**RFC 005 — `cargo fuzz` for the JWT parser**

- `fuzz/` directory (NOT a workspace member — keeps nightly fuzz deps
  out of the stable lockfile).
  - `fuzz/Cargo.toml`: standalone crate with `libfuzzer-sys = "0.4"` and
    `cesauth-core` path dep. `[package.metadata] cargo-fuzz = true`.
  - `fuzz/fuzz_targets/jwt_parse.rs`: single fuzz target exercising both
    `verify::<AccessTokenClaims>` and `verify_for_introspect::<AccessTokenClaims>`
    with a fixed test keypair (seed `[1u8; 32]`; not a production key).
    Non-UTF-8 byte sequences are skipped (the verifier's contract is `&str`).
    Return value is intentionally discarded — the goal is panic-freedom, not
    verification success.
  - `fuzz/corpus/jwt_parse/` (10 seed files): `empty.bin`, `single-dot.bin`,
    `two-dots.bin`, `three-dots.bin`, `alg-none.bin`, `valid-header-garbage-payload.bin`,
    `well-formed-no-real-sig.bin`, `oversized-header.bin`, `truncated-payload.bin`,
    `ascii-with-dots.bin`. Corpus seeds cover the key parser code-paths
    (empty input, segment-count edge cases, `alg: none` rejection, known-bad-sig).
- `.github/workflows/fuzz.yml` (new): runs `cargo +nightly fuzz run jwt_parse
  -- -max_total_time=60` on PRs touching `crates/core/src/jwt/**` or `fuzz/**`.
  Manual dispatch supports custom time limits. Fuzz artifacts uploaded on
  failure for offline analysis.
- `.gitignore`: `fuzz/target/` and `fuzz/artifacts/` excluded (ephemeral);
  `fuzz/corpus/` IS committed (seed corpus).
- `Cargo.toml` workspace comment: explicit note that `fuzz/` is intentionally
  excluded from the workspace.

### Fuzz target goals

1. **Panic-freedom**: `verify` must return `Ok` or `Err` on any byte sequence;
   never panic or abort.
2. **OOM resistance**: malformed tokens with giant claimed payloads must not
   cause unbounded allocation.
3. **DoS resistance**: pathological input must not trigger super-linear parsing
   work.

### Running locally

```sh
# From cesauth/fuzz/

# One-shot (60 seconds, matching CI):
cargo +nightly fuzz run jwt_parse -- -max_total_time=60

# Extended run (hours, deeper coverage):
cargo +nightly fuzz run jwt_parse

# Suppress benign leak-on-exit false positives:
cargo +nightly fuzz run jwt_parse -- -detect_leaks=0
```

Findings go to `fuzz/artifacts/jwt_parse/`. Report via `.github/SECURITY.md`.
Do NOT push findings in public PRs.

### Tests

No change to lib test count (871 total, same as v0.51.1). The fuzz target is
not a `#[test]`; it runs under libFuzzer in CI.

### Schema / wire / DO changes

None. Patch-only: no code change to any production crate, no new routes,
no new env vars, no schema migration.

### Upgrade procedure

```
1. Deploy v0.51.2 (drop-in; no action required).
2. The fuzz CI job runs automatically on future JWT-touching PRs.
```

## [0.51.1] - 2026-05-06

Patch release. Implements RFC 004 (WebAuthn typed error responses) and
RFC 003 (property-based tests). Both are internal or additive: no new
routes, no schema changes, no new env vars.

### Why this release

**RFC 004**: WebAuthn ceremony failures currently collapse to a generic
HTTP 500 with `{"error": "server_error"}`. Clients can't render specific
recovery guidance — they don't know whether to try a different
authenticator, ask their admin, or simply retry. A small typed `kind`
field (six values) lets clients branch on the category while keeping the
diagnostic detail string server-side only.

**RFC 003**: Property-based tests on two surfaces that example-based tests
can't adequately cover: JWT sign/verify crypto round-trips (where the input
space is vast) and the `redirect_uri` exact-match invariant (historically
the most bug-prone part of an OAuth server).

### What shipped

**RFC 004 — WebAuthn typed error responses**

- `cesauth_core::webauthn::error` (new module): `WebAuthnErrorKind` — a
  six-variant enum (`UnknownCredential`, `RelyingPartyMismatch`,
  `UserCancelled`, `SignatureInvalid`, `ChallengeMismatch`, `Other`)
  with `as_str() -> &'static str` and `Serialize`/`Deserialize` deriving
  to snake_case.
- `classify(detail: &str) -> WebAuthnErrorKind` — centralised mapping from
  diagnostic strings to kind. Falls through to `Other` for unmapped strings;
  new diagnostic strings from future dependency upgrades are safe.
- `cesauth_core::webauthn` re-exports: `pub use error::{WebAuthnErrorKind,
  classify as classify_webauthn_error}`.
- `cesauth_worker::error::oauth_error_response`: WebAuthn failures now
  produce `{"error": "server_error", "kind": "<snake_case_kind>"}`. All
  other error variants are unchanged. The diagnostic detail string does NOT
  appear on the wire (privacy invariant; stays in audit events and
  `console_error!` logs only).
- Three new tests in `worker::error::tests` pinning: (a) the kind field is
  present and correctly classified; (b) the kind value is not the raw
  diagnostic string; (c) all six variants have distinct `as_str()` values.
- Ten unit tests in `webauthn::error::tests` covering every explicitly
  mapped diagnostic string, the `Other` fallthrough (two cases), serde
  snake_case, and a `classify_covers_all_known_cesauth_diagnostic_strings`
  comprehensive pin.

**RFC 003 — Property-based tests (`proptest`)**

- `proptest = "1"` added to `[workspace.dependencies]` (dev-dep only).
- `proptest.workspace = true` added to `cesauth-core [dev-dependencies]`.
- `crates/core/src/jwt/proptests.rs` (new): five properties.
  - `jwt_sign_verify_round_trip` — arbitrary claim strings + arbitrary Ed25519
    seeds; decoded claims equal originals.
  - `jwt_single_byte_tamper_causes_verify_failure` — flip any single byte at
    any position; verify must return `Err`.
  - `jwt_wrong_key_causes_verify_failure` — token signed with key A must not
    verify under key B.
  - `magic_link_issue_verify_round_trip` — any `now` value; issued OTP
    verifies before expiry.
  - `magic_link_tampered_otp_fails_verify` — first character flipped; must
    not verify.
- `crates/core/src/oidc/authorization/redirect_uri_proptests.rs` (new):
  seven properties exercising the `redirect_uri` exact-match invariant.
  - `matcher_accepts_byte_equal_uri` — registered URI accepted.
  - `matcher_rejects_uri_not_in_allowed_set` — unregistered URI rejected.
  - `matcher_rejects_trailing_slash_variant` — `uri/` rejected when only
    `uri` is registered (classic open-redirect class).
  - `matcher_rejects_path_suffix_appended` — both `uri/suffix` and
    `urisuffix` rejected.
  - `matcher_treats_explicit_443_as_distinct_from_no_port` — `:443`
    explicit vs implicit are distinct strings.
  - `matcher_treats_http_and_https_as_distinct` — scheme difference always
    rejected.
  - `matcher_is_case_sensitive` — uppercase variant rejected.

### Tests

481 `cesauth-core` lib tests pass (was 459 in v0.51.0). The proptest
properties run 256 cases each by default, so the test suite is heavier
than the raw count suggests.

| Crate | Before | After | Delta |
|---|---|---|---|
| `cesauth-core` | 459 | 481 | +22 (10 RFC 004 unit + 12 proptest functions) |
| `cesauth-adapter-test` | 117 | 117 | — |
| `cesauth-ui` | 244 | 244 | — |
| `cesauth-worker` host subset | 5 | 8 | +3 (RFC 004 error shape pins) |

### Schema / wire / DO changes

- **No schema migration.** SCHEMA_VERSION remains 10.
- **Wire format additive only**: WebAuthn error responses gain a `kind` field.
  Clients that ignore unknown JSON fields (the correct default) see no change.
- **No new env vars**, no new bindings, no `wrangler.toml` changes.
- **No DO state changes.**

### Operator notes

No action required to upgrade. The `kind` field in WebAuthn error responses
is available to clients immediately after deploying v0.51.1.

If you maintain a client-side WebAuthn integration:
- Branch on `response.kind` for specific error recovery guidance.
- `"unknown_credential"` → prompt to try a different authenticator or register.
- `"relying_party_mismatch"` → deployment misconfiguration; contact admin.
- `"user_cancelled"` → retry the ceremony.
- `"signature_invalid"` → authenticator may be cloned; try another.
- `"challenge_mismatch"` → re-issue the ceremony (challenge likely expired).
- `"other"` → generic failure.

### ADR changes

None.

### Upgrade procedure

```
1. Deploy v0.51.1 (no migration, no new config).
2. WebAuthn error responses now include "kind" field.
```

## [0.51.0] - 2026-05-06

Minor release. Implements RFC 010 (MagicLinkMailer port) and closes
RFC 002 (client_secret_hash documentation drift). RFC 010 introduces new
operator-visible configuration — three optional env vars for the HTTPS
provider adapter — which earns the minor version bump per the versioning
policy.

### Why this release

**RFC 010 (P0 structural)**: RFC 008 (v0.50.3) stopped the audit log leak
of Magic Link OTP plaintext. However, without a defined delivery contract,
operators under deadline pressure would reintroduce the hack — the audit
log was previously the only delivery path that existed. RFC 010 builds the
`MagicLinkMailer` trait the development directive claimed existed but which
had zero code hits in the workspace. The dev directive's promise is now
truth.

**RFC 002 (documentation drift)**: `migrations/0001_initial.sql` described
`client_secret_hash` as `argon2id(secret)`. No Argon2 implementation ever
existed; the actual path has always been SHA-256, matching `admin_tokens`
and the magic-link OTP hash. The schema comment is now corrected.

### What shipped

**RFC 010 — MagicLinkMailer port + provider adapters**

- `cesauth_core::magic_link::mailer` (new module): `MagicLinkMailer` async
  trait, `MagicLinkPayload`, `MagicLinkReason`, `DeliveryReceipt`,
  `MailerError`. Pub-re-exported from `cesauth_core::magic_link`.
- `cesauth-adapter-cloudflare::mailer` (new module): four reference adapters
  and the `from_env` factory.
  - `DevConsoleMailer`: logs handle (never code) to worker console. Active
    only when `WRANGLER_LOCAL=1`. The factory enforces this guard.
  - `UnconfiguredMailer`: returns `NotConfigured` on every send. The default
    when no provider env var is set. Surfaces misconfig via audit on first use.
  - `ServiceBindingMailer`: sends a JSON envelope through the
    `MAGIC_LINK_MAILER` CF service binding to an operator mail worker.
    Preferred path — stays within Cloudflare's network.
  - `HttpsProviderMailer`: POSTs a SendGrid v3-compatible JSON body to
    `MAILER_PROVIDER_URL` with `Authorization: $MAILER_PROVIDER_AUTH_HEADER`.
    Works with SendGrid, Resend, Postmark, Mailgun, SES-via-gateway.
  - `from_env(env)` factory: selects DevConsole → ServiceBinding → Https →
    Unconfigured in priority order.
- `cesauth_worker::adapter::mailer` (new module): thin re-export of
  `from_env` so route handlers import from `crate::adapter`.
- `routes::magic_link::request`: wires the mailer after `MagicLinkIssued`
  audit. On `Ok(receipt)` → emits `MagicLinkDelivered` (handle +
  `provider_msg_id`). On `Err(e)` → emits `MagicLinkDeliveryFailed` (handle
  + `e.audit_kind()`), logs at Error, returns the same success-shaped
  response (no enumeration leak via differential response).
- `routes::api_v1::anonymous` (promote path): same mailer wiring pattern
  with `reason = AnonymousPromote`.
- New audit kinds: `MagicLinkDelivered` (`magic_link_delivered`),
  `MagicLinkDeliveryFailed` (`magic_link_delivery_failed`).
- `cesauth_worker::i18n`: `locale_str(Locale) -> &'static str` helper for
  mailer payload locale field.
- `docs/src/deployment/email-delivery.md` (new): operator chapter covering
  adapter selection, configuration per option (service binding / HTTPS /
  defer), local dev workflow, monitoring dashboard queries, and security
  considerations (enumeration prevention, provider-side responsibility,
  bounce handling).
- `docs/src/expert/adr/015-magic-link-mailer.md` (new): ADR-015, Accepted.
  Documents 9 design questions including trait location, async signature,
  adapter selection priority, fail-open vs fail-closed on delivery failure,
  timing-attack mitigation, and body template scope.

**RFC 002 — `client_secret_hash` documentation drift resolved**

- `migrations/0001_initial.sql`: column comment corrected from
  `argon2id(secret)` to `sha256_hex(secret)`.
- `service::client_auth` module doc: updated to record the resolution and
  explain why SHA-256 is correct for server-minted 256-bit secrets (RFC 002
  reasoning inline).

### Tests

820 lib tests pass (was 817 in v0.50.3). Net +3:

| Crate | Before | After | Delta |
|---|---|---|---|
| `cesauth-core` | 456 | 459 | +3 (MagicLinkMailer/MailerError/MagicLinkReason unit tests) |
| `cesauth-adapter-test` | 117 | 117 | — |
| `cesauth-ui` | 244 | 244 | — |
| `cesauth-worker` host subset | 2 | 2 | — |

### Schema / wire / DO changes

- **No schema migration.** SCHEMA_VERSION remains 10. The migration 0001
  comment edit is cosmetic.
- **Wire format unchanged.** No new HTTP endpoints. Existing Magic Link
  endpoint behavior is identical from the user's perspective.
- **DO state unchanged.**
- **New env vars (optional)**:

| Var | Adapter | Required? |
|---|---|---|
| `MAGIC_LINK_MAILER` | ServiceBinding (wrangler.toml `[[services]]`) | No |
| `MAILER_PROVIDER_URL` | HttpsProvider | Required for HttpsProvider |
| `MAILER_PROVIDER_AUTH_HEADER` | HttpsProvider | Required for HttpsProvider |
| `MAILER_PROVIDER_FROM_ADDRESS` | HttpsProvider | Required for HttpsProvider |
| `MAILER_PROVIDER_FROM_NAME` | HttpsProvider | Optional (display name) |

None of these vars changes existing behavior if absent — the default is
`UnconfiguredMailer`, which matches the pre-v0.51.0 "no mailer" state.

### Operator notes

1. **Choose your delivery path** before deploying v0.51.0 to production:
   - Service binding (recommended): add `[[services]]` block to
     `wrangler.toml`.
   - HTTPS provider: `wrangler secret put` for the three required vars.
   - Defer: do nothing; Magic Link issuances will audit as
     `magic_link_delivery_failed kind=not_configured`.
2. **Add a dashboard panel** for `magic_link_delivery_failed` broken down
   by `kind` field. A spike of `not_configured` means your deployment has
   no mail provider wired; `permanent` means provider rejection.
3. **Local dev workflow**: with `WRANGLER_LOCAL=1`, the handle is logged to
   the worker console. Retrieve the OTP hash from local D1 via `wrangler d1
   execute`. See `docs/src/deployment/email-delivery.md` for details.
4. **RFC 008 OTP purge**: if you haven't run the v0.50.3 purge runbook yet,
   do so before deploying v0.51.0. The mailer wiring is now active; leaked
   OTP rows from pre-v0.50.3 deployments are the only remaining exposure.

### ADR changes

- ADR-015 `015-magic-link-mailer.md`: new, Accepted in v0.51.0.
  `docs/src/SUMMARY.md` updated.

### Upgrade procedure

```
1. Choose a delivery path (service binding / HTTPS / defer).
2. Configure the chosen adapter (wrangler.toml or secrets).
3. Deploy v0.51.0.
4. Issue a test Magic Link in staging; confirm audit shows
   magic_link_delivered (or magic_link_delivery_failed kind=not_configured
   if intentionally deferred).
5. Deploy production.
```

## [0.50.3] - 2026-05-06

Security and hardening patch. Implements RFC 008, RFC 009, and RFC 011
from the v0.50.1 external codebase review — the three items classified
as Tier 0 (production blockers) and Tier 1 (P1 hardening) that do not
require new operator-visible configuration.

### Why this release

Three findings from the external review required immediate attention:

- **RFC 008 (P0)**: Every Magic Link issuance wrote the OTP plaintext
  into the audit log, violating cesauth's own "no token material ever"
  invariant. Anyone with D1 read access, a Logpush forwarder, or access
  to a migration export could log in as any user who used Magic Link
  during the retention window.
- **RFC 009 (P0)**: `introspect_token` was called with `expected_aud =
  issuer` while access tokens carry `aud = client.id`. The test suite
  masked the bug by setting `AUD = ISS` in the fixture. Every valid
  access-token introspection in production returned `{"active": false}`.
  The v0.50.0 audience gate (ADR-014 §Q1) consequently never fired.
  The companion finding: on D1 storage error, the audience gate fell
  open (fail-open), silently disabling the security boundary for
  deployments that had opted into per-client audience scoping.
- **RFC 011 (P1)**: `csrf::mint()` swallowed `getrandom` failure with
  `let _ =`, producing a predictable all-zero token when the platform
  CSPRNG failed. Negative env values for rate-limit thresholds silently
  wrapped to huge `u32` via `as u32`, effectively disabling rate limits.
  Three `/me/security/sessions` routes were registered twice in `lib.rs`
  (merge-conflict residue from v0.35.0).

### What shipped

**RFC 008 — Eliminate plaintext OTP in audit log**

- `routes::magic_link::request` and `routes::api_v1::anonymous`: the
  `reason` field on `EventKind::MagicLinkIssued` now carries
  `handle=<handle>` only. The OTP plaintext is gone.
- `cesauth_core::magic_link::IssuedOtp`: renamed `code_plaintext` →
  `delivery_payload`. The name signals intent — this value is for
  delivery, not logging.
- `crates/worker/src/audit.rs`: module doc gains an explicit "Invariant:
  no token material in audit" section naming the specific fields and the
  RFC 008 history.
- `crates/worker/src/audit/tests.rs` (new): `no_audit_reason_format_string_contains_secret_substring` — a static-grep test that walks every `.rs` source file at test time and asserts no `audit::write_*` call site references `code=`, `code_plaintext`, `otp=`, `secret=`, `password=`, or `plaintext`. Prevents reintroduction.
- `docs/src/deployment/runbook.md`: new section "Operation: purge
  plaintext OTP audit leaks (one-time, v0.50.1 → v0.50.3 upgrade)" with
  the exact SQL, the export-for-forensic-preservation variant, and the
  chain re-baseline procedure.

**RFC 009 — Introspection access-token `aud` correctness + fail-closed gate**

- `cesauth_core::jwt::signer::verify_for_introspect` (new): a dedicated
  verifier for the `/introspect` path that omits `aud` enforcement.
  Access tokens carry `aud = client.id`; the pre-v0.50.3 verifier
  expected `aud = issuer`, rejecting every valid production token. The
  audience gate in the worker handler (`apply_introspection_audience_gate`,
  ADR-014 §Q1) is now the sole aud-policy point. The strict `verify()`
  function is unchanged and continues to be used by all other callers.
- `cesauth_core::service::introspect::introspect_token`: `expected_aud`
  parameter removed. Module doc updated with the RFC 009 rationale.
- Worker handler `routes::oidc::introspect`: audience-gate client lookup
  is now fail-closed. `Ok(None)` (admin DELETE race post-auth) → HTTP 401
  + new `EventKind::IntrospectionRowMissing` audit event. `Err(_)` (D1
  storage outage) → HTTP 503.
- Test fixture: `const AUD: &str` changed from the issuer URL to
  `"client_X"` — the production-realistic shape. Existing tests updated.
- Three new regression tests in `service::introspect::tests::rfc009_aud_correctness`.
- ADR-014 §Q1: amendment paragraph noting the v0.50.3 tightening.

**RFC 011 — Worker-layer hardening**

- `csrf::mint()`: return type changed from `String` to
  `Result<String, getrandom::Error>`. On `Err`, all callers now emit a
  `CsrfRngFailure` audit event and return HTTP 500 rather than silently
  producing a predictable all-zero token. New `CsrfRngFailure` audit kind.
- `config.rs`: new `var_u32_bounded(name, default, max)` helper that
  rejects negative values (preventing `as u32` silent wrap) and values
  above `max`. Applied to `REFRESH_RATE_LIMIT_THRESHOLD`,
  `INTROSPECTION_RATE_LIMIT_THRESHOLD`, and their `_WINDOW_SECS` variants.
  A mis-configuration now fails at startup with a clear message rather
  than silently disabling rate limits.
- `lib.rs`: removed the second (duplicate) registration block for
  `GET /me/security/sessions`, `POST /me/security/sessions/revoke-others`,
  and `POST /me/security/sessions/:session_id/revoke`. These were
  merge-conflict residue from v0.35.0.
- `lib.rs` tests: `no_duplicate_route_registrations` — static-grep test
  that asserts each `(method, path)` tuple appears at most once. Prevents
  recurrence.
- `docs/src/expert/adr/012-session-hardening.md`: Superseded header added
  (canonical is `012-sessions.md`). `SUMMARY.md` index updated.
- Two new tests for `csrf::mint() -> Result` shape.

### Tests

817 lib tests pass (was 814 in v0.50.2). Breakdown by crate:

| Crate | Before | After | Delta |
|---|---|---|---|
| `cesauth-core` | 453 | 456 | +3 (RFC 009 regression pins) |
| `cesauth-adapter-test` | 117 | 117 | — |
| `cesauth-ui` | 244 | 244 | — |
| `cesauth-worker` (host subset) | — | 2 | +2 (RFC 011: csrf + route pins) |

### Schema / wire / DO changes

- **No schema migration.** SCHEMA_VERSION remains 10.
- **Wire format**: `/introspect` now returns `active: true` (and populates
  `aud`) for valid access tokens that previously returned `active: false`
  due to the RFC 009 bug. This is a **behavior change at upgrade**: RPs
  that relied on the (broken) `inactive` response will now receive the
  correct `active` response. Release notes recommend testing introspection
  flows against v0.50.3 in staging before production rollout.
- **No new bindings**, no new env vars, no `wrangler.toml` changes.
- **DO state unchanged** (FamilyState, ActiveSession, etc.).

### Operator notes

1. **Run the OTP purge runbook** if you ran any v0.16.0–v0.50.1 in
   production. See `docs/src/deployment/runbook.md` → "Operation: purge
   plaintext OTP audit leaks". Fresh deployments that never ran ≤ v0.50.1
   can skip this.
2. **Introspection behavior change**: access-token introspection now returns
   correct results. Check your resource-server introspection clients — if
   they were silently falling back on `active: false`, they now see `true`.
3. **Rate-limit env validation**: if you have `REFRESH_RATE_LIMIT_THRESHOLD`
   or `INTROSPECTION_RATE_LIMIT_THRESHOLD` set to a negative value (which
   would previously have silently disabled rate limits), v0.50.3 will now
   refuse to start. Correct the value before deploying.
4. **No rollback to v0.50.1** after running the OTP purge — that version
   reintroduces the audit-as-delivery path.

### ADR changes

- ADR-014 §Q1: amended to note the RFC 009 verifier fix and gate
  tightening. The §Q1 design is now actually in effect.

### Upgrade procedure

```
1. Deploy v0.50.3 (no schema migration needed).
2. Verify /introspect works correctly for access tokens.
3. Run the OTP purge runbook if applicable.
4. Watch audit_chain_cron on next 04:00 UTC run; verify the
   chain status page shows ✓ valid after the re-baseline.
```



Documentation-only patch release. Adds 11 new RFCs
(008-018) to `rfcs/` triaging the v0.50.1 external
codebase review findings, plus a ROADMAP entry tracking
the v0.50.2 production-blocker sweep.

This release ships the **specifications** for the
production-blocker sweep; the **implementation** lands
in subsequent minor releases starting with the next
v0.50.x or v0.51.0.

### Background

An external Rust + Cloudflare codebase review of
v0.50.1 surfaced three production blockers, three
security hardening items, and four quality-and-
operations items. Each finding was independently
verified against the v0.50.1 source tree before
acceptance. The triage produced 7 RFCs (008-014).

A follow-up operator question — "is server logging
sufficient, can client requests be traced
end-to-end, and is a file-writing logger needed?" —
produced an 8th RFC (015) covering request
correlation, audit cross-link, and explicit
documentation of the deliberate file-logger absence.
RFC 015 ships in the same v0.50.2 patch release.

A third source — an external UI/UX design update
reviewing v0.50.1 — surfaced three admin-surface
gaps not covered by the code review or the
logging follow-up: scope-badge inconsistency
across admin frames; the v0.50.0-deferred admin UI
for `oidc_clients.audience` (operators currently
run direct D1 SQL); the absence of an explicit
"impact preview before apply" pattern for
destructive admin operations. These produced RFCs
016, 017, 018 — the **Tier 4 admin UX hardening**
section, deferred behind Tiers 0-3 but tracked in
the same v0.50.2 release.

### What ships

#### Tier 0 — Production blockers (P0/P1, ship in next release)

- **RFC 008** — Eliminate plaintext OTP in audit log.
  P0. The audit module's self-declared "No token
  material ever" invariant is violated at two sites
  (`worker/src/routes/magic_link/request.rs:170-178`,
  `worker/src/routes/api_v1/anonymous.rs:254-264`)
  where the Magic Link OTP plaintext is logged into
  the audit `reason` field. Fix removes the plaintext,
  adds a static-grep pin test against reintroduction,
  renames `code_plaintext` → `delivery_payload` for
  intent clarity, and provides an operator runbook
  for purging already-leaked rows + chain
  re-baseline.
- **RFC 009** — Introspection access-token `aud`
  correctness + audience-gate fail-closed. P0 + P1.
  Token mints with `aud=client.id` but `/introspect`
  verifies with `expected_aud=issuer`; the test
  fixture sets `ISS == AUD` so the production bug is
  invisible to tests. Result: every production access-
  token introspection returns `{"active":false}`,
  silently breaking RP integration. ADR-014 §Q1's
  audience gate consequently never fires. Fix removes
  `expected_aud` enforcement from the verifier (gate
  becomes canonical aud check), updates fixture to
  `AUD = "client_X"`, and tightens the gate to
  fail-closed on storage error (HTTP 503) and on
  client row missing post-auth (HTTP 401, new audit
  kind `IntrospectionRowMissing`).
- **RFC 010** — Magic Link real delivery. P0.
  Workspace-wide grep confirms no `MagicLinkMailer`
  trait exists despite the development directive
  declaring one. The audit log IS the OTP delivery
  mechanism today, which is why RFC 008's plaintext
  leak exists. Fix builds the trait the directive
  promised: `MagicLinkMailer` in `cesauth-core` with
  audit-disjoint crate boundary, four reference
  adapters (Cloudflare service binding, HTTPS
  provider, dev console gated on `WRANGLER_LOCAL=1`,
  `UnconfiguredMailer` fallback), new audit kinds
  `MagicLinkDelivered` / `MagicLinkDeliveryFailed`,
  ADR-015 alongside, new operator chapter
  `docs/src/deployment/email-delivery.md`.
- **RFC 011** — Worker-layer hardening. P1 + P2.
  Bundle of four mechanical fixes: CSRF
  `mint()` returns `Result<String>` (current code
  swallows `getrandom` error and produces a
  predictable constant token); `var_parsed_u32_bounded`
  config helper rejects negative values (current
  `as u32` cast wraps to huge u32, silently disabling
  rate limits); duplicate route registration
  deletion (`worker/src/lib.rs:193-200` is residue
  from v0.35.0); `docs/src/expert/adr/012-session-hardening.md`
  marked Superseded by `012-sessions.md`.

#### Tier 3 — Quality and operations (defer behind P0 sweep)

- **RFC 012** — Doc and repo hygiene. README rewrites
  to drop "No management GUI" and "land in R2" claims;
  mechanical split of `crates/core/src/migrate.rs`
  (2568 lines) into 9 submodules under 500 lines
  each; development directive corrections (rate-limit
  is DO not KV; `crates/do` is skeleton); drift-scan
  CI workflow with stale-phrase pattern list.
- **RFC 013** — Operational envelope. ADR-016 declares
  Cloudflare Paid plan as floor; bundle-size CI gate
  at 7 MB gzipped; configurable cron batch sizes;
  `nodejs_compat` removal or in-tree justification;
  new `docs/src/deployment/operational-envelope.md`
  chapter with per-request budget tables; bundle-history
  trend doc.
- **RFC 014** — Audit append performance. Path A
  (acceptance + telemetry) for v0.50.x: instrument
  `append` with latency / retry warnings, document
  ~100/s sustained ceiling, ship operator runbook.
  Path B (DO-serialized append, ADR-017) deferred
  until Path A telemetry triggers.
- **RFC 015** — Request traceability. Operator
  follow-up question on logging completeness. Existing
  `log` module is well-designed (categorized,
  level-gated, sensitivity-gated) but request-scope
  correlation is missing: log lines from the same
  request are not grouped, audit events can't be
  cross-linked to log lines, and HTTP request
  lifecycle isn't logged consistently. Fix adds a
  `cf-ray`-derived `request_id` (free, already in CF /
  Logpush, observable client-side via response
  header) threaded through `LogConfig` and
  `NewAuditEvent`; one middleware-emitted HTTP
  lifecycle log per request (replacing ad-hoc
  per-handler `Category::Http` lines, net log volume
  same or fewer); new nullable
  `audit_events.request_id` column for cross-link
  (SCHEMA_VERSION 10 → 11, ALTER-only migration,
  non-chained additive — chain integrity unaffected).
  **Deliberately documents the absence of a
  file-writing logger** as ADR-018: Cloudflare
  Workers has no filesystem; per-line writes to
  KV/R2/D1 would contradict the security posture
  ("セキュリティ重視のため不要なログは出力したりファイルに残し
  たりすることは不要") by adding a persistence surface
  outside operator's existing audit/log governance.
  The four reasons (no FS / security posture /
  redundancy with Cloudflare Logs + audit / no-
  unnecessary-logs discipline) are recorded in
  ADR-018 so future "why don't we write logs to a
  file" questions get redirected to the ADR.

#### Tier 4 — Admin UX hardening (defer behind P0 sweep + Tier 3)

- **RFC 016** — Admin scope badge standardization.
  The three admin frames (`/admin/console/*`
  system, `/admin/tenancy/*` tenancy,
  `/admin/t/<slug>/*` tenant) currently have
  visually distinct chrome but no semantic
  "you are operating in scope X" badge consistent
  across all three. Adds `ScopeBadge` enum
  (System / Tenancy / Tenant(slug)) + 3 colour
  tokens (purple / blue / green, deliberately
  distinct from the existing semantic
  success / warning / danger / info tokens) + 3
  MessageKey variants. Single-place chrome change;
  no schema or wire impact.

- **RFC 017** — OIDC client audience-scoping admin
  editor. v0.50.0 shipped the audience-scoping
  schema + `/introspect` gate but explicitly
  deferred the admin UI ("Admin console UI for
  this is out of v0.50.0 scope"). Operators
  currently run `wrangler d1 execute "UPDATE
  oidc_clients SET audience = ? WHERE id = ?"`
  against production. RFC 017 closes the gap:
  tenant admin editor surface with explicit
  3-state form (radio + text: Unscoped / Scoped+
  empty / Scoped+value) distinguishing NULL vs
  `""` vs `"value"` semantics; per-tenant
  uniqueness check with `?force=1` override for
  intentional sharing; new audit kind
  `OidcClientAudienceChanged` with before / after
  payload; audit-trail section showing recent
  changes for the client. ADR-014 §Q1
  Resolved-paragraph gets a v0.50.x amendment
  noting this RFC closes the deferred admin UI.

- **RFC 018** — Preview-and-apply pattern for
  destructive admin operations. The deck's
  "状態 → 影響 → 実行 → 監査" framing surfaces a
  real gap: today's `config_edit`, token rotation,
  and similar admin operations apply directly on
  submit, with no explicit "impact preview" step.
  RFC 018 establishes reusable infrastructure:
  `ImpactStatement{title, bullets, rollback,
  severity}`; HMAC-signed `PreviewToken` (5-min
  TTL, session HMAC key, binds operation_id +
  before + after + csrf to prevent replay); paired
  `OperationPreviewed` / `OperationApplied` audit
  events for forensic correlation. First adopters:
  LOG_LEVEL change (medium severity), token
  rotation (high severity), audience editor (RFC
  017 ideally rides on this pattern). ADR-019
  establishes the convention so future destructive
  admin operations adopt it by default. Read-only
  admins can reach preview but not apply
  (privilege boundary at apply, not at preview).

#### `rfcs/README.md` — Tier 0 + Tier 3 + Tier 4 sections added

The README index now has Tier 0 (production blockers)
above Tier 1 / Tier 2 / Tier 3. Recommended
implementation order spelled out: v0.50.2 ships
RFCs 008-010 (and possibly 011); v0.51.0 ships
RFC 001 (id_token); v0.51.x / 0.52.0 picks up
quality (RFCs 002, 011 if not earlier, 012); v0.52.x
operations (RFCs 013, 014 Path A); RFCs 003-007
later as opportunity allows.

#### ROADMAP entry

`## Planned (0.x) / Next minor releases` gains a
top-priority entry "v0.50.2 production-blocker sweep
— external review remediation" describing each of
RFCs 008-018 inline with the verified evidence
behind each.

### Tests

No test count change — documentation-only release.
v0.50.1's 1025 tests carry forward.

### Schema / wire / DO

- Schema unchanged (SCHEMA_VERSION = 10).
- Wire format unchanged.
- DO state unchanged.
- No new dependencies.

### Operator-visible changes

None. This release adds engineering documentation;
no behavior change. No `wrangler.toml` change. No
new env vars. No new bindings.

### ADR changes

No ADR shipped or revised. RFC 010 will produce
ADR-015 on implementation; RFC 013 will produce
ADR-016; RFC 014 may produce ADR-017 if Path B
triggers. RFC 009 will amend ADR-014 §Q1's
Resolved-paragraph with v0.50.2 tightening note.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.50.1 → 0.50.2.
- UI footers + tests bumped to v0.50.2.
- `rfcs/008-018-*.md` — 11 new RFC files (RFC 015 added in response to operator question on logging completeness — see entry below).
- `rfcs/README.md` — Tier 0 (P0/P1 blockers) and
  Tier 3 (quality/scaling) sections added; existing
  Tier 1 / Tier 2 unchanged; Recommended
  implementation order section added.
- `ROADMAP.md` — v0.50.2 production-blocker sweep
  entry under "Planned (0.x) / Next minor releases".
- This CHANGELOG entry.

### Upgrade path 0.50.1 → 0.50.2

1. Extract this tarball, OR pull the git tag.
2. No build needed — no code change.
3. No deploy needed — no behavior change.

This is a patch in the strictest sense: an
implementer reads the new RFCs to start the
production-blocker work; an operator running v0.50.1
in production has nothing to do.

**Operators planning the v0.50.2 → v0.50.3 upgrade**
(when the production-blocker fixes ship) should
read RFC 008 §"Step 4 — Operator data hygiene
runbook" and RFC 010 §"Migration / upgrade path"
ahead of time — both involve operator-side actions
that take time to plan (mailer choice, audit
purge, chain re-baseline).

---

## [0.50.1] - 2026-05-05

Documentation-only patch release. Adds the `rfcs/`
directory: implementation-handover specifications for
ROADMAP themes that are ready to be picked up by an
engineer.

### What ships

#### `rfcs/` — new directory

Engineering specs distinct from the ADR system. Where
ADRs answer "why this design", RFCs answer "what does
the implementer need to build". Where a theme has a
linked ADR, the RFC builds on it; where a theme is
small and self-contained, the RFC stands alone.

Index at `rfcs/README.md` lists priority order. Seven
RFCs in this initial batch:

**Tier 1** (ready to implement, design settled):

- **RFC 001** — OIDC `id_token` issuance. Builds on
  ADR-008 (Draft, all eleven design questions
  Resolved). Medium scope: ~600 LOC across 4 files +
  one schema field on `Challenge::AuthCode` and
  `RefreshTokenFamily` (`#[serde(default)]` for
  in-flight compatibility), one wire change (id_token
  populated when `openid` scope present), discovery
  doc restored to OIDC posture from v0.25.0's honest-
  reset OAuth-only state. ~30 new tests across pure
  module + service integration + discovery shape
  inversions. Recommended 5-PR progression in the
  RFC.
- **RFC 002** — `oidc_clients.client_secret_hash`
  documentation drift. Decides Path B (relax schema
  comment to SHA-256, unify with bearer-secret
  hashing) over Path A (implement Argon2id) on the
  honest reasoning that `client_secret` is server-
  minted at 256-bit entropy — Argon2's password-
  hashing value proposition doesn't apply.
  Schema-comment edit + `verify_client_credentials`
  audit + unified hashing helper + 4 tests.
- **RFC 003** — Property-based tests (`proptest`)
  for crypto round-trips and `redirect_uri` matcher.
  Two property modules, ~10 properties, dev-dep only.
  No production-code change.
- **RFC 004** — WebAuthn error → typed client
  responses. Conservative 6-variant `WebAuthnErrorKind`
  enum mapped from existing diagnostic strings;
  surfaces on the wire as a `kind` JSON field;
  preserves the privacy invariant that diagnostic
  detail strings stay in server-side logs.

**Tier 2** (lighter, internal-design-only):

- **RFC 005** — `cargo fuzz` for the JWT parser
  surface. Single fuzz target, GitHub Actions one-shot
  (60s) on PRs touching jwt or fuzz dirs. Deeper
  continuous fuzzing parked under "Later".
- **RFC 006** — CSP without `'unsafe-inline'` (per-
  request nonces). Medium-scope refactor; touches
  every HTML template render path. Plans
  `RenderContext { locale, nonce }` introduction to
  minimize call-site churn.
- **RFC 007** — Cesauth-specific attack-surface review
  cadence. Defines the per-review deliverable shape
  + checklist + before-v1.0/by-2027-Q4 schedule for
  the next pass.

### Themes not covered

The README explicitly lists themes excluded from this
batch:

- ADR-012 §Q2 / §Q3 / §Q5 — blocked on infrastructure
  cesauth doesn't yet have (email pipeline, GeoIP) or
  on Cloudflare DO platform limitations.
- OIDC client_secret brute-force lockout — has an
  explicit trigger condition that hasn't fired.
- Domain-metric observability / Rate-limit bucket
  tuning / Login → tenant resolution / External IdP
  federation — design ambiguity too large for an RFC
  without a prerequisite ADR.
- Protocol extensions (Device Authorization Grant,
  Dynamic Client Registration, Request Objects, PAR,
  full FIDO attestation) — speculative; write the RFC
  when a deployment requires one.

### Tests

No test count change — documentation-only release.
1025 tests as of v0.50.0 carry forward.

### Schema / wire / DO

- Schema unchanged.
- Wire format unchanged.
- DO state unchanged.
- No new dependencies.

### Operator-visible changes

None. This release adds engineering documentation; no
behavior change. No `wrangler.toml` change. No new env
vars. No new bindings.

### ADR changes

No ADR shipped or revised. RFC 001 references ADR-008
(Draft); RFC 006 references ADR-007's §Q3 limitation
note. All ADR statuses unchanged.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.50.0 → 0.50.1.
- UI footers + tests bumped to v0.50.1.
- `rfcs/README.md` + 7 RFC files added.
- This CHANGELOG entry.
- ROADMAP unchanged at the row level (no
  feature shipped); the RFCs reference ROADMAP
  themes as their source.

### Upgrade path 0.50.0 → 0.50.1

1. Extract this tarball, OR pull the git tag.
2. No build needed — no code change.
3. No deploy needed — no behavior change.

This is a patch in the strictest sense: an implementer
clones the tree to read the RFCs; an operator running
v0.50.0 in production has nothing to do.

---

## [0.50.0] - 2026-05-04

Per-client audience scoping for `/introspect`.
**ADR-014 §Q1 Resolved.** First release after the
six-item operator-requested batch (v0.44–v0.49)
completed. Picked from the four open security-track
items the v0.49.0 changelog flagged as the only
candidate that's both ready-to-ship and security-
meaningful.

### Why this matters

v0.38.0 shipped `/introspect` with a global trust
model: any authenticated confidential client could
introspect any token. The ADR-014 §Q1 paragraph
flagged this as a privilege-escalation concern for
multi-tenant deployments where one cesauth issues
tokens for many resource servers. Pre-v0.50.0, an
RS_A holding valid introspection credentials could
ask cesauth about RS_B's tokens — and learn whether
they were currently active, what their scopes were,
which user they belonged to. Cross-RS visibility,
unintended.

v0.50.0 closes this with a per-client audience scope
that's **off by default** (existing deployments
upgrade unchanged) and **opt-in per client** (no
deployment-wide flag — operators enable it for the
clients that need it).

### What ships

#### Schema migration

`migrations/0010_introspection_audience.sql` adds
`audience TEXT` (nullable) to `oidc_clients`.
**SCHEMA_VERSION 9 → 10** — first schema bump since
v0.35.0.

NULL means "unscoped — pre-v0.50.0 behavior". A
non-NULL value means "this client may introspect
ONLY tokens whose `aud` claim matches verbatim".
Single string column, not JSON array — RFC 7662
doesn't model multi-audience introspecters; if
demand surfaces for clients needing multiple
allowed audiences, a future migration can broaden.
No CHECK constraint on the value (audiences are
operator-controlled identifiers; the truth check
is the runtime comparison, not a schema constraint).

#### Pure gate function

`cesauth_core::service::introspect::apply_introspection_audience_gate(response, requesting_client_audience) -> IntrospectionGateOutcome`.

```rust
pub enum IntrospectionGateOutcome {
    PassedThrough(IntrospectionResponse),
    AudienceDenied {
        response:                  IntrospectionResponse,
        requesting_client_audience: String,
        token_audience:             String,
    },
}
```

The orchestrator (`introspect_token`) stays pure —
it produces a response based purely on token
validity. The gate runs separately, in the worker
handler, which applies it after `introspect_token`
returns. This keeps the orchestrator testable
without touching audit infrastructure AND surfaces
the gate-fired signal to the handler for distinct
audit emission.

The gate is a no-op when:

- `requesting_client_audience` is `None` (client is
  unscoped — the default).
- `response.active` is false (already inactive — gate
  has nothing to add).
- `response.aud` is `None` (refresh-token responses;
  documented out-of-scope below).

#### Privacy invariant on denial

On audience mismatch, the response is replaced with
`IntrospectionResponse::inactive()` — wire form
`{"active":false}`, byte-identical to v0.38.0's
privacy-preserving inactive shape. Returning 403
would let an attacker probe whether tokens exist
for other audiences by trying their own credentials
(the same enumeration-side-channel concern v0.38.0
documented for unknown-client vs wrong-secret).

Test pin `mismatch_response_serializes_to_bare_inactive`
asserts the wire form byte-exact — defense in depth
against a future change adding a field to
`IntrospectionResponse` that the gate forgets to
clear.

#### `IntrospectionResponse.aud` added

RFC 7662 §2.2 lists `aud` as an optional response
field. v0.38.0 deliberately omitted it because no
resource servers cesauth supported needed it; v0.50.0
surfaces it because (a) the gate reads it internally
so we may as well expose it on the wire, and (b)
standard introspection libraries expect it.

Active access responses populate `aud` from the JWT's
`aud` claim. Active refresh responses leave it
`None`. Inactive responses (including audience-
denied) leave it `None`.

`#[serde(skip_serializing_if = "Option::is_none")]` —
clients consuming only the fields they need are
unaffected.

#### `active_access` constructor signature change

```rust
pub fn active_access(
    scope:     String,
    client_id: String,
    sub:       String,
    jti:       String,
    iat:       i64,
    exp:       i64,
    aud:       Option<String>,   // ← new
) -> Self
```

`active_refresh` and `active_refresh_with_ext`
unchanged (refresh responses always have
`aud: None`).

External code constructing `IntrospectionResponse`
directly will need a one-line update. In-tree call
sites updated alongside.

#### Refresh-token introspection out of v0.50.0 scope

`FamilyState` doesn't record an audience — the
audience is determined per access-token mint, not
per family. Refresh introspection therefore returns
`aud: None`, and the gate falls through (a refresh
response won't trip the audience check regardless of
the requesting client's scope).

Audience scoping for refresh introspection is
architecturally distinct (the family doesn't bind to
a single audience; tokens minted from a refresh
inherit `aud` from the request) and is left to a
future iteration if operator demand surfaces.

#### `EventKind::IntrospectionAudienceMismatch`

New audit kind, snake_case
`introspection_audience_mismatch`. Payload:

```json
{
  "requesting_client_id":       "client_abc",
  "requesting_client_audience": "rs.a.example",
  "token_audience":             "rs.b.example"
}
```

Both audiences are operator-controlled identifiers,
not secret material — their presence in audit doesn't
reveal token contents. The introspected token itself
is NOT in the payload (same privacy invariant as
`TokenIntrospected`).

Distinct from `IntrospectionRateLimited` (which fires
before any token check) and `TokenIntrospected`
(which fires on any authenticated request that
proceeded to checks). A spike of these events likely
indicates a misconfigured resource server (its
`oidc_clients.audience` doesn't match what its tokens
carry) or a legitimate-but-unintended cross-RS
introspection probe.

#### Worker handler integration

`POST /introspect` now:

1. Authenticates client (existing).
2. Rate-limit gate (existing, v0.43.0).
3. **NEW**: Fetches the authenticated client row to
   read `audience`. Storage outage on this lookup
   treats the client as unscoped (lets the request
   proceed under pre-v0.50.0 behavior) rather than
   fail-closing on a transient hiccup. Errors log a
   warning.
4. `introspect_token` (existing).
5. **NEW**: `apply_introspection_audience_gate`. On
   `AudienceDenied`: emit
   `IntrospectionAudienceMismatch` audit event with
   the operator-controlled identifiers; replace
   response with bare `inactive()`.
6. Audit `TokenIntrospected` (existing).
7. Render JSON (existing).

### Tests

986 → **996** lib (+10). With migrate integration:
1015 → **1025**.

- core: 443 → 453 (+10). All in
  `service::introspect::tests::audience_gate`:
  - `unscoped_client_passes_through_active_response` —
    NULL client.audience = legacy behavior.
  - `matching_audience_passes_through` — happy path.
  - `mismatched_audience_returns_inactive_no_leak` —
    critical privacy pin: response on denial has zero
    leaked claims.
  - `mismatch_response_serializes_to_bare_inactive` —
    wire-form byte-exact `{"active":false}`.
  - `already_inactive_response_passes_through_unchanged`
    — gate doesn't double-wrap.
  - `refresh_token_response_with_no_aud_passes_through`
    — documented v0.50.0 scope: refresh responses
    aren't gated.
  - `empty_string_audiences_compared_byte_exact` —
    "" matches "" only; legitimate edge.
  - `case_sensitive_audience_comparison` — RFC 7519
    §4.1.3 case-sensitivity preserved.
  - `substring_match_does_not_satisfy_gate` — defensive:
    "rs" must NOT match "rs.example.com"; nor vice
    versa.
  - `mismatched_audience_audit_payload_contains_both_values`
    — audit payload contract.
- ui: 244 → 244.
- worker: 182 → 182 (handler wiring; testable
  transformation is in pure core).

### Schema / wire / DO

- **Schema migration** (SCHEMA_VERSION 9 → 10).
  Single ALTER TABLE; ~milliseconds for any
  realistic deployment size.
- **Wire format additive only**: `aud` added to
  `IntrospectionResponse`; spec-conformant clients
  ignore unknown fields. Existing inactive-response
  byte-form unchanged. Audience-denied responses
  byte-equal to legacy inactive responses.
- **DO state unchanged**: refresh families don't
  store audience.
- **No new dependencies**.

### Operator-visible changes

- **No production behavior change** until an operator
  sets `oidc_clients.audience` to a non-NULL value
  for at least one client. Default behavior is
  unchanged.
- **Schema migration** runs on next deploy
  automatically via existing migrate machinery
  (SCHEMA_VERSION bump triggers).
- **Recommended deployment progression for multi-RS
  deployments**:
  1. Upgrade to v0.50.0. No clients have audience
     set. Behavior unchanged.
  2. Identify which resource-server clients should
     be scoped. For each, decide its allowed
     audience (typically the RS's stable hostname
     or identifier).
  3. Set `oidc_clients.audience` for those clients
     via direct D1 statement
     (`UPDATE oidc_clients SET audience = ? WHERE id = ?`).
     Admin console UI for this is out of v0.50.0
     scope.
  4. Watch audit logs for
     `introspection_audience_mismatch` events. A
     spike right after enabling typically indicates
     either (a) misconfiguration — the audience
     value doesn't match what the tokens actually
     carry, or (b) the discovered cross-RS
     introspection that motivated the scoping in
     the first place.
- **No `wrangler.toml` change**. No new bindings.
  No new env vars.

### ADR changes

- **ADR-014 §Q1** marked **Resolved**. Inline
  resolution paragraph follows the ADR-011 §Q1 /
  ADR-012 §Q1, §Q4, §Q1.5 / ADR-014 §Q4, §Q2, §Q3
  inline-resolution style.
- No new ADR.

### Open security-track items remaining

After v0.50.0, the open items the v0.49.0 changelog
flagged are:

- **ADR-012 §Q2** (idle-timeout user notification) —
  needs an email pipeline, which cesauth doesn't
  yet have. Defer until that's built.
- **ADR-012 §Q3** (geo/device-fingerprint columns
  on `user_sessions`) — needs GeoIP infrastructure;
  cesauth has none. Defer until operator demand
  + infrastructure choice surface together.
- **ADR-012 §Q5** (orphan DOs — DO has no D1 row)
  — structurally blocked by Cloudflare not
  supporting DO namespace iteration. No good
  resolution path exists with current platform
  primitives.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.49.0 → 0.50.0.
- UI footers + tests bumped to v0.50.0.
- ROADMAP: v0.50.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.49.0 → 0.50.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   dependencies.**
3. `wrangler deploy`. **One schema migration runs
   (0010, ALTER TABLE oidc_clients ADD COLUMN
   audience TEXT).**
4. **Optionally** set
   `oidc_clients.audience` for clients you want
   scoped. Default behavior is unchanged.
5. **Watch audit logs** for
   `introspection_audience_mismatch` events after
   enabling scoping for any client.

---

