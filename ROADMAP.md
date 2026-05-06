# Roadmap

cesauth is pre-1.0 software. This file tracks what ships today, what
is planned, and what is deliberately out of scope.

Format inspired by [Keep a Changelog](https://keepachangelog.com/) and
the [Semantic Versioning](https://semver.org/) naming for priorities.

---

## Shipped (pre-1.0)

The following subsystems are implemented end-to-end and covered by
host tests. "Initial" here means the happy path and the documented
failure modes are in place; it does not imply production-ready with
zero remaining issues.

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
| **Tenancy-service data model + authz** | ✅       | Tenants, organizations, groups, memberships, role/permission engine, plans, subscriptions (0.5.0). Cloudflare D1 adapters for every port + `users` table tenant-aware (0.6.0). `/api/v1/...` HTTP routes for tenant / org / group / membership / role-assignment / subscription CRUD with plan-quota enforcement (0.7.0). Read-only HTML console at `/admin/tenancy/*` (0.8.0, originally `/admin/saas/*`). Mutation forms with preview/confirm pattern (0.9.0) for tenant / organization / group / subscription. Membership add/remove + role grant/revoke forms (0.10.0) bring the HTML console to feature parity with the v0.7.0 JSON API. ADR-001/002/003 settle the tenant-scoped admin surface design (0.11.0) and ship the schema + type foundation (`admin_tokens.user_id`, `AdminPrincipal::user_id`, `is_system_admin()`). Project-hygiene release with naming-debt cleanup (0.12.0) — `saas/` → `tenancy_console/`, `/admin/saas/*` → `/admin/tenancy/*`, plus author/license metadata and `.github/` community documents. Buffer/follow-up release with stale-narrative cleanup + dependency audit (0.12.1). Tenant-scoped admin surface read pages shipped at `/admin/t/<slug>/*` with auth gate + `check_permission` integration (0.13.0). High-risk mutation forms plus a system-admin token-mint UI shipped (0.14.0). Additive membership forms (× 3 flavors) plus affordance gating shipped (0.15.0) — the tenant-scoped surface reaches feature parity with the system-admin tenancy console. Security-fix and audit-infrastructure release (0.15.1): RUSTSEC-2023-0071 in transitive `rsa` removed via `jsonwebtoken` feature narrowing, `cargo audit` integrated via initial sweep + GitHub Actions workflow + operator docs. |
| mdBook documentation                   | ✅       | `docs/`                                            |

---

## Planned (0.x)

Approximate priority order. Items near the top are closer to being
started.

### Next minor releases

- **Real mail provider for Magic Link delivery.** The current
  `dev-delivery` audit line containing the plaintext OTP must be
  replaced with a transactional mail HTTP call keyed by
  `MAGIC_LINK_MAIL_API_KEY` before any production deployment.
  (Release gate — see [Security → Pre-production release gates](docs/src/expert/security.md).)

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
    language tightened: "Tenancy" / "Tenancy" replaced
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
    added; the pre-1.0 SemVer caveat permits the hard rename.

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

- **Anonymous trial → human user promotion (next planned).**
  Spec §3.3 introduces `Anonymous` as an account type and §11
  priority 5 asks for a promotion flow. The promotion
  lifecycle (token issuance for anonymous principals, retention
  window, conversion ceremony, audit trail) is unspecified and
  deserves its own design pass — likely a small ADR before
  implementation, on the v0.11.0 model. Target slot: 0.16.0 or
  later (0.15.1 took the slot for the security-fix +
  audit-infrastructure release).

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

- **A generic `KeyValueStore` trait.** See [Storage responsibilities](docs/src/expert/storage.md)
  for the reasoning.

- **`mod.rs` module files.** See [Crate layout](docs/src/expert/crate-layout.md).

---

## How to propose changes

Open an issue describing the use case. If it aligns with cesauth's
scope, we'll discuss the design tradeoffs before code. A formal
`CONTRIBUTING.md` is planned but not yet written.
