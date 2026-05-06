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
| **Tenancy data model + authz** | ✅       | Tenants, organizations, groups, memberships, role/permission engine, plans, subscriptions (0.5.0). Cloudflare D1 adapters for every port + `users` table tenant-aware (0.6.0). `/api/v1/...` HTTP routes for tenant / org / group / membership / role-assignment / subscription CRUD with plan-quota enforcement (0.7.0). Read-only HTML SaaS console at `/admin/saas/*` (0.8.0). Mutation forms with preview/confirm pattern (0.9.0) for tenant / organization / group / subscription. Membership add/remove + role grant/revoke forms (0.10.0) bring the HTML console to feature parity with the v0.7.0 JSON API. ADR-001/002/003 settle the tenant-scoped admin surface design (0.11.0) and ship the schema + type foundation (`admin_tokens.user_id`, `AdminPrincipal::user_id`, `is_system_admin()`). Tenant-scoped surface implementation deferred to 0.12.0. |
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

- **Tenancy HTTP routes (shipped in 0.7.0).** The
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
  adapters that read the new column. No UI yet — that's 0.12.0.

- **Tenant-scoped admin surface implementation (0.12.0).**
  Builds on the 0.11.0 foundation. Adds:
  - The `/admin/t/<slug>/...` route surface (likely 6-10
    pages mirroring the v0.8.0-0.10.0 system-admin console
    but filtered to the caller's tenant).
  - Per-route auth gate that requires
    `principal.user_id.is_some()` and `users.tenant_id` of that
    user matching the URL slug.
  - A token-mint flow that produces user-bound tokens
    (extending `AdminTokenRepository::create` or adding a
    sibling method).
  - `check_permission` integration on the tenant-scoped
    routes, since the principal now carries the `user_id`
    needed by spec §9.2.

- **Anonymous trial → human user promotion (0.12.1).** Spec §3.3
  introduces `Anonymous` as an account type and §11 priority 5
  asks for a promotion flow. The promotion lifecycle (token issuance
  for anonymous principals, retention window, conversion ceremony,
  audit trail) is unspecified and deserves its own design pass.

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
