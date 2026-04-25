# Changelog

All notable changes to cesauth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

cesauth is pre-1.0. The public surface — endpoints, `wrangler.toml`
variable names, secret names, D1 schema, and `core::ports` traits —
may change between minor versions until 1.0. Breaking changes will
always be called out here.

---

## [0.4.2] - 2026-04-25

The HTTP API surface for the tenancy service data model. v0.4.0
shipped the data model and central authz function; v0.4.1 shipped
the Cloudflare D1 adapters and made `users` tenant-aware; v0.4.2
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

- **27 routes wired** into `lib.rs` under a `// --- tenancy
  API (v0.4.2)` block, contiguous with the existing
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

- Total: **144 passing** (+8 over 0.4.1's 136).
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
  multi-tenant admin console (0.4.3). So 0.4.2 ships an API
  surface for *cesauth's operator staff* to provision tenants.
  Self-service tenant operations are deferred. The route handlers
  go through `ensure_role_allows` (admin-side capability) rather
  than `check_permission` (tenancy-side capability); the two
  converge in 0.4.3+ when user bearers arrive.

- **JSON-only, no Accept negotiation.** HTML belongs in 0.4.3 with
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

### Deferred — still tracked for 0.4.3+

- **Multi-tenant admin console** (0.4.3) — HTML surface for
  tenant-scoped admins. Opens user-as-bearer, login → tenant
  resolution, and Accept negotiation as one design pass.
- **Anonymous-trial promotion** (0.4.4).
- **External IdP federation**.

---

## [0.4.1] - 2026-04-25

The runtime backing for v0.4.0's tenancy service data model.
Implements the Cloudflare D1 adapters for every port the 0.4.0 core
defined, and migrates the existing `users` table to be tenant-aware.
Routes / multi-tenant admin console / login-tenant resolution remain
deferred (see "Deferred" below).

### Added

- **Cloudflare D1 adapters for every 0.4.0 port** (10 adapters
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
  Backfills every pre-0.4.1 user into `tenant-default` with
  `account_type = 'human_user'`. Also auto-inserts a
  `user_tenant_memberships` row so every user has a membership in
  their bootstrap tenant — no orphaned users post-migration.

- **`User` struct gains `tenant_id` and `account_type`** in
  `cesauth_core::types`. Both fields use `serde(default = ...)` so
  pre-0.4.1 cached payloads continue to deserialize cleanly. The
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
  variant arrives with the multi-tenant login flow in 0.4.2+.

### Changed

- **User construction sites updated.**
  `routes/admin/legacy.rs::create_user` and
  `routes/magic_link/verify.rs` (auto-signup at first verification)
  now stamp `tenant_id = tenant-default` and
  `account_type = HumanUser` when creating users. A multi-tenant
  signup path will land alongside the multi-tenant routes.

### Tests

- Total: **136 passing** (+3 over 0.4.0's 133).
  - core: 93 (was 90) — three new `User` serde tests covering
    forward, backward, and default-value behavior.
  - adapter-test: 32 (unchanged).
  - ui: 11 (unchanged).
- The Cloudflare D1 adapters are not exercised by host tests
  (they require a Workers runtime). The host tests in
  `adapter-test` cover the same trait surface against the
  in-memory adapters; the CF adapters' contract correctness is
  verified at deploy time via `wrangler dev`.

### Deferred — still tracked for 0.4.2+

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

## [0.4.0] - 2026-04-25

Implements the data model and core authorization engine from
`Tenancy service + authz 拡張開発指示書.md` §3-§5 and §16.1,
§16.3, §16.6. Routes / UI / multi-tenant admin console are deferred
to 0.4.1 by design (see "Deferred" below).

### Added

- **Tenancy domain** (`cesauth_core::tenancy`). New entities:
  - `Tenant` — top-level boundary (§3.1). States: pending, active,
    suspended, deleted.
  - `Organization` — business unit within a tenant (§3.2).
    `parent_organization_id` column reserved for future hierarchy;
    flat in 0.4.0.
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
    applies to this org") is tagged as a follow-up — for 0.4.0 the
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

- **Tests** (+30 over 0.3.1's 103, total 133):
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

### Deferred — not in 0.4.0, tracked for 0.4.1+

The spec's §16 receive criteria are broad. 0.4.0 ships the data
model and the central authz engine; the items below are
prerequisites for a fully-receivable v0.4 but each carries enough
design surface to deserve its own release:

- **HTTP routes** for tenant / organization / group / role CRUD.
  The service layer has one function per operation; the route layer
  needs an admin-bearer extension carrying `(user, tenant?, org?)`
  context that a 0.4.1 design pass should specify before wiring.
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

## [0.3.1] - 2026-04-24

### Added

- **HTML two-step confirmation UI for bucket-safety edits.** The
  pre-0.3.1 preview/apply JSON API is unchanged; 0.3.1 adds a
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

- **Configuration Review's "Editing" section rewritten.** Pre-0.3.1
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

### Deferred (for 0.3.1)

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
  HTML surface lands in 0.3.1.
- **Workers-request counter hot-path instrumentation.** 0.3.0 reads
  the `counter:workers:requests:*` KV keys and will report whatever
  is there; the actual `.increment()` call on every request is the
  0.3.1 work. Fresh deployments see zeros.
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
