# Changelog

All notable changes to cesauth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

cesauth is pre-1.0. The public surface — endpoints, `wrangler.toml`
variable names, secret names, D1 schema, and `core::ports` traits —
may change between minor versions until 1.0. Breaking changes will
always be called out here.

---

## [0.4.5] - 2026-04-25

Completes the SaaS console mutation surface. v0.4.4 covered the
high-risk operations (status changes, plan changes, group delete);
v0.4.5 fills in the additive ones that were carved out of 0.4.4 to
keep its scope contained — three flavors of membership add/remove
and role-assignment grant/revoke. With this release the HTML
console reaches feature parity with the v0.4.2 JSON API for
operator-driven mutations.

The larger "tenant-scoped admin surface" item (where tenant admins
administer their own tenant rather than every tenant) is **not**
in this release — it has unresolved design questions on URL
shape, user-as-bearer mechanism, and tenant-boundary leakage that
deserve their own design pass. **0.4.6+** picks it up.

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
  Each handler delegates to the existing v0.4.0/0.4.1
  service-layer adapters and emits the appropriate audit event
  (`MembershipAdded`, `MembershipRemoved`, `RoleGranted`,
  `RoleRevoked`) with the `via=saas-console` reason marker.

- **16 new routes** wired in `lib.rs` under a new
  `// SaaS console mutations (v0.4.5: memberships + role assignments)`
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
  "v0.4.4 (mutation forms enabled for Operations+)" to
  "v0.4.5 (full mutation surface for Operations+)".

### Tests

- Total: **216 passing** (+20 over 0.4.4's 196).
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

### Auth caveat (unchanged from 0.3.x and 0.4.4)

Forms POST same-origin and the bearer rides on the
`Authorization` header. Operators still need a tool that sets
the header (curl, browser extension). Cookie-based admin auth
remains a 0.4.6+ design pass alongside user-as-bearer.

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
  v0.4.2 JSON API takes a tagged Scope enum. Asking operators
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

### Deferred — still tracked for 0.4.6+

- **Tenant-scoped admin surface**. The v0.4.3-0.4.5 console
  serves the cesauth deployment's operator staff — one console,
  every tenant. A tenant-scoped admin surface (where tenant
  admins administer their own tenant rather than every tenant)
  is a parallel UI reachable from a tenant-side login, gated
  through user-as-bearer plus `check_permission`, and filtered
  to the caller's tenant. **0.4.6+.** Three open design
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
- **Anonymous-trial promotion.** **0.4.7.**
- **External IdP federation.**

---

## [0.4.4] - 2026-04-25

The mutation surface for the SaaS console. v0.4.3 shipped the read
pages; v0.4.4 wraps the v0.4.2 JSON API in HTML forms with a
preview/confirm flow for destructive operations, mirroring the
v0.3.1 pattern used for bucket safety edits. Operations+ only;
ReadOnly continues to see the read pages from v0.4.3 with mutation
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
  - The pattern is the same one v0.3.1 introduced: first POST
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

- **Footer marker** updated from "v0.4.3 (read-only)" to
  "v0.4.4 (mutation forms enabled for Operations+)".

### Tests

- Total: **196 passing** (+30 over 0.4.3's 166).
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

### Auth caveat (unchanged from 0.3.x and 0.4.3)

Forms POST same-origin and the bearer rides on the
`Authorization: Bearer ...` header — same as the read pages
and same as the v0.3.x edit forms. The `Authorization` header
is not auto-forged by browsers across origins, which is the
CSRF defense; but it also means operators must use a tool
that sets the header (curl, browser extension, or once it
lands, the v0.4.5+ user-as-bearer cookie path). This is the
existing 0.3.x limitation; v0.4.4 inherits rather than
relaxes it. The v0.4.5+ cookie-based auth design pass is
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

### Deferred — still tracked for 0.4.5+

The 0.4.4 surface focuses on the mutations operators do most
often. Items still pending:

- **Role grant / revoke forms.** Today these go through the
  v0.4.2 JSON API or wrangler. A "Grant role" form on a user's
  role assignments page is the natural fit. Slated for the
  next iteration.
- **Membership add / remove forms.** Same as above — frequent,
  low-risk; the JSON API handles them today.
- **Tenant-scoped admin surface.** Tenant admins administering
  their own tenant rather than every tenant. **0.4.5+.** This
  is the user-as-bearer / login → tenant resolution / cookie-
  auth design pass.
- **`check_permission` integration on the API surface.**
  Blocked on user-as-bearer.
- **Anonymous-trial promotion.** **0.4.6.**
- **External IdP federation.**

---

## [0.4.3] - 2026-04-25

A read-only HTML console at `/admin/saas/*` for cesauth's operator
staff to inspect tenancy / billing state. Sits parallel to (and
visually distinct from) the v0.3.x cost / data-safety console at
`/admin/console/*`. Mutation continues to flow through the v0.4.2
JSON API; the HTML preview/confirm flow that wraps those mutations
is slated for v0.4.4 with the same two-step pattern v0.3.1
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
  cannot mistake this surface for the writable v0.4.4 follow-up.

- **Tests** (+22 over 0.4.2's 144, total 166):
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

No breaking changes. The 0.4.2 JSON API at `/api/v1/...` continues
to work identically. The 0.4.3 console only **reads** through the
existing service-layer ports + D1 adapters.

### Deferred — still tracked for 0.4.4+

The 0.4.3 console is read-only by design. The mutation surface
(create / update / delete forms with the v0.3.1 preview/confirm
pattern) is the headline 0.4.4 feature. Other still-deferred items
are unchanged from 0.4.2:

- **HTML mutation forms with two-step confirmation** (0.4.4) —
  same preview-then-confirm pattern v0.3.1 introduced for bucket
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

- **27 routes wired** into `lib.rs` under a `// --- Tenancy service
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

The tenancy service foundation. Implements the data model and core
authorization engine from
`cesauth-Tenancy service + authz 拡張開発指示書.md` §3-§5 and §16.1,
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
