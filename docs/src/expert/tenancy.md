# Tenancy

Starting with v0.5.0 cesauth ships the data model and authorization
engine for multi-tenant SaaS deployments. The single-tenant
deployment that v0.3.x supports continues to work unchanged; the new
machinery is additive.

This chapter is the operator-facing reference for how the new model
fits together. The matching domain spec is
`cesauth-Tenancy 化可能な構成への拡張開発指示書.md` in the
repository root; this chapter implements §3-§5 and §16.1, §16.3,
§16.6.

> **Status of v0.4.x.**
> v0.5.0 shipped the data model
> (`crates/core/src/{tenancy,authz,billing}/`), the in-memory
> adapters for host tests, the central `check_permission` function,
> and the D1 schema in migration `0003_tenancy.sql`.
>
> v0.6.0 added the **Cloudflare D1 adapters** for every port and
> made the existing `users` table tenant-aware via migration
> `0004_user_tenancy_backfill.sql`. Every existing user is now
> associated to the bootstrap tenant; email uniqueness becomes
> per-tenant.
>
> v0.7.0 shipped the **`/api/v1/...` HTTP API** for tenant /
> organization / group / membership / role-assignment / subscription
> CRUD, with plan-quota enforcement on the create paths. The API is
> gated through the existing 0.3.x admin-bearer mechanism with two
> new capabilities (`ViewTenancy` / `ManageTenancy`).
>
> v0.8.0 shipped a **read-only HTML SaaS console** at
> `/admin/saas/*` for cesauth's operator staff to inspect tenancy
> state without curling the JSON API.
>
> v0.9.0 added the **mutation surface**: HTML forms wrapping the
> v0.7.0 JSON API with a risk-graded preview/confirm pattern.
> Eight forms: tenant / organization / group create, tenant /
> organization status change, group delete, subscription plan /
> status change. Affordance buttons gate on
> `Role::can_manage_tenancy()` so ReadOnly operators don't see
> broken-link buttons.
>
> v0.10.0 completed the SaaS console mutation surface with the
> additive forms 0.9.0 carved out — three flavors of membership
> add/remove (tenant / organization / group) and role assignment
> grant/revoke. With that release the HTML console reaches feature
> parity with the v0.7.0 JSON API for operator-driven mutations.
>
> v0.11.0 settles the design for the **tenant-scoped admin surface**
> (where tenant admins administer their own tenant rather than the
> cesauth operator administering every tenant). Three architecture
> decision records at `docs/src/expert/adr/` answer the three open
> questions: ADR-001 picks path-based URLs (`/admin/t/<slug>/...`),
> ADR-002 extends `admin_tokens` with an optional `user_id` column
> rather than introducing cookies or JWTs, and ADR-003 commits to
> complete URL-prefix separation between system-admin and
> tenant-admin surfaces (no in-page mode switch). The release also
> ships the schema + type foundation reflecting these decisions —
> migration `0005`, `AdminPrincipal::user_id`, the
> `is_system_admin()` helper. The full implementation lands in
> **0.12.0+**.

---

## The four boundaries

cesauth's tenancy model layers four orthogonal concerns on
top of `users` / `sessions`:

1. **Tenancy** (`crate::tenancy`) — *who is in what?* Tenants,
   organizations, groups. Every tenant-scoped row carries a
   `tenant_id` that anchors it; cross-tenant data leakage is
   prevented at the data layer rather than relying on application
   code to remember to filter.

2. **Account type** (`tenancy::AccountType`) — *what kind of
   principal is this?* `HumanUser`, `ServiceAccount`,
   `SystemOperator`, `Anonymous`, `ExternalFederatedUser`.
   Deliberately separate from authorization. A `SystemOperator`
   account is *not* automatically privileged; capabilities come
   only from role assignments.

3. **Authorization** (`crate::authz`) — *what can they do, and
   where?* Permissions, roles, scoped role assignments. There is
   exactly one entry point, `check_permission`, that callers must
   use. Spec §9.2 ("権限判定関数を単一のモジュールに集約する")
   is enforced by convention and by the absence of any other
   permission-checking surface in the crate.

4. **Billing** (`crate::billing`) — *what does the tenant pay for?*
   Plans, subscriptions, subscription history. Plans and
   subscriptions are strictly separated (§8.6); a plan upgrade is a
   single subscription update, not a re-stamp of tenant data.

Memberships connect (1) and the rest. A user belongs to a tenant
through `user_tenant_memberships`; to organizations through
`user_organization_memberships`; to groups through
`user_group_memberships`. Memberships are **relations, not
attributes** (spec §2 principle 4): nothing on the `users` row says
"I'm in tenant X". Multiple memberships per user are first-class.

---

## Tenancy

A `Tenant` is the outermost boundary. Every tenant carries a slug
(URL-safe key, immutable in practice) and a status:

- `pending` — created but not yet activated (placeholder for the
  invitation / billing-completion flows that arrive with self-signup).
- `active` — normal operation.
- `suspended` — operator action; data retained, sign-in blocked.
- `deleted` — soft-deleted; a future retention job purges.

A new deployment migrates with one bootstrap tenant whose id is the
constant `tenancy::DEFAULT_TENANT_ID` (`"tenant-default"`). Existing
v0.3.x rows in `users`, `sessions`, etc. are not yet associated to
this tenant — the backfill that adds a `tenant_id` column to those
tables is part of 0.6.0's schema work.

### Organizations

A tenant's interior structure. Departments, customer sub-accounts,
operational teams. Org slugs are unique per tenant (the `unique
(tenant_id, slug)` index in 0003_tenancy.sql).

The `parent_organization_id` column exists for future hierarchy.
v0.5.0's service layer ignores it; trees of orgs are not modeled.

### Groups

A logical unit usable for both membership ("these people belong
together") and authorization ("grant this role to these people at
once"). Spec §3.3 cautions that the use-case must be clear; the
data model does not enforce a distinction, so operator discipline is
required.

A group's parent is encoded by [`GroupParent`]:

```rust
pub enum GroupParent {
    Tenant,
    Organization { organization_id: Id },
}
```

Tenant-scoped groups (`GroupParent::Tenant`) live directly under a
tenant — useful for "all-staff" or "billing-admins" groups that
cross every org. Org-scoped groups live under one organization —
"engineering-oncall", "ops-team". The CHECK in 0003_tenancy.sql
enforces that `parent_kind = 'tenant'` rows have NULL
`organization_id`, and the converse.

---

## Account types

Five values, none of which imply administrative capability:

| `AccountType`             | Used for                                                        |
|---------------------------|------------------------------------------------------------------|
| `human_user`              | Ordinary end-user, password / passkey, self-registered.          |
| `service_account`         | Machine principal for API integrations. Bearer / mTLS.            |
| `system_operator`         | cesauth's own operators (separate from a tenant's admins).        |
| `anonymous`               | Bounded trial principal. Promotion flow is a 0.12.1 follow-up.     |
| `external_federated_user` | Identity in an external IdP, role assignments local to cesauth. Federation wiring is a follow-up. |

Spec §5 is explicit: "user_type のみで admin 判定を行わない".
Even `system_operator` requires a `system_admin` role assignment to
do anything privileged. The data model and the authz engine refuse
to mix the two concepts.

---

## Authorization

### Permissions

A `Permission` is a string like `"tenant:update"` or
`"organization:member:add"`. The `permissions` table in
0003_tenancy.sql ships seeded with 25 entries; operators may add
their own rows for custom workflows.

The constants in `cesauth_core::authz::PermissionCatalog` mirror the
shipped set. Application code referencing a permission should always
go through one of those constants — the migration is what guarantees
the row exists.

### Roles

A role is a named bundle of permissions. Two flavors:

- **System roles** (`tenant_id IS NULL`) — visible from every
  tenant. The six built-ins are seeded by 0003_tenancy.sql:
  `system_admin`, `system_readonly`, `tenant_admin`,
  `tenant_readonly`, `organization_admin`, `organization_member`.
- **Tenant-local roles** (`tenant_id = T`) — defined by a tenant
  for itself, invisible to other tenants. The CRUD surface for
  these arrives with 0.6.0's routes.

### Role assignments

A row in `role_assignments` says: "user U has role R within scope S,
granted by G at time T, optionally expiring at X". The `Scope` enum
is the heart of the model:

```rust
pub enum Scope {
    System,
    Tenant       { tenant_id:       Id },
    Organization { organization_id: Id },
    Group        { group_id:        Id },
    User         { user_id:         Id },
}
```

A `System` scope is for cesauth's own operator staff; only system
operators ever get one. The other four scope flavors are the natural
addressing of the tenancy tree.

### `check_permission` — the one entry point

Every authorization check funnels through:

```rust
async fn check_permission<RA, RR>(
    assignments: &RA,
    roles:       &RR,
    user_id:    &str,
    permission: &str,
    scope:      ScopeRef<'_>,
    now_unix:   i64,
) -> PortResult<CheckOutcome>;
```

The function is pure over its port reads — it never writes audit
events, never has side effects. Callers decide what to log around
the check.

The result is `CheckOutcome::Allowed { role_id, scope }` (carries
which assignment granted it, for the caller's audit) or
`CheckOutcome::Denied(DenyReason)`. The deny reasons are
distinguishable on purpose:

| `DenyReason`        | Meaning                                                   |
|---------------------|-----------------------------------------------------------|
| `NoAssignments`     | User has no role assignments at all.                      |
| `ScopeMismatch`     | Has assignments, none cover the queried scope.            |
| `PermissionMissing` | Covers the scope, but no role grants the permission.      |
| `Expired`           | A would-have-been-allowed assignment has expired.         |

Surfacing `Expired` separately makes "access broke because the grant
expired" patterns visible in the audit log.

### Scope-covering lattice

A `System` grant covers every scope. Otherwise, in v0.5.0, a grant
covers only the **same-id** scope (a `Tenant{T}` grant covers a
query at `Tenant{T}`, not at `Organization{O in T}`).

Cross-tier coverage — "my tenant grant should apply to every org
inside" — is implemented by **the caller**, not by
`check_permission`: the caller knows which tenant the operation
naturally lives in and queries at that scope. The decision to keep
`check_permission` lattice-direct rather than full-tree-walking is
deliberate:

- The function stays pure and cheap (one port read, plus role lookups).
- The route handler always knows the operation's natural scope (the
  operation operates on a specific tenant / org / group / user); it
  passes that as the `ScopeRef` and the lattice does the rest.
- Adding cross-tier coverage later, if needed, is a layered helper
  (`check_permission_with_tree(..., tree_reader)`) — additive, not a
  semantics change.

---

## Billing

`Plan` and `Subscription` are strictly separated. The four built-in
plans seeded by 0003_tenancy.sql are `free`, `trial`, `pro`,
`enterprise`. Each carries:

- `features` — list of `FeatureFlag` strings (e.g. `pro_features`).
  Stable string keys so a feature flag can be added without a Rust
  release.
- `quotas` — list of `Quota { name, value }` pairs. Value `-1`
  means unlimited; positive values are hard caps. Names are stable
  keys: `max_users`, `max_organizations`, `max_groups`.
- `price_description` — display hint for the admin UI. cesauth does
  NOT compute invoices.

A `Subscription` is the one-active-row-per-tenant relationship:

- `lifecycle` (`trial` / `paid` / `grace`) and `status` (`active` /
  `past_due` / `cancelled` / `expired`) are **orthogonal**: a trial
  can be Active or Cancelled; a paid subscription can be Active or
  PastDue. Spec §8.6 ("試用状態と本契約状態を分ける") is the
  reason.
- `current_period_end` and `trial_ends_at` are nullable wall-clock
  reference points; cesauth schedules nothing yet (no cron is wired
  up in 0.5.0).

`SubscriptionHistoryEntry` is append-only. One row per state change
gives the audit answer to "when did this tenant move plans?" without
relying on log archaeology.

> **Quota enforcement is deferred.** The plan carries the numbers;
> the runtime checks at user-create / org-create / group-create
> arrive with 0.6.0 alongside the route layer.

---

## What ships in v0.4.x and what does not

### Ships in 0.5.0

- All entity types (`Tenant`, `Organization`, `Group`, `User`-via-existing,
  `Permission`, `Role`, `RoleAssignment`, `Plan`, `Subscription`,
  `SubscriptionHistoryEntry`).
- All membership types and the unified `MembershipRepository` port.
- The full `check_permission` engine.
- In-memory adapters for every new port (host-test layer).
- D1 schema in `migrations/0003_tenancy.sql` — seeded with one
  bootstrap tenant, six system roles, four built-in plans, and 25
  catalog permissions.

### Added in 0.6.0

- **Cloudflare D1 adapters** for all ten new ports
  (`tenancy::Cloudflare{Tenant,Organization,Group,Membership}Repository`,
  `authz::Cloudflare{Permission,Role,RoleAssignment}Repository`,
  `billing::Cloudflare{Plan,Subscription,SubscriptionHistory}Repository`).
- **`User` table tenant-aware** via
  `migrations/0004_user_tenancy_backfill.sql`. Every pre-0.6.0 user
  is migrated into the `tenant-default` bootstrap tenant. Email
  uniqueness becomes per-tenant: two tenants may both have an
  `alice@example.com`. The `User` struct gains
  `tenant_id` + `account_type` (with `serde(default)` for
  forward/back compat with cached payloads).
- **Auto-membership backfill**: every existing user gets a
  `user_tenant_memberships` row in the bootstrap tenant with role
  `member`, so post-migration there are zero tenant-less users.

### Added in 0.7.0

- **`/api/v1/...` HTTP API** for the tenancy data model.
  Tenants, organizations, groups, three flavors of membership,
  role assignments, subscriptions — full CRUD for each, JSON-only,
  gated through the existing admin-bearer mechanism. See the
  CHANGELOG `[0.7.0]` entry for the route catalogue.
- **Two new admin capabilities**: `ViewTenancy` (every valid role)
  and `ManageTenancy` (Operations+ — same tier as `EditBucketSafety`
  / `EditThreshold` / `CreateUser`).
- **Plan-quota enforcement** at organization-create and group-create.
  The pure decision logic is `cesauth_core::billing::quota_decision`;
  the worker reads the current count via `SELECT COUNT(*)` and feeds
  it in. A `quota_exceeded:max_organizations` (or `max_groups`) 409
  surfaces to the caller. `max_users` enforcement waits for the
  user-create surface to land in 0.8.0+ (today users are created
  by the legacy admin route which bypasses quota).
- **14 new audit `EventKind` variants** for tenancy mutations —
  `TenantCreated` through `SubscriptionStatusChanged`. Every
  mutating route emits one with actor (admin token id), subject
  (created/affected row id), and a structured `reason` field.

### Added in 0.8.0

- **Read-only HTML SaaS console** at `/admin/saas/*`, parallel to
  (and visually distinct from) the v0.3.x cost / data-safety
  console at `/admin/console/*`. Five pages:
  - `/admin/saas` — overview with deployment-wide counters and a
    per-plan subscriber breakdown.
  - `/admin/saas/tenants` — list of every non-deleted tenant.
  - `/admin/saas/tenants/:tid` — single tenant view (summary,
    subscription with plan label, organization list, member list).
  - `/admin/saas/organizations/:oid` — single organization view
    (groups, members).
  - `/admin/saas/tenants/:tid/subscription/history` — append-only
    change log, reverse-chronological.
  - `/admin/saas/users/:uid/role_assignments` — every assignment
    held by one user, across every scope, with rendered scope
    drill-links.
- **Distinct nav frame** (`SaasTab`) with two top-level tabs
  (Overview, Tenants); the User-roles tab is a drill-in
  destination only and is filtered out of the nav even when
  active. Footer carries a `read-only` marker.
- The console is read-only **by design**. Mutations continue to
  flow through the v0.7.0 JSON API. The HTML preview/confirm
  forms (the v0.4.0-style two-step pattern, applied to tenancy
  mutations) ship in v0.9.0. The split mirrors the 0.3.0 → 0.4.0
  split and lets the read pages settle before the write surface
  arrives.

### Added in 0.9.0

- **Eight HTML mutation forms** wrapping the v0.7.0 JSON API.
  Risk-graded: one-click submit for additive operations,
  v0.4.0-style preview/confirm for destructive ones.
  - **One-click**: tenant create, organization create, group
    create (tenant- and org-rooted variants).
  - **Preview/confirm**: tenant set-status, organization
    set-status, group delete, subscription set-plan,
    subscription set-status.
- **16 new routes** (8 GET form + 8 POST submit) at
  `/admin/saas/tenants/new`, `/admin/saas/tenants/:tid/status`,
  `/admin/saas/tenants/:tid/organizations/new`,
  `/admin/saas/organizations/:oid/status`,
  `/admin/saas/tenants/:tid/groups/new`,
  `/admin/saas/organizations/:oid/groups/new`,
  `/admin/saas/groups/:gid/delete`,
  `/admin/saas/tenants/:tid/subscription/plan`,
  `/admin/saas/tenants/:tid/subscription/status`. All gated on
  `AdminAction::ManageTenancy` (Operations+).
- **Affordance buttons** on the read pages, conditional on
  `Role::can_manage_tenancy()`. Tenants list grows
  "+ New tenant"; tenant detail grows
  "+ New organization", "+ New tenant-scoped group",
  "Change tenant status", and (when a subscription is on file)
  "Change plan" + "Change subscription status"; organization
  detail grows "+ New group", "Change organization status", and
  per-row "Delete" links in the groups table. ReadOnly operators
  see no buttons — clicking a button cannot lead to a 403 page.
- **Quota delta visualization** on the subscription plan-change
  confirm page. Each quota in the target plan renders as a
  current → target row, with `⚠` markers on quotas that
  *decrease*. Existing usage above the new limit is documented
  as not auto-pruned but blocking new creates.
- **Destructive-operation warnings** baked into confirm pages:
  tenant suspend warns "refuses sign-ins for every user in this
  tenant"; tenant delete warns "Recovery requires manual SQL";
  subscription expire warns "plan-quota enforcement falls
  through to no-plan allow-all"; subscription cancel notes
  "current period continues to be honored".
- **Sticky form values on re-render.** A failed submit (slug
  collision, missing field, quota exceeded) re-renders the
  form with the operator's existing inputs preserved.
- **POST/Redirect/GET via 303 See Other** after successful
  mutations. Page refreshes don't re-submit.
- **`Role::can_manage_tenancy()` helper** on
  `cesauth_core::admin::types::Role`, with a parity test
  pinning it to `role_allows(_, ManageTenancy)`.
- **Footer marker** updated from "v0.8.0 (read-only)" to
  "v0.9.0 (mutation forms enabled for Operations+)".

### Added in 0.10.0

- **Five new HTML form templates** completing the SaaS console
  mutation surface. With this release the console reaches feature
  parity with the v0.7.0 JSON API for operator-driven mutations.
  - **Membership add** — three entry points (tenant /
    organization / group). Tenant form has a 3-option role select
    (owner / admin / member); org form has a 2-option select
    (admin / member); group form omits the role field. One-click
    submit; no preview.
  - **Membership remove** — three entry points. One-step confirm
    with a "user loses access; data is not destroyed" warning.
  - **Role assignment grant** at
    `/admin/saas/users/:uid/role_assignments/new` with full
    structured Scope picker (system / tenant / organization /
    group / user) plus optional `expires_at`. Re-renders with
    sticky values + helpful messages on validation failure.
  - **Role assignment revoke** with a one-step confirm screen
    that shows the role label, scope, granted_by/at, and a
    warning that "session is not invalidated" — operators get
    the right mental model for what revoke does.

- **16 new routes** under `/admin/saas/...` (8 GET form + 8 POST
  submit). All gated through `AdminAction::ManageTenancy`
  (Operations+).

- **Affordance buttons on existing read pages**:
  - Tenant detail grows "+ Add tenant member" + per-row "Remove"
    on members table.
  - Organization detail grows "+ Add organization member" +
    per-row "Remove" on members table.
  - User role assignments grows "+ Grant role" + per-row
    "Revoke" on each assignment.
  All gate on `Role::can_manage_tenancy()` — ReadOnly operators
  see no buttons.

- **Defensive lookup of role assignment by id**. The
  `RoleAssignmentRepository` was designed for `list_for_user`-
  driven paths and does not expose `get_by_id`. The delete
  handler walks the user's list to find the matching row;
  the confirm-page URL carries `?user_id=...` and the POST
  form carries it as a hidden field. Handler-local
  `fetch_assignment` helper localizes the pattern.

- **Footer marker** updated from
  "v0.9.0 (mutation forms enabled for Operations+)" to
  "v0.10.0 (full mutation surface for Operations+)".

### Added in 0.11.0

This is a foundation-only release. No new HTML or routes; the
shippable artifact is the design (three ADRs) plus the schema and
type changes those ADRs imply.

- **Three Architecture Decision Records** at
  `docs/src/expert/adr/`:
  - **ADR-001** picks path-based URLs (`/admin/t/<slug>/...`)
    over subdomain-based for the tenant-scoped admin surface.
    Single cert, single origin.
  - **ADR-002** picks extending `admin_tokens` with an optional
    `user_id` column over session cookies or JWTs as the user-
    as-bearer mechanism. `Authorization: Bearer` continues as
    the wire format.
  - **ADR-003** picks complete URL-prefix separation between
    system-admin (`/admin/saas/*`) and tenant-admin
    (`/admin/t/<slug>/*`) over an in-page mode switch.

- **Migration `0005_admin_token_user_link.sql`**: adds a
  nullable `user_id` column to `admin_tokens` and a partial
  index on it. Application-layer FK enforcement (consistent
  with how the rest of the schema handles foreign keys).

- **`AdminPrincipal::user_id: Option<String>`** field. Every
  existing call site defaults to `None` — preserves all
  v0.3.x and v0.4.x behavior. The Cloudflare D1 adapter reads
  the new column and propagates it.

- **`AdminPrincipal::is_system_admin()`** helper. Returns
  `true` iff `user_id.is_none()`. v0.12.0 will use it to
  enforce ADR-003's surface separation.

- **JSON-shape compatibility** preserved through
  `#[serde(skip_serializing_if = "Option::is_none")]`. A
  principal with `user_id: None` serializes exactly like the
  v0.3.x principals did — no surprise for any consumer of
  the audit log or admin-token list endpoint.

### Does NOT ship in v0.4.x (yet)

The CHANGELOG `Deferred` sections and `ROADMAP.md` track each item.
Headlines:

- **Tenant-scoped admin surface implementation**. v0.11.0
  shipped the design and foundation; v0.12.0 builds the routes
  + views + per-route auth gate that requires
  `principal.user_id == Some(_)` matching the URL slug.
- **Token-mint flow with `user_id`.** Today
  `AdminTokenRepository::create` mints system-admin tokens
  only. v0.12.0 introduces a parallel mint path (or extended
  signature) that produces user-bound tokens. The mint flow
  itself raises questions (who can mint? what's the
  authorization on the mint?) that v0.12.0 will answer.
- **`check_permission` integration on the API surface.** v0.7.0
  routes go through `ensure_role_allows` (admin-side capability)
  rather than `check_permission` because admin tokens had no
  user binding. With v0.11.0's `AdminPrincipal::user_id`, this
  becomes possible — and v0.12.0 will wire it up for the
  tenant-scoped routes.
- **Cookie-based auth for admin forms.** Explicitly *not* the
  user-as-bearer mechanism, per ADR-002. May appear as an
  *additional* mechanism in a later ADR if there's a concrete
  need.
- **Anonymous-trial promotion.** The account type exists; the
  promotion lifecycle is unspecified. **0.12.1.**
- **External IdP federation.** `AccountType::ExternalFederatedUser`
  is reserved; no IdP wiring exists yet.

---

## Operator runbook (v0.4.x)

### Running the migrations

A 0.3.x → 0.6.0 upgrade runs two migrations:

```bash
# 0003 — adds tenancy / authz / billing schema. Idempotent
# (INSERT OR IGNORE throughout); safe to re-run.
wrangler d1 execute cesauth --remote --file migrations/0003_tenancy.sql

# 0004 — adds tenant_id + account_type to the users table and
# backfills every existing row into the bootstrap tenant. Uses
# SQLite "rename, recreate, copy"; not safe to run against a live
# writer (same caveat as the 0001 baseline).
wrangler d1 execute cesauth --remote --file migrations/0004_user_tenancy_backfill.sql
```

After 0004, every user has `tenant_id = 'tenant-default'`,
`account_type = 'human_user'`, and a matching row in
`user_tenant_memberships` with role `member`. Re-grade owners /
admins / service-accounts out-of-band — the migration cannot infer
those from pre-0.4 data.

### Inspecting the seeded catalog

```bash
# Permissions catalog
wrangler d1 execute cesauth --remote \
  --command "SELECT name FROM permissions ORDER BY name"

# System roles
wrangler d1 execute cesauth --remote \
  --command "SELECT slug, display_name FROM roles WHERE tenant_id IS NULL"

# Built-in plans
wrangler d1 execute cesauth --remote \
  --command "SELECT slug, display_name, active FROM plans"
```

### Promoting an operator to system_admin

The HTML form for granting roles lands with v0.9.0's mutation
console; in the meantime — and for emergency recoveries — use
wrangler:

```bash
# Replace USER_ID with an existing row from `users`.
wrangler d1 execute cesauth --remote --command "
  INSERT INTO role_assignments (id, user_id, role_id, scope_type, scope_id,
                                granted_by, granted_at)
  VALUES (lower(hex(randomblob(16))),
          'USER_ID',
          'role-system-admin',
          'system', NULL,
          'wrangler-bootstrap',
          strftime('%s','now'));
"
```

After this, calling code that goes through `check_permission`
with `ScopeRef::System` (or any narrower scope) will see this user
as Allowed.

### Re-grading an account type

`account_type` is updatable through the standard
`UserRepository::update` path (the v0.6.0 D1 adapter writes the
column). To convert an end-user row into a service account
out-of-band:

```bash
wrangler d1 execute cesauth --remote --command "
  UPDATE users SET account_type = 'service_account', updated_at = strftime('%s','now')
  WHERE id = 'USER_ID';
"
```

`tenant_id` is NOT updatable via the repository; moving a user
between tenants is destructive (it orphans every membership and
role assignment) and requires its own dedicated path. None ships
in 0.4.x.

### What about existing users?

Pre-0.6.0, the `users` table had no tenancy concept. Migration
0004 retroactively places every user in `tenant-default` (the
bootstrap tenant seeded by 0003) with `account_type = 'human_user'`,
and inserts a matching `user_tenant_memberships` row.
For single-tenant deployments this is the entire story — keep
running, no operator action required.

### Inspecting tenancy state in the browser (v0.8.0+)

The SaaS console at `/admin/saas/*` is the read-only HTML view of
the same data the API surface exposes. Use the same admin bearer
as the API:

```bash
# Browser: paste this URL after loading any /admin/console/* page
# (which establishes the admin bearer in the browser session via
# the existing session-cookie path), or curl with the bearer header.

curl -sS -H "Authorization: Bearer $ADMIN_API_KEY" \
     https://cesauth.example/admin/saas
```

Pages:

| URL                                                           | Shows                                                                     |
|---------------------------------------------------------------|---------------------------------------------------------------------------|
| `/admin/saas`                                                 | Counters + per-plan subscriber breakdown                                  |
| `/admin/saas/tenants`                                         | Every non-deleted tenant                                                  |
| `/admin/saas/tenants/{id}`                                    | One tenant: summary, subscription, organizations, members                 |
| `/admin/saas/tenants/{id}/subscription/history`               | Append-only change log for that tenant's subscription                     |
| `/admin/saas/organizations/{id}`                              | One organization: groups, members                                         |
| `/admin/saas/users/{id}/role_assignments`                     | Every role assignment held by one user, across every scope                |

Every page is gated through `AdminAction::ViewTenancy`, which is
open to **all four roles** (ReadOnly, Security, Operations, Super).
Mutating the underlying state still requires `ManageTenancy`
(Operations+), and the only way to trigger that capability today
is via the v0.7.0 JSON API or a wrangler shell. The HTML mutation
console is v0.9.0.

### Mutating tenancy state via the SaaS console (v0.9.0+)

For Operations / Super operators, every read page now grows the
appropriate mutation buttons. Drill into a tenant to see
"+ New organization", "Change tenant status", etc. ReadOnly
operators continue to see only the read views.

The forms POST same-origin and the bearer rides on the
`Authorization` header — same as the read pages. Browsers do not
auto-set Authorization, so a bare browser cannot submit forms;
operators use one of:

- **curl with `--cookie` and a custom-Authorization extension**
  (operator's own setup).
- **A browser extension** that injects
  `Authorization: Bearer $ADMIN_TOKEN` on the
  `cesauth.example` origin.
- **Cookie-based admin auth** (slated for 0.10.0+ alongside the
  user-as-bearer design pass).

Risk-graded confirm pattern:

| Operation                          | Pattern              | Released |
|-----------------------------------|----------------------|----------|
| Tenant create                      | One-click submit     | 0.9.0    |
| Organization create                | One-click submit     | 0.9.0    |
| Group create                       | One-click submit     | 0.9.0    |
| Tenant set-status                  | Preview / confirm    | 0.9.0    |
| Organization set-status            | Preview / confirm    | 0.9.0    |
| Group delete                       | Confirm screen       | 0.9.0    |
| Subscription set-plan              | Preview / confirm    | 0.9.0    |
| Subscription set-status            | Preview / confirm    | 0.9.0    |
| Tenant membership add              | One-click submit     | 0.10.0    |
| Tenant membership remove           | Confirm screen       | 0.10.0    |
| Organization membership add        | One-click submit     | 0.10.0    |
| Organization membership remove     | Confirm screen       | 0.10.0    |
| Group membership add               | One-click submit     | 0.10.0    |
| Group membership remove            | Confirm screen       | 0.10.0    |
| Role assignment grant              | One-click submit     | 0.10.0    |
| Role assignment revoke             | Confirm screen       | 0.10.0    |

Destructive operations re-render with a diff banner and a
separate "Apply" button. The confirm step records the same
audit event (`TenantStatusChanged`, etc.) the JSON API does,
plus a `via=saas-console` marker in the `reason` field so
operators can split console-driven mutations from
script-driven ones in the audit log.

### API smoke-test (v0.7.0+)

The `/api/v1/...` surface is gated through the same admin-bearer
mechanism as the `/admin/console/...` routes. A fresh deployment
can use the `ADMIN_API_KEY` bootstrap secret directly; once a
named Super token exists, prefer that for traceable audit lines.

```bash
ADMIN=$ADMIN_API_KEY  # or a minted Super token

# 1. Provision a tenant + owner. The owner must already exist in
#    `users`; this API does not auto-create users.
curl -sS -X POST -H "Authorization: Bearer $ADMIN" \
     -H "Content-Type: application/json" \
     -d '{"slug":"acme","display_name":"Acme Corp","owner_user_id":"USER_ID"}' \
     https://cesauth.example/api/v1/tenants

# 2. Create an organization in that tenant.
curl -sS -X POST -H "Authorization: Bearer $ADMIN" \
     -H "Content-Type: application/json" \
     -d '{"slug":"engineering","display_name":"Engineering"}' \
     https://cesauth.example/api/v1/tenants/TENANT_ID/organizations

# 3. Create a tenant-scoped group.
curl -sS -X POST -H "Authorization: Bearer $ADMIN" \
     -H "Content-Type: application/json" \
     -d '{"parent_kind":"tenant","slug":"all-staff","display_name":"All Staff"}' \
     https://cesauth.example/api/v1/tenants/TENANT_ID/groups

# 4. Grant the owner the system tenant_admin role within their tenant.
curl -sS -X POST -H "Authorization: Bearer $ADMIN" \
     -H "Content-Type: application/json" \
     -d '{
           "user_id": "USER_ID",
           "role_id": "role-tenant-admin",
           "scope":   { "scope": "tenant", "tenant_id": "TENANT_ID" }
         }' \
     https://cesauth.example/api/v1/role_assignments

# 5. Move the tenant onto the Pro plan (subscription must already exist).
curl -sS -X POST -H "Authorization: Bearer $ADMIN" \
     -H "Content-Type: application/json" \
     -d '{"plan_id":"plan-pro"}' \
     https://cesauth.example/api/v1/tenants/TENANT_ID/subscription/plan
```

Plan-quota enforcement (`max_organizations`, `max_groups`) returns
`409 Conflict` with body `{"error":"quota_exceeded:max_organizations"}`
when the next create would exceed the plan's limit. Free-plan
defaults are 1 organization and 10 groups; see the seeded `plans`
table in `0003_tenancy.sql`.

---

## Further reading

- Source: `crates/core/src/tenancy/`, `crates/core/src/authz/`,
  `crates/core/src/billing/`. Each module has a one-paragraph
  doc-comment summarizing its slice of the model.
- Spec: `cesauth-Tenancy 化可能な構成への拡張開発指示書.md`
  in the repo root. The implementation maps section-by-section to
  §3-§5 and §16.1, §16.3, §16.6.
- Tests: `crates/adapter-test/src/tenancy/tests.rs` — the
  end-to-end flow exercises every public service function against
  the in-memory adapters; it is the runnable answer to "what does
  this thing actually do?"
