# Tenancy

Starting with v0.4.0 cesauth ships the data model and authorization
engine for multi-tenant SaaS deployments. The single-tenant
deployment that v0.3.x supports continues to work unchanged; the new
machinery is additive.

This chapter is the operator-facing reference for how the new model
fits together. The matching domain spec is
`users, roles, tenants, organizations, groups data model + authz 拡張開発指示書` in the
repository root; this chapter implements §3-§5 and §16.1, §16.3,
§16.6.

> **Status of v0.4.x.**
> v0.4.0 shipped the data model
> (`crates/core/src/{tenancy,authz,billing}/`), the in-memory
> adapters for host tests, the central `check_permission` function,
> and the D1 schema in migration `0003_tenancy.sql`.
>
> v0.4.1 added the **Cloudflare D1 adapters** for every port and
> made the existing `users` table tenant-aware via migration
> `0004_user_tenancy_backfill.sql`. Every existing user is now
> associated to the bootstrap tenant; email uniqueness becomes
> per-tenant.
>
> HTTP routes for tenant / organization / group / role CRUD land
> in **v0.4.2**. Until then the new domain is reachable only from
> the service layer; the 0.3.x routes (auth flows, single-deployment
> admin console) continue to work against the bootstrap tenant.

---

## The four boundaries

cesauth's service model layers four orthogonal concerns on
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
tables is part of 0.4.1's schema work.

### Organizations

A tenant's interior structure. Departments, customer sub-accounts,
operational teams. Org slugs are unique per tenant (the `unique
(tenant_id, slug)` index in 0003_tenancy.sql).

The `parent_organization_id` column exists for future hierarchy.
v0.4.0's service layer ignores it; trees of orgs are not modeled.

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
| `anonymous`               | Bounded trial principal. Promotion flow is a 0.4.3 follow-up.     |
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
  these arrives with 0.4.1's routes.

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

A `System` grant covers every scope. Otherwise, in v0.4.0, a grant
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
  up in 0.4.0).

`SubscriptionHistoryEntry` is append-only. One row per state change
gives the audit answer to "when did this tenant move plans?" without
relying on log archaeology.

> **Quota enforcement is deferred.** The plan carries the numbers;
> the runtime checks at user-create / org-create / group-create
> arrive with 0.4.1 alongside the route layer.

---

## What ships in v0.4.x and what does not

### Ships in 0.4.0

- All entity types (`Tenant`, `Organization`, `Group`, `User`-via-existing,
  `Permission`, `Role`, `RoleAssignment`, `Plan`, `Subscription`,
  `SubscriptionHistoryEntry`).
- All membership types and the unified `MembershipRepository` port.
- The full `check_permission` engine.
- In-memory adapters for every new port (host-test layer).
- D1 schema in `migrations/0003_tenancy.sql` — seeded with one
  bootstrap tenant, six system roles, four built-in plans, and 25
  catalog permissions.

### Added in 0.4.1

- **Cloudflare D1 adapters** for all ten new ports
  (`tenancy::Cloudflare{Tenant,Organization,Group,Membership}Repository`,
  `authz::Cloudflare{Permission,Role,RoleAssignment}Repository`,
  `billing::Cloudflare{Plan,Subscription,SubscriptionHistory}Repository`).
- **`User` table tenant-aware** via
  `migrations/0004_user_tenancy_backfill.sql`. Every pre-0.4.1 user
  is migrated into the `tenant-default` bootstrap tenant. Email
  uniqueness becomes per-tenant: two tenants may both have an
  `alice@example.com`. The `User` struct gains
  `tenant_id` + `account_type` (with `serde(default)` for
  forward/back compat with cached payloads).
- **Auto-membership backfill**: every existing user gets a
  `user_tenant_memberships` row in the bootstrap tenant with role
  `member`, so post-migration there are zero tenant-less users.

### Does NOT ship in v0.4.x (yet)

The CHANGELOG `Deferred` sections and `ROADMAP.md` track each item.
Headlines:

- **HTTP routes** for tenant / org / group / role-assignment CRUD.
  The service layer exists, the D1 adapters exist; what's missing is
  the bearer-extension that carries
  `(user_id, tenant_id?, organization_id?)` context through the
  router and the Accept-aware HTML/JSON rendering. **0.4.2.**
- **Multi-tenant admin console**. The 0.3.x console assumes a
  single deployment-wide operator. **0.4.3.**
- **Login → tenant resolution.** Today `users.email` is globally
  queried (with a `LIMIT 1` fallback). Multi-tenant deployments
  need either tenant-scoped email login or a tenant-picker step.
  UX is open.
- **Plan-quota enforcement at runtime.** The plan numbers are
  recorded; the runtime checks at user-create / org-create /
  group-create arrive with the route layer.
- **Anonymous-trial promotion.** The account type exists; the
  promotion lifecycle is unspecified.
- **External IdP federation.** `AccountType::ExternalFederatedUser`
  is reserved; no IdP wiring exists yet.

---

## Operator runbook (v0.4.x)

### Running the migrations

A 0.3.x → 0.4.1 upgrade runs two migrations:

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

The proper admin-console UI lands with v0.4.3's multi-tenant
console; in the meantime use wrangler:

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
`UserRepository::update` path (the v0.4.1 D1 adapter writes the
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

Pre-0.4.1, the `users` table had no tenancy concept. Migration
0004 retroactively places every user in `tenant-default` (the
bootstrap tenant seeded by 0003) with `account_type = 'human_user'`,
and inserts a matching `user_tenant_memberships` row.
For single-tenant deployments this is the entire story — keep
running, no operator action required.

---

## Further reading

- Source: `crates/core/src/tenancy/`, `crates/core/src/authz/`,
  `crates/core/src/billing/`. Each module has a one-paragraph
  doc-comment summarizing its slice of the model.
- Spec: `users, roles, tenants, organizations, groups data model + authz 拡張開発指示書`
  in the repo root. The implementation maps section-by-section to
  §3-§5 and §16.1, §16.3, §16.6.
- Tests: `crates/adapter-test/src/tenancy/tests.rs` — the
  end-to-end flow exercises every public service function against
  the in-memory adapters; it is the runnable answer to "what does
  this thing actually do?"
