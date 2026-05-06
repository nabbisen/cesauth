# Tenancy service

Starting with v0.5.0 cesauth ships the data model and authorization
engine for multi-tenant deployments. The single-tenant deployment
that v0.3.x supports continues to work unchanged; the new machinery
is additive.

This chapter is the operator-facing reference for how the new model
fits together. The matching domain spec is
`cesauth-Tenancy service + authz 拡張開発指示書.md` in the repository root;
this chapter implements §3-§5 and §16.1, §16.3, §16.6.

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
> v0.8.0 shipped a **read-only HTML tenancy console** at
> `/admin/tenancy/*` for cesauth's operator staff to inspect tenancy
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
> v0.10.0 completed the tenancy console mutation surface with the
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
> `is_system_admin()` helper.
>
> v0.12.0 is a project-hygiene release with the naming-debt
> cleanup folded in: project framing language tightened
> ("tenancy" replaced with "tenancy service"),
> authorship and license metadata aligned with reality,
> `.github/` community-process documents added, and the
> module-path / URL-prefix / public-type rename
> (`saas/` → `tenancy_console/`, `/admin/saas/*` →
> `/admin/tenancy/*`, `SaasTab` → `TenancyConsoleTab`)
> completed.
>
> v0.13.0 ships the tenant-scoped admin surface — read pages
> only — at `/admin/t/<slug>/...`. The per-route auth gate
> enforces ADR-003's three invariants (principal is
> user-bound, slug resolves to a tenant, the principal's
> user belongs to that tenant) and `check_permission`
> integration replaces `ensure_role_allows` for action-level
> authorization on these routes.
>
> v0.14.0 adds high-risk mutation forms at
> `/admin/t/<slug>/...` (organization create + status, group
> create + delete, role-assignment grant + revoke) and a
> system-admin token-mint UI at
> `/admin/tenancy/users/:uid/tokens/new` exposing
> `AdminTokenRepository::create_user_bound`. Per ADR-003,
> the grant form rejects `Scope::System` and pins tenant
> scope to the current tenant; defense-in-depth checks
> verify child resources (Organization, Group, User) belong
> to the current tenant before mutating.
>
> v0.15.0 completes the tenant-scoped surface: additive
> membership forms (× 3 flavors — tenant, organization,
> group) plus affordance gating on every read and form page
> (mutation buttons render only when the operator's
> `check_permission` would allow them). Two new permission
> slugs (`TENANT_MEMBER_ADD/REMOVE`) fill the symmetry gap.
> The new `check_permissions_batch` helper makes affordance
> gating cheap — one D1 round-trip per page render.

---

## The four boundaries

cesauth's tenancy-service model layers four orthogonal concerns on
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
| `anonymous`               | Bounded trial principal. Promotion flow is a 0.14.0 follow-up.    |
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

- **`/api/v1/...` HTTP API** for the tenancy-service data model.
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

- **Read-only HTML tenancy console** at `/admin/tenancy/*`, parallel to
  (and visually distinct from) the v0.3.x cost / data-safety
  console at `/admin/console/*`. Five pages:
  - `/admin/tenancy` — overview with deployment-wide counters and a
    per-plan subscriber breakdown.
  - `/admin/tenancy/tenants` — list of every non-deleted tenant.
  - `/admin/tenancy/tenants/:tid` — single tenant view (summary,
    subscription with plan label, organization list, member list).
  - `/admin/tenancy/organizations/:oid` — single organization view
    (groups, members).
  - `/admin/tenancy/tenants/:tid/subscription/history` — append-only
    change log, reverse-chronological.
  - `/admin/tenancy/users/:uid/role_assignments` — every assignment
    held by one user, across every scope, with rendered scope
    drill-links.
- **Distinct nav frame** (`TenancyConsoleTab`) with two top-level tabs
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
  `/admin/tenancy/tenants/new`, `/admin/tenancy/tenants/:tid/status`,
  `/admin/tenancy/tenants/:tid/organizations/new`,
  `/admin/tenancy/organizations/:oid/status`,
  `/admin/tenancy/tenants/:tid/groups/new`,
  `/admin/tenancy/organizations/:oid/groups/new`,
  `/admin/tenancy/groups/:gid/delete`,
  `/admin/tenancy/tenants/:tid/subscription/plan`,
  `/admin/tenancy/tenants/:tid/subscription/status`. All gated on
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

- **Five new HTML form templates** completing the tenancy console
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
    `/admin/tenancy/users/:uid/role_assignments/new` with full
    structured Scope picker (system / tenant / organization /
    group / user) plus optional `expires_at`. Re-renders with
    sticky values + helpful messages on validation failure.
  - **Role assignment revoke** with a one-step confirm screen
    that shows the role label, scope, granted_by/at, and a
    warning that "session is not invalidated" — operators get
    the right mental model for what revoke does.

- **16 new routes** under `/admin/tenancy/...` (8 GET form + 8 POST
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
    system-admin (`/admin/tenancy/*`) and tenant-admin
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
  `true` iff `user_id.is_none()`. v0.13.0 will use it to
  enforce ADR-003's surface separation.

- **JSON-shape compatibility** preserved through
  `#[serde(skip_serializing_if = "Option::is_none")]`. A
  principal with `user_id: None` serializes exactly like the
  v0.3.x principals did — no surprise for any consumer of
  the audit log or admin-token list endpoint.

### Added in 0.12.0

A project-hygiene release. The code change is mostly mechanical
but touches a wide surface. The deliverable bundles two threads:
metadata cleanup, and a naming-debt rename that retires the
"SaaS console" framing in favor of "tenancy console."

Metadata:

- **Authorship, license, and repository metadata** in the workspace
  `Cargo.toml` and the `LICENSE` Apache-2.0 boilerplate copyright
  line are now `nabbisen` /
  `https://github.com/nabbisen/cesauth`. Per-crate `Cargo.toml`
  files inherit through `.workspace = true`.

- **Project framing language** tightened. "Tenancy" /
  "Tenancy" — including in spec references, comments, and prose
  — has been replaced with "tenancy service" or equivalent
  functional descriptions. The earlier framing was ambiguous and
  risked giving users and contributors the wrong impression about
  the project's intent. The replaced terms are concrete and
  describe what the code does.

- **`.github/`** gains community-process documents:
  - `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1.
  - `CONTRIBUTING.md` — workspace test flow, code-review
    priorities, PR checklist, what lands smoothly vs. what
    needs discussion first.
  - `ISSUE_TEMPLATE/{bug_report,feature_request,documentation}.yml`
    — structured templates with version / environment / scope
    fields.
  - `ISSUE_TEMPLATE/config.yml` — links security reports to the
    private advisory path and open questions to Discussions.

Naming-debt cleanup:

- **Module paths** renamed:
  `crates/ui/src/saas/` → `crates/ui/src/tenancy_console/`,
  `crates/worker/src/routes/admin/saas/` →
  `crates/worker/src/routes/admin/tenancy_console/`. All
  `mod`/`use` statements and re-exports updated.

- **URL prefix** renamed: `/admin/saas/*` → `/admin/tenancy/*`.
  The path *suffixes* (`tenants`, `organizations/:oid`,
  `users/:uid/role_assignments`, etc.) are unchanged.
  **Operator-visible breaking change** — any external script
  targeting the old prefix needs updating. The pre-1.0 SemVer
  caveat permits this; no compatibility-redirect routes were
  added.

- **Public types and identifiers** renamed:
  `SaasTab` → `TenancyConsoleTab`,
  `saas_frame()` → `tenancy_console_frame()`. Footer chrome
  reads "tenancy console" throughout.

- **Audit reason marker** renamed:
  `via=saas-console` → `via=tenancy-console`. Audit consumers
  that filter on this value need updating. Past audit entries
  retain the old marker (the audit log is append-only).

### Added in 0.12.1

A small buffer/follow-up release after the v0.12.0 rename. Two
threads:

- **Stale-narrative cleanup** — three docstrings carried
  forward-references and historical claims invalidated by the
  v0.12.0 rename and intervening release-slot reshuffles. Fixed
  in `crates/ui/src/tenancy_console.rs` (false "URL prefix
  preserved" claim and wrong "since v0.18.0" marker) and
  `crates/core/src/tenancy/types.rs` (`AccountType::Anonymous`
  forward-ref and `ExternalFederatedUser` forward-ref).
- **Dependency audit** — manual review of every direct
  workspace dependency. No bumps. `getrandom 0.2` and
  `rand_core 0.6` are intentionally pinned at the older line
  for wasm32-unknown-unknown + Cloudflare Workers integration;
  bumping is gated on the workers-rs ecosystem aligning on the
  corresponding 0.3 / 0.9 lines. Every other direct dep is
  current.

### Added in 0.13.0

The tenant-scoped admin surface — read pages only. The 0.11.0
ADR foundation lands as a working surface that tenant admins
can actually visit. Mutation forms come in 0.14.0, mirroring
the v0.8.0 → v0.9.0 split for the system-admin surface.

- **Domain layer** — new module `crates/core/src/tenant_admin/`
  owning the auth-gate decision logic. Pure (no network calls
  of its own), generic over the repository ports it consumes,
  host-testable. Exports:
  - **`TenantAdminContext`** — successful gate pass carries
    the resolved principal, tenant, and user.
  - **`TenantAdminFailure`** — typed failure modes
    (`NotUserBound`, `UnknownTenant`, `UnknownUser`,
    `WrongTenant`, `Unavailable`) with their HTTP status code
    semantics: `NotUserBound`/`WrongTenant` → 403,
    `UnknownTenant` → 404, `UnknownUser` → 401,
    `Unavailable` → 503.
  - **`resolve_tenant_admin(principal, slug, tenants, users)`**
    — the gate. Enforces, in order: principal is user-bound,
    slug resolves to a tenant, principal's user belongs to
    that tenant. The third invariant is the structural
    defense ADR-003 promises.

- **Port additions** — two new repository methods:
  - **`AdminTokenRepository::create_user_bound`** — mints a
    token with `admin_tokens.user_id` populated. Resulting
    `AdminPrincipal` has `user_id == Some(...)`, which
    `is_system_admin()` reads as "tenant-admin, not
    system-admin" per ADR-002. Implementations land in both
    adapters.
  - **`UserRepository::list_by_tenant`** — active
    (non-deleted) users belonging to a given tenant. Powers
    the tenant-scoped users page. Pagination intentionally
    omitted at this stage.

- **UI module** — new `crates/ui/src/tenant_admin/` mirroring
  the shape of `tenancy_console` but tenant-scoped. Per ADR-003,
  no chrome is shared between the two surfaces — the
  structural separation is the visual signal that an operator
  has switched contexts. Six pages: overview, organizations
  list + detail, users list, role-assignments drill-in,
  subscription history. All read-only.

- **Worker route layer** — `crates/worker/src/routes/admin/tenant_admin/`.
  Each handler runs the same opening sequence: bearer →
  principal, tenant-admin gate, action-level
  `check_permission` against the resolved tenant scope.
  Defense-in-depth checks for child-resource ids (`:oid`,
  `:uid`) verify they belong to the user's tenant — a tenant
  admin who types in another tenant's organization id gets a
  403, not the wrong tenant's data.

- **Six new GET routes** registered in
  `crates/worker/src/lib.rs`:
  - `/admin/t/:slug` (overview)
  - `/admin/t/:slug/organizations`
  - `/admin/t/:slug/organizations/:oid`
  - `/admin/t/:slug/users`
  - `/admin/t/:slug/users/:uid/role_assignments`
  - `/admin/t/:slug/subscription`

- **Authorization model** — system-admin surface continues to
  use `auth::ensure_role_allows(principal, AdminAction::*)`;
  tenant-scoped surface uses `check_permission(user_id,
  permission, scope)`. Both mechanisms coexist; ADR-003's
  URL-prefix separation means neither leaks across.

- **Audit emission** for cross-tenant access attempts and
  stale-principal refusals. The gate audits `WrongTenant` and
  `UnknownUser` failures as `AdminLoginFailed` events with
  reason text identifying the principal id and the attempted
  slug. `check_permission` denials are also audited.

### Added in 0.14.0

High-risk mutation forms for the tenant-scoped surface, plus
a system-admin token-mint UI. Mirrors the v0.9.0 → v0.10.0 split
for the system-admin surface: high-risk forms first, additive
ones in 0.15.0.

- **Six tenant-scoped form pairs** at `/admin/t/<slug>/...`:
  - `organizations/new` — additive, one-click. Permission:
    `ORGANIZATION_CREATE`. Plan-quota enforcement on
    `max_organizations`.
  - `organizations/:oid/status` — preview/confirm.
    Permission: `ORGANIZATION_UPDATE`. Active / Suspended /
    Deleted picker with required reason.
  - `organizations/:oid/groups/new` — additive, one-click.
    Permission: `GROUP_CREATE`.
  - `groups/:gid/delete` — preview/confirm. Permission:
    `GROUP_DELETE`. Preview counts affected role assignments
    and memberships.
  - `users/:uid/role_assignments/new` — preview/confirm.
    Permission: `ROLE_ASSIGN`. Scope picker omits System
    (per ADR-003) and pins tenant scope's scope_id to the
    current tenant. `verify_scope_in_tenant` walks storage
    to confirm Organization / Group / User scopes belong
    to this tenant before granting.
  - `role_assignments/:id/delete` — preview/confirm.
    Permission: `ROLE_UNASSIGN`.

- **System-admin token-mint UI** at
  `/admin/tenancy/users/:uid/tokens/new` (GET + POST). Three
  pages: form (role + nickname), preview/confirm, applied
  (plaintext shown ONCE with prominent warning + post-mint
  usage instructions linking to `/admin/t/<slug>/...`). Re-uses
  `mint_plaintext()` and `hash_hex()` from existing
  `console/tokens.rs`; calls
  `AdminTokenRepository::create_user_bound`. Gated on
  `ManageAdminTokens`. The applied page resolves the user's
  tenant **slug** (not id) for the URL hint — leaking the
  internal tenant id into operator-facing URLs would be a
  bug, pinned by a dedicated test.

- **Gate API change**: the v0.13.0 `gate::check_read` is now a
  thin wrapper around `gate::check_action(ctx_ta, permission,
  scope, ctx)` accepting an explicit `ScopeRef`. Mutation
  forms operate on child resources (Organization, Group) and
  need narrower scopes; reads use the wrapper for the common
  "permission at tenant scope" case.

- **Audit reason marker**: tenant-scoped mutations carry
  `via=tenant-admin,tenant=<id>` so log analyses can split
  by surface origin (system-admin entries continue to use
  `via=tenancy-console`).

- **Defense-in-depth invariants** pinned by tests: scope
  picker omits System, tenant id pinned in help text,
  preview round-trips every form field, group_delete shows
  affected counts, plaintext token HTML-escaped, applied
  page uses tenant slug not id. Total **257 tests** passing
  (+12 over v0.13.0).

### Added in 0.15.0

Additive membership forms plus affordance gating. The
tenant-scoped surface now reaches feature parity with what the
system-admin tenancy console reached at v0.10.0.

- **Six membership form pairs** at slug-relative URLs:
  - `memberships/new` + `memberships` (POST add) +
    `memberships/<uid>/delete` (confirm + apply)
  - `organizations/<oid>/memberships/...` — same shape.
  - `groups/<gid>/memberships/...` — same shape, no role
    select (group memberships don't carry a role variant).
  Add forms are one-click additive submits; remove forms use
  a confirm page → POST-with-`confirm=yes` to apply.
  Defense-in-depth: target user_id is verified to belong to
  the current tenant before any add proceeds.

- **Two new permission slugs** filling the `*_MEMBER_*`
  symmetry: `TENANT_MEMBER_ADD` (`tenant:member:add`) and
  `TENANT_MEMBER_REMOVE` (`tenant:member:remove`). The
  v0.9.0/v0.10.0 system-admin paths used the coarse
  `ManageTenancy` capability, but the tenant-scoped surface
  gates per-action via `check_permission`, so the slugs had
  to be enumerated.

- **Affordance gating** — every tenant-scoped page now
  renders mutation links/buttons conditionally:
  - **`Affordances` struct** in
    `cesauth_ui::tenant_admin::affordances` — twelve boolean
    flags, one per affordance type. `Default` is all-false
    (the safe default); `all_allowed()` is provided for tests.
  - **`gate::build_affordances`** in worker — issues a single
    `check_permissions_batch` call and maps the parallel
    `Vec<bool>` back into the struct. One D1 round-trip per
    page render.
  - **Templates** take `&Affordances` and emit conditional
    HTML for `+ New organization`, `Change status`,
    `+ New group`, `delete`, `+ Add member`, `+ Grant role`,
    `revoke`, etc.

  The route handlers behind each affordance still re-check on
  submit (defense in depth). The affordance gate is the
  operator's first signal — clicking what they can't do
  already returned 403 since v0.13.0, but they shouldn't have
  to find out by clicking.

- **`check_permissions_batch`** new in
  `cesauth_core::authz::service`. Evaluates N (permission,
  scope) queries with **one** `assignments.list_for_user`
  call + cached role lookups. The scope-walk is in-memory.
  Naive callers paying N round-trips for the same N queries
  collapse to one. Tested for equivalence to per-query
  `check_permission`.

### Added in 0.16.0

Anonymous trial — design (ADR-004) and foundation. Lays the
schema, types, repository port, and adapters for the visitor-
without-an-account flow. HTTP routes and the daily retention
sweep ship in v0.17.0 and v0.18.0 respectively.

- **ADR-004** at `docs/src/expert/adr/004-anonymous-trial-promotion.md`
  walks five design questions and picks one coherent point.
  The headline decisions: server-issued single-shot bearer
  (24h TTL, opaque, not refreshable), 7-day row retention with
  daily Cron Trigger sweep, promotion via Magic Link →
  UPDATE-in-place (preserving `User.id` so all FK references
  survive without remap).

- **Migration `0006_anonymous.sql`** adds the
  `anonymous_sessions` table. PK on `token_hash` (SHA-256 hex
  of the bearer plaintext); FK CASCADEs to `users` and
  `tenants`; indexes for the retention sweep and per-user
  revocation paths. Mirrors the `admin_tokens` shape but lives
  in a separate table so the auth surface stays narrow — an
  anonymous principal has no admin role and cannot acquire one
  through this token.

- **`cesauth_core::anonymous`** — new module with:
  - `AnonymousSession` value type. `is_expired(now_unix)`
    helper; boundary semantics (`<=` is "expired") pinned by
    test.
  - `AnonymousSessionRepository` trait: `create`, `find_by_hash`
    (hot path), `revoke_for_user` (used by the promotion path),
    `delete_expired` (used by the daily sweep).
  - `ANONYMOUS_TOKEN_TTL_SECONDS` (24h) and
    `ANONYMOUS_USER_RETENTION_SECONDS` (7d) constants. A test
    asserts the strict inequality (retention strictly outlives
    token TTL).

- **In-memory and D1 adapters** for the new port. Same shape
  as the existing `AdminTokenRepository` adapters.

- **`EventKind`** gains `AnonymousCreated`,
  `AnonymousExpired`, `AnonymousPromoted`. The variants land
  in 0.16.0 even though no code path emits them yet — the
  catalog is enum-stringly-typed and downstream audit dashboards
  treat unknown values as the type-system error they are.
  Adding the variants now spares 0.17.0 a coordinated
  audit-schema bump.

### Added in 0.17.0

Anonymous trial — HTTP routes. ADR-004 graduates from `Draft`
to `Accepted` because the design now has a working
implementation on both ends.

Two routes land:

- **`POST /api/v1/anonymous/begin`** — unauthenticated. Per-IP
  rate-limited (`anonymous_begin_per_ip:<ip>`, 20 over 5
  minutes, escalation at 10). Mints a 32-byte URL-safe-base64
  bearer + the SHA-256 hash for storage; INSERTs the `users`
  row (`account_type=Anonymous`, `email=NULL`,
  `display_name='Anon-XXXXX'`) and the `anonymous_sessions`
  row; audits `AnonymousCreated` with `via=anonymous-begin,ip=<masked>`.
  `cf-connecting-ip` populates the bucket key; IP is masked
  in audit (IPv4 last octet → 0; IPv6 → `/64` prefix).

- **`POST /api/v1/anonymous/promote`** — anonymous-bearer
  authenticated. **Two-step body shape distinguishes phases**:
  - **Step A (no `code`)** — issues a Magic Link OTP for
    the supplied email, returns `{ handle, expires_at }`.
    Reuses `magic_link::issue` + `AuthChallengeStore`; the
    OTP plaintext is logged into the audit reason
    `via=anonymous-promote,handle=<>,code=<plaintext>` so
    the existing mail-delivery pipeline picks it up
    automatically.
  - **Step B (with `code`)** — verifies OTP via
    `magic_link::verify`, runs the in-tenant email-collision
    check, UPDATEs the user row in place (id preserved,
    `email`/`email_verified` filled, `account_type` flipped
    to `HumanUser`), revokes the anonymous bearer via
    `revoke_for_user`, audits `AnonymousPromoted`.

#### Promotion ceremony walkthrough

```
                                    cesauth
                                       |
visitor       browser                  |
  |             |                      |
  |             | POST /anonymous/begin
  |             |--------------------->|  (no auth)
  |             |                      |
  |             |   201 { user_id, token, expires_at }
  |             |<---------------------|
  |             |                      |
  | "I want to claim my work"         |
  |------------>|                      |
  |             | POST /anonymous/promote
  |             | Bearer: <token>      |
  |             | { email }            |
  |             |--------------------->|
  |             |                      |
  |             |   200 { handle }     |
  |             |<---------------------|
  |             |                      |
  |       (email arrives, OTP visible)
  |<------------|                      |
  |             |                      |
  |             | POST /anonymous/promote
  |             | Bearer: <token>      |
  |             | { email, handle, code }
  |             |--------------------->|
  |             |                      |
  |             |   verify OTP ----.   |
  |             |                  |   |
  |             |   collision check
  |             |                  |   |
  |             |   UPDATE users (id preserved)
  |             |                  |   |
  |             |   revoke_for_user|   |
  |             |                  |   |
  |             |   audit AnonymousPromoted
  |             |                  |   |
  |             |   200 { user_id, promoted: true }
  |             |<-----------------'   |
  |             |                      |
  |    (visitor logs in with email
  |    via the regular OIDC flow next time)
```

#### Defense-in-depth checks

The `/promote` Step B handler enforces, in order:
- The challenge handle exists and isn't expired.
- The challenge's bound email **matches** the body email.
  Without this, an attacker who observed a handle for
  someone else's promotion attempt could splice it into
  their own request.
- The OTP verifies against the stored hash within its TTL.
- No other user owns the email in this tenant. If one does,
  the response is `email_already_registered` —
  distinguishable from `verification_failed`, so the client
  can render "log in to existing account" guidance vs
  "please re-enter the code".
- The user row's `account_type` is **still** `Anonymous`.
  A racy double-submit lands here as `not_anonymous`.

The `/promote` handler revokes the anonymous bearer
**before** the user-row UPDATE lands. The reverse order
opens a small window where the bearer authenticates a row
that's already a `human_user`. The fail-safe ordering is
pinned by an adapter-level test
(`promotion_pattern_revokes_then_user_update`) and called
out explicitly in the route handler.

#### Anonymous-bearer resolution

The handler-side helper `resolve_anonymous_bearer` extracts
`Authorization: Bearer ...`, hashes the plaintext with
SHA-256, looks up `anonymous_sessions` by hash, then runs
three checks. Any failure returns 401 with
`WWW-Authenticate: Bearer realm="cesauth"` and a JSON
`{ error: "<reason>" }` body distinguishing the cause:

- `missing_bearer` — header absent or malformed.
- `unknown_token` — hash not in `anonymous_sessions`.
- `token_expired` — `now >= session.expires_at`.
- `user_not_found` — the linked user row was already swept.
- `not_anonymous` — the user row was promoted (defense in
  depth; in practice unreachable because the promotion
  path revokes the bearer before flipping the type).

### Added in 0.18.0

Anonymous trial — daily retention sweep. ADR-004 Phase 3, the
final piece. The flow is now **feature-complete**: visitor mints
anonymous principal (0.17.0 `/begin`), optionally promotes to
`human_user` (0.17.0 `/promote`), or — if neither — gets cleaned
up by the sweep shipped here.

#### Cloudflare Workers Cron Trigger

`wrangler.toml` gains a new `[triggers]` block:

```toml
[triggers]
crons = ["0 4 * * *"]
```

This is cesauth's first Cron Trigger. Operators upgrading from
0.17.0 must add the block; the new `#[event(scheduled)]`
handler ships in the binary regardless, but Cloudflare won't
invoke it without the configuration. The schedule is daily at
04:00 UTC — late enough that the previous day's promotion-flow
stragglers have settled, early enough that operators in any
timezone see the result before their workday.

The handler in `crates/worker/src/lib.rs` dispatches on
`event.cron()`:
- `"0 4 * * *"` → `sweep::run(&env)`.
- Any other value → `console_warn!` and continue. Future
  scheduled tasks branch here.

#### Sweep handler (`crates/worker/src/sweep.rs`)

One pass:

1. Loads `Config`, computes `cutoff = now -
   ANONYMOUS_USER_RETENTION_SECONDS` (7 days).
2. `UserRepository::list_anonymous_expired(cutoff)` returns
   every row matching `account_type='anonymous' AND
   email IS NULL AND created_at < cutoff`. The
   `email IS NULL` clause structurally exempts promoted
   users.
3. For each row: emits `EventKind::AnonymousExpired` audit
   FIRST with reason
   `via=anonymous-sweep,age_secs=<n>`, then calls
   `delete_by_id`. FK CASCADEs (via 0006 + 0003) clean up
   `anonymous_sessions`, memberships, role assignments.
4. Logs one `Info` summary line:
   `"anonymous sweep complete: X/Y rows deleted"`.

#### Why audit before delete

ADR-004 §Q5 contract: `User.id` remains queryable across the
row's full lifetime, including its sweep. If the audit row
records the principal first, then the delete fails for storage
reasons, the operator's diagnostic query (residual-count check
in the runbook) shows whether the row actually disappeared —
the audit is the durable signal of intent.

#### Why list-then-delete instead of bulk DELETE

A single `DELETE FROM users WHERE ...` would be one round-trip
but gives no per-row audit. ADR-004 §Q5 is the load-bearing
constraint here. Steady-state volume (anonymous trials per day
in tens-to-hundreds) makes the extra round-trips irrelevant.

#### Best-effort failure semantics

Per-row delete failures log `Warn` and the sweep continues
with the next row. Aborting on first failure would let one
bad row block the whole sweep indefinitely; partial progress
is strictly better for storage-growth bounds. The next day's
sweep retries the survivors. Persistent failures show up as a
growing residual count via the runbook's diagnostic query.

#### `UserRepository` extensions

Two new port methods:
- `list_anonymous_expired(cutoff_unix) -> Vec<User>`.
- `delete_by_id(id) -> ()`. Idempotent; missing-row delete
  is `Ok(())` so the sweep can race with itself or with a
  concurrent admin delete without spurious errors.

Both implemented in the in-memory adapter + D1 adapter.

### Does NOT ship in v0.5.x (yet)

The CHANGELOG `Deferred` sections and `ROADMAP.md` track each item.
Headlines:

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

## Operator runbook (v0.5.x)

### Verifying dependencies before an upgrade

cesauth's threat model assumes the deployed binary's dependency
tree is free of known CVEs. The `audit.yml` GitHub Actions
workflow runs `cargo audit` on every push, every PR, and weekly
on Mondays — a green main branch means "no known CVEs as of the
last advisory-db update". For a manual upgrade, re-run the audit
locally against the latest database before deploying:

```bash
cargo install cargo-audit   # one-time per machine
cd /path/to/cesauth
cargo audit
```

If the run is clean, proceed. If it reports findings, see the
triage steps in `docs/src/deployment/production.md` (Step 7).

The dep-narrowing pattern shipped in 0.15.1 — replacing the
`jsonwebtoken` blanket `rust_crypto` feature with explicit
`ed25519-dalek` + `rand` to drop the unused `rsa` transitive —
is the model fix when a CVE lands on a dep we don't actually
call.

### Verifying the anonymous-trial retention sweep ran

v0.18.0 added a Cloudflare Workers Cron Trigger that fires the
`#[event(scheduled)]` handler in `crates/worker/src/lib.rs` at
04:00 UTC daily. The handler runs `sweep::run`, which:

1. Lists every `users` row with `account_type='anonymous' AND
   email IS NULL AND created_at < now - 7d`.
2. Emits one `AnonymousExpired` audit event per row.
3. Deletes each row (FK CASCADEs clean up
   `anonymous_sessions`, memberships, role assignments).

#### Did it run?

Cloudflare's dashboard surfaces invocation history under
**Workers & Pages → cesauth → Settings → Triggers**. Each
scheduled invocation appears with its start time and outcome.
A run that completed cleanly logs one `Info` line via the
operational log channel (visible in `wrangler tail`):

```
{"ts":...,"level":"info","category":"storage",
 "msg":"anonymous sweep complete: 12/12 rows deleted"}
```

The first number is rows actually deleted; the second is the
count surveyed. A discrepancy (`X/Y` where `X < Y`) means at
least one row's delete failed and was logged at `Warn` —
inspect the `wrangler tail` output for the per-row diagnostic.

#### Did it sweep what it should?

Run the audit-trail query for the previous day:

```sql
SELECT subject, reason, ts
  FROM audit_events
 WHERE kind = 'anonymous_expired'
   AND ts >= unixepoch() - 86400
 ORDER BY ts;
```

(Audit events live in R2; this query shape is conceptual — the
actual access uses `cesauth-do/audit_query` or the
`/admin/console/audit` page.) The reason carries
`via=anonymous-sweep,age_secs=<n>`; ages around 604_800 (7 days)
or slightly above are normal.

#### Diagnostic: residual count

To check whether anonymous rows are accumulating despite the
sweep — i.e. the sweep is not catching what it should — run:

```sql
SELECT count(*) FROM users
 WHERE account_type = 'anonymous'
   AND email IS NULL
   AND created_at < unixepoch() - 7 * 86400;
```

A healthy deployment returns `0` shortly after each sweep. A
non-zero value persisting across sweeps points at a row
that's failing to delete (storage error per row, or an
orphaned FK reference). The per-row `Warn` log is the next
place to look.

#### Manual invocation

`wrangler` does not currently expose a "run scheduled now"
button. To smoke-test the sweep without waiting for 04:00 UTC,
two options:

1. **Local**: `wrangler dev --test-scheduled` invokes the
   scheduled handler against the local dev environment. Use
   for sanity-checking the code path, not for production
   data.
2. **Production**: temporarily change the cron expression in
   `wrangler.toml` to fire imminently (e.g. `*/5 * * * *`),
   `wrangler deploy`, wait for the next 5-minute boundary,
   then revert and redeploy. Avoid running this against a
   loaded production deployment — the sweep is best-effort,
   not transactional, so a partial run leaves the operator
   with the same diagnostic state as a normal sweep.

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

The tenancy console at `/admin/tenancy/*` is the read-only HTML view of
the same data the API surface exposes. Use the same admin bearer
as the API:

```bash
# Browser: paste this URL after loading any /admin/console/* page
# (which establishes the admin bearer in the browser session via
# the existing session-cookie path), or curl with the bearer header.

curl -sS -H "Authorization: Bearer $ADMIN_API_KEY" \
     https://cesauth.example/admin/tenancy
```

Pages:

| URL                                                           | Shows                                                                     |
|---------------------------------------------------------------|---------------------------------------------------------------------------|
| `/admin/tenancy`                                                 | Counters + per-plan subscriber breakdown                                  |
| `/admin/tenancy/tenants`                                         | Every non-deleted tenant                                                  |
| `/admin/tenancy/tenants/{id}`                                    | One tenant: summary, subscription, organizations, members                 |
| `/admin/tenancy/tenants/{id}/subscription/history`               | Append-only change log for that tenant's subscription                     |
| `/admin/tenancy/organizations/{id}`                              | One organization: groups, members                                         |
| `/admin/tenancy/users/{id}/role_assignments`                     | Every role assignment held by one user, across every scope                |

Every page is gated through `AdminAction::ViewTenancy`, which is
open to **all four roles** (ReadOnly, Security, Operations, Super).
Mutating the underlying state still requires `ManageTenancy`
(Operations+), and the only way to trigger that capability today
is via the v0.7.0 JSON API or a wrangler shell. The HTML mutation
console is v0.9.0.

### Mutating tenancy state via the tenancy console (v0.9.0+)

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
plus a `via=tenancy-console` marker in the `reason` field so
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
- Spec: `cesauth-Tenancy service + authz 拡張開発指示書.md`
  in the repo root. The implementation maps section-by-section to
  §3-§5 and §16.1, §16.3, §16.6.
- Tests: `crates/adapter-test/src/tenancy/tests.rs` — the
  end-to-end flow exercises every public service function against
  the in-memory adapters; it is the runnable answer to "what does
  this thing actually do?"
