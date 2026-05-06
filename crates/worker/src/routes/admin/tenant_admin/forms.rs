//! Worker-side handlers for the v0.14.0 tenant-scoped mutation
//! forms. Each module owns one form and its preview/confirm flow.
//!
//! Every handler runs the same opening sequence:
//!
//! 1. **Resolve bearer → principal** (`auth::resolve_or_respond`).
//! 2. **Tenant-admin gate** (`gate::resolve_or_respond`) — enforces
//!    ADR-003's three invariants.
//! 3. **`check_permission`** at the appropriate scope:
//!    - tenant scope for organization-level operations
//!      (`ORGANIZATION_CREATE`, `ORGANIZATION_UPDATE`)
//!    - tenant scope for group-level operations as well — since
//!      tenant admins may want to manage groups across orgs in
//!      their tenant. The scope-walk picks up tenant-scoped roles
//!      that cover narrower scopes.
//!    - tenant scope for role-assignment grants/revokes.
//! 4. **Preview/confirm gating** via the `confirm` form field
//!    (additive forms skip this and submit on the first POST).
//! 5. **Audit emission** on apply.
//!
//! The handlers re-use `routes::admin::tenancy_console::forms::common`
//! for shared concerns (`parse_form`, `confirmed`, `redirect_303`).
//! `require_manage` from that module is *not* used here — the
//! tenant-scoped surface uses its own gate composition.

pub mod organization_create;
pub mod organization_set_status;
pub mod group_create;
pub mod group_delete;
pub mod role_assignment_grant;
pub mod role_assignment_revoke;
pub mod membership_add;
pub mod membership_remove;
