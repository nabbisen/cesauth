//! Per-page affordance gating (introduced v0.15.0).
//!
//! Templates render mutation links/buttons only when the user
//! actually has permission to perform the underlying action. A
//! tenant admin who can't create organizations sees no "New
//! organization" button — the route handler would refuse the
//! attempt anyway, but the affordance gate spares the user the
//! trip.
//!
//! Cost: one extra D1 round-trip per page render for the
//! `list_for_user` call inside `check_permissions_batch`. Per-role
//! lookups inside the batch helper are cached, so the marginal
//! cost of N affordances on one page is negligible.
//!
//! Templates take an `Affordances` reference and render conditional
//! HTML. The struct is built by the route handler from
//! `cesauth_core::authz::service::check_permissions_batch`.

/// Boolean flags for the affordances a single tenant-scoped page
/// might render. Each field is `true` if the current user is
/// allowed to perform that action *somewhere* in scope of the
/// tenant — the route handler aggregates the relevant permissions
/// before populating it.
///
/// New fields are added as new affordances ship. The struct is
/// `Default` so a new affordance defaults to "not allowed" until a
/// caller opts in — the safe default.
#[derive(Debug, Clone, Default)]
pub struct Affordances {
    pub can_create_organization:   bool,
    pub can_update_organization:   bool,
    pub can_create_group:          bool,
    pub can_delete_group:          bool,
    pub can_assign_role:           bool,
    pub can_unassign_role:         bool,
    pub can_add_tenant_member:     bool,
    pub can_remove_tenant_member:  bool,
    pub can_add_org_member:        bool,
    pub can_remove_org_member:     bool,
    pub can_add_group_member:      bool,
    pub can_remove_group_member:   bool,
}

impl Affordances {
    /// All-allowed: convenient for tests that just want to render
    /// a page with every button visible.
    pub fn all_allowed() -> Self {
        Self {
            can_create_organization:   true,
            can_update_organization:   true,
            can_create_group:          true,
            can_delete_group:          true,
            can_assign_role:           true,
            can_unassign_role:         true,
            can_add_tenant_member:     true,
            can_remove_tenant_member:  true,
            can_add_org_member:        true,
            can_remove_org_member:     true,
            can_add_group_member:      true,
            can_remove_group_member:   true,
        }
    }
}
