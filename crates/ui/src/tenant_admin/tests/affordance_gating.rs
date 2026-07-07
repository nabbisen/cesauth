//! Originally part of `crates/ui/src/tenant_admin/tests.rs`. Split
//! into a sibling file in v0.77.0 — test-file modularization track.

use super::common::*;            // shared fixtures (sample_tenant, sample_principal, etc.)
use super::super::*;             // reaches the tenant_admin module
use super::super::affordances::Affordances;
use super::super::frame::{tenant_admin_frame, TenantAdminTab};
#[allow(unused_imports)]
use cesauth_core::admin::types::{AdminPrincipal, Role};
#[allow(unused_imports)]
use cesauth_core::tenancy::AccountType;
#[allow(unused_imports)]
use cesauth_core::tenancy::types::{Tenant, TenantStatus};
#[allow(unused_imports)]
use cesauth_core::types::{User, UserStatus};

// v0.15.0 affordance gating.
//
// Pages render mutation links/buttons only when the current user
// holds the relevant permission. The route handler builds the
// Affordances flag struct via gate::build_affordances; the template
// reads the booleans and emits HTML conditionally. Tests pin the
// "denied → not rendered" direction because that's the security-
// relevant one — a regression that surfaces an unauthorized link
// is worse than one that hides an authorized link.
// ---------------------------------------------------------------------

#[test]
fn organizations_page_hides_create_button_when_denied() {
    let p = principal();
    let t = tenant();
    let aff = Affordances::default();  // all denied
    let html = organizations_page(&p, &t, &[], &aff);
    assert!(!html.contains("New organization"),
        "create-organization link must be hidden when permission is denied");
    assert!(!html.contains(r#"href="/admin/t/acme/organizations/new""#),
        "the destination URL must not appear either");
}

#[test]
fn organizations_page_shows_create_button_when_allowed() {
    let p = principal();
    let t = tenant();
    let aff = Affordances {
        can_create_organization: true,
        ..Affordances::default()
    };
    let html = organizations_page(&p, &t, &[], &aff);
    assert!(html.contains(r#"href="/admin/t/acme/organizations/new""#),
        "create-organization link must render when permission is allowed");
}

#[test]
fn organization_detail_page_hides_all_actions_when_all_denied() {
    use cesauth_core::tenancy::types::{Organization, OrganizationStatus};
    let p = principal();
    let t = tenant();
    let org = Organization {
        id: "o-1".into(), tenant_id: "t-acme".into(),
        slug: "engineering".into(), display_name: "Engineering".into(),
        status: OrganizationStatus::Active,
        parent_organization_id: None, created_at: 0, updated_at: 0,
    };
    let aff = Affordances::default();
    let html = super::super::organizations::organization_detail_page(&p, &t, &org, &[], &aff);
    // None of the action links/buttons should appear.
    assert!(!html.contains(r#"organizations/o-1/status""#),
        "Change-status link must be hidden");
    assert!(!html.contains(r#"organizations/o-1/groups/new""#),
        "New-group link must be hidden");
    assert!(!html.contains(r#"organizations/o-1/memberships/new""#),
        "Add-member link must be hidden");
}

#[test]
fn overview_page_hides_quick_actions_when_all_denied() {
    let p = principal();
    let t = tenant();
    let counts = TenantOverviewCounts {
        organizations: 0, users: 1, groups: 0, current_plan: None,
    };
    let aff = Affordances::default();
    let html = overview_page(&p, &t, &counts, &aff);
    assert!(!html.contains("Quick actions"),
        "the Quick actions section header should not render at all when no buttons would be shown");
    assert!(!html.contains("New organization"));
    assert!(!html.contains("Add tenant member"));
}

#[test]
fn overview_page_shows_only_allowed_quick_actions() {
    // Granular check: if can_create_organization is true but
    // can_add_tenant_member is false, only the first button
    // appears. This pins the per-flag independence.
    let p = principal();
    let t = tenant();
    let counts = TenantOverviewCounts {
        organizations: 0, users: 1, groups: 0, current_plan: None,
    };
    let aff = Affordances {
        can_create_organization: true,
        can_add_tenant_member:   false,
        ..Affordances::default()
    };
    let html = overview_page(&p, &t, &counts, &aff);
    assert!(html.contains("New organization"));
    assert!(!html.contains("Add tenant member"),
        "denied affordance must not render even when sibling is allowed");
}

#[test]
fn role_assignments_page_hides_grant_button_when_denied() {
    use crate::tenant_admin::role_assignments::TenantUserRoleAssignmentsInput;
    let p = principal();
    let t = tenant();
    let u = user("u-alice", "Alice");
    let input = TenantUserRoleAssignmentsInput {
        subject_user: &u,
        assignments:  &[],
        role_labels:  &[],
    };
    let aff = Affordances::default();
    let html = crate::tenant_admin::role_assignments_page(&p, &t, &input, &aff);
    assert!(!html.contains("Grant role"),
        "Grant role button must be hidden when can_assign_role = false");
}

#[test]
fn role_assignments_page_shows_grant_button_when_allowed() {
    use crate::tenant_admin::role_assignments::TenantUserRoleAssignmentsInput;
    let p = principal();
    let t = tenant();
    let u = user("u-alice", "Alice");
    let input = TenantUserRoleAssignmentsInput {
        subject_user: &u,
        assignments:  &[],
        role_labels:  &[],
    };
    let aff = Affordances {
        can_assign_role: true,
        ..Affordances::default()
    };
    let html = crate::tenant_admin::role_assignments_page(&p, &t, &input, &aff);
    assert!(html.contains(r#"href="/admin/t/acme/users/u-alice/role_assignments/new""#),
        "Grant role link must render with the right href when allowed");
}

#[test]
fn role_assignments_page_revoke_link_is_only_for_existing_assignments_when_allowed() {
    // Even with can_unassign_role = true, an empty assignment list
    // must not produce orphan revoke links — this defends against
    // a future refactor that emits revoke buttons unconditionally.
    use crate::tenant_admin::role_assignments::TenantUserRoleAssignmentsInput;
    let p = principal();
    let t = tenant();
    let u = user("u-alice", "Alice");
    let input = TenantUserRoleAssignmentsInput {
        subject_user: &u,
        assignments:  &[],
        role_labels:  &[],
    };
    let aff = Affordances {
        can_unassign_role: true,
        ..Affordances::default()
    };
    let html = crate::tenant_admin::role_assignments_page(&p, &t, &input, &aff);
    assert!(!html.contains("revoke"),
        "no assignments → no revoke links, even when can_unassign_role = true");
}

#[test]
fn affordances_default_is_all_denied() {
    // The all-denied default is the safe initial state. If a future
    // refactor flips a flag to `true` by default, every page that
    // uses Default::default() in a test path would suddenly render
    // affordances the user shouldn't have. Pin it down.
    let aff = Affordances::default();
    assert!(!aff.can_create_organization);
    assert!(!aff.can_update_organization);
    assert!(!aff.can_create_group);
    assert!(!aff.can_delete_group);
    assert!(!aff.can_assign_role);
    assert!(!aff.can_unassign_role);
    assert!(!aff.can_add_tenant_member);
    assert!(!aff.can_remove_tenant_member);
    assert!(!aff.can_add_org_member);
    assert!(!aff.can_remove_org_member);
    assert!(!aff.can_add_group_member);
    assert!(!aff.can_remove_group_member);
}

#[test]
fn affordances_all_allowed_is_all_true() {
    let aff = Affordances::all_allowed();
    assert!(aff.can_create_organization);
    assert!(aff.can_update_organization);
    assert!(aff.can_create_group);
    assert!(aff.can_delete_group);
    assert!(aff.can_assign_role);
    assert!(aff.can_unassign_role);
    assert!(aff.can_add_tenant_member);
    assert!(aff.can_remove_tenant_member);
    assert!(aff.can_add_org_member);
    assert!(aff.can_remove_org_member);
    assert!(aff.can_add_group_member);
    assert!(aff.can_remove_group_member);
}

// ---------------------------------------------------------------------
