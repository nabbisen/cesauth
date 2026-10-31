//! RFC 145 cycle 2 — the twelve tenant-admin GET routes that used to
//! return the Leptos shell with no matching `app.rs` route (HTTP 200
//! rendering `<NotFound/>`).
//!
//! Each test calls the exact template function the route's GET handler
//! now renders, with the same arguments a fresh (non-error, non-preview)
//! GET supplies, and asserts a string that only that template emits —
//! never on the *absence* of a shell/NotFound marker, which an empty
//! body would also satisfy (RFC 145 cycle-2 handoff §9.1).

use super::common::*;
use cesauth_core::authz::types::{RoleAssignment, Scope};
use cesauth_core::tenancy::types::{Group, GroupParent, GroupStatus, Organization, OrganizationStatus};

fn sample_org() -> Organization {
    Organization {
        id: "o-1".into(), tenant_id: "t-acme".into(),
        slug: "engineering".into(), display_name: "Engineering".into(),
        status: OrganizationStatus::Active,
        parent_organization_id: None, created_at: 0, updated_at: 0,
    }
}

fn sample_group() -> Group {
    Group {
        id: "g-1".into(), tenant_id: "t-acme".into(),
        parent: GroupParent::Organization { organization_id: "o-1".into() },
        slug: "platform".into(), display_name: "Platform".into(),
        status: GroupStatus::Active, parent_group_id: None,
        created_at: 0, updated_at: 0,
    }
}

/// 1. `GET /admin/t/:slug/organizations/:oid` -> `organization_detail_page`.
#[test]
fn organization_detail_page_renders_the_real_page() {
    use super::super::affordances::Affordances;
    use super::super::organizations::organization_detail_page;
    let p = principal();
    let t = tenant();
    let org = sample_org();
    let html = organization_detail_page(&p, &t, &org, &[sample_group()], &Affordances::all_allowed());
    assert!(html.contains("Organization — Engineering"),
        "must render the real organization-detail title, not the shell");
    assert!(html.contains("platform"), "must list the organization's groups");
}

/// 2. `GET /admin/t/:slug/organizations/:oid/status` -> `form_page`.
#[test]
fn organization_set_status_form_renders_the_real_page() {
    use super::super::forms::organization_set_status::form_page;
    let p = principal();
    let t = tenant();
    let org = sample_org();
    let html = form_page(&p, &t, &org, None, "", None, "tok-1");
    assert!(html.contains("Organization status: engineering"),
        "must render the real status-change form title, not the shell");
    assert!(html.contains("Preview change"));
}

/// 3. `GET /admin/t/:slug/organizations/:oid/groups/new` -> `group_create_form`.
#[test]
fn group_create_form_renders_the_real_page() {
    use super::super::forms::group_create::group_create_form;
    let p = principal();
    let t = tenant();
    let org = sample_org();
    let html = group_create_form(&p, &t, &org, "", "", None, "tok-1");
    assert!(html.contains("New group in: engineering"),
        "must render the real group-create form title, not the shell");
}

/// 4. `GET /admin/t/:slug/organizations/:oid/memberships/new` -> `membership_add::for_organization`.
#[test]
fn membership_add_for_organization_renders_the_real_page() {
    use super::super::forms::membership_add::for_organization;
    let p = principal();
    let t = tenant();
    let html = for_organization(&p, &t, "o-1", "engineering", "", "", None, "tok-1");
    assert!(html.contains("Add organization member: engineering"),
        "must render the real org-membership-add form title, not the shell");
}

/// 5. `GET /admin/t/:slug/groups/:gid/memberships/new` -> `membership_add::for_group`.
#[test]
fn membership_add_for_group_renders_the_real_page() {
    use super::super::forms::membership_add::for_group;
    let p = principal();
    let t = tenant();
    let html = for_group(&p, &t, "g-1", "platform", "o-1", "", None, "tok-1");
    assert!(html.contains("Add group member: platform"),
        "must render the real group-membership-add form title, not the shell");
}

/// 6. `GET /admin/t/:slug/memberships/:uid/delete` -> `membership_remove::for_tenant`.
#[test]
fn membership_remove_for_tenant_renders_the_real_page() {
    use super::super::forms::membership_remove::for_tenant;
    let p = principal();
    let t = tenant();
    let html = for_tenant(&p, &t, "u-alice", "(unknown)", "tok-1");
    assert!(html.contains("Remove tenant member: u-alice"),
        "must render the real tenant-membership-remove confirm page, not the shell");
}

/// 7. `GET /admin/t/:slug/organizations/:oid/memberships/:uid/delete` -> `membership_remove::for_organization`.
#[test]
fn membership_remove_for_organization_renders_the_real_page() {
    use super::super::forms::membership_remove::for_organization;
    let p = principal();
    let t = tenant();
    let html = for_organization(&p, &t, "o-1", "engineering", "u-alice", "(unknown)", "tok-1");
    assert!(html.contains("Remove org member: u-alice"),
        "must render the real org-membership-remove confirm page, not the shell");
}

/// 8. `GET /admin/t/:slug/groups/:gid/memberships/:uid/delete` -> `membership_remove::for_group`.
#[test]
fn membership_remove_for_group_renders_the_real_page() {
    use super::super::forms::membership_remove::for_group;
    let p = principal();
    let t = tenant();
    let html = for_group(&p, &t, "g-1", "platform", "o-1", "u-alice", "tok-1");
    assert!(html.contains("Remove group member: u-alice"),
        "must render the real group-membership-remove confirm page, not the shell");
}

/// 9. `GET /admin/t/:slug/groups/:gid/delete` -> `group_delete::form_page`.
#[test]
fn group_delete_form_renders_the_real_page() {
    use super::super::forms::group_delete::form_page;
    let p = principal();
    let t = tenant();
    let g = sample_group();
    let html = form_page(&p, &t, &g, "engineering", "o-1", "", None, "tok-1");
    assert!(html.contains("Delete group: platform"),
        "must render the real group-delete form title, not the shell");
    assert!(html.contains("Preview delete"));
}

/// 10. `GET /admin/t/:slug/users/:uid/role_assignments` -> `role_assignments_page`.
#[test]
fn role_assignments_page_renders_the_real_page() {
    use super::super::affordances::Affordances;
    use super::super::role_assignments_page;
    use super::super::TenantUserRoleAssignmentsInput;
    let p = principal();
    let t = tenant();
    let u = user("u-alice", "Alice");
    let assignment = RoleAssignment {
        id: "a-1".into(), user_id: "u-alice".into(), role_id: "r-admin".into(),
        scope: Scope::Tenant { tenant_id: "t-acme".into() },
        granted_by: "tk-sys".into(), granted_at: 0, expires_at: None,
    };
    let labels = vec![("r-admin".to_owned(), "admin".to_owned(), "Admin".to_owned())];
    let input = TenantUserRoleAssignmentsInput {
        subject_user: &u,
        assignments: &[assignment],
        role_labels: &labels,
    };
    let html = role_assignments_page(&p, &t, &input, &Affordances::all_allowed());
    assert!(html.contains("Role assignments — Alice"),
        "must render the real role-assignments listing, not the shell");
    assert!(html.contains("Admin"));
}

/// 11. `GET /admin/t/:slug/users/:uid/role_assignments/new` -> `role_assignment_grant::grant_form`.
#[test]
fn role_assignment_grant_form_renders_the_real_page() {
    use super::super::forms::role_assignment_grant::{grant_form, GrantInput};
    let p = principal();
    let t = tenant();
    let u = user("u-alice", "Alice");
    let html = grant_form(&p, &t, &GrantInput {
        subject_user: &u, available_roles: &[],
        role_id: "", scope_type: "", scope_id: "", expires_at: "", error: None, csrf: "tok-1",
    });
    assert!(html.contains("Grant role to user: Alice"),
        "must render the real grant-role form title, not the shell");
}

/// 12. `GET /admin/t/:slug/role_assignments/:id/delete` -> `role_assignment_revoke::form_page`.
#[test]
fn role_assignment_revoke_form_renders_the_real_page() {
    use super::super::forms::role_assignment_revoke::{form_page, RevokeInput};
    let p = principal();
    let t = tenant();
    let u = user("u-alice", "Alice");
    let a = RoleAssignment {
        id: "a-1".into(), user_id: "u-alice".into(), role_id: "r-admin".into(),
        scope: Scope::Tenant { tenant_id: "t-acme".into() },
        granted_by: "tk-sys".into(), granted_at: 0, expires_at: None,
    };
    let html = form_page(&p, &t, &RevokeInput {
        assignment: &a, subject_user: &u, role_label: "Admin (admin)", error: None, csrf: "tok-1",
    });
    assert!(html.contains("Revoke role from: Alice"),
        "must render the real revoke-role form title, not the shell");
}
