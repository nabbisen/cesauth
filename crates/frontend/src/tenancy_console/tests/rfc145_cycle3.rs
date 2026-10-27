//! RFC 145 cycle 3 — the twenty-one `/admin/tenancy/*` GET routes that
//! used to return the Leptos shell with no matching `app.rs` route (HTTP
//! 200 rendering `<NotFound/>`), plus route 10
//! (`/admin/tenancy/tenants/new`), which was shadowed by `:tid` instead.
//!
//! Each test calls the exact template function the route's GET handler
//! now renders, with the same arguments a fresh (non-error, non-preview)
//! GET supplies, and asserts a string that only that template emits —
//! never on the *absence* of a shell/NotFound marker (handoff §8.0/§8.1:
//! these are template-level tests, not response-level; the wiring guard
//! is E3 and §3's new gate, not these).

use cesauth_core::admin::types::{AdminPrincipal, Role};
use cesauth_core::authz::types::{RoleAssignment, Scope};
use cesauth_core::billing::types::{Plan, Subscription, SubscriptionHistoryEntry, SubscriptionLifecycle, SubscriptionStatus};
use cesauth_core::tenancy::types::{Group, GroupParent, GroupStatus, Organization, OrganizationStatus, Tenant, TenantStatus};
use cesauth_core::types::{User, UserStatus};

fn p() -> AdminPrincipal {
    AdminPrincipal { id: "tk-1".into(), name: Some("alice".into()), role: Role::Operations, user_id: None }
}

fn tenant() -> Tenant {
    Tenant {
        id: "t-acme".into(), slug: "acme".into(), display_name: "Acme Corporation".into(),
        status: TenantStatus::Active, created_at: 0, updated_at: 0,
    }
}

fn org() -> Organization {
    Organization {
        id: "o-1".into(), tenant_id: "t-acme".into(),
        slug: "engineering".into(), display_name: "Engineering".into(),
        status: OrganizationStatus::Active, parent_organization_id: None,
        created_at: 0, updated_at: 0,
    }
}

fn group() -> Group {
    Group {
        id: "g-1".into(), tenant_id: "t-acme".into(),
        parent: GroupParent::Organization { organization_id: "o-1".into() },
        slug: "platform".into(), display_name: "Platform".into(),
        status: GroupStatus::Active, parent_group_id: None,
        created_at: 0, updated_at: 0,
    }
}

fn user(id: &str, name: &str) -> User {
    User {
        id: id.into(), tenant_id: "t-acme".into(),
        email: Some(format!("{name}@acme.example")), email_verified: true,
        display_name: Some(name.into()), account_type: cesauth_core::tenancy::AccountType::HumanUser,
        status: UserStatus::Active, created_at: 0, updated_at: 0,
    }
}

fn subscription() -> Subscription {
    Subscription {
        id: "s-1".into(), tenant_id: "t-acme".into(), plan_id: "plan-pro".into(),
        lifecycle: SubscriptionLifecycle::Paid, status: SubscriptionStatus::Active,
        started_at: 0, current_period_end: None, trial_ends_at: None,
        status_changed_at: 0, updated_at: 0,
    }
}

fn plan(id: &str, slug: &str, name: &str) -> Plan {
    Plan {
        id: id.into(), slug: slug.into(), display_name: name.into(),
        active: true, features: vec![], quotas: vec![],
        price_description: None, created_at: 0, updated_at: 0,
    }
}

/// 1. `GET /admin/tenancy/organizations/:oid` -> `organization_detail_page`.
#[test]
fn organization_detail_page_renders_the_real_page() {
    use super::super::organizations::{organization_detail_page, OrganizationDetailInput};
    let o = org();
    let html = organization_detail_page(&p(), &OrganizationDetailInput {
        organization: &o, groups: &[group()], members: &[],
    });
    assert!(html.contains("Organization: engineering"),
        "must render the real organization-detail title, not the shell");
    assert!(html.contains("platform"), "must list the organization's groups");
}

/// 2. `GET /admin/tenancy/organizations/:oid/status` -> `form_page`.
#[test]
fn organization_set_status_form_renders_the_real_page() {
    use super::super::forms::organization_set_status::form_page;
    let html = form_page(&p(), &org(), None, "", None);
    assert!(html.contains("Organization status: engineering"),
        "must render the real status-change form title, not the shell");
}

/// 3. `GET /admin/tenancy/organizations/:oid/groups/new` -> `group_create::for_organization`.
#[test]
fn group_create_for_organization_renders_the_real_page() {
    use super::super::forms::group_create::for_organization;
    let html = for_organization(&p(), "o-1", "engineering", "", "", None);
    assert!(html.contains("New group in organization: engineering"),
        "must render the real group-create form title, not the shell");
}

/// 4. `GET /admin/tenancy/organizations/:oid/memberships/new` -> `membership_add::for_organization`.
#[test]
fn membership_add_for_organization_renders_the_real_page() {
    use super::super::forms::membership_add::for_organization;
    let html = for_organization(&p(), "o-1", "engineering", "", "", None);
    assert!(html.contains("Add organization member: engineering"),
        "must render the real org-membership-add form title, not the shell");
}

/// 5. `GET /admin/tenancy/organizations/:oid/memberships/:uid/delete` -> `membership_remove::for_organization`.
#[test]
fn membership_remove_for_organization_renders_the_real_page() {
    use super::super::forms::membership_remove::for_organization;
    let html = for_organization(&p(), "o-1", "engineering", "u-alice", "(unknown)");
    assert!(html.contains("Remove org member: u-alice"),
        "must render the real org-membership-remove confirm page, not the shell");
}

/// 6. `GET /admin/tenancy/groups/:gid/delete` -> `group_delete::confirm_page`.
#[test]
fn group_delete_confirm_page_renders_the_real_page() {
    use super::super::forms::group_delete::confirm_page;
    let html = confirm_page(&p(), &group());
    assert!(html.contains("Delete group: platform"),
        "must render the real group-delete confirm title, not the shell");
}

/// 7. `GET /admin/tenancy/groups/:gid/memberships/new` -> `membership_add::for_group`.
#[test]
fn membership_add_for_group_renders_the_real_page() {
    use super::super::forms::membership_add::for_group;
    let html = for_group(&p(), "g-1", "platform", "t-acme", "", None);
    assert!(html.contains("Add group member: platform"),
        "must render the real group-membership-add form title, not the shell");
}

/// 8. `GET /admin/tenancy/groups/:gid/memberships/:uid/delete` -> `membership_remove::for_group`.
#[test]
fn membership_remove_for_group_renders_the_real_page() {
    use super::super::forms::membership_remove::for_group;
    let html = for_group(&p(), "g-1", "platform", "t-acme", "u-alice");
    assert!(html.contains("Remove group member: u-alice"),
        "must render the real group-membership-remove confirm page, not the shell");
}

/// 9. `GET /admin/tenancy/role_assignments/:id/delete` -> `role_assignment_delete::confirm_page`.
#[test]
fn role_assignment_delete_confirm_page_renders_the_real_page() {
    use super::super::forms::role_assignment_delete::confirm_page;
    let u = user("u-alice", "Alice");
    let a = RoleAssignment {
        id: "a-1".into(), user_id: "u-alice".into(), role_id: "r-admin".into(),
        scope: Scope::Tenant { tenant_id: "t-acme".into() },
        granted_by: "tk-sys".into(), granted_at: 0, expires_at: None,
    };
    let html = confirm_page(&p(), &u.id, &a, "Admin (admin)");
    assert!(html.contains("Revoke role assignment"),
        "must render the real revoke-assignment confirm title, not the shell");
    assert!(html.contains("u-alice"));
}

/// 10. `GET /admin/tenancy/tenants/new` -> `tenant_create::tenant_create_form`.
/// The shadowed route (handoff §2) — wiring it removes the symptom
/// (the client router never sees this path once the server renders it).
#[test]
fn tenant_create_form_renders_the_real_page() {
    use super::super::forms::tenant_create::tenant_create_form;
    let html = tenant_create_form(&p(), "", "", "", None);
    assert!(html.contains("New tenant"),
        "must render the real tenant-create form, not the shadowed tenant-detail page");
}

/// 11. `GET /admin/tenancy/tenants/:tid/status` -> `tenant_set_status::form_page`.
#[test]
fn tenant_set_status_form_renders_the_real_page() {
    use super::super::forms::tenant_set_status::form_page;
    let html = form_page(&p(), &tenant(), None, "", None);
    assert!(html.contains("Tenant status: acme"),
        "must render the real tenant-status form title, not the shell");
}

/// 12. `GET /admin/tenancy/tenants/:tid/groups/new` -> `group_create::for_tenant`.
#[test]
fn group_create_for_tenant_renders_the_real_page() {
    use super::super::forms::group_create::for_tenant;
    let html = for_tenant(&p(), "t-acme", "acme", "", "", None);
    assert!(html.contains("New group in tenant: acme"),
        "must render the real group-create form title, not the shell");
}

/// 13. `GET /admin/tenancy/tenants/:tid/memberships/new` -> `membership_add::for_tenant`.
#[test]
fn membership_add_for_tenant_renders_the_real_page() {
    use super::super::forms::membership_add::for_tenant;
    let html = for_tenant(&p(), "t-acme", "acme", "", "member", None);
    assert!(html.contains("Add tenant member: acme"),
        "must render the real tenant-membership-add form title, not the shell");
    // RFC 145 cycle 3: this template's action used to point at the
    // unregistered `.../memberships` path (missing `/new`); confirm the
    // fix landed, not just the wiring.
    assert!(html.contains(r#"action="/admin/tenancy/tenants/t-acme/memberships/new""#),
        "form must post to the route lib.rs actually registers");
}

/// 14. `GET /admin/tenancy/tenants/:tid/memberships/:uid/delete` -> `membership_remove::for_tenant`.
#[test]
fn membership_remove_for_tenant_renders_the_real_page() {
    use super::super::forms::membership_remove::for_tenant;
    let html = for_tenant(&p(), "t-acme", "acme", "u-alice", "(unknown)");
    assert!(html.contains("Remove tenant member: u-alice"),
        "must render the real tenant-membership-remove confirm page, not the shell");
}

/// 15. `GET /admin/tenancy/tenants/:tid/organizations/new` -> `organization_create::organization_create_form`.
#[test]
fn organization_create_form_renders_the_real_page() {
    use super::super::forms::organization_create::organization_create_form;
    let html = organization_create_form(&p(), &tenant(), "", "", None);
    assert!(html.contains("New organization in: acme"),
        "must render the real organization-create form title, not the shell");
}

/// 16. `GET /admin/tenancy/tenants/:tid/subscription/history` -> `subscription_history_page`.
#[test]
fn subscription_history_page_renders_the_real_page() {
    use super::super::subscription_history_page;
    let entry = SubscriptionHistoryEntry {
        id: "h-1".into(), subscription_id: "s-1".into(), tenant_id: "t-acme".into(),
        event: "plan_changed".into(), from_plan_id: Some("plan-free".into()),
        to_plan_id: Some("plan-pro".into()), from_status: None, to_status: None,
        actor: "tk-1".into(), occurred_at: 0,
    };
    let html = subscription_history_page(&p(), "t-acme", "acme", &[entry]);
    assert!(html.contains("Subscription history: acme"),
        "must render the real subscription-history title, not the shell");
}

/// 17. `GET /admin/tenancy/tenants/:tid/subscription/plan` -> `subscription_set_plan::form_page`.
#[test]
fn subscription_set_plan_form_renders_the_real_page() {
    use super::super::forms::subscription_set_plan::form_page;
    let cur_plan = plan("plan-pro", "pro", "Pro");
    let html = form_page(&p(), "t-acme", "acme", &subscription(), Some(&cur_plan), &[], "", None);
    assert!(html.contains("Change plan: acme"),
        "must render the real plan-change form title, not the shell");
}

/// 18. `GET /admin/tenancy/tenants/:tid/subscription/status` -> `subscription_set_status::form_page`.
#[test]
fn subscription_set_status_form_renders_the_real_page() {
    use super::super::forms::subscription_set_status::form_page;
    let html = form_page(&p(), "t-acme", "acme", &subscription(), None, None);
    assert!(html.contains("Subscription status: acme"),
        "must render the real subscription-status form title, not the shell");
}

/// 19. `GET /admin/tenancy/users/:uid/role_assignments` -> `user_role_assignments_page`.
#[test]
fn user_role_assignments_page_renders_the_real_page() {
    use super::super::role_assignments::UserRoleAssignmentsInput;
    use super::super::user_role_assignments_page;
    let a = RoleAssignment {
        id: "a-1".into(), user_id: "u-alice".into(), role_id: "r-admin".into(),
        scope: Scope::Tenant { tenant_id: "t-acme".into() },
        granted_by: "tk-sys".into(), granted_at: 0, expires_at: None,
    };
    let labels = vec![("r-admin".to_owned(), "admin".to_owned(), "Admin".to_owned())];
    let input = UserRoleAssignmentsInput { user_id: "u-alice", assignments: &[a], role_labels: &labels };
    let html = user_role_assignments_page(&p(), &input);
    assert!(html.contains("Role assignments: user u-alice"),
        "must render the real role-assignments listing, not the shell");
    assert!(html.contains("Admin"));
}

/// 20. `GET /admin/tenancy/users/:uid/role_assignments/new` -> `role_assignment_create::role_assignment_create_form`.
#[test]
fn role_assignment_create_form_renders_the_real_page() {
    use super::super::forms::role_assignment_create::{role_assignment_create_form, RoleAssignmentCreateInput};
    let html = role_assignment_create_form(&p(), &RoleAssignmentCreateInput {
        user_id: "u-alice", available_roles: &[],
        role_id: "", scope_type: "", scope_id: "", expires_at: "", error: None,
    });
    assert!(html.contains("Grant role to user: u-alice"),
        "must render the real grant-role form title, not the shell");
}

/// 21. `GET /admin/tenancy/users/:uid/tokens/new` -> `token_mint::form_page`.
#[test]
fn token_mint_form_renders_the_real_page() {
    use super::super::forms::token_mint::{form_page, MintInput};
    let u = user("u-alice", "Alice");
    let html = form_page(&p(), &MintInput { subject_user: &u, role: "", name: "", error: None });
    assert!(html.contains("Mint user-bound admin token: Alice"),
        "must render the real token-mint form title, not the shell");
}
