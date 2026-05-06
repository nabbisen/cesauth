//! Cross-module sanity-check tests for the tenant-admin surface.
//!
//! Per-template tests live next to each template. These tests assert
//! invariants across the module: that every page goes through
//! `tenant_admin_frame` and includes the tenant identity, that nav
//! links are slug-relative, and that drill-in tabs don't bleed into
//! the nav.

use super::affordances::Affordances;
use super::frame::{tenant_admin_frame, TenantAdminTab};
use super::overview::{TenantOverviewCounts, overview_page};
use super::organizations::organizations_page;
use super::users::users_page;
use cesauth_core::admin::types::{AdminPrincipal, Role};
use cesauth_core::tenancy::AccountType;
use cesauth_core::tenancy::types::{Tenant, TenantStatus};
use cesauth_core::types::{User, UserStatus};

// ---------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------

fn principal() -> AdminPrincipal {
    AdminPrincipal {
        id:      "tk-1".into(),
        name:    Some("alice".into()),
        role:    Role::Operations,
        user_id: Some("u-alice".into()),
    }
}

fn tenant() -> Tenant {
    Tenant {
        id:           "t-acme".into(),
        slug:         "acme".into(),
        display_name: "Acme Corporation".into(),
        status:       TenantStatus::Active,
        created_at:   0,
        updated_at:   0,
    }
}

fn user(id: &str, name: &str) -> User {
    User {
        id:             id.into(),
        tenant_id:      "t-acme".into(),
        email:          Some(format!("{name}@acme.example")),
        email_verified: true,
        display_name:   Some(name.into()),
        account_type:   AccountType::HumanUser,
        status:         UserStatus::Active,
        created_at:     0,
        updated_at:     0,
    }
}

// ---------------------------------------------------------------------
// Frame invariants.
// ---------------------------------------------------------------------

#[test]
fn frame_renders_tenant_slug_and_display_name_in_header() {
    let html = tenant_admin_frame(
        "Test", "acme", "Acme Corporation",
        Role::Operations, Some("alice"),
        TenantAdminTab::Overview, "<p>body</p>",
    );
    // Tenant identity is in the header — operators reading
    // screenshots should never wonder which tenant they're seeing.
    assert!(html.contains("Acme Corporation"));
    assert!(html.contains("acme"));
    assert!(html.contains("<p>body</p>"));
}

#[test]
fn frame_marks_active_tab_with_aria_current() {
    let html = tenant_admin_frame(
        "Test", "acme", "Acme",
        Role::ReadOnly, None,
        TenantAdminTab::Users, "",
    );
    assert!(html.contains(r#"href="/admin/t/acme/users" aria-current="page""#));
    // Overview should NOT be marked.
    assert!(!html.contains(r#"href="/admin/t/acme" aria-current="page""#));
}

#[test]
fn frame_nav_links_are_slug_relative() {
    // Every nav href should start with /admin/t/<slug>/. This is
    // the structural piece of ADR-001's "tenant identity in URL"
    // promise. If a future refactor accidentally builds
    // /admin/tenancy/... links here, that's a tenant-boundary
    // bug.
    let html = tenant_admin_frame(
        "Test", "acme", "Acme",
        Role::Super, None,
        TenantAdminTab::Overview, "",
    );
    // System-admin URL prefix must NOT appear in the nav.
    let nav = html.split("<nav>").nth(1).unwrap_or("")
                  .split("</nav>").next().unwrap_or("");
    assert!(!nav.contains("/admin/tenancy"),
        "tenant-admin nav must not link to system-admin surface, got: {nav}");
    // Every visible href must include the slug.
    for tab in ["/admin/t/acme", "/admin/t/acme/organizations",
                "/admin/t/acme/users", "/admin/t/acme/subscription"] {
        assert!(nav.contains(tab),
            "expected nav to contain {tab}, got: {nav}");
    }
}

#[test]
fn frame_does_not_show_drill_in_tab_in_nav() {
    // UserRoleAssignments and OrganizationDetail are drill-in
    // destinations, not nav entries. Even when active, they
    // should not appear in the nav bar.
    let html = tenant_admin_frame(
        "Test", "acme", "Acme",
        Role::ReadOnly, None,
        TenantAdminTab::UserRoleAssignments, "",
    );
    let nav = html.split("<nav>").nth(1).unwrap_or("")
                  .split("</nav>").next().unwrap_or("");
    assert!(!nav.contains("User roles"),
        "drill-in tab must not appear in nav, got: {nav}");
    assert!(!nav.contains("Organization "),
        "drill-in tab must not appear in nav, got: {nav}");
}

#[test]
fn frame_footer_carries_version_marker() {
    let html = tenant_admin_frame(
        "Test", "acme", "Acme",
        Role::Super, None,
        TenantAdminTab::Overview, "",
    );
    assert!(html.contains("v0.42.0"),
        "frame footer must mark the current release; \
         operators reading the page need a version anchor");
}

#[test]
fn frame_chrome_visually_distinct_from_system_admin_surface() {
    // Per ADR-003, the two surfaces share no chrome. We pin the
    // distinct header background-color string here so a future
    // refactor can't accidentally reuse the system-admin colors
    // (which would dilute the visual signal that this is a
    // different surface).
    let html = tenant_admin_frame(
        "Test", "acme", "Acme",
        Role::Operations, None,
        TenantAdminTab::Overview, "",
    );
    // Tenant-admin uses a deeper navy. System-admin uses #2c3e50.
    assert!(html.contains("#1e3a5f"),
        "tenant-admin frame must use its own header color; \
         sharing the system-admin color undermines ADR-003");
    // The system-admin header color must not appear in this
    // frame's CSS.
    assert!(!html.contains("background: #2c3e50"),
        "tenant-admin frame must not reuse system-admin chrome");
}

// ---------------------------------------------------------------------
// Page-level tests.
// ---------------------------------------------------------------------

#[test]
fn overview_page_shows_tenant_card_and_counters() {
    let p      = principal();
    let t      = tenant();
    let counts = TenantOverviewCounts {
        organizations: 3,
        users:         12,
        groups:        5,
        current_plan:  Some("starter".into()),
    };
    let html = overview_page(&p, &t, &counts, &Affordances::all_allowed());

    // Tenant card.
    assert!(html.contains("Acme Corporation"));
    assert!(html.contains(r#"<code>acme</code>"#));
    assert!(html.contains(r#"<span class="badge ok">active</span>"#));

    // Counters.
    assert!(html.contains(">3<"));   // organizations
    assert!(html.contains(">12<"));  // users
    assert!(html.contains(">5<"));   // groups
    assert!(html.contains(r#"<code>starter</code>"#));
}

#[test]
fn overview_page_handles_no_subscription() {
    let p      = principal();
    let t      = tenant();
    let counts = TenantOverviewCounts {
        organizations: 0,
        users:         1,
        groups:        0,
        current_plan:  None,
    };
    let html = overview_page(&p, &t, &counts, &Affordances::all_allowed());
    assert!(html.contains("none"),
        "current_plan = None must render as 'none', not as blank");
}

#[test]
fn organizations_page_renders_drill_through_links() {
    use cesauth_core::tenancy::types::{Organization, OrganizationStatus};
    let p = principal();
    let t = tenant();
    let orgs = vec![Organization {
        id: "o-1".into(),
        tenant_id: "t-acme".into(),
        slug: "engineering".into(),
        display_name: "Engineering".into(),
        status: OrganizationStatus::Active,
        parent_organization_id: None,
        created_at: 0,
        updated_at: 0,
    }];
    let html = organizations_page(&p, &t, &orgs, &Affordances::all_allowed());
    // Drill-through must include the tenant slug.
    assert!(html.contains(r#"href="/admin/t/acme/organizations/o-1""#));
    assert!(html.contains("Engineering"));
}

#[test]
fn organizations_page_shows_empty_state() {
    let p = principal();
    let t = tenant();
    let html = organizations_page(&p, &t, &[], &Affordances::all_allowed());
    assert!(html.contains("No organizations"),
        "empty list must render an explicit empty state");
}

#[test]
fn users_page_renders_drill_through_to_role_assignments() {
    let p = principal();
    let t = tenant();
    let users = vec![user("u-1", "Alice"), user("u-2", "Bob")];
    let html = users_page(&p, &t, &users);
    assert!(html.contains(r#"href="/admin/t/acme/users/u-1/role_assignments""#));
    assert!(html.contains(r#"href="/admin/t/acme/users/u-2/role_assignments""#));
    assert!(html.contains("Alice"));
    assert!(html.contains("Bob"));
}

#[test]
fn users_page_renders_account_type_label() {
    let p = principal();
    let t = tenant();
    let mut u = user("u-1", "Alice");
    u.account_type = AccountType::ServiceAccount;
    let html = users_page(&p, &t, &[u]);
    assert!(html.contains("service account"),
        "non-default account type must render its human label");
}

#[test]
fn html_escapes_user_supplied_values_in_tenant_chrome() {
    // Defense in depth: even though slugs / display names come
    // from validated repository rows, we still escape on render.
    let mut t = tenant();
    t.display_name = "<script>alert('x')</script>".into();
    let html = tenant_admin_frame(
        "Test", &t.slug, &t.display_name,
        Role::ReadOnly, None,
        TenantAdminTab::Overview, "",
    );
    assert!(!html.contains("<script>alert"),
        "display_name must be HTML-escaped in chrome");
    assert!(html.contains("&lt;script&gt;"),
        "escaped form must render");
}

// ---------------------------------------------------------------------
// v0.14.0 mutation form templates.
//
// These tests pin down the design invariants that protect ADR-003
// at the *template* level — the worker handlers also enforce the
// same invariants server-side, but if a future template refactor
// dropped one of these checks, an attacker who could cause a form
// to be rendered with attacker-controlled inputs would notice
// before the server did.
// ---------------------------------------------------------------------

#[test]
fn organization_create_form_action_is_slug_relative() {
    use super::forms::organization_create::organization_create_form;
    let p = principal();
    let t = tenant();
    let html = organization_create_form(&p, &t, "", "", None);
    assert!(html.contains(r#"action="/admin/t/acme/organizations/new""#),
        "form action must build off the URL slug, not the tenant id");
    // Critical: must not target the system-admin surface.
    assert!(!html.contains("/admin/tenancy/"),
        "tenant-admin form action must not point at system-admin URLs");
}

#[test]
fn organization_create_form_renders_error_message() {
    use super::forms::organization_create::organization_create_form;
    let p = principal();
    let t = tenant();
    let html = organization_create_form(
        &p, &t, "bad slug", "name",
        Some("Slug already taken in this tenant"),
    );
    assert!(html.contains("Slug already taken in this tenant"));
    // Sticky values on re-render after a failed submit.
    assert!(html.contains(r#"value="bad slug""#));
}

#[test]
fn organization_set_status_preview_carries_confirm_yes() {
    use super::forms::organization_set_status::preview_page;
    use cesauth_core::tenancy::types::{Organization, OrganizationStatus};
    let p = principal();
    let t = tenant();
    let org = Organization {
        id: "o-1".into(), tenant_id: "t-acme".into(),
        slug: "engineering".into(), display_name: "Engineering".into(),
        status: OrganizationStatus::Active,
        parent_organization_id: None, created_at: 0, updated_at: 0,
    };
    let html = preview_page(&p, &t, &org, OrganizationStatus::Suspended,
                            "billing past due");
    // The hidden confirm=yes is what flips the next POST from
    // "render preview" to "apply". Without it, an Apply button
    // click would just re-render the preview indefinitely.
    assert!(html.contains(r#"name="confirm" value="yes""#),
        "preview page must carry the confirm=yes hidden field");
    // Diff visible.
    assert!(html.contains("active"));
    assert!(html.contains("suspended"));
    // Reason persisted into the apply form's hidden field.
    assert!(html.contains("billing past due"));
}

#[test]
fn group_delete_preview_shows_affected_counts() {
    use super::forms::group_delete::preview_page;
    use cesauth_core::tenancy::types::{Group, GroupParent};
    let p = principal();
    let t = tenant();
    let g = Group {
        id: "g-1".into(), tenant_id: "t-acme".into(),
        parent: GroupParent::Organization { organization_id: "o-1".into() },
        slug: "platform".into(), display_name: "Platform".into(),
        status: cesauth_core::tenancy::types::GroupStatus::Active,
        parent_group_id: None,
        created_at: 0, updated_at: 0,
    };
    let html = preview_page(&p, &t, &g, "o-1", "wind down team", 7, 12);
    // Counts must be visible — that's the whole point of the
    // diff page for a destructive operation.
    assert!(html.contains(">7<"));
    assert!(html.contains(">12<"));
    assert!(html.contains("wind down team"));
    assert!(html.contains(r#"name="confirm" value="yes""#));
}

#[test]
fn role_assignment_grant_form_omits_system_scope() {
    // ADR-003: tenant admins cannot grant cesauth-wide roles.
    // The scope picker must not even present that option.
    use super::forms::role_assignment_grant::{grant_form, GrantInput};
    let p = principal();
    let t = tenant();
    let u = user("u-alice", "Alice");
    let html = grant_form(&p, &t, &GrantInput {
        subject_user: &u,
        available_roles: &[],
        role_id: "", scope_type: "tenant", scope_id: "", expires_at: "",
        error: None,
    });
    // Critical: no `value="system"` radio button.
    assert!(!html.contains(r#"value="system""#),
        "scope picker must not present the system option to tenant admins");
    // Tenant scope must be present.
    assert!(html.contains(r#"value="tenant""#));
    assert!(html.contains(r#"value="organization""#));
    assert!(html.contains(r#"value="group""#));
}

#[test]
fn role_assignment_grant_form_pins_tenant_id_in_help_text() {
    // The tenant scope's scope_id is forced server-side. The form
    // tells the operator that explicitly so they're not confused
    // when typing in a different value has no effect.
    use super::forms::role_assignment_grant::{grant_form, GrantInput};
    let p = principal();
    let t = tenant();
    let u = user("u-alice", "Alice");
    let html = grant_form(&p, &t, &GrantInput {
        subject_user: &u,
        available_roles: &[],
        role_id: "", scope_type: "tenant", scope_id: "", expires_at: "",
        error: None,
    });
    // The tenant id appears next to the tenant-scope radio so
    // the operator sees what scope_id will be used.
    assert!(html.contains("t-acme"),
        "tenant scope label must show the tenant id that will be used");
}

#[test]
fn role_assignment_grant_preview_carries_all_form_fields_for_apply() {
    // The preview's hidden form must round-trip every field
    // the apply path needs. If it dropped, say, expires_at, the
    // applied grant would silently differ from the previewed one.
    use super::forms::role_assignment_grant::{preview_page, PreviewInput};
    let p = principal();
    let t = tenant();
    let u = user("u-alice", "Alice");
    let html = preview_page(&p, &t,
        "r-admin", "tenant", "", "1735689600",
        &PreviewInput {
            subject_user: &u,
            role_label:   "Admin (admin)",
            scope_label:  "tenant t-acme",
            expires_at:   Some("1735689600"),
        },
    );
    assert!(html.contains(r#"name="role_id" value="r-admin""#));
    assert!(html.contains(r#"name="scope_type" value="tenant""#));
    assert!(html.contains(r#"name="expires_at" value="1735689600""#));
    assert!(html.contains(r#"name="confirm" value="yes""#));
}

#[test]
fn role_assignment_revoke_preview_round_trips_assignment_id() {
    use super::forms::role_assignment_revoke::{preview_page, RevokeInput};
    use cesauth_core::authz::types::{RoleAssignment, Scope};
    let p = principal();
    let t = tenant();
    let u = user("u-alice", "Alice");
    let a = RoleAssignment {
        id:         "a-1".into(),
        user_id:    "u-alice".into(),
        role_id:    "r-admin".into(),
        scope:      Scope::Tenant { tenant_id: "t-acme".into() },
        granted_by: "tk-sys".into(),
        granted_at: 0,
        expires_at: None,
    };
    let html = preview_page(&p, &t, &RevokeInput {
        assignment: &a, subject_user: &u, role_label: "Admin (admin)",
        error: None,
    });
    // Apply path posts to /admin/t/acme/role_assignments/a-1/delete.
    assert!(html.contains(r#"action="/admin/t/acme/role_assignments/a-1/delete""#));
    assert!(html.contains(r#"name="confirm" value="yes""#));
}

// ---------------------------------------------------------------------
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
    let html = super::organizations::organization_detail_page(&p, &t, &org, &[], &aff);
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
// v0.15.0 membership form templates.
// ---------------------------------------------------------------------

#[test]
fn membership_add_tenant_form_is_slug_relative() {
    use crate::tenant_admin::forms::membership_add::for_tenant;
    let p = principal();
    let t = tenant();
    let html = for_tenant(&p, &t, "", "member", None);
    assert!(html.contains(r#"action="/admin/t/acme/memberships""#),
        "form action must be slug-relative");
    assert!(!html.contains("/admin/tenancy/"),
        "must not point at the system-admin surface");
}

#[test]
fn membership_add_tenant_form_renders_three_role_options() {
    use crate::tenant_admin::forms::membership_add::for_tenant;
    let p = principal();
    let t = tenant();
    let html = for_tenant(&p, &t, "", "member", None);
    assert!(html.contains(r#"value="owner""#));
    assert!(html.contains(r#"value="admin""#));
    assert!(html.contains(r#"value="member""#));
}

#[test]
fn membership_add_organization_form_renders_two_role_options() {
    use crate::tenant_admin::forms::membership_add::for_organization;
    let p = principal();
    let t = tenant();
    let html = for_organization(&p, &t, "o-eng", "engineering", "", "member", None);
    assert!(html.contains(r#"value="admin""#));
    assert!(html.contains(r#"value="member""#));
    // Org-level memberships do NOT have an Owner role.
    assert!(!html.contains(r#"value="owner""#),
        "organization memberships have no Owner variant");
}

#[test]
fn membership_remove_carries_confirm_yes() {
    use crate::tenant_admin::forms::membership_remove::for_tenant;
    let p = principal();
    let t = tenant();
    let html = for_tenant(&p, &t, "u-bob", "member");
    // Apply path is gated by confirm=yes, same convention as the
    // 0.14.0 high-risk forms. Without it, a stray POST with no
    // body would silently apply.
    assert!(html.contains(r#"name="confirm" value="yes""#),
        "confirm page must include confirm=yes hidden field");
    assert!(html.contains(r#"action="/admin/t/acme/memberships/u-bob/delete""#));
}
