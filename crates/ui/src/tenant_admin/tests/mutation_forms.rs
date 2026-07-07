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
    use super::super::forms::organization_create::organization_create_form;
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
    use super::super::forms::organization_create::organization_create_form;
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
    use super::super::forms::organization_set_status::preview_page;
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
    use super::super::forms::group_delete::preview_page;
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
    use super::super::forms::role_assignment_grant::{grant_form, GrantInput};
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
    use super::super::forms::role_assignment_grant::{grant_form, GrantInput};
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
    use super::super::forms::role_assignment_grant::{preview_page, PreviewInput};
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
    use super::super::forms::role_assignment_revoke::{preview_page, RevokeInput};
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
