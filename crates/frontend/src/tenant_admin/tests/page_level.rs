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
