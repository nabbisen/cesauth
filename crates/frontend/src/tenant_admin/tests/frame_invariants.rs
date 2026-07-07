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
    // RFC 071: version captions removed from footers
    assert!(!html.contains("v0.50.2"),
        "frame footer must NOT contain hardcoded version after RFC 071");
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
