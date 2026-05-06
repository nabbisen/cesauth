//! Cross-module sanity check tests for the tenancy console.
//!
//! Per-template tests live next to each template. These tests assert
//! invariants across the module: that every page goes through the
//! same frame, that every drill-through link matches the route shape
//! the worker registers.

use super::frame::{tenancy_console_frame, TenancyConsoleTab};
use cesauth_core::admin::types::{AdminPrincipal, Role};

#[test]
fn frame_renders_role_badge() {
    let p = AdminPrincipal { id: "x".into(), name: None,role: Role::Operations, user_id: None };
    let html = tenancy_console_frame("Test", p.role, p.name.as_deref(), TenancyConsoleTab::Overview, "<p>body</p>");
    assert!(html.contains(r#"class="badge operations"#));
    assert!(html.contains("Operations"));
    assert!(html.contains("<p>body</p>"));
}

#[test]
fn frame_marks_active_tab_with_aria_current() {
    let p = AdminPrincipal { id: "x".into(), name: None,role: Role::ReadOnly, user_id: None };
    let html = tenancy_console_frame("Test", p.role, p.name.as_deref(), TenancyConsoleTab::Tenants, "");
    // The Tenants tab should carry aria-current="page".
    assert!(html.contains(r#"href="/admin/tenancy/tenants" aria-current="page""#));
    // Overview should NOT.
    let overview_marker = r#"href="/admin/tenancy" aria-current="page""#;
    assert!(!html.contains(overview_marker),
        "overview must not be marked current when active_tab is Tenants");
}

#[test]
fn frame_does_not_show_drill_in_tab_in_nav() {
    // UserRoleAssignments is reachable via drill-through, not nav.
    // Even when it's the active tab, it should not appear in the
    // navigation list.
    let p = AdminPrincipal { id: "x".into(), name: None,role: Role::ReadOnly, user_id: None };
    let html = tenancy_console_frame("Test", p.role, p.name.as_deref(), TenancyConsoleTab::UserRoleAssignments, "");
    // The navigation should still contain Overview + Tenants only.
    assert!(html.contains(r#"href="/admin/tenancy""#));
    assert!(html.contains(r#"href="/admin/tenancy/tenants""#));
    // Drill-in label shouldn't appear in the visible nav.
    let nav_section = html.split("<nav>").nth(1).unwrap_or("").split("</nav>").next().unwrap_or("");
    assert!(!nav_section.contains("User roles"),
        "drill-in tab must not appear in nav, got nav HTML: {nav_section}");
}

#[test]
fn frame_footer_carries_version_marker() {
    let p = AdminPrincipal { id: "x".into(), name: None,role: Role::Super, user_id: None };
    let html = tenancy_console_frame("Test", p.role, p.name.as_deref(), TenancyConsoleTab::Overview, "");
    assert!(html.contains("v0.12.0"),
        "footer should carry the version marker so operators can tell which build they're on");
}
