//! Cross-module sanity check tests for the SaaS console.
//!
//! Per-template tests live next to each template. These tests assert
//! invariants across the module: that every page goes through the
//! same frame, that every drill-through link matches the route shape
//! the worker registers.

use super::frame::{saas_frame, SaasTab};
use cesauth_core::admin::types::{AdminPrincipal, Role};

#[test]
fn frame_renders_role_badge() {
    let p = AdminPrincipal { id: "x".into(), name: None, role: Role::Operations };
    let html = saas_frame("Test", p.role, p.name.as_deref(), SaasTab::Overview, "<p>body</p>");
    assert!(html.contains(r#"class="badge operations"#));
    assert!(html.contains("Operations"));
    assert!(html.contains("<p>body</p>"));
}

#[test]
fn frame_marks_active_tab_with_aria_current() {
    let p = AdminPrincipal { id: "x".into(), name: None, role: Role::ReadOnly };
    let html = saas_frame("Test", p.role, p.name.as_deref(), SaasTab::Tenants, "");
    // The Tenants tab should carry aria-current="page".
    assert!(html.contains(r#"href="/admin/saas/tenants" aria-current="page""#));
    // Overview should NOT.
    let overview_marker = r#"href="/admin/saas" aria-current="page""#;
    assert!(!html.contains(overview_marker),
        "overview must not be marked current when active_tab is Tenants");
}

#[test]
fn frame_does_not_show_drill_in_tab_in_nav() {
    // UserRoleAssignments is reachable via drill-through, not nav.
    // Even when it's the active tab, it should not appear in the
    // navigation list.
    let p = AdminPrincipal { id: "x".into(), name: None, role: Role::ReadOnly };
    let html = saas_frame("Test", p.role, p.name.as_deref(), SaasTab::UserRoleAssignments, "");
    // The navigation should still contain Overview + Tenants only.
    assert!(html.contains(r#"href="/admin/saas""#));
    assert!(html.contains(r#"href="/admin/saas/tenants""#));
    // Drill-in label shouldn't appear in the visible nav.
    let nav_section = html.split("<nav>").nth(1).unwrap_or("").split("</nav>").next().unwrap_or("");
    assert!(!nav_section.contains("User roles"),
        "drill-in tab must not appear in nav, got nav HTML: {nav_section}");
}

#[test]
fn frame_marks_console_as_read_only_in_footer() {
    let p = AdminPrincipal { id: "x".into(), name: None, role: Role::Super };
    let html = saas_frame("Test", p.role, p.name.as_deref(), SaasTab::Overview, "");
    assert!(html.contains("read-only"),
        "0.4.3 console must clearly mark itself as read-only");
}
