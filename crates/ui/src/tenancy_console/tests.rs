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
    // RFC 071: version captions removed from footers (operators identify build from wrangler/deploy logs)
    assert!(!html.contains("v0.50.2"),
        "footer must NOT contain hardcoded version string after RFC 071");
}

// ---------------------------------------------------------------------
// v0.14.0 token-mint UI.
// ---------------------------------------------------------------------

#[cfg(test)]
mod token_mint_tests {
    use super::*;
    use crate::tenancy_console::forms::token_mint::{
        applied_page, form_page, preview_page, MintInput, MintPreviewInput,
    };
    use cesauth_core::admin::types::Role as AdminRole;
    use cesauth_core::tenancy::AccountType;
    use cesauth_core::types::{User, UserStatus};

    fn admin() -> AdminPrincipal {
        AdminPrincipal {
            id: "tk-sys".into(),
            name: Some("ops".into()),
            role: AdminRole::Super,
            user_id: None,
        }
    }

    fn target_user() -> User {
        User {
            id:             "u-alice".into(),
            tenant_id:      "t-acme".into(),
            email:          Some("alice@acme.example".into()),
            email_verified: true,
            display_name:   Some("Alice".into()),
            account_type:   AccountType::HumanUser,
            status:         UserStatus::Active,
            created_at:     0,
            updated_at:     0,
        }
    }

    #[test]
    fn form_renders_radio_for_each_admin_role() {
        let html = form_page(&admin(), &MintInput {
            subject_user: &target_user(),
            role: "operations", name: "", error: None,
        });
        for r in ["read_only", "security", "operations", "super"] {
            assert!(html.contains(&format!(r#"value="{r}""#)),
                "form must offer the {r} role");
        }
    }

    #[test]
    fn preview_warns_about_one_time_plaintext_visibility() {
        // The plaintext-shown-once invariant is the most important
        // operator-facing thing. The preview must surface it
        // prominently before the operator clicks Apply.
        let html = preview_page(&admin(), &MintPreviewInput {
            subject_user: &target_user(),
            role: AdminRole::Operations,
            name: "alice's first token",
        });
        // Some version of "shown once / cannot recover" must appear.
        let warns = html.contains("once") || html.contains("only once");
        assert!(warns,
            "preview must warn that plaintext is visible only once");
        // The "stores only the hash" assurance.
        assert!(html.contains("hash"),
            "preview must explain that only the hash is stored");
    }

    #[test]
    fn applied_page_carries_plaintext_token_and_post_mint_link() {
        let plaintext = "abc123def456";
        let html = applied_page(&admin(), &target_user(), "acme",
                                AdminRole::Operations, plaintext);
        assert!(html.contains(plaintext),
            "applied page must surface the plaintext token");
        // Link back to the user's role assignments page.
        assert!(html.contains(r#"href="/admin/tenancy/users/u-alice/role_assignments""#));
        // Usage hint includes the tenant *slug*, not the tenant id.
        // This is the bug we caught and fixed during v0.14.0
        // implementation — the slug is what /admin/t/<slug>/...
        // expects, not the internal id.
        assert!(html.contains("/admin/t/acme/"),
            "post-mint usage hint must use the tenant slug, not the tenant id");
        assert!(!html.contains("/admin/t/t-acme/"),
            "must not leak the internal tenant id into the URL hint");
    }

    #[test]
    fn applied_page_html_escapes_plaintext() {
        // Defense in depth: although the plaintext is generated
        // server-side from getrandom output and never contains HTML
        // metachars in practice, the template still escapes it.
        // A regression here would be a stored-XSS vector.
        let plaintext = r#"abc<script>alert(1)</script>"#;
        let html = applied_page(&admin(), &target_user(), "acme",
                                AdminRole::Operations, plaintext);
        assert!(!html.contains("<script>alert(1)</script>"),
            "plaintext must be HTML-escaped on render");
        assert!(html.contains("&lt;script&gt;"));
    }
}

// =====================================================================
// RFC 105 — design-token unification
// =====================================================================

/// Helper: render the tenancy console frame directly with minimal args.
fn tenancy_console_frame_html() -> String {
    let p = AdminPrincipal { id: "x".into(), name: None, role: Role::Operations, user_id: None };
    tenancy_console_frame("Test", p.role, p.name.as_deref(), TenancyConsoleTab::Overview, "<p>body</p>")
}

#[test]
fn tenancy_console_frame_embeds_shared_semantic_tokens() {
    let out = tenancy_console_frame_html();
    for var in ["--success:", "--success-bg:", "--warning:", "--warning-bg:",
                "--danger:", "--danger-bg:", "--info:", "--info-bg:",
                "--ok:", "--warn:", "--critical:"] {
        assert!(out.contains(var),
            "tenancy_console frame must embed shared semantic token {var}");
    }
}

#[test]
fn tenancy_console_frame_embeds_shared_scope_tokens() {
    let out = tenancy_console_frame_html();
    for var in ["--scope-system:", "--scope-tenancy:", "--scope-tenant:"] {
        assert!(out.contains(var),
            "tenancy_console frame must embed shared scope token {var}");
    }
}

#[test]
fn tenancy_console_frame_carries_dark_mode_override() {
    let out = tenancy_console_frame_html();
    assert!(out.contains("@media (prefers-color-scheme: dark)"),
        "tenancy_console frame must carry the dark-mode override block");
}
