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

// ── RFC 071 — footer version hygiene ─────────────────────────────────────

#[test]
fn tenant_admin_frame_footer_has_no_version_caption() {
    let out = tenant_admin_frame(
        "Test", "test-slug", "Test Corp",
        cesauth_core::admin::types::Role::ReadOnly,
        None,
        TenantAdminTab::Overview,
        "",
    );
    // should not contain version captions like "v0.50.2 (mutations...)"
    assert!(!out.contains("v0.50"), "tenant_admin footer must not contain v0.50.x");
    assert!(!out.contains("v0.4."),  "tenant_admin footer must not contain v0.4.x");
}

// ── RFC 073 — scope badge standardization ────────────────────────────────

#[test]
fn tenant_admin_frame_renders_scope_badge_with_correct_class() {
    use cesauth_core::admin::types::Role;
    use super::super::frame::TenantAdminTab;
    let out = super::super::frame::tenant_admin_frame(
        "Users", "acme", "Acme Corp",
        Role::Operations, None,
        TenantAdminTab::Users, "",
    );
    assert!(out.contains("scope-badge scope-tenant"),
        "tenant admin frame must carry scope-badge scope-tenant class");
}

#[test]
fn tenant_admin_scope_badge_has_aria_label() {
    use cesauth_core::admin::types::Role;
    use super::super::frame::TenantAdminTab;
    let out = super::super::frame::tenant_admin_frame(
        "Users", "acme", "Acme Corp",
        Role::ReadOnly, None,
        TenantAdminTab::Overview, "",
    );
    assert!(out.contains("aria-label="),
        "scope badge must have aria-label for screen reader");
}

#[test]
fn tenant_admin_scope_badge_css_has_scope_tenant_color_rule() {
    use cesauth_core::admin::types::Role;
    use super::super::frame::TenantAdminTab;
    let out = super::super::frame::tenant_admin_frame(
        "Test", "slug", "Name",
        Role::ReadOnly, None,
        TenantAdminTab::Overview, "",
    );
    assert!(out.contains("scope-tenant"),
        "frame CSS must define scope-tenant color rule");
}

// ── RFC 078 — Tenant admin UI i18n tests ─────────────────────────────────

#[test]
fn invitations_page_renders_ja_section_title() {
    use super::super::invitations::invitations_page;
    let p = principal();
    let t = tenant();
    let html = invitations_page(&p, &t, &[], 1_700_000_000);
    assert!(html.contains("ユーザーを招待する"),
        "invite section title must be in JA");
    assert!(html.contains("招待を送信"),
        "submit button must be in JA");
}

#[test]
fn invitations_page_empty_state_ja() {
    use super::super::invitations::invitations_page;
    let p = principal();
    let t = tenant();
    let html = invitations_page(&p, &t, &[], 1_700_000_000);
    assert!(html.contains("保留中の招待はありません"),
        "empty state must be in JA");
}

#[test]
fn invitations_page_pending_badge_ja() {
    use super::super::invitations::invitations_page;
    use cesauth_core::invitation::Invitation;
    let p = principal();
    let t = tenant();
    let inv = Invitation {
        id:          "inv-1".into(),
        tenant_id:   "t-acme".into(),
        email:       "user@example.com".into(),
        role:        "tenant_member".into(),
        issued_by:   "admin".into(),
        issued_at:   1_700_000_000,
        expires_at:  1_700_100_000,
        accepted_at: None,
        accepted_by: None,
        revoked_at:  None,
        revoked_by:  None,
    };
    let html = invitations_page(&p, &t, &[inv], 1_700_000_000);
    assert!(html.contains("user@example.com"),
        "email must appear in row");
    assert!(html.contains("保留中"),
        "pending status must be in JA");
    assert!(html.contains("取り消す"),
        "revoke button must be in JA");
}

#[test]
fn deletion_requests_page_empty_state_ja() {
    use super::super::deletions::deletion_requests_page;
    let p = principal();
    let t = tenant();
    let html = deletion_requests_page(&p, &t, &[], 1_700_000_000);
    assert!(html.contains("保留中の削除リクエストはありません"),
        "empty state must be in JA");
    assert!(html.contains("削除リクエスト"),
        "page title must be in JA");
}

#[test]
fn deletion_requests_page_grace_period_notice_ja() {
    use super::super::deletions::deletion_requests_page;
    let p = principal();
    let t = tenant();
    let html = deletion_requests_page(&p, &t, &[], 1_700_000_000);
    assert!(html.contains("削除リクエストはスケジュール日以降に実行されます"),
        "grace period notice must be in JA");
}

#[test]
fn deletion_requests_page_no_hardcoded_english() {
    use super::super::invitations::invitations_page;
    use super::super::deletions::deletion_requests_page;
    let p = principal();
    let t = tenant();
    let inv_html = invitations_page(&p, &t, &[], 1_700_000_000);
    let del_html = deletion_requests_page(&p, &t, &[], 1_700_000_000);
    // Must not have old hardcoded English strings
    assert!(!inv_html.contains("Invite a user"),
        "invitations page must not have hardcoded English");
    assert!(!inv_html.contains("No pending invitations"),
        "invitations page must not have hardcoded English");
    assert!(!del_html.contains("No pending deletion requests"),
        "deletion page must not have hardcoded English");
    assert!(!del_html.contains("Execute now"),
        "deletion page must not have hardcoded English");
}

// =====================================================================
