//! v0.45.0 — sessions bulk-revoke (ADR-012 §Q4).
//!
//! Split out from `templates/tests.rs` in v0.75.0 (test-file
//! modularization per the dev guidelines' 500-ELOC strongly-recommended
//! split threshold).

use super::super::*;
use super::super::chrome::frame;
#[allow(unused_imports)]
use cesauth_core::i18n::Locale;
#[allow(unused_imports)]
use super::common::{strip_inline_style, sample_item};

// v0.45.0 — bulk "revoke all other sessions" button (ADR-012 §Q4)
// =====================================================================

#[test]
fn sessions_page_renders_bulk_revoke_button_when_other_sessions_exist() {
    let items = vec![
        sample_item("s_current", true,  "passkey", 100),
        sample_item("s_phone",   false, "passkey", 200),
    ];
    let html = sessions_page_for(&items, "csrf-tok", "", Locale::Ja);

    // Form posts to the bulk endpoint.
    assert!(html.contains(r#"action="/me/security/sessions/revoke-others""#),
        "bulk revoke form must POST to the v0.45.0 endpoint: {html}");
    // CSRF token is wired into the form.
    assert!(html.contains(r#"value="csrf-tok""#));
    // Button label (JA).
    assert!(html.contains("他のすべてのセッションを取り消す"));
    // Confirmation copy (JA).
    assert!(html.contains("現在のセッション以外のすべての端末でサインアウトします"));
}

#[test]
fn sessions_page_renders_bulk_revoke_button_in_english() {
    let items = vec![
        sample_item("s_current", true,  "passkey", 100),
        sample_item("s_laptop",  false, "passkey", 150),
    ];
    let html = sessions_page_for(&items, "csrf", "", Locale::En);
    assert!(html.contains("Sign out all other devices"));
    assert!(html.contains("All other devices will be signed out"));
}

#[test]
fn sessions_page_hides_bulk_revoke_button_when_only_current_session() {
    // Pin the conditional: with only the current session,
    // the button is hidden. Showing it would either be a
    // no-op or accidentally revoke the current session.
    let items = vec![sample_item("s_only", true, "passkey", 100)];
    let html = sessions_page_for(&items, "csrf", "", Locale::Ja);

    assert!(!html.contains("/me/security/sessions/revoke-others"),
        "bulk endpoint form must NOT render when no other sessions: {html}");
    assert!(!html.contains("他のすべてのセッションを取り消す"));
}

#[test]
fn sessions_page_hides_bulk_revoke_button_when_empty() {
    // Empty session list — also hide. Edge case: a page
    // with no active sessions still shouldn't offer a
    // "revoke all" button.
    let html = sessions_page_for(&[], "csrf", "", Locale::Ja);
    assert!(!html.contains("/me/security/sessions/revoke-others"));
}

#[test]
fn sessions_page_shows_bulk_button_when_current_session_not_listed() {
    // Edge case from session-index drift (v0.40.0 §Q5):
    // the current session might not appear in the user's
    // listing. The page renders ALL listed sessions as
    // non-current, so the bulk button should render
    // (every listed item is "other" by definition).
    let items = vec![
        sample_item("s_phone",  false, "passkey", 100),
        sample_item("s_laptop", false, "passkey", 200),
    ];
    let html = sessions_page_for(&items, "csrf", "", Locale::En);
    assert!(html.contains("Sign out all other devices"));
}

// =====================================================================
