//! v0.35.0 — sessions_page rendering + i18n (EN locale).
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

// v0.35.0 — sessions_page rendering tests
// =====================================================================

#[test]
fn sessions_page_empty_renders_zero_state_message() {
    let html = sessions_page(&[], "csrf-token", "");
    assert!(html.contains("アクティブなセッションはありません"),
        "empty list must render the zero-state message");
    // No flash banner div is present (the page-frame may carry
    // CSS rules for `.flash--success` etc., so only check for
    // the rendered banner element, not its style classes).
    assert!(!html.contains(r##"role="status""##),
        "no flash banner element should render when flash_html is empty");
}

#[test]
fn sessions_page_renders_one_row_per_session() {
    let items = vec![
        SessionListItem {
            session_id:    "uuid-aaa-111".into(),
            auth_method:   "passkey".into(),
            client_id:     "web-app".into(),
            created_at:    1_700_000_000,
            last_seen_at:  1_700_000_500,
            is_current:    false,
        },
        SessionListItem {
            session_id:    "uuid-bbb-222".into(),
            auth_method:   "magic_link".into(),
            client_id:     "web-app".into(),
            created_at:    1_700_001_000,
            last_seen_at:  1_700_001_000,
            is_current:    true,
        },
    ];
    let html = sessions_page(&items, "csrf-token", "");

    // Both sessions surface — short ids in the body.
    assert!(html.contains("uuid-aaa"));
    assert!(html.contains("uuid-bbb"));
    // Auth method labels translate.
    assert!(html.contains("パスキー"));
    assert!(html.contains("Magic Link"));
}

#[test]
fn sessions_page_current_session_is_marked_and_button_disabled() {
    // Pin the v0.35.0 invariant: the current session shows the
    // "this device" badge and its revoke button is disabled.
    // Revoking your own session via this page would cause the
    // next request to bounce to /login — surprising UX. The
    // user should use the explicit logout flow instead.
    let items = vec![SessionListItem {
        session_id:    "uuid-current".into(),
        auth_method:   "passkey".into(),
        client_id:     "web".into(),
        created_at:    1_700_000_000,
        last_seen_at:  1_700_000_000,
        is_current:    true,
    }];
    let html = sessions_page(&items, "csrf-token", "");
    assert!(html.contains("この端末"),
        "current session must surface the 'this device' badge");
    assert!(html.contains(r#"disabled"#),
        "current session's revoke button must be disabled");
    // The form action for the current row should not appear —
    // only the disabled <button> chrome.
    assert!(!html.contains("/me/security/sessions/uuid-current/revoke"),
        "current session must NOT carry a revoke form");
}

#[test]
fn sessions_page_non_current_session_carries_revoke_form_with_csrf() {
    let items = vec![SessionListItem {
        session_id:    "uuid-other".into(),
        auth_method:   "passkey".into(),
        client_id:     "web".into(),
        created_at:    1_700_000_000,
        last_seen_at:  1_700_000_000,
        is_current:    false,
    }];
    let html = sessions_page(&items, "csrf-abc", "");
    assert!(html.contains("/me/security/sessions/uuid-other/revoke"),
        "non-current session must carry a POST form action");
    assert!(html.contains(r#"value="csrf-abc""#),
        "CSRF token must be embedded in the form");
    assert!(html.contains(">取り消す<"),
        "non-current session's button must be the 取り消す action label");
}

#[test]
fn sessions_page_unknown_auth_method_falls_back_to_unknown_label() {
    // Defensive: if the audit-method enum grows a variant the
    // renderer doesn't know about, the page must still render
    // (don't 500). The label falls back to the 不明 fallback.
    let items = vec![SessionListItem {
        session_id:    "uuid".into(),
        auth_method:   "future-method-not-yet-defined".into(),
        client_id:     "x".into(),
        created_at:    1_700_000_000,
        last_seen_at:  1_700_000_000,
        is_current:    false,
    }];
    let html = sessions_page(&items, "csrf", "");
    assert!(html.contains("不明"),
        "unknown auth_method must render the 不明 fallback");
}

#[test]
fn sessions_page_splices_flash_html_into_layout() {
    // The flash chrome lives in `frame_with_flash`; sessions_page
    // hands it through. Pin that the supplied flash HTML actually
    // appears in the rendered page.
    let flash_html = r##"<div class="flash flash--success">セッションを取り消しました</div>"##;
    let html = sessions_page(&[], "csrf", flash_html);
    assert!(html.contains("セッションを取り消しました"),
        "flash content must reach the rendered page");
    assert!(html.contains("flash--success"));
}

#[test]
fn sessions_page_session_id_is_html_escaped() {
    // session_id values come from UUIDv4 in production but the
    // template must still escape them defensively in case a
    // future change sources them from anywhere user-influenceable.
    let items = vec![SessionListItem {
        session_id:    "<script>alert(1)</script>".into(),
        auth_method:   "passkey".into(),
        client_id:     "x".into(),
        created_at:    1_700_000_000,
        last_seen_at:  1_700_000_000,
        is_current:    false,
    }];
    let html = sessions_page(&items, "csrf", "");
    assert!(!html.contains("<script>alert(1)</script>"),
        "session_id with HTML payload must be escaped");
    assert!(html.contains("&lt;script&gt;"),
        "escaped form must appear");
}

// =====================================================================
// v0.35.0 sessions_page tests
// =====================================================================

#[test]
fn sessions_page_empty_renders_no_active_message() {
    let html = sessions_page(&[], "csrf", "");
    assert!(html.contains("アクティブなセッションはありません"),
        "empty state must surface a localized empty message");
}

#[test]
fn sessions_page_lists_each_session() {
    let items = vec![
        sample_item("s1-uuid", true,  "passkey",    100),
        sample_item("s2-uuid", false, "magic_link", 200),
    ];
    let html = sessions_page(&items, "csrf", "");

    // Each session_id appears (in shortened form for display
    // and full form in the form action URL).
    assert!(html.contains("s1-uuid"));
    assert!(html.contains("s2-uuid"));

    // Auth methods get their localized label.
    assert!(html.contains("パスキー"));
    assert!(html.contains("Magic Link"));
}

#[test]
fn sessions_page_disables_current_session_revoke() {
    // The "current device" must not show an active revoke
    // button — that would just self-log-the-user-out and be
    // confusing UX.
    let items = vec![sample_item("current", true, "passkey", 100)];
    let html = sessions_page(&items, "csrf", "");

    // The badge for the current device.
    assert!(html.contains("この端末"),
        "current session must render a 'this device' badge");
    // The disabled button.
    assert!(html.contains("disabled"));
    assert!(html.contains("使用中"));
    // No POST form for the current session.
    assert!(!html.contains(r#"action="/me/security/sessions/current/revoke""#),
        "current session must NOT have a revoke POST form");
}

#[test]
fn sessions_page_renders_revoke_form_for_other_sessions() {
    let items = vec![sample_item("other-id", false, "passkey", 100)];
    let html = sessions_page(&items, "csrf-token", "");

    // POST form with the right action.
    assert!(html.contains(r#"action="/me/security/sessions/other-id/revoke""#));
    // CSRF token.
    assert!(html.contains(r#"value="csrf-token""#));
    // The submit button.
    assert!(html.contains("取り消す"));
}

#[test]
fn sessions_page_csrf_token_html_escaped() {
    // If the CSRF token ever carried HTML-meaningful characters
    // (it shouldn't; we mint base64-shaped tokens), the form
    // must escape it. Pin with a deliberately-dangerous token.
    let items = vec![sample_item("s1", false, "passkey", 100)];
    let html = sessions_page(&items, r#"<script>x</script>"#, "");
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains("<script>x</script>"));
}

#[test]
fn sessions_page_splices_flash_block() {
    let flash = r##"<div class="flash flash--success">test-flash</div>"##;
    let html = sessions_page(&[], "csrf", flash);
    assert!(html.contains("test-flash"),
        "flash block must be spliced into the rendered page");
}

#[test]
fn sessions_page_links_back_to_security_center() {
    let html = sessions_page(&[], "csrf", "");
    assert!(html.contains(r#"href="/me/security""#),
        "page must offer a way back to the Security Center");
}

// =====================================================================
// v0.36.0 i18n: sessions_page renders English under Locale::En
// =====================================================================


#[test]
fn sessions_page_for_en_renders_english_chrome() {
    let html = sessions_page_for(&[], "csrf", "", Locale::En);
    // English chrome strings are present.
    assert!(html.contains("Active sessions"));
    assert!(html.contains("No active sessions."));
    assert!(html.contains("Back to Security Center"));
    // No Japanese chrome leaking through.
    assert!(!html.contains("アクティブなセッション"),
        "EN rendering must not carry the JA title");
    assert!(!html.contains("セキュリティ センター"),
        "EN rendering must not carry the JA back-link text");
}

#[test]
fn sessions_page_for_en_renders_english_method_labels() {
    let items = vec![
        sample_item("s1", false, "passkey",    100),
        sample_item("s2", false, "magic_link", 200),
        sample_item("s3", false, "admin",      300),
    ];
    let html = sessions_page_for(&items, "csrf", "", Locale::En);

    assert!(html.contains("Passkey"));
    assert!(html.contains("Magic Link")); // brand string, same in both locales
    assert!(html.contains("Admin sign-in"));
    // No Japanese method labels.
    assert!(!html.contains("パスキー"));
    assert!(!html.contains("管理者ログイン"));
}

#[test]
fn sessions_page_for_en_uses_english_revoke_button() {
    let items = vec![sample_item("s1", false, "passkey", 100)];
    let html = sessions_page_for(&items, "csrf", "", Locale::En);
    assert!(html.contains(">Revoke<"));
    assert!(!html.contains(">取り消す<"));
}

#[test]
fn sessions_page_for_en_uses_english_current_badge() {
    let items = vec![sample_item("s1", true, "passkey", 100)];
    let html = sessions_page_for(&items, "csrf", "", Locale::En);
    assert!(html.contains("This device"));
    assert!(html.contains(">Current<"));
    assert!(!html.contains("この端末"));
    assert!(!html.contains("使用中"));
}

#[test]
fn sessions_page_default_shorthand_still_renders_japanese() {
    // Backward compatibility: the locale-less shorthand
    // continues to produce the pre-i18n rendering. This is
    // important because existing handlers (and tests)
    // haven't all been migrated to thread a Locale.
    let html = sessions_page(&[], "csrf", "");
    assert!(html.contains("アクティブなセッション"));
    assert!(html.contains("アクティブなセッションはありません"));
}

// =====================================================================
