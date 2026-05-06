//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn pending_cookie_header_shape() {
    let h = set_pending_cookie_header("abc-123", 600);
    assert!(h.starts_with(&format!("{PENDING_COOKIE_NAME}=abc-123")));
    assert!(h.contains("HttpOnly"));
    assert!(h.contains("Secure"));
}

#[test]
fn extract_pending_handle_present() {
    let h = format!("other=1; {PENDING_COOKIE_NAME}=my-handle; more=2");
    assert_eq!(extract_pending_handle(&h), Some("my-handle"));
}

#[test]
fn url_encode_component_encodes_reserved() {
    assert_eq!(url_encode_component("a b"), "a%20b");
    assert_eq!(url_encode_component("a&b"), "a%26b");
    assert_eq!(url_encode_component("ABCxyz-._~0"), "ABCxyz-._~0");
}

// =====================================================================
// TOTP gate cookie (__Host-cesauth_totp). v0.29.0+.
// =====================================================================
//
// Pin attribute set + extraction logic. The TOTP gate cookie uses
// SameSite=Strict (not Lax like the pending cookie) because the
// TOTP prompt is post-primary-auth state — no cross-site flow
// should ever carry it. Distinct from the pending-authorize
// cookie which uses Lax to support OAuth redirect chains.

#[test]
fn totp_cookie_header_shape() {
    let h = set_totp_cookie_header("totp-abc", 300);
    assert!(h.starts_with(&format!("{TOTP_COOKIE_NAME}=totp-abc")));
    assert!(h.contains("HttpOnly"));
    assert!(h.contains("Secure"));
    assert!(h.contains("SameSite=Strict"),
        "TOTP gate cookie must be SameSite=Strict, not Lax: {h}");
    assert!(h.contains("Max-Age=300"),
        "TTL passed in must appear in Max-Age: {h}");
}

#[test]
fn totp_cookie_header_uses_host_prefix() {
    // The `__Host-` prefix guarantees Path=/, Secure, and no
    // Domain attribute. Pin so a future helper rewrite can't
    // silently drop the prefix and weaken the cookie.
    let h = set_totp_cookie_header("x", 1);
    assert!(h.starts_with("__Host-"),
        "TOTP cookie must use __Host- prefix: {h}");
    assert!(h.contains("Path=/"),
        "__Host- requires Path=/: {h}");
}

#[test]
fn clear_totp_cookie_header_zeros_max_age() {
    let h = clear_totp_cookie_header();
    assert!(h.contains("Max-Age=0"),
        "clearing must zero Max-Age: {h}");
    assert!(h.contains("SameSite=Strict"),
        "clear path must keep the same SameSite as set path: {h}");
}

#[test]
fn extract_totp_handle_present() {
    let h = format!("foo=1; {TOTP_COOKIE_NAME}=h-xyz; bar=2");
    assert_eq!(extract_totp_handle(&h), Some("h-xyz"));
}

#[test]
fn extract_totp_handle_absent_returns_none() {
    let h = format!("foo=1; {PENDING_COOKIE_NAME}=other; bar=2");
    assert_eq!(extract_totp_handle(&h), None);
}

#[test]
fn extract_totp_handle_does_not_match_pending_cookie() {
    // Pin that we don't accidentally accept the pending-authorize
    // cookie's value when the TOTP cookie is missing — these are
    // distinct scopes and confusing them would cross authentication
    // contexts.
    let h = format!("{PENDING_COOKIE_NAME}=ar-handle; nothing=else");
    assert_eq!(extract_totp_handle(&h), None);
    // And the inverse:
    let h2 = format!("{TOTP_COOKIE_NAME}=totp-handle; nothing=else");
    assert_eq!(extract_pending_handle(&h2), None);
}

// =====================================================================
// TOTP enrollment cookie (__Host-cesauth_totp_enroll). v0.29.0+.
// =====================================================================

#[test]
fn totp_enroll_cookie_header_shape() {
    let h = set_totp_enroll_cookie_header("auth-row-uuid", 900);
    assert!(h.starts_with(&format!("{TOTP_ENROLL_COOKIE_NAME}=auth-row-uuid")));
    assert!(h.contains("HttpOnly"));
    assert!(h.contains("Secure"));
    assert!(h.contains("SameSite=Strict"));
    assert!(h.contains("Max-Age=900"));
}

#[test]
fn totp_enroll_cookie_distinct_name_from_gate_cookie() {
    // Critical: the enroll cookie and gate cookie are distinct
    // breadcrumbs — the enroll one carries an authenticator row id
    // (during enrollment), the gate one carries a PendingTotp
    // challenge handle (during post-MagicLink verify). Confusing
    // them would let an enrollment cookie short-circuit the gate
    // or vice versa. Pin distinctness.
    assert_ne!(TOTP_COOKIE_NAME, TOTP_ENROLL_COOKIE_NAME);
}

#[test]
fn extract_totp_enroll_id_present() {
    let h = format!("a=1; {TOTP_ENROLL_COOKIE_NAME}=row-uuid; b=2");
    assert_eq!(extract_totp_enroll_id(&h), Some("row-uuid"));
}

#[test]
fn extract_totp_enroll_id_absent_returns_none() {
    let h = format!("a=1; {TOTP_COOKIE_NAME}=gate-handle; b=2");
    assert_eq!(extract_totp_enroll_id(&h), None);
}

#[test]
fn totp_gate_ttl_is_short() {
    // 5 minutes — short enough that an abandoned TOTP prompt
    // doesn't tie up state forever, long enough for a user
    // fumbling with their authenticator app.
    assert!(TOTP_GATE_TTL_SECS >= 60 && TOTP_GATE_TTL_SECS <= 600,
        "TOTP_GATE_TTL_SECS = {TOTP_GATE_TTL_SECS} should be 1-10 min");
}

#[test]
fn totp_enroll_ttl_is_generous() {
    // 15 minutes — generous because enrollment requires switching
    // to the authenticator app, scanning, and switching back —
    // app-context-switch cost can be substantial. Still bounded
    // so an abandoned half-enrollment doesn't pollute storage
    // (the cron sweep at v0.30.0 will prune unconfirmed rows
    // older than 24h independently of cookie TTL).
    assert!(TOTP_ENROLL_TTL_SECS >= 300 && TOTP_ENROLL_TTL_SECS <= 1800,
        "TOTP_ENROLL_TTL_SECS = {TOTP_ENROLL_TTL_SECS} should be 5-30 min");
}
