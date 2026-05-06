//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn cookie_header_shape() {
    let h = set_cookie_header("abc");
    assert!(h.starts_with(&format!("{CSRF_COOKIE_NAME}=abc")));
    assert!(h.contains("HttpOnly"));
    assert!(h.contains("Secure"));
    assert!(h.contains("SameSite=Strict"));
}

#[test]
fn extract_present() {
    let h = format!("other=1; {CSRF_COOKIE_NAME}=tok; more=2");
    assert_eq!(extract_from_cookie_header(&h), Some("tok"));
}

#[test]
fn extract_missing() {
    assert_eq!(extract_from_cookie_header("other=1; more=2"), None);
}

#[test]
fn extract_does_not_match_prefix_collision() {
    // A different cookie whose name happens to start the same way
    // must not match. The `strip_prefix` + `=` check guards this.
    let h = format!("{CSRF_COOKIE_NAME}x=bad; other=1");
    assert_eq!(extract_from_cookie_header(&h), None);
}

#[test]
fn constant_time_eq_correctness() {
    assert!(constant_time_eq("abc", "abc"));
    assert!(!constant_time_eq("abc", "abd"));
    assert!(!constant_time_eq("abc", "ab"));
    assert!(!constant_time_eq("",    "a"));
    assert!(constant_time_eq("",     ""));
}

#[test]
fn verify_rejects_empty() {
    assert!(!verify("",    "cookie-val"));
    assert!(!verify("sub", ""));
    assert!(!verify("",    ""));
}

#[test]
fn verify_passes_when_equal() {
    assert!(verify("tok", "tok"));
}

#[test]
fn mint_produces_unique_nonempty_tokens() {
    let a = mint();
    let b = mint();
    assert!(!a.is_empty());
    assert_ne!(a, b);
}

// =====================================================================
// check_origin_or_referer — added in v0.24.0 as part of the CSRF
// audit. See `docs/src/expert/csrf-audit.md`.
// =====================================================================

const ORIGIN: &str = "https://cesauth.example.com";

#[test]
fn origin_check_passes_on_same_origin_origin_header() {
    assert!(check_origin_or_referer(Some(ORIGIN), None, ORIGIN));
}

#[test]
fn origin_check_fails_on_cross_origin_origin_header() {
    assert!(!check_origin_or_referer(Some("https://attacker.com"), None, ORIGIN));
}

#[test]
fn origin_check_fails_on_origin_null() {
    // Browsers send `Origin: null` for opaque origins (sandboxed
    // iframes, data: URLs). Don't accept.
    assert!(!check_origin_or_referer(Some("null"), None, ORIGIN));
}

#[test]
fn origin_check_passes_on_referer_when_origin_absent() {
    // Older browsers may suppress Origin; Referer fallback covers.
    assert!(check_origin_or_referer(
        None,
        Some(&format!("{ORIGIN}/login")),
        ORIGIN,
    ));
    // Referer with query / fragment also acceptable.
    assert!(check_origin_or_referer(None, Some(&format!("{ORIGIN}/?a=b")), ORIGIN));
    assert!(check_origin_or_referer(None, Some(&format!("{ORIGIN}/#x")),  ORIGIN));
    // Referer matching the origin exactly with no path is also OK.
    assert!(check_origin_or_referer(None, Some(ORIGIN), ORIGIN));
}

#[test]
fn origin_check_rejects_referer_prefix_attack() {
    // `attacker.com.attacker.com` shouldn't match against
    // `attacker.com` and similar variants. The boundary check
    // requires the next character after the prefix to be `/`,
    // `?`, `#`, or end-of-string.
    assert!(!check_origin_or_referer(
        None,
        // Hostname extends past expected_origin — must NOT match.
        Some("https://cesauth.example.com.attacker.com/path"),
        ORIGIN,
    ));
    // Cross-origin URL that contains expected_origin as a query
    // parameter substring must NOT match.
    assert!(!check_origin_or_referer(
        None,
        Some("https://attacker.com/?fake=https://cesauth.example.com"),
        ORIGIN,
    ));
}

#[test]
fn origin_check_does_not_fall_through_to_referer_when_origin_mismatches() {
    // If both headers are present but Origin says cross-origin,
    // we don't trust Referer to override. Otherwise an attacker
    // who controls Origin could spoof Referer.
    assert!(!check_origin_or_referer(
        Some("https://attacker.com"),
        Some(&format!("{ORIGIN}/login")),  // forged
        ORIGIN,
    ));
}

#[test]
fn origin_check_fails_on_no_headers() {
    // Real browsers send at least one of Origin or Referer on
    // POST. A complete absence is suspicious; fail closed.
    assert!(!check_origin_or_referer(None, None, ORIGIN));
}

#[test]
fn origin_check_fails_on_empty_expected_origin() {
    // Mis-configured deployment: an empty expected_origin would
    // otherwise match any Referer that happens to contain the
    // empty string at position 0 (i.e., all of them). Fail
    // closed.
    assert!(!check_origin_or_referer(Some("https://anything"), None, ""));
    assert!(!check_origin_or_referer(None, Some("https://anything/x"), ""));
}
