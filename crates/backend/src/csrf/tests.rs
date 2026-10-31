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
    let a = mint().expect("mint");
    let b = mint().expect("mint");
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

// ── RFC 011 (v0.50.3) — CSRF mint now returns Result ──────────────
#[test]
fn mint_returns_ok_with_32_char_url_safe_no_pad_base64() {
    let token = mint().expect("getrandom should succeed on test platform");
    // 24 bytes → 32 URL-safe base64 characters (no padding).
    assert_eq!(token.len(), 32, "24 bytes base64url-no-pad = 32 chars");
    assert!(
        token.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
        "token must be URL-safe base64 characters only"
    );
}

#[test]
fn mint_result_is_ok_under_normal_conditions() {
    // The Result wrapper must not be Err in any normal environment —
    // Cloudflare Workers and standard Linux both provide a working CSPRNG.
    assert!(mint().is_ok());
}

// =====================================================================
// mint_csrf / verify_csrf — RFC 152 half B stage 1, relocated here from
// `tenancy_console/forms/common.rs` by half C: both the tenancy-console/
// tenant-admin surfaces and the operator console now depend on this
// triple, so it lives next to the primitives it wraps rather than under
// a name (`tenancy_console`) that is not a neutral home for either.
// `attach_csrf_cookie` is not tested here for the same reason it never
// was in its old home: `worker::Response`/`Headers` are wasm-bindgen
// imports that panic on a non-wasm host target.
// =====================================================================

use std::collections::HashMap;

fn form_with(csrf: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("csrf".to_owned(), csrf.to_owned());
    m
}

#[test]
fn verify_csrf_rejects_a_form_with_no_token_at_all() {
    let (_, cookie) = mint_csrf().expect("getrandom must succeed in tests");
    assert!(!verify_csrf(&HashMap::new(), &cookie),
        "a form with no csrf field at all must not verify");
}

#[test]
fn verify_csrf_rejects_a_wrong_token() {
    let (_, cookie) = mint_csrf().expect("getrandom must succeed in tests");
    let form = form_with("attacker-supplied-value");
    assert!(!verify_csrf(&form, &cookie),
        "a submitted token that does not match the cookie must not verify");
}

#[test]
fn verify_csrf_accepts_a_matching_token() {
    let (token, cookie) = mint_csrf().expect("getrandom must succeed in tests");
    let form = form_with(&token);
    assert!(verify_csrf(&form, &cookie),
        "a submitted token matching the cookie must verify");
}

#[test]
fn verify_csrf_rejects_an_empty_cookie_header_even_with_a_submitted_token() {
    // A request with no Cookie header at all (first-ever visit, or a
    // cookie-stripping proxy) -- extract_from_cookie_header returns
    // None, and the empty fallback must not compare equal to an empty
    // submitted field either.
    let form = form_with("");
    assert!(!verify_csrf(&form, ""));
}

/// RFC 152 half B §3's trap: every re-render that carries a form must
/// mint a FRESH token, not reuse the one that was just spent.
#[test]
fn mint_csrf_mints_a_fresh_token_and_a_distinct_set_cookie_string_each_call() {
    let (token_a, cookie_a) = mint_csrf().expect("getrandom must succeed in tests");
    let (token_b, cookie_b) = mint_csrf().expect("getrandom must succeed in tests");
    assert_ne!(token_a, token_b,
        "two mints in a row must not produce the same token");
    assert_ne!(cookie_a, cookie_b);
    assert!(cookie_b.contains(&token_b),
        "the set-cookie string attach_csrf_cookie would append must carry the freshly minted token");
}
