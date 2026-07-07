//! Unit tests for the auth helper module — focused on the
//! v0.31.0 P1-A `next` parameter pieces (validate_next_path,
//! decode_and_validate_next, cookie helpers, login_next
//! extraction). The session-resolving paths (`resolve_or_redirect`)
//! need a `worker::Env` and are exercised by handler integration
//! tests in PR-9.

use super::*;

// ---------------------------------------------------------------------
// validate_next_path — allowlist policy
// ---------------------------------------------------------------------

#[test]
fn allows_root_path() {
    assert_eq!(validate_next_path("/"), Some("/"));
}

#[test]
fn allows_me_root() {
    assert_eq!(validate_next_path("/me"), Some("/me"));
}

#[test]
fn allows_security_center() {
    assert_eq!(validate_next_path("/me/security"), Some("/me/security"));
}

#[test]
fn allows_totp_subpaths() {
    assert_eq!(validate_next_path("/me/security/totp/enroll"), Some("/me/security/totp/enroll"));
    assert_eq!(validate_next_path("/me/security/totp/disable"), Some("/me/security/totp/disable"));
    assert_eq!(validate_next_path("/me/security/totp/verify"), Some("/me/security/totp/verify"));
}

#[test]
fn allows_query_string_on_allowlisted_path() {
    assert_eq!(
        validate_next_path("/me/security?foo=bar"),
        Some("/me/security?foo=bar"),
    );
    assert_eq!(
        validate_next_path("/me/security?utm_source=email&id=42"),
        Some("/me/security?utm_source=email&id=42"),
    );
}

// ---------------------------------------------------------------------
// validate_next_path — open-redirect rejections
// ---------------------------------------------------------------------

#[test]
fn rejects_protocol_relative_url() {
    // `//evil.com/foo` would redirect off-origin if the browser
    // appended it to the deployment scheme. Pin reject — this
    // is THE classic open-redirect vector.
    assert_eq!(validate_next_path("//evil.com/foo"), None);
    assert_eq!(validate_next_path("//"), None);
}

#[test]
fn rejects_https_absolute_url() {
    assert_eq!(validate_next_path("https://evil.com/foo"), None);
    assert_eq!(validate_next_path("http://evil.com"), None);
}

#[test]
fn rejects_javascript_scheme() {
    // XSS via redirect. Even if the browser refused to follow
    // a `Location: javascript:...`, the client-side router
    // could pick it up. Defense in depth.
    assert_eq!(validate_next_path("javascript:alert(1)"), None);
}

#[test]
fn rejects_data_scheme() {
    assert_eq!(validate_next_path("data:text/html,<script>alert(1)</script>"), None);
}

#[test]
fn rejects_mailto_scheme() {
    // Less obviously dangerous, but no legitimate use as a
    // post-login landing target.
    assert_eq!(validate_next_path("mailto:victim@example.com"), None);
}

#[test]
fn rejects_windows_unc_path() {
    // UNC paths might tunnel through a permissive URL parser
    // on Windows clients. Pin reject.
    assert_eq!(validate_next_path("\\\\evil.com\\share"), None);
}

#[test]
fn rejects_admin_paths() {
    // Admin uses bearer-token auth, NOT cookie auth. Bouncing
    // a freshly-cookie-authenticated user to /admin/* would
    // mix auth contexts. Plus admin shouldn't be a UX target
    // for end-user flows.
    assert_eq!(validate_next_path("/admin/console"), None);
    assert_eq!(validate_next_path("/admin/tenancy"), None);
    assert_eq!(validate_next_path("/admin/t/acme/users"), None);
}

#[test]
fn rejects_api_paths() {
    // JSON API endpoints aren't browser landing targets.
    assert_eq!(validate_next_path("/api/v1/tenants"), None);
    assert_eq!(validate_next_path("/api/v1/anonymous/begin"), None);
}

#[test]
fn rejects_oauth_endpoints() {
    // Auth-flow endpoints aren't direct user navigation targets.
    assert_eq!(validate_next_path("/authorize"), None);
    assert_eq!(validate_next_path("/token"), None);
    assert_eq!(validate_next_path("/revoke"), None);
}

#[test]
fn rejects_login_self_loop() {
    // Bouncing back to /login after sign-in completes is a UX
    // hole. Reject so the fallback (`/`) takes over.
    assert_eq!(validate_next_path("/login"), None);
    assert_eq!(validate_next_path("/logout"), None);
}

#[test]
fn rejects_dev_only_paths() {
    assert_eq!(validate_next_path("/__dev/audit"), None);
    assert_eq!(validate_next_path("/__dev/stage-auth-code/x"), None);
}

#[test]
fn rejects_machine_endpoints() {
    assert_eq!(validate_next_path("/jwks.json"), None);
    assert_eq!(validate_next_path("/.well-known/openid-configuration"), None);
}

#[test]
fn rejects_webauthn_and_magic_link_endpoints() {
    // POST-only auth handlers, not GET landing targets.
    assert_eq!(validate_next_path("/webauthn/authenticate/start"), None);
    assert_eq!(validate_next_path("/magic-link/request"), None);
}

#[test]
fn rejects_paths_not_starting_with_slash() {
    assert_eq!(validate_next_path("me/security"), None);
    assert_eq!(validate_next_path("foo"), None);
}

#[test]
fn rejects_empty_string() {
    assert_eq!(validate_next_path(""), None);
}

#[test]
fn me_prefix_only_matches_with_trailing_slash_or_exact() {
    // `/menu` should NOT match `/me` allowlist — pin so a future
    // refactor doesn't widen the prefix accidentally to a
    // `starts_with("/me")` check.
    assert_eq!(validate_next_path("/menu"), None);
    assert_eq!(validate_next_path("/method"), None);
    assert_eq!(validate_next_path("/me-something"), None);
}

// ---------------------------------------------------------------------
// decode_and_validate_next — the round-trip from cookie value
// ---------------------------------------------------------------------

#[test]
fn decode_round_trips_a_valid_path() {
    let encoded = URL_SAFE_NO_PAD.encode(b"/me/security");
    assert_eq!(decode_and_validate_next(&encoded), Some("/me/security".to_owned()));
}

#[test]
fn decode_handles_path_with_query() {
    let encoded = URL_SAFE_NO_PAD.encode(b"/me/security?tab=totp");
    assert_eq!(
        decode_and_validate_next(&encoded),
        Some("/me/security?tab=totp".to_owned()),
    );
}

#[test]
fn decode_rejects_disallowed_path_after_decoding() {
    // Even properly base64-encoded, a disallowed path is rejected.
    // Defense in depth: the encoding step in build_next_query
    // should prevent this from being set in the first place,
    // but the consumer must validate too.
    let encoded = URL_SAFE_NO_PAD.encode(b"/admin/console");
    assert_eq!(decode_and_validate_next(&encoded), None);
}

#[test]
fn decode_rejects_decoded_open_redirect() {
    let encoded = URL_SAFE_NO_PAD.encode(b"//evil.com/foo");
    assert_eq!(decode_and_validate_next(&encoded), None);
}

#[test]
fn decode_rejects_invalid_base64() {
    assert_eq!(decode_and_validate_next("not!valid!base64"), None);
    assert_eq!(decode_and_validate_next(""), None);
}

#[test]
fn decode_rejects_non_utf8_bytes() {
    // Forge a base64 value whose decoded bytes aren't valid UTF-8.
    let raw_bytes = [0xff, 0xfe, 0xfd];
    let encoded = URL_SAFE_NO_PAD.encode(raw_bytes);
    assert_eq!(decode_and_validate_next(&encoded), None);
}

// ---------------------------------------------------------------------
// Cookie helpers — login_next
// ---------------------------------------------------------------------

#[test]
fn set_login_next_cookie_carries_required_attrs() {
    let h = set_login_next_cookie_header("dGVzdA");
    assert!(h.contains(&format!("{LOGIN_NEXT_COOKIE}=dGVzdA")));
    assert!(h.contains("Max-Age=300"));
    assert!(h.contains("Path=/"));
    assert!(h.contains("HttpOnly"));
    assert!(h.contains("Secure"));
    // Lax (not Strict) — the value must survive a top-level
    // navigation initiated outside the deployment, like
    // returning from a magic-link click.
    assert!(h.contains("SameSite=Lax"),
        "login_next must be SameSite=Lax: {h}");
}

#[test]
fn login_next_cookie_uses_host_prefix() {
    assert!(LOGIN_NEXT_COOKIE.starts_with("__Host-"));
}

#[test]
fn clear_login_next_cookie_zeros_max_age() {
    let h = clear_login_next_cookie_header();
    assert!(h.contains("Max-Age=0"));
    assert!(h.contains("SameSite=Lax"));
    assert!(h.contains("Path=/"));
}

#[test]
fn login_next_ttl_is_in_reasonable_range() {
    // Plan §3.2 P1-A: 5 minutes. The user must complete sign-in
    // within that window. Pin a sane band so a future tweak
    // doesn't quietly extend it to "forever".
    assert!(LOGIN_NEXT_TTL_SECS >= 60 && LOGIN_NEXT_TTL_SECS <= 900,
        "LOGIN_NEXT_TTL_SECS = {LOGIN_NEXT_TTL_SECS}, expected 60-900s");
}

#[test]
fn extract_login_next_finds_value_in_typical_header() {
    let header = format!("foo=1; {LOGIN_NEXT_COOKIE}=eXk; bar=2");
    assert_eq!(extract_login_next(&header), Some("eXk"));
}

#[test]
fn extract_login_next_returns_none_when_absent() {
    assert_eq!(extract_login_next("foo=1; bar=2"), None);
    assert_eq!(extract_login_next(""), None);
}

#[test]
fn extract_login_next_does_not_match_prefix_substring() {
    // `__Host-cesauth_login_next_other` is not our cookie.
    let h = format!("__Host-cesauth_login_next_other=trick; ok=ok");
    assert_eq!(extract_login_next(&h), None);
}
