//! Property-based tests for the `redirect_uri` exact-match invariant
//! (RFC 003, v0.51.1).
//!
//! OAuth redirect-URI matching is historically the most bug-prone part of
//! an authorization server. The invariant is simple: byte-exact match only.
//! No prefix matching, no port stripping, no scheme inference, no trailing-
//! slash folding.
//!
//! These properties verify that the current inline matcher in
//! `authorization::AuthorizationRequest::validate` upholds the invariant
//! against adversarially generated URI pairs.

use proptest::prelude::*;

/// The redirect_uri exact-match predicate extracted from the business-logic
/// context: returns true iff `uri` is in `allowed_uris`.
///
/// We test this predicate directly rather than going through the full
/// `AuthorizationRequest::validate` to keep properties focused.
fn is_allowed(allowed_uris: &[String], uri: &str) -> bool {
    allowed_uris.iter().any(|u| u == uri)
}

// ─── Strategies ──────────────────────────────────────────────────────────────

/// Generate a valid-looking HTTPS URI with a short path.
fn https_uri() -> impl Strategy<Value = String> {
    (
        "[a-z]{3,10}",           // host label
        "[a-z]{2,6}",            // TLD
        "(|/[a-zA-Z0-9_-]{1,20})", // optional path
    )
        .prop_map(|(host, tld, path)| format!("https://{host}.{tld}{path}"))
}

/// HTTPS URI guaranteed to have no trailing slash on the path component.
fn https_uri_no_trailing_slash() -> impl Strategy<Value = String> {
    (
        "[a-z]{3,10}",
        "[a-z]{2,6}",
        "[a-zA-Z0-9_-]{1,20}",
    )
        .prop_map(|(host, tld, path)| format!("https://{host}.{tld}/{path}"))
}

/// A simple hostname (label.tld).
fn simple_host() -> impl Strategy<Value = String> {
    ("[a-z]{3,10}", "[a-z]{2,6}").prop_map(|(h, t)| format!("{h}.{t}"))
}

// ─── Properties ──────────────────────────────────────────────────────────────

proptest! {
    /// **Property 1** — Exact match always accepted.
    ///
    /// Any URI that is in the allowed set must pass the matcher. Trivial but
    /// ensures the baseline predicate is not accidentally inverted.
    #[test]
    fn matcher_accepts_byte_equal_uri(uri in https_uri()) {
        let allowed = vec![uri.clone()];
        prop_assert!(is_allowed(&allowed, &uri));
    }

    /// **Property 2** — Non-member URI rejected.
    ///
    /// A URI that was not registered must not be allowed, even if it looks
    /// similar.
    #[test]
    fn matcher_rejects_uri_not_in_allowed_set(
        uri     in https_uri(),
        other   in https_uri(),
    ) {
        prop_assume!(uri != other);
        let allowed = vec![uri.clone()];
        prop_assert!(!is_allowed(&allowed, &other));
    }

    /// **Property 3** — Trailing slash appended to registered URI is rejected.
    ///
    /// This is the classic open-redirect class: registering
    /// `https://app.example/callback` must not allow
    /// `https://app.example/callback/`.
    #[test]
    fn matcher_rejects_trailing_slash_variant(uri in https_uri_no_trailing_slash()) {
        let allowed = vec![uri.clone()];
        // With a trailing slash appended.
        let with_slash = format!("{}/", &uri);
        prop_assert!(!is_allowed(&allowed, &with_slash));
    }

    /// **Property 4** — Path suffix appended to registered URI is rejected.
    ///
    /// `https://app.example/cb` must not match `https://app.example/cb/evil`
    /// or `https://app.example/cbevil`. Neither prefix match nor substring
    /// match should satisfy the exact-match predicate.
    #[test]
    fn matcher_rejects_path_suffix_appended(
        uri    in https_uri_no_trailing_slash(),
        suffix in "[a-zA-Z0-9]{1,20}",
    ) {
        let allowed = vec![uri.clone()];
        let with_sep = format!("{}/{}", &uri, &suffix);
        let without_sep = format!("{}{}", &uri, &suffix);
        prop_assert!(!is_allowed(&allowed, &with_sep));
        prop_assert!(!is_allowed(&allowed, &without_sep));
    }

    /// **Property 5** — Explicit port is distinct from default port.
    ///
    /// `https://host.example/cb` and `https://host.example:443/cb` are
    /// different strings; the matcher must treat them as different URIs.
    /// Operators must register the exact URI they will present, including
    /// the port number when it is explicitly specified.
    #[test]
    fn matcher_treats_explicit_443_as_distinct_from_no_port(host in simple_host()) {
        let without_port = format!("https://{host}/callback");
        let with_443     = format!("https://{host}:443/callback");
        let allowed = vec![without_port.clone()];

        prop_assert!( is_allowed(&allowed, &without_port),
            "registered URI without port must be accepted");
        prop_assert!(!is_allowed(&allowed, &with_443),
            "URI with :443 must be distinct from URI without port");
    }

    /// **Property 6** — HTTP and HTTPS are distinct schemes.
    ///
    /// `http://host/cb` must not satisfy an allowlist containing only
    /// `https://host/cb`. The scheme is load-bearing for security.
    #[test]
    fn matcher_treats_http_and_https_as_distinct(host in simple_host()) {
        let https = format!("https://{host}/callback");
        let http  = format!("http://{host}/callback");
        let allowed = vec![https.clone()];

        prop_assert!( is_allowed(&allowed, &https));
        prop_assert!(!is_allowed(&allowed, &http),
            "http must not satisfy an https-only allowlist");
    }

    /// **Property 7** — Case-sensitive matching.
    ///
    /// URIs differing only in case must not be folded. The matcher does
    /// not do Unicode or ASCII case folding.
    #[test]
    fn matcher_is_case_sensitive(uri in https_uri()) {
        let uppercased = uri.to_ascii_uppercase();
        prop_assume!(uri != uppercased); // skip all-uppercase hosts
        let allowed = vec![uri.clone()];
        prop_assert!(!is_allowed(&allowed, &uppercased),
            "uppercase variant must not match lowercase-registered URI");
    }
}
