//! HTTP security response headers — the pure-function half.
//!
//! See ADR-007 for the design rationale and decision summary.
//! This module builds header name/value pairs; the Worker
//! middleware in `cesauth-worker` calls these and writes the
//! results to the outgoing `worker::Response`. By keeping the
//! construction logic here, in pure Rust with no Worker
//! dependencies, the load-bearing tests live alongside the
//! data and never need a Worker harness.
//!
//! ## What's a "security header" in this module?
//!
//! Eight headers, split into two sets:
//!
//! **Universal** (every response):
//! - `X-Content-Type-Options: nosniff`
//! - `Referrer-Policy: strict-origin-when-cross-origin`
//! - `Strict-Transport-Security: max-age=63072000; includeSubDomains`
//! - `Permissions-Policy: ...` (disabling features cesauth doesn't use)
//!
//! **HTML-only** (gated by `Content-Type: text/html`):
//! - `Content-Security-Policy: ...`
//! - `X-Frame-Options: DENY`
//!
//! ## Operator overrides
//!
//! ADR-007 §Q7 specifies three env-var knobs:
//!
//! - `SECURITY_HEADERS_CSP` — overrides the default CSP string.
//! - `SECURITY_HEADERS_STS` — overrides the default STS string.
//! - `SECURITY_HEADERS_DISABLE_HTML_ONLY` — when set to `"true"`,
//!   disables CSP and X-Frame-Options entirely (debugging escape
//!   hatch).
//!
//! The library here exposes a `SecurityHeadersConfig` struct that
//! the Worker middleware populates from env. Pure config in,
//! pure header list out.

/// Config for the security-headers middleware. Populated by the
/// Worker layer from `wrangler.toml` env vars; the pure
/// construction code here is config-driven.
///
/// All fields default to the ADR-007 §Decision-Summary values.
/// Operators override via env vars (see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHeadersConfig {
    /// CSP value to send. ADR-007 §Q3 specifies the default;
    /// operators can override by setting `SECURITY_HEADERS_CSP`.
    pub csp:                String,
    /// STS value to send. ADR-007 §Q4 specifies the default
    /// (`max-age=63072000; includeSubDomains`); operators
    /// can upgrade to `preload` by overriding via
    /// `SECURITY_HEADERS_STS`.
    pub sts:                String,
    /// When true, the HTML-only header set (CSP, X-Frame-Options)
    /// is suppressed. Operator escape hatch; logged loudly.
    pub disable_html_only:  bool,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            csp: DEFAULT_CSP.to_owned(),
            sts: DEFAULT_STS.to_owned(),
            disable_html_only: false,
        }
    }
}

impl SecurityHeadersConfig {
    /// Build a config from operator-supplied env values. Any
    /// `None` argument falls back to the ADR-007 default.
    /// `disable_html_only` is true iff the env value
    /// case-insensitively equals `"true"`. Anything else
    /// (including `"1"` or `"yes"`) is treated as false —
    /// strict matching is intentional, this is a debugging
    /// escape hatch and a typo should not silently disable
    /// security headers.
    pub fn from_env(
        csp_override: Option<&str>,
        sts_override: Option<&str>,
        disable_html_only_value: Option<&str>,
    ) -> Self {
        Self {
            csp: csp_override.map(str::to_owned).unwrap_or_else(|| DEFAULT_CSP.to_owned()),
            sts: sts_override.map(str::to_owned).unwrap_or_else(|| DEFAULT_STS.to_owned()),
            disable_html_only: disable_html_only_value
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        }
    }
}

/// Default CSP. ADR-007 §Q3.
///
/// The directives, with rationale:
/// - `default-src 'none'` — start from nothing, allow
///   specifically.
/// - `script-src 'self'` — same-origin scripts only. No
///   `unsafe-inline`, no `unsafe-eval`.
/// - `style-src 'self'` — same-origin stylesheets only. No
///   `unsafe-inline` for styles either.
/// - `img-src 'self' data:` — needed for inline SVGs/favicons.
/// - `connect-src 'self'` — fetch/XHR/WebSocket same-origin.
/// - `form-action 'self'` — form posts stay same-origin.
/// - `frame-ancestors 'none'` — equivalent to
///   `X-Frame-Options: DENY` for CSP-aware browsers.
/// - `base-uri 'none'` — `<base>` element disabled.
pub const DEFAULT_CSP: &str = "default-src 'none'; \
script-src 'self'; \
style-src 'self'; \
img-src 'self' data:; \
connect-src 'self'; \
form-action 'self'; \
frame-ancestors 'none'; \
base-uri 'none'";

/// Default Strict-Transport-Security. ADR-007 §Q4.
///
/// 2 years (Mozilla's recommended duration) plus
/// `includeSubDomains`. `preload` is operator opt-in via the
/// `SECURITY_HEADERS_STS` env var.
pub const DEFAULT_STS: &str = "max-age=63072000; includeSubDomains";

/// Default Permissions-Policy. ADR-007 §Q5.
///
/// Disables every feature cesauth's HTML pages don't use.
/// Empty allowlist `()` means "this feature is disabled for
/// this origin and all framed contexts".
pub const DEFAULT_PERMISSIONS_POLICY: &str = "camera=(), \
microphone=(), \
geolocation=(), \
payment=(), \
usb=(), \
magnetometer=(), \
gyroscope=(), \
accelerometer=(), \
midi=(), \
serial=(), \
bluetooth=(), \
fullscreen=(), \
picture-in-picture=()";

/// Default `X-Frame-Options`. The constant exists so a future
/// operator override can swap it; current ADR-007 doesn't
/// expose this knob (CSP `frame-ancestors` carries the same
/// information for modern browsers, and a deployment that
/// needs partner-frame embedding should be carving out an
/// explicit per-tenant policy, not weakening the global
/// X-Frame-Options).
pub const DEFAULT_XFO: &str = "DENY";

/// One header to apply: a `(name, value)` pair. The middleware
/// in `cesauth-worker` walks this list and calls
/// `Response::headers_mut().set(name, value)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name:  &'static str,
    pub value: String,
}

/// Build the list of headers to apply for one outgoing response.
///
/// `is_html` should be `true` iff the response's
/// `Content-Type` starts with `text/html` (case-insensitive).
/// The Worker middleware extracts this from the response
/// before calling. A response with no `Content-Type` (which
/// shouldn't happen — handlers should always set one — but is
/// possible) is treated as non-HTML; safer default.
///
/// `already_set` is the list of header names the route handler
/// has already set on the response. The library skips any
/// header in this list — "don't clobber what the route set"
/// is a library responsibility, made auditable by being a
/// single test surface. The comparison is case-insensitive
/// (HTTP header names are).
///
/// The order in the returned list is stable but not
/// semantically meaningful — HTTP doesn't care about header
/// order. The order chosen here reflects the order they appear
/// in ADR-007 for ease of reading test assertions.
pub fn headers_for_response(
    config:      &SecurityHeadersConfig,
    is_html:     bool,
    already_set: &[&str],
) -> Vec<Header> {
    let is_already_set = |name: &str| -> bool {
        already_set.iter().any(|s| s.eq_ignore_ascii_case(name))
    };

    let mut out = Vec::with_capacity(6);

    // Universal headers — every response.
    if !is_already_set("X-Content-Type-Options") {
        out.push(Header {
            name: "X-Content-Type-Options",
            value: "nosniff".to_owned(),
        });
    }
    if !is_already_set("Referrer-Policy") {
        out.push(Header {
            name: "Referrer-Policy",
            value: "strict-origin-when-cross-origin".to_owned(),
        });
    }
    if !is_already_set("Strict-Transport-Security") {
        out.push(Header {
            name: "Strict-Transport-Security",
            value: config.sts.clone(),
        });
    }
    if !is_already_set("Permissions-Policy") {
        out.push(Header {
            name: "Permissions-Policy",
            value: DEFAULT_PERMISSIONS_POLICY.to_owned(),
        });
    }

    // HTML-only headers, gated by content type AND not disabled
    // via operator escape hatch.
    if is_html && !config.disable_html_only {
        if !is_already_set("Content-Security-Policy") {
            out.push(Header {
                name: "Content-Security-Policy",
                value: config.csp.clone(),
            });
        }
        if !is_already_set("X-Frame-Options") {
            out.push(Header {
                name: "X-Frame-Options",
                value: DEFAULT_XFO.to_owned(),
            });
        }
    }

    out
}

/// Determine whether a `Content-Type` header value indicates
/// HTML. The check is case-insensitive on the type/subtype
/// portion ("text/html" matches "TEXT/HTML"), and tolerates
/// trailing parameters (`text/html; charset=utf-8`).
///
/// The Worker middleware passes its response's `Content-Type`
/// here; this function does the parsing so the middleware
/// stays a thin shim.
pub fn is_html_content_type(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else { return false; };
    let lower = ct.to_ascii_lowercase();
    // Match "text/html" at the start, optionally followed by
    // whitespace, semicolon, or end-of-string. Avoids false
    // positives like "text/html-something" if such a thing
    // ever existed.
    let bytes = lower.as_bytes();
    if !lower.starts_with("text/html") {
        return false;
    }
    match bytes.get("text/html".len()) {
        None        => true,
        Some(b';')  => true,
        Some(b' ')  => true,
        Some(b'\t') => true,
        Some(_)     => false,  // e.g. "text/htmlx"
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Default values — pin the ADR §Decision-Summary contract
    // -----------------------------------------------------------------

    #[test]
    fn default_csp_has_no_unsafe_inline() {
        // Tripwire: ADR-007 §Q3 specifies that the DEFAULT CSP
        // (used as fallback for HTML routes that don't set their
        // own) has no unsafe-inline / unsafe-eval. Per-route CSPs
        // in cesauth-worker (login, authorize, admin console)
        // currently DO use unsafe-inline due to inline <style>
        // and <script> blocks in templates; that's a known
        // limitation tracked for a future release. Those routes
        // set their CSP explicitly and the middleware doesn't
        // override.
        //
        // This test pins the DEFAULT CSP — the fallback — to
        // remain strict. A future maintainer relaxing it without
        // amending the ADR fails this test.
        assert!(!DEFAULT_CSP.contains("unsafe-inline"));
        assert!(!DEFAULT_CSP.contains("unsafe-eval"));
    }

    #[test]
    fn default_csp_has_default_src_none() {
        // ADR-007 §Q3 specifies `default-src 'none'` as the
        // starting-from-nothing posture.
        assert!(DEFAULT_CSP.contains("default-src 'none'"));
    }

    #[test]
    fn default_csp_disables_framing() {
        // Both forms must be there: CSP `frame-ancestors 'none'`
        // for modern browsers, and X-Frame-Options DENY at the
        // header level for older ones.
        assert!(DEFAULT_CSP.contains("frame-ancestors 'none'"));
        assert_eq!(DEFAULT_XFO, "DENY");
    }

    #[test]
    fn default_csp_disables_base_uri() {
        // `<base>` injection is a known XSS-amplifier; ADR-007
        // §Q3 disables it.
        assert!(DEFAULT_CSP.contains("base-uri 'none'"));
    }

    #[test]
    fn default_sts_is_two_years_with_subdomains() {
        // ADR-007 §Q4. Pin the exact value.
        assert_eq!(DEFAULT_STS, "max-age=63072000; includeSubDomains");
        // No preload — that's operator opt-in.
        assert!(!DEFAULT_STS.contains("preload"));
    }

    #[test]
    fn default_permissions_policy_disables_sensitive_features() {
        // Each must appear with empty allowlist `()`.
        // (Spot-check — full list is in the constant.)
        for feature in &["camera", "microphone", "geolocation", "payment"] {
            let needle = format!("{feature}=()");
            assert!(DEFAULT_PERMISSIONS_POLICY.contains(&needle),
                "expected `{needle}` in default permissions-policy: \
                 {DEFAULT_PERMISSIONS_POLICY}");
        }
    }

    // -----------------------------------------------------------------
    // is_html_content_type
    // -----------------------------------------------------------------

    #[test]
    fn is_html_recognizes_plain_text_html() {
        assert!(is_html_content_type(Some("text/html")));
    }

    #[test]
    fn is_html_recognizes_text_html_with_charset() {
        // `text/html; charset=utf-8` is the most common form.
        assert!(is_html_content_type(Some("text/html; charset=utf-8")));
        assert!(is_html_content_type(Some("text/html;charset=utf-8")));
    }

    #[test]
    fn is_html_is_case_insensitive() {
        assert!(is_html_content_type(Some("TEXT/HTML")));
        assert!(is_html_content_type(Some("Text/HTML; CharSet=UTF-8")));
    }

    #[test]
    fn is_html_rejects_json() {
        assert!(!is_html_content_type(Some("application/json")));
        assert!(!is_html_content_type(Some("application/json; charset=utf-8")));
    }

    #[test]
    fn is_html_rejects_text_plain() {
        assert!(!is_html_content_type(Some("text/plain")));
    }

    #[test]
    fn is_html_rejects_partial_match() {
        // `text/htmlx` (hypothetical) must NOT match. Without
        // proper boundary handling, a naive `starts_with` would
        // pass this case and cause CSP to be applied to non-HTML
        // responses.
        assert!(!is_html_content_type(Some("text/htmlx")));
        assert!(!is_html_content_type(Some("text/html-form")));
    }

    #[test]
    fn is_html_rejects_missing_content_type() {
        // No content-type → not HTML (safer default than guessing).
        assert!(!is_html_content_type(None));
    }

    // -----------------------------------------------------------------
    // SecurityHeadersConfig::from_env
    // -----------------------------------------------------------------

    #[test]
    fn config_from_env_with_no_overrides_uses_defaults() {
        let c = SecurityHeadersConfig::from_env(None, None, None);
        assert_eq!(c.csp, DEFAULT_CSP);
        assert_eq!(c.sts, DEFAULT_STS);
        assert!(!c.disable_html_only);
    }

    #[test]
    fn config_from_env_csp_override_takes_effect() {
        let custom = "default-src 'self'";
        let c = SecurityHeadersConfig::from_env(Some(custom), None, None);
        assert_eq!(c.csp, custom);
        // Other fields keep defaults.
        assert_eq!(c.sts, DEFAULT_STS);
    }

    #[test]
    fn config_from_env_sts_override_takes_effect() {
        let custom = "max-age=86400; includeSubDomains; preload";
        let c = SecurityHeadersConfig::from_env(None, Some(custom), None);
        assert_eq!(c.sts, custom);
    }

    #[test]
    fn config_from_env_disable_html_only_strict_match() {
        // ADR-007 §Q7: strict matching on "true". A typo like
        // "Tru" or "1" should NOT silently disable headers.
        assert!( SecurityHeadersConfig::from_env(None, None, Some("true")).disable_html_only);
        assert!( SecurityHeadersConfig::from_env(None, None, Some("TRUE")).disable_html_only);
        assert!( SecurityHeadersConfig::from_env(None, None, Some("True")).disable_html_only);

        assert!(!SecurityHeadersConfig::from_env(None, None, Some("Tru")).disable_html_only);
        assert!(!SecurityHeadersConfig::from_env(None, None, Some("1")).disable_html_only);
        assert!(!SecurityHeadersConfig::from_env(None, None, Some("yes")).disable_html_only);
        assert!(!SecurityHeadersConfig::from_env(None, None, Some("")).disable_html_only);
    }

    // -----------------------------------------------------------------
    // headers_for_response
    // -----------------------------------------------------------------

    fn names(headers: &[Header]) -> Vec<&str> {
        headers.iter().map(|h| h.name).collect()
    }

    #[test]
    fn html_response_gets_full_set() {
        let c = SecurityHeadersConfig::default();
        let h = headers_for_response(&c, true, &[]);
        let n = names(&h);
        assert!(n.contains(&"X-Content-Type-Options"));
        assert!(n.contains(&"Referrer-Policy"));
        assert!(n.contains(&"Strict-Transport-Security"));
        assert!(n.contains(&"Permissions-Policy"));
        assert!(n.contains(&"Content-Security-Policy"));
        assert!(n.contains(&"X-Frame-Options"));
        assert_eq!(h.len(), 6);
    }

    #[test]
    fn json_response_gets_universal_set_only() {
        let c = SecurityHeadersConfig::default();
        let h = headers_for_response(&c, false, &[]);
        let n = names(&h);
        assert!(n.contains(&"X-Content-Type-Options"));
        assert!(n.contains(&"Referrer-Policy"));
        assert!(n.contains(&"Strict-Transport-Security"));
        assert!(n.contains(&"Permissions-Policy"));
        assert!(!n.contains(&"Content-Security-Policy"));
        assert!(!n.contains(&"X-Frame-Options"));
        assert_eq!(h.len(), 4);
    }

    #[test]
    fn disable_html_only_suppresses_csp_and_xfo() {
        // The escape hatch suppresses CSP and X-Frame-Options
        // even on HTML responses. Universal headers stay.
        let c = SecurityHeadersConfig {
            disable_html_only: true,
            ..Default::default()
        };
        let h = headers_for_response(&c, true, &[]);
        let n = names(&h);
        assert!(n.contains(&"X-Content-Type-Options"));
        assert!(n.contains(&"Strict-Transport-Security"));
        assert!(!n.contains(&"Content-Security-Policy"),
            "disable_html_only must suppress CSP");
        assert!(!n.contains(&"X-Frame-Options"),
            "disable_html_only must suppress X-Frame-Options");
    }

    #[test]
    fn header_values_carry_through_from_config() {
        let c = SecurityHeadersConfig {
            csp: "test-csp-value".into(),
            sts: "test-sts-value".into(),
            disable_html_only: false,
        };
        let h = headers_for_response(&c, true, &[]);
        let csp = h.iter().find(|x| x.name == "Content-Security-Policy").unwrap();
        let sts = h.iter().find(|x| x.name == "Strict-Transport-Security").unwrap();
        assert_eq!(csp.value, "test-csp-value");
        assert_eq!(sts.value, "test-sts-value");
    }

    #[test]
    fn xframeoptions_is_deny() {
        // Pin the X-Frame-Options value. If a future operator
        // wants ALLOW-FROM, that's a per-tenant decision (not
        // currently scoped — see ADR-007 §Q6).
        let c = SecurityHeadersConfig::default();
        let h = headers_for_response(&c, true, &[]);
        let xfo = h.iter().find(|x| x.name == "X-Frame-Options").unwrap();
        assert_eq!(xfo.value, "DENY");
    }

    #[test]
    fn order_is_stable() {
        // The function must return headers in a deterministic
        // order. Test infrastructure relies on this for
        // assertions; future maintainers shouldn't sort or
        // shuffle.
        let c = SecurityHeadersConfig::default();
        let h1 = headers_for_response(&c, true, &[]);
        let h2 = headers_for_response(&c, true, &[]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn no_security_header_uses_unsafe_inline_or_unsafe_eval() {
        // Defense-in-depth tripwire: even if a future operator
        // override permits unsafe-inline, the construction
        // function should not synthesize one. This test pins
        // the construction logic against accidental hardcoded
        // unsafe values. (Note: per-route CSPs in
        // cesauth-worker DO use unsafe-inline currently; this
        // test only covers the library defaults.)
        let c = SecurityHeadersConfig::default();
        for h in headers_for_response(&c, true, &[]) {
            assert!(!h.value.contains("unsafe-inline"),
                "header {} contains unsafe-inline: {}", h.name, h.value);
            assert!(!h.value.contains("unsafe-eval"),
                "header {} contains unsafe-eval: {}", h.name, h.value);
        }
    }

    // -----------------------------------------------------------------
    // Don't-clobber behavior — load-bearing for cesauth's
    // existing per-route CSPs
    // -----------------------------------------------------------------

    #[test]
    fn already_set_csp_is_not_re_emitted() {
        // The login page sets its own CSP. The middleware must
        // not clobber it. Pin the contract.
        let c = SecurityHeadersConfig::default();
        let h = headers_for_response(&c, true, &["Content-Security-Policy"]);
        let n = names(&h);
        assert!(!n.contains(&"Content-Security-Policy"),
            "library must not re-emit CSP when route already set one");
        // Other headers still come through.
        assert!(n.contains(&"X-Content-Type-Options"));
        assert!(n.contains(&"X-Frame-Options"));
    }

    #[test]
    fn already_set_check_is_case_insensitive() {
        // HTTP header names are case-insensitive. The
        // already_set check must respect that, since route
        // handlers may set headers in any case (and worker
        // crates sometimes lowercase before storing).
        let c = SecurityHeadersConfig::default();
        let h = headers_for_response(&c, true, &["content-security-policy"]);
        assert!(!names(&h).contains(&"Content-Security-Policy"));

        let h = headers_for_response(&c, true, &["CONTENT-SECURITY-POLICY"]);
        assert!(!names(&h).contains(&"Content-Security-Policy"));

        // "X-Frame-Options" with weird case
        let h = headers_for_response(&c, true, &["x-FRAME-options"]);
        assert!(!names(&h).contains(&"X-Frame-Options"));
    }

    #[test]
    fn already_set_universal_headers_are_skipped() {
        // If a route handler set Referrer-Policy itself, don't
        // overwrite. (This is unusual but could happen for a
        // route that wants no-referrer-at-all.)
        let c = SecurityHeadersConfig::default();
        let h = headers_for_response(&c, false, &["Referrer-Policy"]);
        let n = names(&h);
        assert!(!n.contains(&"Referrer-Policy"));
        // Other universal headers still come through.
        assert!(n.contains(&"X-Content-Type-Options"));
        assert!(n.contains(&"Strict-Transport-Security"));
        assert!(n.contains(&"Permissions-Policy"));
    }

    #[test]
    fn already_set_unrelated_header_does_not_affect_output() {
        // A route that set "Set-Cookie" or "Cache-Control"
        // shouldn't have any effect on the security-header set.
        let c = SecurityHeadersConfig::default();
        let h_clean   = headers_for_response(&c, true, &[]);
        let h_unrel   = headers_for_response(&c, true, &["Set-Cookie", "Cache-Control"]);
        assert_eq!(h_clean, h_unrel);
    }
}
