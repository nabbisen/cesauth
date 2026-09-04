//! HTML shell routes for the Leptos CSR frontend.
//!
//! These handlers render the minimal HTML that the browser needs to
//! bootstrap the Leptos WASM bundle.  All subsequent rendering happens
//! client-side once the bundle loads.
//!
//! ## Shell design
//!
//! The shell carries:
//! - Page title and `<html lang>` attribute (server-known, faster)
//! - `<link rel="preload">` for the WASM bundle (starts download early)
//! - `<script type="module" nonce="…">` that initialises the bundle
//! - Strict CSP header with the per-request nonce (RFC 006)
//! - `<div id="root">` mount point for Leptos
//!
//! ## Asset path
//!
//! The WASM bundle is served from the Workers Static Assets binding
//! at `/assets/`. Trunk's *default* output names are the Cargo package
//! name — **hyphenated** (`cesauth-frontend`, not `cesauth_frontend`) —
//! plus a content hash: `cesauth-frontend-<16-hex-hash>.js` /
//! `..._bg.wasm`. `Makefile`'s `build-frontend` target passes
//! `--filehash false` (RFC 130 S2), which drops the hash and produces the
//! deterministic names below.
//!
//! **There is no `dist/manifest.json`.** An earlier version of this
//! comment claimed Trunk emits one and that a "Phase C" would read it to
//! inject a hashed name automatically; that was wrong — `trunk build
//! --help` has no such output, and `dist/` only ever contains the `.js`,
//! `_bg.wasm`, and `index.html` (RFC 130 §2.1). What Trunk *does* emit is
//! `dist/index.html` itself, containing the real `href="…"` — a future
//! change that wants hashed names back would parse that file into a
//! manifest at build time, not read one Trunk already wrote.
//!
//! ## CSP note
//!
//! `'wasm-unsafe-eval'` is NOT required.  Leptos compiles to a
//! standard WASM binary loaded via `WebAssembly.instantiateStreaming`;
//! that pathway is permitted by `default-src 'self'` and does not
//! need an extra CSP directive in modern browsers.

use worker::{Request, Response, Result, RouteContext};

use crate::config::Config;

/// Asset filenames produced by `trunk build --release --filehash false`
/// (RFC 130 S2) — deterministic, hyphenated to match the Cargo package
/// name `cesauth-frontend`. Verified against a real `dist/` build
/// (`Makefile`'s `build-frontend` target), not assumed: see the RFC 130
/// review request's mechanical filename assertion.
///
/// Still hardcoded, not read from a manifest — see the module doc for
/// why there is no manifest to read.
const LEPTOS_JS:   &str = "cesauth-frontend.js";
const LEPTOS_WASM: &str = "cesauth-frontend_bg.wasm";

/// Render the HTML shell that bootstraps the Leptos CSR bundle.
///
/// Used by `poc_handler` now; will be used by all Leptos-backed route
/// handlers once screens are migrated in Phase C.
pub async fn leptos_html_shell(
    _req: &Request,
    env: &worker::Env,
    title: &str,
    lang: &str,
) -> Result<Response> {
    let csp_nonce = match cesauth_core::security_headers::CspNonce::generate() {
        Ok(n) => n,
        Err(_) => {
            worker::console_error!("csp_nonce_failure in leptos_html_shell");
            return Response::error("service temporarily unavailable", 500);
        }
    };

    // Also set the nonce on the SSR render-context layer so any
    // remaining string-template screens that share this request still
    // pick up the right nonce value.
    cesauth_frontend::set_render_nonce(csp_nonce.as_str());

    let n = csp_nonce.as_str();

    let shell = format!(
        r#"<!DOCTYPE html>
<html lang="{lang}">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{title}</title>
  <!-- Prefetch the WASM binary so it arrives before the JS loader asks for it. -->
  <link rel="preload"
        href="/assets/{wasm}"
        as="fetch"
        type="application/wasm"
        crossorigin/>
</head>
<body>
  <!-- Leptos mounts into this div. -->
  <div id="root"></div>
  <noscript>
    <p>This application requires JavaScript and WebAssembly.
       Please enable them in your browser settings.</p>
  </noscript>
  <!--
    Bootstrap script.  The `nonce` attribute satisfies the CSP
    `script-src 'nonce-{n}'` directive.  No inline event handlers or
    eval are used; 'unsafe-eval' and 'wasm-unsafe-eval' are not needed.
  -->
  <script type="module" nonce="{n}">
    import init from "/assets/{js}";
    import {{ cesauthPasskeyAuthenticate }} from "/assets/webauthn.js";
    // Expose WebAuthn helper so Rust/WASM can call it via js_sys reflection.
    window.__cesauth = {{ passkeyAuthenticate: cesauthPasskeyAuthenticate }};
    init();
  </script>
</body>
</html>"#,
        lang  = lang,
        title = title,
        wasm  = LEPTOS_WASM,
        js    = LEPTOS_JS,
        n     = n,
    );

    let mut resp = Response::from_html(shell)?;
    let h = resp.headers_mut();

    let csp = format!(
        "default-src 'self'; \
         script-src 'nonce-{n}'; \
         style-src 'self' 'nonce-{n}'; \
         img-src 'self' data:; \
         font-src 'self'; \
         connect-src 'self'; \
         frame-ancestors 'none'; \
         form-action 'self'; \
         base-uri 'self'; \
         object-src 'none'",
        n = n,
    );
    let _ = h.set("content-security-policy", &csp);
    let _ = h.set("cache-control",           "no-store");
    let _ = h.set("x-content-type-options",  "nosniff");
    let _ = h.set("x-frame-options",         "DENY");
    let _ = h.set("referrer-policy",         "strict-origin-when-cross-origin");

    Ok(resp)
}
