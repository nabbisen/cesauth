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
//! --help` has no such output. A future change that wants hashed names
//! back would need its own mechanism, not a manifest Trunk never wrote.
//!
//! **Layout, current as of RFC 134 C1-134.** `dist/` contains only an
//! `assets/` subdirectory — `assets/cesauth-frontend.js`,
//! `assets/cesauth-frontend_bg.wasm`, `assets/webauthn.js` — matching
//! the `/assets/...` paths this shell requests above. Trunk itself still
//! emits `dist/index.html` as a build template on every run; `Makefile`'s
//! `build-frontend` target deletes it (RFC 131 C2-131) rather than
//! shipping it, because Cloudflare Workers Static Assets would otherwise
//! serve that file directly at `/` — ahead of this shell, with none of
//! its security headers — and nests everything else under `assets/`
//! rather than `dist/`'s root, so no future built filename can shadow an
//! application route the same way (RFC 134 C1-134). This paragraph has
//! been wrong twice before (the `manifest.json` claim above, then a
//! `dist/index.html`-and-nothing-nested description that C1-134 made
//! false); re-verify it against `Makefile`'s `build-frontend` target
//! before trusting it a third time.
//!
//! ## CSP note
//!
//! `'wasm-unsafe-eval'` **is** required, and this shell's `script-src`
//! grants it (RFC 135 W1). `WebAssembly.instantiateStreaming` — the
//! call the bootstrap script's `init()` reaches — is exactly what CSP
//! gates: compiling a WASM module is a distinct capability from
//! running a script, so a `nonce` authorises the loader but not the
//! module it loads. Without the directive the browser throws
//! `CompileError: ... violates the following Content Security Policy
//! directive`, `#root` stays empty, and every `client` surface is a
//! blank page — which is what RFC 131 R5's M2 browser probe found.
//!
//! This paragraph previously asserted the opposite, citing
//! `instantiateStreaming` as the reason none was needed. It is the
//! reason one is.
//!
//! `'unsafe-eval'` remains barred (ADR-007, amended 2026-09-12). The
//! two are distinct directives: `'wasm-unsafe-eval'` permits WASM
//! compilation *without* permitting JavaScript `eval`. Both directions
//! are asserted by tests in this file and by
//! `scripts/runtime-smoke-check.sh`.
//!
//! The directive is scoped to this shell by construction: only routes
//! calling `leptos_html_shell` receive it, and RFC 132's E3 asserts no
//! `server`-declared route does.

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
    `script-src 'nonce-{n}'` directive.  No inline event handlers and
    no JavaScript eval are used, so 'unsafe-eval' is not needed and is
    not granted.  'wasm-unsafe-eval' IS needed and IS granted: init()
    reaches WebAssembly.instantiateStreaming, and compiling a WASM
    module is a capability the nonce does not cover (RFC 135).
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

    let csp = shell_csp(n);
    let _ = h.set("content-security-policy", &csp);
    let _ = h.set("cache-control",           "no-store");
    let _ = h.set("x-content-type-options",  "nosniff");
    let _ = h.set("x-frame-options",         "DENY");
    let _ = h.set("referrer-policy",         "strict-origin-when-cross-origin");

    Ok(resp)
}

/// The Content-Security-Policy served with the Leptos shell.
///
/// Extracted from the handler (RFC 135 W3) so the directive can be
/// asserted directly rather than only through a live HTTP response.
///
/// `'wasm-unsafe-eval'` is required here and only here: it permits
/// `WebAssembly.instantiateStreaming`, which the bootstrap script's
/// `init()` reaches. `'unsafe-eval'` is a different directive — it
/// permits JavaScript `eval` — and is barred by ADR-007.
fn shell_csp(nonce: &str) -> String {
    format!(
        "default-src 'self'; \
         script-src 'nonce-{n}' 'wasm-unsafe-eval'; \
         style-src 'self' 'nonce-{n}'; \
         img-src 'self' data:; \
         font-src 'self'; \
         connect-src 'self'; \
         frame-ancestors 'none'; \
         form-action 'self'; \
         base-uri 'self'; \
         object-src 'none'",
        n = nonce,
    )
}

#[cfg(test)]
mod tests {
    use super::shell_csp;

    /// RFC 135 W3. Both directions: the WASM directive is present, and
    /// the JavaScript-eval directive ADR-007 bars is absent.
    ///
    /// Quoted forms throughout — `"unsafe-eval"` unquoted is a
    /// substring of `'wasm-unsafe-eval'`, so an unquoted assertion
    /// would conflate the two directives and pass (or fail) for the
    /// wrong reason.
    #[test]
    fn shell_csp_grants_wasm_but_not_js_eval() {
        let csp = shell_csp("test-nonce");

        assert!(
            csp.contains("'wasm-unsafe-eval'"),
            "the Leptos shell must grant 'wasm-unsafe-eval' or the WASM \
             bundle cannot compile and every client surface is blank \
             (RFC 135): {csp}"
        );

        let without_wasm_directive = csp.replace("'wasm-unsafe-eval'", "");
        assert!(
            !without_wasm_directive.contains("'unsafe-eval'"),
            "ADR-007 bars 'unsafe-eval'; only 'wasm-unsafe-eval' is \
             permitted here: {csp}"
        );
    }

    /// The nonce reaches both directives that need it.
    #[test]
    fn shell_csp_carries_the_nonce() {
        let csp = shell_csp("abc123");
        assert!(csp.contains("script-src 'nonce-abc123' 'wasm-unsafe-eval'"), "{csp}");
        assert!(csp.contains("style-src 'self' 'nonce-abc123'"), "{csp}");
    }
}
