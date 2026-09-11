//! # cesauth-frontend
//!
//! Server-rendered HTML. Per spec §7 the UI is semantic HTML first and
//! accessibility is a hard requirement: every form control has a label,
//! error / status regions use `aria-live`, and the pages work with
//! JavaScript disabled except for the WebAuthn client-side call itself.
//!
//! The module purposely ships **zero** template engine dependencies.
//! The pages are small; `format!` is obvious; there is no upside to
//! pulling in askama or handlebars for something this size.
//!
//! ## v0.52.0 — CSP nonce (RFC 006)
//!
//! cesauth injects a per-request, CSPRNG-generated nonce into every
//! inline `<style>` and `<script>` tag so the Content-Security-Policy
//! can drop `'unsafe-inline'`. The nonce is stored in a `thread_local!`
//! (a per-Isolate static in the Cloudflare Workers WASM runtime) so the
//! public template API does not change:
//!
//! ```rust,ignore
//! // Worker handler — before rendering any HTML:
//! let nonce = cesauth_core::security_headers::CspNonce::generate()?;
//! cesauth_frontend::set_render_nonce(nonce.as_str());
//! let html = cesauth_frontend::templates::login_page_for(csrf, err, sk, locale);
//! // The inline <style> in the rendered HTML carries nonce="<value>".
//! ```

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms)]

use std::cell::RefCell;

pub mod admin;
pub mod design_tokens;
pub mod tenancy_console;
pub mod tenant_admin;
pub mod templates;

// ── Per-request nonce store ──────────────────────────────────────────
//
// Cloudflare Workers uses a single WASM isolate per request (v8 Isolate
// — not an OS thread). `thread_local!` in `wasm32-unknown-unknown` is
// implemented as a regular static + cell, so it behaves as a per-request
// global within the isolate. It is safe to use here.

thread_local! {
    static RENDER_NONCE: RefCell<String> = RefCell::new(String::new());
}

/// Set the CSP nonce for the current render pass.
///
/// Call once per HTML response, **before** calling any template function.
/// Uses a `thread_local!` which is per-Isolate in Cloudflare Workers
/// (single-threaded WASM runtime) — safe to call and read within one
/// request handler.
pub fn set_render_nonce(nonce: &str) {
    RENDER_NONCE.with(|n| *n.borrow_mut() = nonce.to_owned());
}

/// Read the CSP nonce set for this render pass.
///
/// Returns an empty string if `set_render_nonce` was not called yet
/// (which is fine for non-HTML responses or for the `'unsafe-inline'`
/// fallback path before v0.52.0 is fully deployed).
pub fn render_nonce() -> String {
    RENDER_NONCE.with(|n| n.borrow().clone())
}

/// Minimal HTML attribute-value escaper. Covers the five characters
/// that must be escaped inside an attribute or text node.
///
/// We deliberately do not expose "safe" unescaped HTML insertion
/// anywhere. Anything the caller wants rendered passes through here.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&'  => out.push_str("&amp;"),
            '<'  => out.push_str("&lt;"),
            '>'  => out.push_str("&gt;"),
            '"'  => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _    => out.push(c),
        }
    }
    out
}

/// Encode `s` as a double-quoted JavaScript string literal,
/// suitable for inlining into `<script>` blocks. Adopted in
/// v0.39.0 alongside the i18n-aware login page where the
/// passkey-failed error message comes from a catalog and can
/// contain characters that would break a naive interpolation
/// (quotes, backslashes, newlines, or — for JA translations —
/// multi-byte UTF-8 that must NOT be split mid-codepoint).
///
/// Specifically escapes: `\\`, `"`, the control characters
/// `\n` / `\r` / `\t`, the byte ranges `0x00..=0x1f` that
/// aren't named above (encoded as `\uXXXX`), and the two
/// character sequences that would let the string break out
/// of a `<script>` block: `</` (becomes `<\/`) and `<!--`
/// (becomes `<\!--`).
///
/// Multi-byte UTF-8 (non-ASCII letters, JA translations, etc.)
/// passes through unchanged — JS source files are UTF-8 and
/// the browser parses them correctly.
///
/// The returned string includes the surrounding double quotes,
/// so callers interpolate it directly: `err.textContent =
/// {js_string};`.
pub fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"'  => out.push_str(r#"\""#),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            // </script> escape: a bare `</` inside a JS
            // string would still close the surrounding
            // <script> tag during HTML parsing. Insert a
            // backslash so the HTML parser sees `<\/` and
            // doesn't terminate the script element.
            '<' if chars.peek() == Some(&'/') => {
                out.push_str(r"<\/");
                chars.next();
            }
            // Same defensive treatment for `<!--`.
            '<' if {
                // peek 3 chars without consuming
                let mut iter = chars.clone();
                iter.next() == Some('!') && iter.next() == Some('-') && iter.next() == Some('-')
            } => {
                out.push_str(r"<\!--");
                chars.next(); chars.next(); chars.next();
            }
            // Other control characters: \uXXXX. The ASCII
            // controls are the only ones that need this
            // (codepoints above 0x7f pass through fine).
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(&mut out, "\\u{:04x}", c as u32);
            }
            // Everything else (including multi-byte UTF-8)
            // passes through verbatim.
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests;

// ── Leptos CSR layer ─────────────────────────────────────────────────────────
//
// Only compiled when the `csr` feature is active, i.e. when Trunk
// builds the browser WASM bundle.  cesauth-backend links this crate
// without the `csr` feature and never sees these items.

#[cfg(feature = "csr")]
pub mod app;

#[cfg(feature = "csr")]
pub mod pages;

// RFC 131 R2a — mockup foundation import (view_models, icons, and the
// i18n-free primitives). Dormant until R3 wires a screen to them; not
// referenced by `app`/`pages` yet, so `cargo check --features csr` is
// the only thing exercising them until then.
#[cfg(feature = "csr")]
pub mod components;

#[cfg(feature = "csr")]
pub mod icons;

#[cfg(feature = "csr")]
pub mod view_models;

/// Browser WASM entry point.
///
/// Trunk generates a `<script type="module">` that imports the
/// compiled WASM and calls the `#[wasm_bindgen(start)]`-tagged
/// export.  That calls into `leptos::mount::mount_to`, which mounts
/// the Leptos root component into the `<div id="root">` that the
/// backend's HTML shell provides.
///
/// RFC 135 W4: this used `mount_to_body`, which appends to `<body>`
/// and leaves `#root` empty — so the shell's own comment, and this
/// one, were false. Mounting into `#root` makes both true and keeps
/// the app's subtree separate from `<noscript>`.
#[cfg(feature = "csr")]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn leptos_start() {
    // Surface Rust panics as readable console errors in the browser.
    console_error_panic_hook::set_once();

    use wasm_bindgen::JsCast;
    let root = web_sys::window()
        .expect("no `window` — not running in a browser")
        .document()
        .expect("`window` has no `document`")
        .get_element_by_id("root")
        .expect("shell defect: no element with id `root` to mount into")
        .dyn_into::<web_sys::HtmlElement>()
        .expect("shell defect: `#root` is not an HtmlElement");

    // `.forget()` is required, not decorative: `UnmountHandle`'s `Drop`
    // unmounts the app, so dropping it here would mount and immediately
    // unmount, leaving `#root` empty with no error — indistinguishable
    // from the outage this fixes. `mount_to_body` calls `.forget()`
    // internally for the same reason.
    leptos::mount::mount_to(root, app::App).forget();
}
