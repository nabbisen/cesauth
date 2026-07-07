//! Login page component — `GET /` and `GET /login`.
//!
//! Migrated from `login_page_for` string template in v0.79.5.
//!
//! ## Authentication paths rendered
//!
//! 1. **Passkey (primary)** — `<button>` triggers `cesauthPasskeyAuthenticate`
//!    (a JS helper loaded by the HTML shell from `/assets/webauthn.js`).
//!    The helper calls `/webauthn/authenticate/start`, invokes
//!    `navigator.credentials.get()`, and posts the result to
//!    `/webauthn/authenticate/finish`.  On success the browser navigates
//!    to the final URL (OIDC redirect_uri or `/me/security`).
//!
//! 2. **Email code (fallback)** — standard `<form method="POST"
//!    action="/magic-link/request">` submission.  The server response
//!    (the OTP input page) is rendered by the existing string template
//!    until that page is migrated in v0.79.6.
//!
//! ## Notes on WebAuthn interop
//!
//! The `cesauthPasskeyAuthenticate` function lives in a JS ES module
//! (`static/webauthn.js`) loaded by the HTML shell's CSP-nonced bootstrap
//! script.  The function is exposed on `window.__cesauth.passkeyAuthenticate`
//! and called via `js_sys::Reflect` reflection.  This approach:
//! - Satisfies strict CSP (`script-src 'nonce-…'` — no `'unsafe-eval'`)
//! - Handles `ArrayBuffer` ↔ base64url conversion in JS (natural)
//! - Keeps the binary serialisation concern out of Rust/WASM

use leptos::prelude::*;

// ─── WebAuthn interop ────────────────────────────────────────────────────────

/// Call `window.__cesauth.passkeyAuthenticate()` via JS reflection.
///
/// Returns `Ok(())` when the browser has navigated to the post-login
/// destination (the Promise resolved).  Returns `Err(String)` with a
/// user-readable error code on any failure.
async fn call_passkey_js() -> Result<(), String> {
    use wasm_bindgen::JsValue;

    let window = web_sys::window().ok_or("no_window")?;

    // window.__cesauth
    let ns = js_sys::Reflect::get(&window, &JsValue::from_str("__cesauth"))
        .map_err(|_| "webauthn_not_loaded")?;
    if ns.is_undefined() || ns.is_null() {
        return Err("webauthn_not_loaded".into());
    }

    // window.__cesauth.passkeyAuthenticate
    let func = js_sys::Reflect::get(&ns, &JsValue::from_str("passkeyAuthenticate"))
        .map_err(|_| "webauthn_not_loaded")?;
    let func: js_sys::Function = func.dyn_into()
        .map_err(|_| "webauthn_not_loaded")?;

    // Call it — returns a Promise
    let result = func.call0(&JsValue::UNDEFINED)
        .map_err(|e| format!("{:?}", e))?;
    let promise: js_sys::Promise = result.dyn_into()
        .map_err(|_| "not_a_promise")?;

    // Await the Promise
    wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map(|_| ())
        .map_err(|e| {
            // The JS helper throws an Error with a code string as message.
            js_sys::Reflect::get(&e, &JsValue::from_str("message"))
                .ok()
                .and_then(|m| m.as_string())
                .unwrap_or_else(|| format!("{:?}", e))
        })
}

// ─── Component ───────────────────────────────────────────────────────────────

/// Login page (`/` and `/login`).
#[component]
pub fn Login() -> impl IntoView {
    // Passkey button state: None = idle, Some(Err) = error shown.
    let (passkey_error, set_passkey_error) = signal(Option::<String>::None);
    let (passkey_busy,  set_passkey_busy)  = signal(false);

    let on_passkey_click = move |_| {
        set_passkey_error.set(None);
        set_passkey_busy.set(true);
        leptos::task::spawn_local(async move {
            match call_passkey_js().await {
                Ok(()) => {
                    // JS navigated the browser; nothing more to do.
                }
                Err(e) => {
                    set_passkey_busy.set(false);
                    let msg = match e.as_str() {
                        "passkey_cancelled"    => "Sign-in was cancelled.",
                        "passkey_unsupported"  => "Passkeys are not supported on this device.",
                        "webauthn_not_loaded"  => "Passkey script not yet loaded. Try again.",
                        _                      => "Sign-in failed. Try your email instead.",
                    };
                    set_passkey_error.set(Some(msg.into()));
                }
            }
        });
    };

    view! {
        <main class="login-page" aria-label="Sign in">
            <div class="login-card">
                <h1>"Sign in to cesauth"</h1>

                // ── Passkey (primary) ────────────────────────────────
                <section aria-labelledby="passkey-heading">
                    <h2 id="passkey-heading" class="sr-only">"Passkey sign-in"</h2>

                    {move || passkey_error.get().map(|e| view! {
                        <p role="alert" class="form-error">{e}</p>
                    })}

                    <button
                        type="button"
                        class="btn-primary btn-passkey"
                        disabled=passkey_busy
                        aria-disabled=passkey_busy
                        aria-busy=passkey_busy
                        on:click=on_passkey_click
                    >
                        {move || if passkey_busy.get() {
                            "Signing in…"
                        } else {
                            "Sign in with passkey"
                        }}
                    </button>
                </section>

                <hr aria-hidden="true" />

                // ── Email OTP (fallback) ─────────────────────────────
                <section aria-labelledby="email-heading">
                    <h2 id="email-heading">"Sign in with email"</h2>
                    <p class="muted">
                        "We'll send a sign-in code to your email address."
                    </p>

                    // Regular HTML form POST — the server responds with
                    // the OTP input page (still served by the existing
                    // string template until v0.79.6).
                    <form method="POST" action="/magic-link/request">
                        <label for="email">"Email address"</label>
                        <input
                            id="email"
                            name="email"
                            type="email"
                            required
                            autocomplete="email"
                            inputmode="email"
                            placeholder="you@example.com"
                        />
                        <button type="submit">"Send sign-in code"</button>
                    </form>
                </section>
            </div>
        </main>
    }
}
