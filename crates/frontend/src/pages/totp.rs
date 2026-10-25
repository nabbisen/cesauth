//! TOTP page components — migrated in v0.79.4.
//!
//! Two screens:
//! - `TotpEnroll`  — `/me/security/totp/enroll`
//! - `TotpDisable` — `/me/security/totp/disable`
//!
//! The third, the 2FA gate at `/me/security/totp/verify`, is **not** here.
//! RFC 143 deleted its CSR duplicate: that route is the only one on the
//! sign-in path still exempt from RFC 132's render-server-side rule, and a
//! user with JavaScript disabled who reached it was stranded mid-sign-in.
//! It is now rendered server-side by
//! `crates/backend/src/routes/me/totp/verify.rs`, from the template at
//! `crates/frontend/src/templates/totp.rs::totp_verify_page_for` — the same
//! template the wrong-code POST path already used.

use leptos::prelude::*;

// ════════════════════════════════════════════════════════════════════════════
// ENROLL
// ════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EnrollData {
    qr_svg:     String,
    secret_b32: String,
    csrf_token: String,
}

async fn fetch_enroll() -> Result<EnrollData, String> {
    let resp = gloo_net::http::Request::get("/me/security/totp/enroll.json")
        .header("Accept", "application/json")
        .send().await
        .map_err(|e| format!("network: {e}"))?;
    match resp.status() {
        200 => resp.json().await.map_err(|e| format!("parse: {e}")),
        401 | 403 => Err("session_expired".into()),
        503 => Err("totp_unconfigured".into()),
        s   => Err(format!("http {s}")),
    }
}

/// TOTP enrollment page — shows QR code + manual entry + confirm form.
#[component]
pub fn TotpEnroll() -> impl IntoView {
    let data = LocalResource::new(|| async { fetch_enroll().await });

    view! {
        <main aria-label="Enable two-factor authentication">
            <Suspense fallback=|| view! {
                <p aria-busy="true" aria-live="polite">"Generating setup code…"</p>
            }>
                {move || data.get().map(|r| match r {
                    Ok(d)  => view! { <EnrollView data=d /> }.into_any(),
                    Err(e) => view! { <EnrollError error=e /> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

#[component]
fn EnrollView(data: EnrollData) -> impl IntoView {
    let csrf  = data.csrf_token.clone();
    let b32   = data.secret_b32.clone();
    let qr    = data.qr_svg.clone();

    view! {
        <div>
            <h1>"Enable two-factor authentication"</h1>
            <p>"Scan the QR code with your authenticator app, then enter "
               "the 6-digit code to confirm."</p>

            // QR code — server-generated SVG injected as raw HTML.
            // Safe: generated from the TOTP secret, not user input.
            <div class="qr-container"
                 aria-label="QR code for authenticator app setup"
                 inner_html=qr />

            // Manual entry fallback
            <details>
                <summary>"Can't scan? Enter the code manually."</summary>
                <p>
                    <code class="b32-secret" aria-label="Manual setup key">
                        {b32}
                    </code>
                </p>
            </details>

            // Confirm form
            <form method="POST" action="/me/security/totp/enroll/confirm">
                <input type="hidden" name="csrf" value=csrf />
                <label for="code">"6-digit code from your app"</label>
                <input id="code" name="code" type="text"
                       inputmode="numeric" pattern="[0-9]{6}"
                       maxlength="6" required
                       autocomplete="one-time-code"
                       aria-describedby="code-hint" />
                <p id="code-hint" class="hint">"Enter the code shown in your authenticator app."</p>
                <button type="submit">"Confirm"</button>
                <a href="/me/security">"Cancel"</a>
            </form>
        </div>
    }
}

#[component]
fn EnrollError(error: String) -> impl IntoView {
    let msg = match error.as_str() {
        "session_expired"   => ("Session expired",
            "Please sign in again.", "/"),
        "totp_unconfigured" => ("TOTP not available",
            "The administrator has not configured TOTP. Contact support.", "/me/security"),
        _ => ("Error",
            "An error occurred setting up two-factor authentication.", "/me/security"),
    };
    view! {
        <div role="alert">
            <h1>{msg.0}</h1>
            <p>{msg.1}</p>
            <p><a href=msg.2>"Go back"</a></p>
        </div>
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DISABLE
// ════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DisableData {
    csrf_token: String,
}

async fn fetch_disable() -> Result<DisableData, String> {
    let resp = gloo_net::http::Request::get("/me/security/totp/disable.json")
        .header("Accept", "application/json")
        .send().await
        .map_err(|e| format!("network: {e}"))?;
    match resp.status() {
        200 => resp.json().await.map_err(|e| format!("parse: {e}")),
        401 | 403 => Err("session_expired".into()),
        s   => Err(format!("http {s}")),
    }
}

/// TOTP disable confirmation page.
#[component]
pub fn TotpDisable() -> impl IntoView {
    let data = LocalResource::new(|| async { fetch_disable().await });

    view! {
        <main aria-label="Disable two-factor authentication">
            <Suspense fallback=|| view! {
                <p aria-busy="true" aria-live="polite">"Loading…"</p>
            }>
                {move || data.get().map(|r| match r {
                    Ok(d)  => view! { <DisableView data=d /> }.into_any(),
                    Err(_) => view! {
                        <div role="alert">
                            <h1>"Session expired"</h1>
                            <p><a href="/">"Sign in again"</a></p>
                        </div>
                    }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

#[component]
fn DisableView(data: DisableData) -> impl IntoView {
    let csrf = data.csrf_token.clone();
    view! {
        <div>
            <h1>"Disable two-factor authentication"</h1>

            <div role="alert" class="warning-box">
                <p>
                    <strong>"Warning:"</strong>
                    " Disabling two-factor authentication reduces your account security. "
                    "Your sign-in will no longer require a code from your authenticator app."
                </p>
            </div>

            <form method="POST" action="/me/security/totp/disable">
                <input type="hidden" name="csrf" value=csrf />
                <button type="submit" class="btn-danger">
                    "Disable two-factor authentication"
                </button>
            </form>

            <p><a href="/me/security">"Cancel"</a></p>
        </div>
    }
}
