//! TOTP page components — migrated in v0.79.4.
//!
//! Three screens:
//! - `TotpEnroll`  — `/me/security/totp/enroll`
//! - `TotpVerify`  — `/me/security/totp/verify`  (2FA gate)
//! - `TotpDisable` — `/me/security/totp/disable`

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
    let data = Resource::new(|| (), |_| async { fetch_enroll().await });

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
// VERIFY (2FA gate)
// ════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct VerifyData {
    csrf_token:  String,
    totp_handle: String,
}

async fn fetch_verify() -> Result<VerifyData, String> {
    let resp = gloo_net::http::Request::get("/me/security/totp/verify.json")
        .header("Accept", "application/json")
        .send().await
        .map_err(|e| format!("network: {e}"))?;
    match resp.status() {
        200 => resp.json().await.map_err(|e| format!("parse: {e}")),
        401 | 403 => Err("gate_expired".into()),
        s   => Err(format!("http {s}")),
    }
}

/// TOTP gate prompt — shown after Magic Link login when TOTP is enabled.
#[component]
pub fn TotpVerify() -> impl IntoView {
    let data = Resource::new(|| (), |_| async { fetch_verify().await });

    view! {
        <main aria-label="Two-factor verification">
            <Suspense fallback=|| view! {
                <p aria-busy="true" aria-live="polite">"Loading…"</p>
            }>
                {move || data.get().map(|r| match r {
                    Ok(d)  => view! { <VerifyForm data=d /> }.into_any(),
                    Err(_) => view! {
                        <div role="alert">
                            <h1>"Verification session expired"</h1>
                            <p><a href="/">"Sign in again"</a></p>
                        </div>
                    }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

#[component]
fn VerifyForm(data: VerifyData) -> impl IntoView {
    // The error signal is set by client-side validation feedback.
    let (error, set_error) = signal(Option::<String>::None);
    let csrf = data.csrf_token.clone();

    view! {
        <div>
            <h1>"Two-factor verification"</h1>
            <p>"Enter the 6-digit code from your authenticator app."</p>

            {move || error.get().map(|e| view! {
                <p role="alert" class="form-error">{e}</p>
            })}

            <form method="POST" action="/me/security/totp/verify">
                <input type="hidden" name="csrf" value=csrf />
                <label for="totp-code">"Authentication code"</label>
                <input id="totp-code" name="code"
                       type="text" inputmode="numeric"
                       pattern="[0-9]{6}" maxlength="6"
                       required autocomplete="one-time-code"
                       on:invalid=move |_| set_error.set(
                           Some("Please enter a 6-digit code.".into())) />
                <button type="submit">"Verify"</button>
            </form>

            <details>
                <summary>"Lost access to your authenticator?"</summary>
                <p>
                    <a href="/me/security/totp/recover">
                        "Use a recovery code"
                    </a>
                </p>
            </details>
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
    let data = Resource::new(|| (), |_| async { fetch_disable().await });

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
