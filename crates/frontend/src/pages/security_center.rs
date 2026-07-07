//! Security Centre page component — `GET /me/security`.
//!
//! Migrated from the string-template `security_center_page_for` in
//! v0.79.2.  The component fetches its own data via the backend JSON
//! API endpoint (`GET /me/security.json`) rather than relying on the
//! backend to embed state in the HTML shell.
//!
//! ## Data flow
//!
//! ```text
//! Browser
//!   1.  GET /me/security         → backend: verify session,
//!                                  return HTML shell (Leptos)
//!   2.  Leptos mounts, Resource fires
//!   3.  GET /me/security.json    → backend: verify session,
//!                                  return SecurityCenterState JSON
//!   4.  Component renders state
//! ```
//!
//! If step 3 returns 401 / 403 the component renders a "session
//! expired" notice with a link back to `/`.

use leptos::prelude::*;

use crate::templates::security_center::{PrimaryAuthMethod, SecurityCenterState};

// ─── API helper ─────────────────────────────────────────────────────────────

/// Fetch the security-centre state from the backend JSON endpoint.
async fn fetch_state() -> Result<SecurityCenterState, String> {
    let resp = gloo_net::http::Request::get("/me/security.json")
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("network error: {e}"))?;

    match resp.status() {
        200 => resp
            .json::<SecurityCenterState>()
            .await
            .map_err(|e| format!("parse error: {e}")),
        401 | 403 => Err("session_expired".to_owned()),
        status => Err(format!("http {status}")),
    }
}

// ─── Top-level page component ────────────────────────────────────────────────

/// Security Centre page (`/me/security`).
#[component]
pub fn SecurityCenter() -> impl IntoView {
    // Resource fires once on mount and re-fires whenever the signal
    // changes (here it never changes — use signal is the unit type).
    let state = Resource::new(|| (), |_| async { fetch_state().await });

    view! {
        <main class="security-center" aria-label="Security centre">
            <Suspense fallback=|| view! {
                <p aria-busy="true" aria-live="polite">"Loading security status…"</p>
            }>
                {move || state.get().map(|result| match result {
                    Ok(s)  => view! { <SecurityCenterView state=s /> }.into_any(),
                    Err(e) => view! { <SecurityCenterError error=e /> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

// ─── State view ─────────────────────────────────────────────────────────────

#[component]
fn SecurityCenterView(state: SecurityCenterState) -> impl IntoView {
    view! {
        <div class="security-status">
            <h1>"Security"</h1>

            // ── Primary credential ───────────────────────────────────────
            <section aria-labelledby="primary-method-heading">
                <h2 id="primary-method-heading">"Primary sign-in method"</h2>
                <p class="badge badge-primary">
                    {primary_method_label(state.primary_method)}
                </p>
            </section>

            // ── TOTP ─────────────────────────────────────────────────────
            {move || match state.primary_method {
                PrimaryAuthMethod::Anonymous => view! {
                    <section>
                        <p>"TOTP is not available for anonymous accounts."</p>
                    </section>
                }.into_any(),
                _ if state.totp_enabled => view! {
                    <section aria-labelledby="totp-heading">
                        <h2 id="totp-heading">"Two-factor authentication"</h2>
                        <p class="badge badge-ok">"Enabled ✓"</p>
                        <p>
                            <strong>{state.recovery_codes_remaining}</strong>
                            " recovery codes remaining."
                        </p>
                        {low_recovery_notice(state.recovery_codes_remaining)}
                        <p>
                            <a href="/me/security/totp/disable">
                                "Disable two-factor authentication"
                            </a>
                        </p>
                    </section>
                }.into_any(),
                _ => view! {
                    <section aria-labelledby="totp-heading">
                        <h2 id="totp-heading">"Two-factor authentication"</h2>
                        <p class="badge badge-warn">"Not enabled"</p>
                        <p>
                            <a href="/me/security/totp/enroll">
                                "Enable two-factor authentication"
                            </a>
                        </p>
                    </section>
                }.into_any(),
            }}

            // ── Sessions ─────────────────────────────────────────────────
            <section aria-labelledby="sessions-heading">
                <h2 id="sessions-heading">"Active sessions"</h2>
                {match state.active_sessions_count {
                    Some(n) => view! {
                        <p>
                            <strong>{n}</strong>
                            " active session(s). "
                            <a href="/me/security/sessions">"Manage sessions"</a>
                        </p>
                    }.into_any(),
                    None => view! {
                        <p>
                            <a href="/me/security/sessions">"Manage sessions"</a>
                        </p>
                    }.into_any(),
                }}
            </section>

            // ── Actions ──────────────────────────────────────────────────
            <section>
                <form method="POST" action="/logout">
                    <button type="submit">"Sign out"</button>
                </form>
            </section>
        </div>
    }
}

// ─── Error view ──────────────────────────────────────────────────────────────

#[component]
fn SecurityCenterError(error: String) -> impl IntoView {
    if error == "session_expired" {
        view! {
            <div role="alert" class="error-terminal">
                <h1>"Session expired"</h1>
                <p>"Your session has expired or is no longer valid."</p>
                <p><a href="/">"Sign in again"</a></p>
            </div>
        }.into_any()
    } else {
        view! {
            <div role="alert" class="error-terminal">
                <h1>"Unable to load security status"</h1>
                <p>"An error occurred. Please reload the page."</p>
                <p><a href="/me/security">"Reload"</a></p>
            </div>
        }.into_any()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn primary_method_label(method: PrimaryAuthMethod) -> &'static str {
    match method {
        PrimaryAuthMethod::Passkey   => "Passkey (WebAuthn)",
        PrimaryAuthMethod::MagicLink => "Email code",
        PrimaryAuthMethod::Anonymous => "Anonymous trial",
    }
}

fn low_recovery_notice(remaining: u32) -> impl IntoView {
    match remaining {
        0 => view! {
            <p role="alert" class="badge badge-danger">
                "⚠ No recovery codes left. "
                <a href="/me/security/totp/enroll">"Re-enroll TOTP"</a>
                " to generate new codes."
            </p>
        }.into_any(),
        1 => view! {
            <p role="alert" class="badge badge-warn">
                "⚠ Only one recovery code remaining."
            </p>
        }.into_any(),
        _ => view! { <></> }.into_any(),
    }
}
