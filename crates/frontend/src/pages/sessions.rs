//! Sessions page component — `GET /me/security/sessions`.
//!
//! Migrated from the string-template `sessions_page_for` in v0.79.3.
//! The component fetches session data, renders the list with
//! inline revoke forms, and shows a "revoke all others" bulk action.
//!
//! Key UX requirements (from ADR-012 + External Design §S-11):
//! - The current session row is marked "This device" and its revoke
//!   button is disabled — revoking your own session is the logout flow.
//! - Bulk revoke shows a success/error notification after redirect.
//! - Every revoke action posts CSRF + session_id; CSRF is fetched from
//!   the backend together with the session list.

use leptos::prelude::*;

use crate::templates::security_center::SessionListItem;

// ─── API response types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SessionsResponse {
    sessions:           Vec<SessionListItem>,
    current_session_id: String,
    /// Fresh CSRF token minted by the server for the revoke forms.
    csrf_token:         String,
}

// ─── API helper ─────────────────────────────────────────────────────────────

async fn fetch_sessions() -> Result<SessionsResponse, String> {
    let resp = gloo_net::http::Request::get("/me/security/sessions.json")
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("network: {e}"))?;

    match resp.status() {
        200 => resp.json().await.map_err(|e| format!("parse: {e}")),
        401 | 403 => Err("session_expired".into()),
        s => Err(format!("http {s}")),
    }
}

// ─── Top-level page component ────────────────────────────────────────────────

/// Sessions page (`/me/security/sessions`).
#[component]
pub fn Sessions() -> impl IntoView {
    let data = Resource::new(|| (), |_| async { fetch_sessions().await });

    view! {
        <main class="sessions-page" aria-label="Active sessions">
            <Suspense fallback=|| view! {
                <p aria-busy="true" aria-live="polite">"Loading sessions…"</p>
            }>
                {move || data.get().map(|result| match result {
                    Ok(r)  => view! { <SessionsView resp=r /> }.into_any(),
                    Err(e) => view! { <SessionsError error=e /> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

// ─── Session list view ───────────────────────────────────────────────────────

#[component]
fn SessionsView(resp: SessionsResponse) -> impl IntoView {
    let has_others = resp.sessions.iter().any(|s| !s.is_current);
    let csrf = resp.csrf_token.clone();
    let csrf_bulk = csrf.clone();

    view! {
        <div>
            <h1>"Active sessions"</h1>
            <p>
                <a href="/me/security">"← Security centre"</a>
            </p>

            // ── Session table ──────────────────────────────────────────
            <table>
                <thead>
                    <tr>
                        <th scope="col">"Device / method"</th>
                        <th scope="col">"Signed in"</th>
                        <th scope="col">"Last seen"</th>
                        <th scope="col"><span class="sr-only">"Actions"</span></th>
                    </tr>
                </thead>
                <tbody>
                    <For
                        each=move || resp.sessions.clone()
                        key=|s| s.session_id.clone()
                        children=move |s| {
                            let token = csrf.clone();
                            view! { <SessionRow item=s csrf=token /> }
                        }
                    />
                </tbody>
            </table>

            // ── Bulk revoke ────────────────────────────────────────────
            {if has_others {
                view! {
                    <form method="POST" action="/me/security/sessions/revoke-others">
                        <input type="hidden" name="csrf" value=csrf_bulk />
                        <button type="submit" class="btn-danger">
                            "Sign out all other sessions"
                        </button>
                    </form>
                }.into_any()
            } else {
                view! {
                    <p class="muted">"No other active sessions."</p>
                }.into_any()
            }}
        </div>
    }
}

// ─── Session row ─────────────────────────────────────────────────────────────

#[component]
fn SessionRow(item: SessionListItem, csrf: String) -> impl IntoView {
    let method_label = method_label(&item.auth_method);
    let created      = format_ts(item.created_at);
    let last_seen    = format_ts(item.last_seen_at);
    let revoke_url   = format!("/me/security/sessions/{}/revoke", item.session_id);

    view! {
        <tr>
            <td>
                {method_label}
                {if item.is_current {
                    view! { <span class="badge badge-current" aria-label="This session">" (this device)"</span> }.into_any()
                } else {
                    view! { <></> }.into_any()
                }}
            </td>
            <td><time>{created}</time></td>
            <td><time>{last_seen}</time></td>
            <td>
                {if item.is_current {
                    view! {
                        <button disabled aria-disabled="true"
                                title="Use the sign-out link to end this session">
                            "Revoke"
                        </button>
                    }.into_any()
                } else {
                    view! {
                        <form method="POST" action=revoke_url>
                            <input type="hidden" name="csrf" value=csrf />
                            <button type="submit" class="btn-danger-small"
                                    aria-label="Revoke this session">
                                "Revoke"
                            </button>
                        </form>
                    }.into_any()
                }}
            </td>
        </tr>
    }
}

// ─── Error view ──────────────────────────────────────────────────────────────

#[component]
fn SessionsError(error: String) -> impl IntoView {
    if error == "session_expired" {
        view! {
            <div role="alert">
                <h1>"Session expired"</h1>
                <p><a href="/">"Sign in again"</a></p>
            </div>
        }.into_any()
    } else {
        view! {
            <div role="alert">
                <h1>"Unable to load sessions"</h1>
                <p>"Please reload the page."</p>
                <p><a href="/me/security/sessions">"Reload"</a></p>
            </div>
        }.into_any()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn method_label(method: &str) -> &'static str {
    match method {
        "passkey"    => "Passkey",
        "magic_link" => "Email code",
        "admin"      => "Admin token",
        _            => "Unknown",
    }
}

fn format_ts(unix: i64) -> String {
    // Simple human-readable format; a JS `Intl.DateTimeFormat` would
    // give locale-aware output but requires more infrastructure.
    // For now emit ISO-8601 which browsers render reasonably.
    use time::OffsetDateTime;
    OffsetDateTime::from_unix_timestamp(unix)
        .map(|dt| format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            dt.year(), dt.month() as u8, dt.day(),
            dt.hour(), dt.minute(),
        ))
        .unwrap_or_else(|_| "—".into())
}
