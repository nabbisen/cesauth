//! System console page components (`/admin/console/*`).
//!
//! Converted to a negotiated locale by RFC 185 §5.3 screen 4, following
//! screen 1/3's own pattern exactly: the server resolves `Locale` from
//! `Accept-Language` and emits it as `<html lang>`
//! (`routes/admin/console/{overview,operations_route,tokens,safety,cost,alerts,config}.rs`);
//! each component here reads it back once, at mount, via
//! [`crate::app::mounted_locale`] — there is no other channel a CSR
//! component has to learn the locale the server negotiated (D5). Each
//! `<main lang>` below follows the same value — the same `<main lang>`
//! trap screen 1's handoff named, seven times here, the most of any
//! slice so far.
//!
//! `console/clients.rs` stays pinned to `Locale::Ja` (`0.106.0`'s own
//! body, out of this slice's scope).

use leptos::prelude::*;
use cesauth_core::i18n::{lookup, MessageKey};

use crate::app::mounted_locale;

// ─── Overview (/admin/console) ───────────────────────────────────────────────

/// Console overview (`/admin/console`).
#[component]
pub fn ConsoleOverview() -> impl IntoView {
    let locale = mounted_locale();
    let data = LocalResource::new(|| async {
        gloo_net::http::Request::get("/admin/console.json")
            .header("Accept", "application/json")
            .send().await
            .ok()
            .map(|r| r.status() == 200)
            .unwrap_or(false)
    });

    view! {
        <main lang=locale.bcp47()>
            <h1>{lookup(MessageKey::ConsoleOverviewHeading, locale)}</h1>
            <nav>
                <ul>
                    <li><a href="/admin/tenancy">{lookup(MessageKey::TenancyOverviewPageTitle, locale)}</a></li>
                    <li><a href="/admin/console/operations">{lookup(MessageKey::OperationsTitle, locale)}</a></li>
                    <li><a href="/admin/console/audit">{lookup(MessageKey::AuditViewerPageTitle, locale)}</a></li>
                    <li><a href="/admin/console/safety">{lookup(MessageKey::ConsoleSafetyHeading, locale)}</a></li>
                    <li><a href="/admin/console/cost">{lookup(MessageKey::ConsoleCostPageTitle, locale)}</a></li>
                    <li><a href="/admin/console/tokens">{lookup(MessageKey::TokensTitle, locale)}</a></li>
                    <li><a href="/admin/console/alerts">{lookup(MessageKey::ConsoleAlertsPageTitle, locale)}</a></li>
                    <li><a href="/admin/console/config">{lookup(MessageKey::ConfigTitle, locale)}</a></li>
                </ul>
            </nav>
            <Suspense fallback=move || view! { <p aria-busy="true">{lookup(MessageKey::FetchLoading, locale)}</p> }>
                {move || data.get().map(|ok| if ok {
                    view! { <p class="status-ok">{lookup(MessageKey::ConsoleStatusOk, locale)}</p> }.into_any()
                } else {
                    view! { <p class="status-warn">{lookup(MessageKey::ConsoleStatusCheckFailed, locale)}</p> }.into_any()
                })}
            </Suspense>
        </main>
    }
}

// ─── Operations (/admin/console/operations) ──────────────────────────────────

/// Operations status (`/admin/console/operations`).
#[component]
pub fn ConsoleOperations() -> impl IntoView {
    let locale = mounted_locale();
    view! {
        <main lang=locale.bcp47()>
            <h1>{lookup(MessageKey::OperationsTitle, locale)}</h1>
            <p><a href="/admin/console">{lookup(MessageKey::OperatorConsoleBackLink, locale)}</a></p>
            <p>{lookup(MessageKey::ConsoleOperationsCronNote, locale)}</p>
            <ul>
                <li>"retention_sweep"</li>
                <li>"audit_chain_verify"</li>
                <li>"session_index_audit"</li>
                <li>"session_index_repair"</li>
            </ul>
        </main>
    }
}

// ─── Tokens (/admin/console/tokens) ─────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TokensData { csrf_token: String }

async fn fetch_tokens() -> Result<TokensData, String> {
    let r = gloo_net::http::Request::get("/admin/console/tokens.json")
        .header("Accept", "application/json")
        .send().await.map_err(|e| e.to_string())?;
    match r.status() { 200 => r.json().await.map_err(|e| e.to_string()), _ => Err("error".into()) }
}

/// Admin token list (`/admin/console/tokens`).
#[component]
pub fn ConsoleTokens() -> impl IntoView {
    let locale = mounted_locale();
    let data = LocalResource::new(|| async { fetch_tokens().await });

    view! {
        <main lang=locale.bcp47()>
            <h1>{lookup(MessageKey::TokensTitle, locale)}</h1>
            <p><a href="/admin/console">{lookup(MessageKey::OperatorConsoleBackLink, locale)}</a></p>
            <Suspense fallback=move || view! { <p aria-busy="true">{lookup(MessageKey::FetchLoading, locale)}</p> }>
                {move || data.get().map(|r| match r {
                    Ok(d) => view! {
                        <div>
                            <p><a href="/admin/console/tokens/new">{lookup(MessageKey::ConsoleTokensIssueLink, locale)}</a></p>
                            <form method="POST" action="/admin/console/tokens/disable">
                                <input type="hidden" name="csrf" value=d.csrf_token />
                                <p>{lookup(MessageKey::ConsoleTokensDisableNote, locale)}</p>
                            </form>
                        </div>
                    }.into_any(),
                    Err(_) => view! { <p role="alert">{lookup(MessageKey::GenericErrorOccurred, locale)}</p> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

// ─── Generic placeholder pages ───────────────────────────────────────────────

/// Safety check (`/admin/console/safety`).
#[component]
pub fn ConsoleSafety() -> impl IntoView {
    let locale = mounted_locale();
    view! { <main lang=locale.bcp47()>
        <h1>{lookup(MessageKey::ConsoleSafetyHeading, locale)}</h1>
        <p><a href="/admin/console">{lookup(MessageKey::OperatorConsoleBackLink, locale)}</a></p>
        <p>{lookup(MessageKey::ConsoleNotImplementedNote, locale)}</p>
    </main> }
}

/// Cost (`/admin/console/cost`).
#[component]
pub fn ConsoleCost() -> impl IntoView {
    let locale = mounted_locale();
    view! { <main lang=locale.bcp47()>
        <h1>{lookup(MessageKey::ConsoleCostPageTitle, locale)}</h1>
        <p><a href="/admin/console">{lookup(MessageKey::OperatorConsoleBackLink, locale)}</a></p>
        <p>{lookup(MessageKey::ConsoleNotImplementedNote, locale)}</p>
    </main> }
}

/// Alerts (`/admin/console/alerts`).
#[component]
pub fn ConsoleAlerts() -> impl IntoView {
    let locale = mounted_locale();
    view! { <main lang=locale.bcp47()>
        <h1>{lookup(MessageKey::ConsoleAlertsPageTitle, locale)}</h1>
        <p><a href="/admin/console">{lookup(MessageKey::OperatorConsoleBackLink, locale)}</a></p>
        <p>{lookup(MessageKey::ConsoleNotImplementedNote, locale)}</p>
    </main> }
}

/// Config (`/admin/console/config`).
#[component]
pub fn ConsoleConfig() -> impl IntoView {
    let locale = mounted_locale();
    view! { <main lang=locale.bcp47()>
        <h1>{lookup(MessageKey::ConfigTitle, locale)}</h1>
        <p><a href="/admin/console">{lookup(MessageKey::OperatorConsoleBackLink, locale)}</a></p>
        <p>{lookup(MessageKey::ConsoleNotImplementedNote, locale)}</p>
    </main> }
}
