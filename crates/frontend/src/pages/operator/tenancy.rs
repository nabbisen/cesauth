//! Tenancy management console components (`/admin/tenancy/*`).
//!
//! Converted to a negotiated locale by RFC 185 §5.3 screen 3, following
//! screen 1's own pattern exactly: the server resolves `Locale` from
//! `Accept-Language` and emits it as `<html lang>`
//! (`routes/admin/tenancy_console/*.rs`); each component here reads it
//! back once, at mount, via [`crate::app::mounted_locale`] — there is no
//! other channel a CSR component has to learn the locale the server
//! negotiated (D5). Each `<main lang>` below follows the same value: an
//! element-level `lang` left at a hardcoded `"ja"` would win over
//! `<html lang>` for that component's entire subtree and silently defeat
//! the conversion (the same `<main lang>` trap screen 1's handoff named,
//! three times here — one per component).

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use cesauth_core::i18n::{lookup, Locale, MessageKey};
use cesauth_core::tenancy::types::Tenant;

use crate::app::mounted_locale;

// ─── Tenancy overview (/admin/tenancy) ───────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
struct OverviewData { tenant_count: usize }

/// Tenancy management overview (`/admin/tenancy`).
#[component]
pub fn TenancyOverview() -> impl IntoView {
    let locale = mounted_locale();
    let data = LocalResource::new(|| async {
        // `Result::and_then` takes a synchronous closure; `.json()` is async,
        // so the fetch/parse must be sequenced with an explicit match rather
        // than chained through `and_then` (RFC 127 R3).
        match gloo_net::http::Request::get("/admin/tenancy.json")
            .header("Accept", "application/json")
            .send().await
        {
            Ok(r)  => r.json::<OverviewData>().await.ok(),
            Err(_) => None,
        }
    });

    view! {
        <main lang=locale.bcp47()>
            <h1>{lookup(MessageKey::TenancyOverviewPageTitle, locale)}</h1>
            <nav>
                <ul>
                    <li><a href="/admin/tenancy/tenants">{lookup(MessageKey::TenancyTenantsPageTitle, locale)}</a></li>
                    <li><a href="/admin/tenancy/tenants/new">{lookup(MessageKey::TenancyCreateTenantLink, locale)}</a></li>
                    <li><a href="/admin/console">{lookup(MessageKey::OperatorConsoleBackLink, locale)}</a></li>
                </ul>
            </nav>
            <Suspense fallback=move || view! { <p aria-busy="true">{lookup(MessageKey::FetchLoading, locale)}</p> }>
                {move || data.get().map(|d| match d {
                    Some(d) => view! {
                        <p>{lookup(MessageKey::TenancyOverviewTenantCountLabel, locale)}" "<strong>{d.tenant_count}</strong></p>
                    }.into_any(),
                    None => view! { <p>{lookup(MessageKey::TenancyOverviewTenantCountFetchFailed, locale)}</p> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

// ─── Tenants list (/admin/tenancy/tenants) ───────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
struct TenantsData { tenants: Vec<Tenant> }

/// Tenant list (`/admin/tenancy/tenants`).
#[component]
pub fn TenancyTenants() -> impl IntoView {
    let locale = mounted_locale();
    let data = LocalResource::new(|| async {
        match gloo_net::http::Request::get("/admin/tenancy/tenants.json")
            .header("Accept", "application/json")
            .send().await
        {
            Ok(r)  => r.json::<TenantsData>().await.ok(),
            Err(_) => None,
        }
    });

    view! {
        <main lang=locale.bcp47()>
            <h1>{lookup(MessageKey::TenancyTenantsPageTitle, locale)}</h1>
            <p><a href="/admin/tenancy">{lookup(MessageKey::TenancyTenantsBackLink, locale)}</a></p>
            <p><a href="/admin/tenancy/tenants/new">{lookup(MessageKey::TenancyCreateTenantLink, locale)}</a></p>
            <Suspense fallback=move || view! { <p aria-busy="true">{lookup(MessageKey::FetchLoading, locale)}</p> }>
                {move || data.get().map(|d| match d {
                    Some(d) if d.tenants.is_empty() => view! {
                        <p>{lookup(MessageKey::TenancyTenantsEmpty, locale)}</p>
                    }.into_any(),
                    Some(d) => view! {
                        <table>
                            <thead><tr>
                                <th>{lookup(MessageKey::TenancyTenantsColSlug, locale)}</th>
                                <th>{lookup(MessageKey::TenancyTenantsColDisplayName, locale)}</th>
                                <th>{lookup(MessageKey::Status, locale)}</th>
                                <th>{lookup(MessageKey::TenantDeletionColActions, locale)}</th>
                            </tr></thead>
                            <tbody>
                                <For each=move || d.tenants.clone()
                                     key=|t| t.id.clone()
                                     children=move |t| view! {
                                         <tr>
                                             <td><code>{t.slug.clone()}</code></td>
                                             <td>{t.display_name.clone()}</td>
                                             <td>{format!("{:?}", t.status)}</td>
                                             <td>
                                                 <a href=format!("/admin/tenancy/tenants/{}", t.id)>
                                                     {lookup(MessageKey::TenancyTenantsRowDetailLink, locale)}
                                                 </a>
                                             </td>
                                         </tr>
                                     }
                                />
                            </tbody>
                        </table>
                    }.into_any(),
                    None => view! { <p role="alert">{lookup(MessageKey::FetchFailed, locale)}</p> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

// ─── Tenant detail (/admin/tenancy/tenants/:tid) ─────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
struct TenantDetailData { csrf_token: String }

/// Tenant detail (`/admin/tenancy/tenants/:tid`).
#[component]
pub fn TenancyTenantDetail() -> impl IntoView {
    let locale = mounted_locale();
    let params = use_params_map();
    let tid = move || params.with(|p| p.get("tid").unwrap_or_default());
    let data = {
        let tid = tid.clone();
        LocalResource::new(move || {
            let tid = tid();
            async move {
                match gloo_net::http::Request::get(&format!("/admin/tenancy/tenants/{tid}/detail.json"))
                    .header("Accept", "application/json")
                    .send().await
                {
                    Ok(r)  => r.json::<TenantDetailData>().await.ok(),
                    Err(_) => None,
                }
            }
        })
    };

    view! {
        <main lang=locale.bcp47()>
            <h1>{lookup(MessageKey::TenancyTenantDetailPageTitle, locale)}</h1>
            <p><a href="/admin/tenancy/tenants">{lookup(MessageKey::TenancyTenantDetailBackLink, locale)}</a></p>
            <Suspense fallback=move || view! { <p aria-busy="true">{lookup(MessageKey::FetchLoading, locale)}</p> }>
                {move || {
                    let t = tid();
                    data.get().map(|d| match d {
                        Some(d) => view! {
                            <div>
                                <section>
                                    <h2>{lookup(MessageKey::TenantDeletionColActions, locale)}</h2>
                                    <ul>
                                        <li>
                                            <a href=format!("/admin/tenancy/tenants/{t}/status")>
                                                {lookup(MessageKey::TenancyTenantDetailStatusChangeLink, locale)}
                                            </a>
                                        </li>
                                        <li>
                                            <a href=format!("/admin/tenancy/tenants/{t}/subscription/history")>
                                                {lookup(MessageKey::TenancyTenantDetailSubscriptionHistoryLink, locale)}
                                            </a>
                                        </li>
                                        <li>
                                            <a href=format!("/admin/tenancy/tenants/{t}/subscription/plan")>
                                                {lookup(MessageKey::TenancyTenantDetailPlanChangeLink, locale)}
                                            </a>
                                        </li>
                                        <li>
                                            <a href=format!("/admin/tenancy/tenants/{t}/memberships/new")>
                                                {lookup(MessageKey::TenancyTenantDetailAddMemberLink, locale)}
                                            </a>
                                        </li>
                                    </ul>
                                </section>
                                <p class="sr-only">"csrf: "{d.csrf_token}</p>
                            </div>
                        }.into_any(),
                        None => view! { <p role="alert">{tenant_detail_fetch_failure_message(locale)}</p> }.into_any(),
                    })
                }}
            </Suspense>
        </main>
    }
}

/// Text `TenancyTenantDetail` shows when its fetch does not succeed --
/// a network error, a non-200 status, or (what the broken
/// `/admin/tenancy/tenants/{tid}.json` URL this RFC fixes actually
/// produced) a 200 whose body isn't `TenantDetailData`-shaped all
/// collapse into `None` via `.ok()`, undistinguished. RFC 162 §2
/// leaves that collapse exactly as it was rather than fixing it in
/// passing; this pins the one thing that IS a decision -- the message
/// itself -- as the witness for what the caller sees when it fails.
/// **RFC 185 §5.3 screen 3, G1 decision §1**: reuses `FetchFailed`
/// rather than this screen's own former wording
/// (`データを取得できませんでした。`).
fn tenant_detail_fetch_failure_message(locale: Locale) -> &'static str {
    lookup(MessageKey::FetchFailed, locale)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_failure_message_is_the_fetch_failed_key() {
        assert_eq!(
            tenant_detail_fetch_failure_message(Locale::Ja),
            lookup(MessageKey::FetchFailed, Locale::Ja),
        );
        assert_eq!(
            tenant_detail_fetch_failure_message(Locale::En),
            lookup(MessageKey::FetchFailed, Locale::En),
        );
    }
}
