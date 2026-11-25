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
use cesauth_core::tenancy::types::{Tenant, TenantStatus};

use crate::app::mounted_locale;

/// **0.110.0-tenancy-console-slice-1, T2 (G1-ruled).** Exhaustive —
/// no `_` arm — so a fifth `TenantStatus` variant is a compile error
/// here rather than a blank cell. `Suspended` reuses
/// `MessageKey::StatusSuspended`: the same fact `SuspendedNotice`
/// already renders, not a new key for an analogous one (G1 decision).
fn tenant_status_key(status: TenantStatus) -> MessageKey {
    match status {
        TenantStatus::Pending   => MessageKey::TenantStatusPending,
        TenantStatus::Active    => MessageKey::TenantStatusActive,
        TenantStatus::Suspended => MessageKey::StatusSuspended,
        TenantStatus::Deleted   => MessageKey::TenantStatusDeleted,
    }
}

/// **D5 — the list's three states**, as a pure function: empty list
/// (200 OK, deployment genuinely has none), a failed fetch (the
/// backend's own error, or a response that doesn't deserialize as
/// `TenantsData` — both collapse to `None` the same way
/// `TenancyTenantDetail`'s fetch already does), or rows. Separated
/// from the component so each state is host-testable without a live
/// fetch (required test 2).
#[derive(Debug, Clone, PartialEq)]
enum TenantsListState {
    Empty,
    FetchFailed,
    Populated(Vec<Tenant>),
}

fn tenants_list_state(data: Option<TenantsData>) -> TenantsListState {
    match data {
        None => TenantsListState::FetchFailed,
        Some(d) if d.tenants.is_empty() => TenantsListState::Empty,
        Some(d) => TenantsListState::Populated(d.tenants),
    }
}

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
                {move || data.get().map(|d| match tenants_list_state(d) {
                    TenantsListState::Empty => view! {
                        <p>{lookup(MessageKey::TenancyTenantsEmpty, locale)}</p>
                    }.into_any(),
                    // D5: a failed read is not an empty deployment —
                    // its own message, never the line above.
                    TenantsListState::FetchFailed => view! {
                        <p role="alert">{lookup(MessageKey::TenancyTenantsFetchFailed, locale)}</p>
                    }.into_any(),
                    TenantsListState::Populated(tenants) => view! {
                        <table>
                            <thead><tr>
                                <th>{lookup(MessageKey::TenancyTenantsColSlug, locale)}</th>
                                <th>{lookup(MessageKey::TenancyTenantsColDisplayName, locale)}</th>
                                <th>{lookup(MessageKey::Status, locale)}</th>
                                <th>{lookup(MessageKey::TenancyTenantsColCreated, locale)}</th>
                                <th>{lookup(MessageKey::ClientsColId, locale)}</th>
                                <th>{lookup(MessageKey::TenantDeletionColActions, locale)}</th>
                            </tr></thead>
                            <tbody>
                                <For each=move || tenants.clone()
                                     key=|t| t.id.clone()
                                     children=move |t| view! {
                                         <tr>
                                             <td><code>{t.slug.clone()}</code></td>
                                             <td>{t.display_name.clone()}</td>
                                             <td>{lookup(tenant_status_key(t.status), locale)}</td>
                                             <td>{cesauth_core::util::format_unix_as_iso8601(t.created_at)}</td>
                                             <td><code>{t.id.clone()}</code></td>
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

    // ── 0.110.0-tenancy-console-slice-1, required test (1): every
    // TenantStatus variant maps to a DISTINCT, non-empty value in both
    // locales — not merely resolvable (the completeness walk already
    // covers that) ───────────────────────────────────────────────────

    const ALL_STATUSES: [TenantStatus; 4] = [
        TenantStatus::Pending, TenantStatus::Active,
        TenantStatus::Suspended, TenantStatus::Deleted,
    ];

    #[test]
    fn every_tenant_status_resolves_to_a_distinct_nonempty_value_in_both_locales() {
        for locale in [Locale::Ja, Locale::En] {
            let mut seen = std::collections::HashSet::new();
            for status in ALL_STATUSES {
                let text = lookup(tenant_status_key(status), locale);
                assert!(!text.is_empty(), "{status:?} in {locale:?} resolved to an empty string");
                assert!(seen.insert(text), "{status:?} in {locale:?} reused a value another status already used: {text:?}");
            }
        }
    }

    // ── required test (2): the three list states, as pure functions ──

    fn tenant(status: TenantStatus) -> Tenant {
        Tenant {
            id: "t-1".to_owned(),
            slug: "acme".to_owned(),
            display_name: "Acme".to_owned(),
            status,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
        }
    }

    #[test]
    fn empty_list_is_the_empty_state() {
        let state = tenants_list_state(Some(TenantsData { tenants: vec![] }));
        assert_eq!(state, TenantsListState::Empty);
    }

    #[test]
    fn a_failed_fetch_is_the_fetch_failed_state_not_empty() {
        // The case that did not exist before D5: a repository error
        // (or any non-`TenantsData`-shaped response) collapses to
        // `None` upstream, same as `TenancyTenantDetail`'s own fetch —
        // and that must render as "could not load", never "no tenants".
        let state = tenants_list_state(None);
        assert_eq!(state, TenantsListState::FetchFailed);
        assert_ne!(state, TenantsListState::Empty);
    }

    #[test]
    fn a_populated_list_carries_its_rows() {
        let rows = vec![tenant(TenantStatus::Active), tenant(TenantStatus::Suspended)];
        let state = tenants_list_state(Some(TenantsData { tenants: rows.clone() }));
        assert_eq!(state, TenantsListState::Populated(rows));
    }
}
