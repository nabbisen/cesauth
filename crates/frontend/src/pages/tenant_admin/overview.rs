//! Tenant overview — `GET /admin/t/:slug`.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;

use cesauth_core::tenancy::types::Tenant;
use crate::tenant_admin::TenantOverviewCounts;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OverviewData {
    tenant: Tenant,
    counts: TenantOverviewCounts,
}

/// Pure decision: given the `/detail.json` fetch's HTTP status, does
/// `fetch` go on to parse a body, or fail outright? Kept separate from
/// `fetch` itself (which needs a real `gloo_net::http::Response` —
/// unconstructable on host, same class of issue as `worker::Response`
/// on the backend) so this exact branch is host-testable (RFC 146 §2's
/// precedent) — the "witness for what the caller sees when a secondary
/// operation fails" RFC 162 asks for, at the one point in this function
/// where failure is a *decision*, not just discarded.
fn classify_overview_status(status: u16) -> Result<(), String> {
    match status {
        200 => Ok(()),
        401 | 403 => Err("unauthorized".into()),
        s => Err(format!("http {s}")),
    }
}

async fn fetch(slug: String) -> Result<OverviewData, String> {
    let resp = gloo_net::http::Request::get(
        &format!("/admin/t/{slug}/detail.json"))
        .header("Accept", "application/json")
        .send().await.map_err(|e| e.to_string())?;
    classify_overview_status(resp.status())?;
    resp.json().await.map_err(|e| e.to_string())
}

/// Tenant overview page (`/admin/t/:slug`).
#[component]
pub fn TenantOverview() -> impl IntoView {
    let params = use_params_map();
    let slug = move || params.with(|p| p.get("slug").unwrap_or_default());
    let data = LocalResource::new(move || {
        let s = slug();
        async move { fetch(s).await }
    });

    view! {
        <main aria-label="Tenant overview">
            <Suspense fallback=|| view! { <p aria-busy="true">"Loading…"</p> }>
                {move || data.get().map(|r| match r {
                    Ok(d) => view! {
                        <div>
                            <h1>{d.tenant.display_name.clone()}" — Admin"</h1>
                            <p class="muted">"Tenant slug: " <code>{d.tenant.slug.clone()}</code></p>
                            <section>
                                <h2>"Summary"</h2>
                                <dl class="stat-grid">
                                    <dt>"Users"</dt><dd>{d.counts.users}</dd>
                                    <dt>"Organisations"</dt><dd>{d.counts.organizations}</dd>
                                    <dt>"Groups"</dt><dd>{d.counts.groups}</dd>
                                    {d.counts.current_plan.clone().map(|p| view! {
                                        <dt>"Plan"</dt><dd>{p}</dd>
                                    })}
                                </dl>
                            </section>
                            <nav>
                                <ul>
                                    <li><a href=format!("/admin/t/{}/users", d.tenant.slug)>"Users"</a></li>
                                    <li><a href=format!("/admin/t/{}/organizations", d.tenant.slug)>"Organisations"</a></li>
                                    <li><a href=format!("/admin/t/{}/invitations", d.tenant.slug)>"Invitations"</a></li>
                                    <li><a href=format!("/admin/t/{}/subscription", d.tenant.slug)>"Subscription"</a></li>
                                </ul>
                            </nav>
                        </div>
                    }.into_any(),
                    Err(e) => view! { <AdminError error=e /> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

/// Pure decision: what message `AdminError` shows for a given `fetch`
/// failure string. Same host-testability reasoning as
/// `classify_overview_status` — this is the other half of "what
/// renders when the fetch does not return the expected shape".
fn admin_error_message(error: &str) -> &'static str {
    if error == "unauthorized" {
        "You do not have access to this tenant."
    } else {
        "An error occurred."
    }
}

#[component]
fn AdminError(error: String) -> impl IntoView {
    view! {
        <div role="alert">
            <h1>"Access denied"</h1>
            <p>{admin_error_message(&error)}</p>
            <p><a href="/admin/tenancy">"Back to tenancy console"</a></p>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 162 §2: the URL fix alone doesn't touch this function's
    // behaviour, which already existed — these pin it as the witness
    // for what the caller sees when the fetch does not return the
    // expected shape, not just when it does.

    #[test]
    fn status_200_is_let_through_to_parse() {
        assert_eq!(classify_overview_status(200), Ok(()));
    }

    #[test]
    fn unauthorized_statuses_map_to_the_unauthorized_message() {
        assert_eq!(classify_overview_status(401), Err("unauthorized".to_string()));
        assert_eq!(classify_overview_status(403), Err("unauthorized".to_string()));
    }

    #[test]
    fn any_other_status_is_witnessed_by_its_own_code_not_swallowed() {
        // 404 is not hypothetical: it is exactly what the broken URL this
        // RFC fixes used to return (`/admin/t/<slug>.json`, `:slug`
        // capturing the literal including the `.json` suffix, so no
        // tenant of that name exists).
        assert_eq!(classify_overview_status(404), Err("http 404".to_string()));
        assert_eq!(classify_overview_status(500), Err("http 500".to_string()));
    }

    #[test]
    fn unauthorized_error_gets_the_specific_message() {
        assert_eq!(admin_error_message("unauthorized"), "You do not have access to this tenant.");
    }

    #[test]
    fn any_other_error_gets_the_generic_message() {
        // This is what a visitor actually saw for the broken URL: not
        // "unauthorized" (the 404 never set that string), the generic
        // message -- "Access denied" over a 404 that has nothing to do
        // with access.
        assert_eq!(admin_error_message("http 404"), "An error occurred.");
    }
}
