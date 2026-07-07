//! Tenant overview — `GET /admin/t/:slug`.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;

use cesauth_core::tenancy::types::Tenant;
use cesauth_frontend::tenant_admin::overview::TenantOverviewCounts;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OverviewData {
    tenant: Tenant,
    counts: TenantOverviewCounts,
}

async fn fetch(slug: String) -> Result<OverviewData, String> {
    let resp = gloo_net::http::Request::get(
        &format!("/admin/t/{slug}.json"))
        .header("Accept", "application/json")
        .send().await.map_err(|e| e.to_string())?;
    match resp.status() {
        200 => resp.json().await.map_err(|e| e.to_string()),
        401 | 403 => Err("unauthorized".into()),
        s => Err(format!("http {s}")),
    }
}

/// Tenant overview page (`/admin/t/:slug`).
#[component]
pub fn TenantOverview() -> impl IntoView {
    let params = use_params_map();
    let slug = move || params.with(|p| p.get("slug").unwrap_or_default());
    let data = Resource::new(slug, |s| async move { fetch(s).await });

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

#[component]
fn AdminError(error: String) -> impl IntoView {
    view! {
        <div role="alert">
            <h1>"Access denied"</h1>
            <p>{if error == "unauthorized" { "You do not have access to this tenant." } else { "An error occurred." }}</p>
            <p><a href="/admin/tenancy">"Back to tenancy console"</a></p>
        </div>
    }
}
