//! Subscription page — `GET /admin/t/:slug/subscription`.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use cesauth_core::tenancy::types::Tenant;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SubData { tenant: Tenant }

async fn fetch_sub(slug: String) -> Result<SubData, String> {
    let r = gloo_net::http::Request::get(&format!("/admin/t/{slug}/subscription.json"))
        .header("Accept","application/json").send().await.map_err(|e|e.to_string())?;
    match r.status() { 200 => r.json().await.map_err(|e|e.to_string()), _ => Err("error".into()) }
}

/// Subscription page (`/admin/t/:slug/subscription`).
#[component]
pub fn TenantSubscription() -> impl IntoView {
    let params = use_params_map();
    let slug = move || params.with(|p| p.get("slug").unwrap_or_default());
    let data = Resource::new(slug, |s| async move { fetch_sub(s).await });

    view! {
        <main>
            <Suspense fallback=|| view! { <p aria-busy="true">"Loading…"</p> }>
                {move || data.get().map(|r| match r {
                    Ok(d) => view! {
                        <div>
                            <h1>"Subscription — "{d.tenant.display_name.clone()}</h1>
                            <p><a href=format!("/admin/t/{}", d.tenant.slug)>"← Overview"</a></p>
                            <p>"Subscription management is handled by the system operator console."</p>
                            <p><a href="/admin/tenancy">"System operator console →"</a></p>
                        </div>
                    }.into_any(),
                    Err(_) => view! { <p role="alert">"Error loading subscription."</p> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}
