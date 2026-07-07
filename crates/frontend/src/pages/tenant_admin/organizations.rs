//! Organisations list — `GET /admin/t/:slug/organizations`.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use cesauth_core::tenancy::types::{Organization, Tenant};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OrgsData { tenant: Tenant, organizations: Vec<Organization>, }

async fn fetch(slug: String) -> Result<OrgsData, String> {
    let r = gloo_net::http::Request::get(&format!("/admin/t/{slug}/organizations.json"))
        .header("Accept", "application/json").send().await.map_err(|e| e.to_string())?;
    match r.status() { 200 => r.json().await.map_err(|e| e.to_string()), _ => Err("error".into()) }
}

#[component]
pub fn TenantOrganizations() -> impl IntoView {
    let params = use_params_map();
    let slug = move || params.with(|p| p.get("slug").unwrap_or_default());
    let data = Resource::new(slug, |s| async move { fetch(s).await });

    view! {
        <main>
            <Suspense fallback=|| view! { <p aria-busy="true">"Loading…"</p> }>
                {move || data.get().map(|r| match r {
                    Ok(d) => view! {
                        <div>
                            <h1>"Organisations — "{d.tenant.display_name.clone()}</h1>
                            <p><a href=format!("/admin/t/{}", d.tenant.slug)>"← Overview"</a></p>
                            <p><a href=format!("/admin/t/{}/organizations/new", d.tenant.slug)>"Create organisation"</a></p>
                            {if d.organizations.is_empty() {
                                view! { <p class="empty">"No organisations yet."</p> }.into_any()
                            } else {
                                view! {
                                    <ul>
                                        <For each=move || d.organizations.clone() key=|o| o.id.clone()
                                            children=move |o| {
                                                let slug2 = d.tenant.slug.clone();
                                                view! {
                                                    <li>
                                                        <a href=format!("/admin/t/{}/organizations/{}", slug2, o.id)>
                                                            {o.display_name.clone()}
                                                        </a>
                                                        " ("{o.slug.clone()}")"
                                                    </li>
                                                }
                                            }
                                        />
                                    </ul>
                                }.into_any()
                            }}
                        </div>
                    }.into_any(),
                    Err(_) => view! { <p role="alert">"Error loading organisations."</p> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}
