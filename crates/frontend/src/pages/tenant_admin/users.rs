//! Users list — `GET /admin/t/:slug/users`.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use cesauth_core::tenancy::types::Tenant;
use cesauth_core::types::User;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct UsersData { tenant: Tenant, users: Vec<User>, }

async fn fetch_users(slug: String) -> Result<UsersData, String> {
    let r = gloo_net::http::Request::get(&format!("/admin/t/{slug}/users.json"))
        .header("Accept", "application/json").send().await.map_err(|e| e.to_string())?;
    match r.status() { 200 => r.json().await.map_err(|e| e.to_string()), _ => Err("error".into()) }
}

#[component]
pub fn TenantUsers() -> impl IntoView {
    let params = use_params_map();
    let slug = move || params.with(|p| p.get("slug").unwrap_or_default());
    let data = Resource::new(slug, |s| async move { fetch_users(s).await });

    view! {
        <main>
            <Suspense fallback=|| view! { <p aria-busy="true">"Loading…"</p> }>
                {move || data.get().map(|r| match r {
                    Ok(d) => view! {
                        <div>
                            <h1>"Users — "{d.tenant.display_name.clone()}</h1>
                            <p><a href=format!("/admin/t/{}", d.tenant.slug)>"← Overview"</a></p>
                            <p><a href=format!("/admin/t/{}/memberships/new", d.tenant.slug)>"Add member"</a></p>
                            {if d.users.is_empty() {
                                view! { <p class="empty">"No users yet."</p> }.into_any()
                            } else {
                                view! {
                                    <table>
                                        <thead><tr>
                                            <th>"Email"</th><th>"Status"</th><th>"Type"</th><th>"Actions"</th>
                                        </tr></thead>
                                        <tbody>
                                            <For each=move || d.users.clone() key=|u| u.id.clone()
                                                children=move |u| {
                                                    let slug2 = d.tenant.slug.clone();
                                                    view! {
                                                        <tr>
                                                            <td>{u.email.clone().unwrap_or_default()}</td>
                                                            <td>{format!("{:?}", u.status)}</td>
                                                            <td>{format!("{:?}", u.account_type)}</td>
                                                            <td>
                                                                <a href=format!("/admin/t/{}/users/{}/role_assignments",
                                                                    slug2, u.id)>"Roles"</a>
                                                            </td>
                                                        </tr>
                                                    }
                                                }
                                            />
                                        </tbody>
                                    </table>
                                }.into_any()
                            }}
                        </div>
                    }.into_any(),
                    Err(_) => view! { <p role="alert">"Error loading users."</p> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}
