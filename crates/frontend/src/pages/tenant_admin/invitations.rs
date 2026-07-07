//! Invitations list — `GET /admin/t/:slug/invitations`.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct InvData { csrf_token: String }

async fn fetch(slug: String) -> Result<InvData, String> {
    let r = gloo_net::http::Request::get(&format!("/admin/t/{slug}/invitations.json"))
        .header("Accept","application/json").send().await.map_err(|e|e.to_string())?;
    match r.status() { 200 => r.json().await.map_err(|e|e.to_string()), _ => Err("error".into()) }
}

/// Invitations page (`/admin/t/:slug/invitations`).
#[component]
pub fn TenantInvitations() -> impl IntoView {
    let params = use_params_map();
    let slug = move || params.with(|p| p.get("slug").unwrap_or_default());
    let slug_cloned = slug.clone();
    let data = Resource::new(slug, move |s| async move { fetch(s).await });

    view! {
        <main>
            <Suspense fallback=|| view! { <p aria-busy="true">"Loading…"</p> }>
                {move || data.get().map(|r| match r {
                    Ok(d) => {
                        let s = slug_cloned();
                        let csrf = d.csrf_token.clone();
                        view! {
                            <div>
                                <h1>"Invitations"</h1>
                                <p><a href=format!("/admin/t/{s}")>"← Overview"</a></p>
                                <section>
                                    <h2>"Invite a new user"</h2>
                                    <form method="POST" action=format!("/admin/t/{s}/invitations")>
                                        <input type="hidden" name="csrf" value=csrf />
                                        <label for="inv-email">"Email address"</label>
                                        <input id="inv-email" name="email" type="email" required />
                                        <label for="inv-role">"Role"</label>
                                        <select id="inv-role" name="role">
                                            <option value="member">"Member"</option>
                                            <option value="admin">"Admin"</option>
                                        </select>
                                        <button type="submit">"Send invitation"</button>
                                    </form>
                                </section>
                            </div>
                        }.into_any()
                    },
                    Err(_) => view! { <p role="alert">"Error loading invitations."</p> }.into_any(),
                })}
            </Suspense>
        </main>
    }
}
