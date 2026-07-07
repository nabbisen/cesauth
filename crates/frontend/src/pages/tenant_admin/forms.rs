//! Generic form components for tenant-admin CRUD operations.
//!
//! All these pages have the same structure: fetch `{ csrf_token }` from
//! the `.json` endpoint, render a form that POSTs to the backend, and
//! the backend redirects on success.
//!
//! Using a single generic `AdminForm` component avoids per-page boilerplate.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;

#[derive(Clone, serde::Deserialize)]
struct CsrfData { csrf_token: String }

/// Generic admin form that fetches a CSRF token and renders the given children.
///
/// `json_path` — the `.json` endpoint (e.g. `/admin/t/slug/organizations/new.json`)
/// `form_action` — the POST target
/// `title` — page `<h1>`
#[component]
pub fn AdminCsrfForm(
    json_path:   String,
    form_action: String,
    title:       String,
    #[prop(optional)] back_link: Option<String>,
    children:    Children,
) -> impl IntoView {
    let url = json_path.clone();
    let data = Resource::new(
        move || url.clone(),
        |u| async move {
            gloo_net::http::Request::get(&u)
                .header("Accept", "application/json")
                .send().await
                .map_err(|e| e.to_string())
                .and_then(|r| if r.status() == 200 { Ok(r) } else { Err(format!("http {}", r.status())) })
                // We parse the whole response, but async closures in chains are tricky:
                // this is done inline below in the view.
        }
    );
    // Simpler: fetch synchronously via Resource
    let data2 = Resource::new(move || json_path.clone(), |u| async move {
        let r = gloo_net::http::Request::get(&u).header("Accept","application/json")
            .send().await.map_err(|e| e.to_string())?;
        if r.status() == 200 { r.json::<CsrfData>().await.map_err(|e| e.to_string()) }
        else { Err(format!("http {}", r.status())) }
    });

    let back = back_link.clone();
    view! {
        <main>
            <Suspense fallback=|| view! { <p aria-busy="true">"Loading…"</p> }>
                {move || data2.get().map(|r| match r {
                    Ok(d) => {
                        let csrf = d.csrf_token.clone();
                        view! {
                            <div>
                                <h1>{title.clone()}</h1>
                                {back.clone().map(|b| view! {
                                    <p><a href=b>"← Back"</a></p>
                                })}
                                <form method="POST" action=form_action.clone()>
                                    <input type="hidden" name="csrf" value=csrf />
                                    {children()}
                                </form>
                            </div>
                        }.into_any()
                    },
                    Err(_) => view! {
                        <p role="alert">"Error loading form. Please try again."</p>
                    }.into_any(),
                })}
            </Suspense>
        </main>
    }
}

// ─── Concrete form pages ─────────────────────────────────────────────────────

/// Create organisation form.
#[component]
pub fn NewOrganization() -> impl IntoView {
    let params = use_params_map();
    let slug = params.with_untracked(|p| p.get("slug").unwrap_or_default());
    view! {
        <AdminCsrfForm
            json_path=format!("/admin/t/{slug}/organizations/new.json")
            form_action=format!("/admin/t/{slug}/organizations/new")
            title="Create organisation".to_string()
            back_link=format!("/admin/t/{slug}/organizations")
        >
            <label for="org-slug">"Slug (URL identifier)"</label>
            <input id="org-slug" name="slug" type="text" required pattern="[a-z0-9-]+" />
            <label for="org-name">"Display name"</label>
            <input id="org-name" name="display_name" type="text" required />
            <button type="submit">"Create"</button>
        </AdminCsrfForm>
    }
}

/// Add tenant member form.
#[component]
pub fn AddTenantMember() -> impl IntoView {
    let params = use_params_map();
    let slug = params.with_untracked(|p| p.get("slug").unwrap_or_default());
    view! {
        <AdminCsrfForm
            json_path=format!("/admin/t/{slug}/memberships/new.json")
            form_action=format!("/admin/t/{slug}/memberships")
            title="Add tenant member".to_string()
            back_link=format!("/admin/t/{slug}/users")
        >
            <label for="add-email">"User email"</label>
            <input id="add-email" name="email" type="email" required />
            <label for="add-role">"Role"</label>
            <select id="add-role" name="role">
                <option value="member">"Member"</option>
                <option value="admin">"Admin"</option>
            </select>
            <button type="submit">"Add member"</button>
        </AdminCsrfForm>
    }
}
