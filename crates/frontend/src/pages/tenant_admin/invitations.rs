//! Invitations list — `GET /admin/t/:slug/invitations`.

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;

/// **RFC 153.** One row of `GET .../invitations.json`'s `invitations`
/// array — a pending (not yet accepted, not revoked) invitation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct InvitationRow {
    id:         String,
    email:      String,
    role:       String,
    issued_at:  i64,
    expires_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct InvData {
    csrf_token:  String,
    /// **RFC 153.** Before this, the endpoint returned only `csrf_token` —
    /// there was no way to see, or revoke, a pending invitation from this
    /// page at all.
    #[serde(default)]
    invitations: Vec<InvitationRow>,
}

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
    let data = LocalResource::new(move || {
        let s = slug();
        async move { fetch(s).await }
    });

    view! {
        <main>
            <Suspense fallback=|| view! { <p aria-busy="true">"Loading…"</p> }>
                {move || data.get().map(|r| match r {
                    Ok(d) => {
                        let s = slug_cloned();
                        let csrf = d.csrf_token.clone();
                        let csrf_for_rows = csrf.clone();
                        let s_for_rows = s.clone();
                        let invitations = d.invitations.clone();
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
                                <section>
                                    <h2>"Pending invitations"</h2>
                                    {if invitations.is_empty() {
                                        view! { <p>"No pending invitations."</p> }.into_any()
                                    } else {
                                        view! {
                                            <table>
                                                <thead>
                                                    <tr>
                                                        <th scope="col">"Email"</th>
                                                        <th scope="col">"Role"</th>
                                                        <th scope="col"><span class="sr-only">"Actions"</span></th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <For
                                                        each=move || invitations.clone()
                                                        key=|i| i.id.clone()
                                                        children=move |i| {
                                                            let slug = s_for_rows.clone();
                                                            let csrf = csrf_for_rows.clone();
                                                            let revoke_url = format!("/admin/t/{slug}/invitations/{}/revoke", i.id);
                                                            view! {
                                                                <tr>
                                                                    <td>{i.email.clone()}</td>
                                                                    <td>{i.role.clone()}</td>
                                                                    <td>
                                                                        <form method="POST" action=revoke_url>
                                                                            <input type="hidden" name="csrf" value=csrf />
                                                                            <button type="submit" class="btn-danger-small"
                                                                                    aria-label=format!("Revoke invitation to {}", i.email)>
                                                                                "Revoke"
                                                                            </button>
                                                                        </form>
                                                                    </td>
                                                                </tr>
                                                            }
                                                        }
                                                    />
                                                </tbody>
                                            </table>
                                        }.into_any()
                                    }}
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
