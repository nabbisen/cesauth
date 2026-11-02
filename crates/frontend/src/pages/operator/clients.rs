//! OIDC クライアント管理コンソール (`/admin/console/clients`) — RFC 141 cycle 2.
//!
//! ADR-013 準拠: 日本語のみ。ロケールネゴシエーションなし。
//!
//! The backend has been complete since v0.85.0; this is a screen on top of
//! it — list, create, update, rotate-secret, delete, all against JSON
//! endpoints. The four write routes require an `X-CSRF-Token` request
//! header (`crate::csrf::verify_csrf_header` on the backend), not a form
//! field — no existing frontend page does a JSON `fetch()` mutation, every
//! prior CSRF-protected action here is a native `<form method="POST">`, so
//! this is the first of its kind in this crate.
//!
//! **The once-only secret (RFC 141 §4.2/§6.1).** `create` (for a
//! confidential client) and `rotate_secret` are the only two responses that
//! ever carry the plaintext secret. The warning is said twice: once in the
//! create form and the rotate-secret confirmation, *before* the action, and
//! again in [`SecretReveal`] after it — a dismissible panel, not a toast,
//! so it survives a narrow viewport and does not rely on CSS alone to be
//! noticed (a `role="alert"` region plus a `readonly` input the operator
//! can select and copy, not a click-away tooltip).

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};

// ─── Data shapes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ClientView {
    id:                String,
    name:              String,
    client_type:       String,
    redirect_uris:     Vec<String>,
    allowed_scopes:    Vec<String>,
    token_auth_method: String,
    #[serde(default)]
    audience:          Option<String>,
    created_at:        i64,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientsResponse {
    clients:    Vec<ClientView>,
    csrf_token: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CreateResponse {
    client:        ClientView,
    #[serde(default)]
    client_secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RotateResponse {
    client_secret: String,
}

/// What the confirm panel is confirming. Carries the client's own id and
/// name so the panel can name it — RFC 141 cycle 2's own requirement for
/// both irreversible actions.
#[derive(Debug, Clone, PartialEq)]
enum PendingConfirm {
    Delete { id: String, name: String },
    Rotate { id: String, name: String },
}

/// What [`SecretReveal`] is showing. `verb` distinguishes the two call
/// sites in copy only ("作成" vs "再発行").
#[derive(Debug, Clone, PartialEq)]
struct Revealed {
    client_label: String,
    secret:       String,
    verb:         &'static str,
}

// ─── Pure decision helpers (host-testable — see crates/frontend/src/pages/
// tenant_admin/overview.rs's own precedent for why these are pulled out of
// the fetch/view functions that need a real gloo_net::http::Response or a
// reactive signal, neither constructable on host) ──────────────────────────

fn format_created_at(unix: i64) -> String {
    use time::OffsetDateTime;
    OffsetDateTime::from_unix_timestamp(unix)
        .map(|dt| format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            dt.year(), dt.month() as u8, dt.day(), dt.hour(), dt.minute(),
        ))
        .unwrap_or_else(|_| "—".into())
}

fn classify_list_status(status: u16) -> Result<(), String> {
    match status {
        200       => Ok(()),
        401 | 403 => Err("unauthorized".into()),
        s         => Err(format!("http {s}")),
    }
}

fn list_error_message(error: &str) -> &'static str {
    if error == "unauthorized" {
        "権限がありません。再度サインインしてください。"
    } else {
        "読み込みに失敗しました。再読み込みしてください。"
    }
}

/// The four write routes' error bodies are not one shape: the CSRF check
/// and a couple of early field checks return plain text
/// (`Response::error`), while `ClientOpError::Validation` and the rest
/// return `{"error": "..."}` (`op_error_response`). Tries JSON first,
/// falls back to the raw text, falls back to a generic message for an
/// empty body — kept pure (no network type) so this three-way decision is
/// under test on its own, not only indirectly through whichever caller
/// happens to exercise the mutation.
fn error_message_from_body(text: &str) -> String {
    let trimmed = text.trim();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(msg) = v.get("error").and_then(|e| e.as_str()) {
            if !msg.is_empty() {
                return msg.to_owned();
            }
        }
    }
    if trimmed.is_empty() {
        "エラーが発生しました。".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn parse_redirect_uris(raw: &str) -> Vec<String> {
    raw.lines().map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

fn parse_scopes(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_owned).collect()
}

/// A display label that never shows an empty string — an operator-named
/// client with a blank `name` field still needs *something* in a
/// confirmation prompt or a secret-reveal panel's heading.
fn client_label(name: &str, id: &str) -> String {
    if name.trim().is_empty() { id.to_owned() } else { format!("{name} ({id})") }
}

// ─── Network calls ─────────────────────────────────────────────────────────

async fn fetch_clients() -> Result<ClientsResponse, String> {
    let resp = gloo_net::http::Request::get("/admin/console/clients.json")
        .header("Accept", "application/json")
        .send().await
        .map_err(|e| format!("network: {e}"))?;
    classify_list_status(resp.status())?;
    resp.json().await.map_err(|e| format!("parse: {e}"))
}

/// One POST, with the CSRF header every one of the four write routes
/// requires. Returns the raw status and body text — callers decode the
/// body themselves, since a success and a failure respond with different
/// shapes (and a failure isn't always JSON; see `error_message_from_body`).
async fn post_with_csrf(url: &str, csrf: &str, body: &serde_json::Value) -> Result<(u16, String), String> {
    let req = gloo_net::http::Request::post(url)
        .header("X-CSRF-Token", csrf)
        .json(body)
        .map_err(|e| format!("encode: {e}"))?;
    let resp = req.send().await.map_err(|e| format!("network: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    Ok((status, text))
}

// ─── Top-level page component ──────────────────────────────────────────────

/// OIDC クライアント一覧・管理 (`/admin/console/clients`)
#[component]
pub fn ConsoleClients() -> impl IntoView {
    let clients     = RwSignal::new(Vec::<ClientView>::new());
    let csrf        = RwSignal::new(String::new());
    let loading     = RwSignal::new(true);
    let load_error  = RwSignal::new(Option::<String>::None);
    let action_busy = RwSignal::new(false);
    let action_error = RwSignal::new(Option::<String>::None);
    let show_create = RwSignal::new(false);
    let revealed    = RwSignal::new(Option::<Revealed>::None);
    let confirm     = RwSignal::new(Option::<PendingConfirm>::None);

    spawn_local(async move {
        match fetch_clients().await {
            Ok(r) => { clients.set(r.clients); csrf.set(r.csrf_token); }
            Err(e) => load_error.set(Some(e)),
        }
        loading.set(false);
    });

    let refresh = move || {
        spawn_local(async move {
            if let Ok(r) = fetch_clients().await {
                clients.set(r.clients);
                csrf.set(r.csrf_token);
            }
        });
    };

    let on_delete_confirmed = move |id: String, name: String| {
        let token = csrf.get_untracked();
        action_busy.set(true);
        action_error.set(None);
        spawn_local(async move {
            let url = format!("/admin/console/clients/{id}/delete");
            match post_with_csrf(&url, &token, &serde_json::json!({})).await {
                Ok((200, _)) => {
                    clients.update(|cs| cs.retain(|c| c.id != id));
                    confirm.set(None);
                }
                Ok((_, body)) => action_error.set(Some(error_message_from_body(&body))),
                Err(e) => action_error.set(Some(e)),
            }
            action_busy.set(false);
            let _ = &name;
        });
    };

    let on_rotate_confirmed = move |id: String, name: String| {
        let token = csrf.get_untracked();
        action_busy.set(true);
        action_error.set(None);
        spawn_local(async move {
            let url = format!("/admin/console/clients/{id}/rotate-secret");
            match post_with_csrf(&url, &token, &serde_json::json!({})).await {
                Ok((200, body)) => {
                    match serde_json::from_str::<RotateResponse>(&body) {
                        Ok(r) => {
                            revealed.set(Some(Revealed {
                                client_label: client_label(&name, &id),
                                secret: r.client_secret,
                                verb: "再発行",
                            }));
                            confirm.set(None);
                        }
                        Err(_) => action_error.set(Some("応答の解析に失敗しました。".into())),
                    }
                }
                Ok((_, body)) => action_error.set(Some(error_message_from_body(&body))),
                Err(e) => action_error.set(Some(e)),
            }
            action_busy.set(false);
        });
    };

    view! {
        <main lang="ja" aria-label="OIDC クライアント管理">
            <h1>"OIDC クライアント"</h1>
            <p><a href="/admin/console">"← コンソール"</a></p>

            {move || revealed.get().map(|r| view! {
                <SecretReveal revealed=r on_dismiss={move || revealed.set(None)} />
            })}

            {move || load_error.get().map(|e| view! {
                <p role="alert">{list_error_message(&e)}</p>
            })}
            {move || action_error.get().map(|e| view! {
                <p role="alert" class="form-error">{e}</p>
            })}

            {move || confirm.get().map(|c| {
                let busy = action_busy.get();
                match c {
                    PendingConfirm::Delete { id, name } => {
                        let id2 = id.clone();
                        let label = client_label(&name, &id);
                        view! {
                            <div role="alertdialog" aria-label="削除の確認" class="confirm-panel">
                                <p>"クライアント "<strong>{label}</strong>" を削除します。この操作は元に戻せません。"</p>
                                <button type="button" class="btn-danger" disabled=busy
                                    on:click=move |_| on_delete_confirmed(id.clone(), name.clone())>
                                    "削除する"
                                </button>
                                <button type="button" disabled=busy on:click=move |_| confirm.set(None)>"キャンセル"</button>
                                <p class="sr-only">{id2}</p>
                            </div>
                        }.into_any()
                    }
                    PendingConfirm::Rotate { id, name } => {
                        let label = client_label(&name, &id);
                        view! {
                            <div role="alertdialog" aria-label="シークレット再発行の確認" class="confirm-panel">
                                <p>"クライアント "<strong>{label}</strong>" のシークレットを再発行します。"</p>
                                <p role="alert">
                                    "現在のシークレットは直ちに無効になり、このクライアントを使っているすべての"
                                    "連携先が認証できなくなります。新しいシークレットは次の画面で一度だけ表示されます — "
                                    "その場で必ずコピーしてください。後から再度表示することはできません。"
                                </p>
                                <button type="button" class="btn-danger" disabled=busy
                                    on:click=move |_| on_rotate_confirmed(id.clone(), name.clone())>
                                    "再発行する"
                                </button>
                                <button type="button" disabled=busy on:click=move |_| confirm.set(None)>"キャンセル"</button>
                            </div>
                        }.into_any()
                    }
                }
            })}

            <Show when=move || !show_create.get()>
                <p>
                    <button type="button" on:click=move |_| show_create.set(true)>
                        "+ 新しいクライアントを登録"
                    </button>
                </p>
            </Show>

            <Show when=move || show_create.get()>
                <CreateClientForm
                    csrf=csrf
                    on_created={move |new_client: ClientView, secret: Option<String>| {
                        clients.update(|cs| cs.push(new_client.clone()));
                        clients.update(|cs| cs.sort_by(|a, b| a.id.cmp(&b.id)));
                        show_create.set(false);
                        if let Some(secret) = secret {
                            revealed.set(Some(Revealed {
                                client_label: client_label(&new_client.name, &new_client.id),
                                secret,
                                verb: "作成",
                            }));
                        }
                    }}
                    on_cancel={move || show_create.set(false)}
                />
            </Show>

            <Show when=move || loading.get()>
                <p aria-busy="true" aria-live="polite">"読み込み中…"</p>
            </Show>

            <Show when=move || !loading.get() && load_error.get().is_none()>
                <Show
                    when=move || !clients.get().is_empty()
                    fallback=|| view! { <p class="muted">"登録されたクライアントはありません。"</p> }
                >
                    <table>
                        <thead>
                            <tr>
                                <th scope="col">"ID"</th>
                                <th scope="col">"名前"</th>
                                <th scope="col">"種別"</th>
                                <th scope="col">"リダイレクトURI"</th>
                                <th scope="col">"作成日時"</th>
                                <th scope="col"><span class="sr-only">"操作"</span></th>
                            </tr>
                        </thead>
                        <tbody>
                            <For
                                each=move || clients.get()
                                key=|c| c.id.clone()
                                children=move |c: ClientView| view! {
                                    <ClientRow client=c confirm=confirm />
                                }
                            />
                        </tbody>
                    </table>
                </Show>
            </Show>

            <p><button type="button" on:click=move |_| refresh()>"再読み込み"</button></p>
        </main>
    }
}

// ─── Row ────────────────────────────────────────────────────────────────────

#[component]
fn ClientRow(client: ClientView, confirm: RwSignal<Option<PendingConfirm>>) -> impl IntoView {
    let id   = client.id.clone();
    let id2  = client.id.clone();
    let name = client.name.clone();
    let name2 = client.name.clone();
    let is_confidential = client.client_type == "confidential";

    view! {
        <tr>
            <td><code>{client.id.clone()}</code></td>
            <td>{client.name.clone()}</td>
            <td>{if is_confidential { "confidential" } else { "public" }}</td>
            <td>
                <ul>
                    {client.redirect_uris.iter().map(|u| view! { <li><code>{u.clone()}</code></li> }).collect_view()}
                </ul>
            </td>
            <td>{format_created_at(client.created_at)}</td>
            <td>
                <Show when=move || is_confidential>
                    <button type="button"
                        on:click={
                            let id = id.clone(); let name = name.clone();
                            move |_| confirm.set(Some(PendingConfirm::Rotate { id: id.clone(), name: name.clone() }))
                        }
                    >
                        "シークレット再発行"
                    </button>
                </Show>
                <button type="button" class="btn-danger"
                    on:click=move |_| confirm.set(Some(PendingConfirm::Delete { id: id2.clone(), name: name2.clone() }))
                >
                    "削除"
                </button>
            </td>
        </tr>
    }
}

// ─── Once-only secret reveal ────────────────────────────────────────────────

#[component]
fn SecretReveal(revealed: Revealed, on_dismiss: impl Fn() + 'static) -> impl IntoView {
    // A real Leptos event handler, not an inline `onclick="..."` HTML
    // attribute: this deployment's CSP has no 'unsafe-inline' for
    // script-src, and an inline event-handler attribute is blocked the
    // same way an inline `style=` attribute is under style-src — found
    // live, not by reading the policy (RFC 141 cycle 2).
    let select_secret = move |_| {
        use wasm_bindgen::JsCast;
        if let Some(input) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id("revealed-secret"))
            .and_then(|el| el.dyn_into::<web_sys::HtmlInputElement>().ok())
        {
            input.select();
        }
    };

    view! {
        <div role="alert" class="secret-reveal-panel">
            <h2>{format!("クライアント「{}」の{}", revealed.client_label, revealed.verb)}</h2>
            <p>
                <strong>"このシークレットは今だけ表示されます。"</strong>
                " このページを離れると二度と表示できません。今すぐ下の値をコピーしてください。"
            </p>
            <p>
                <label for="revealed-secret">"クライアントシークレット(クリックで選択)"</label><br/>
                <input id="revealed-secret" type="text" readonly=true value=revealed.secret.clone()
                    on:click=select_secret />
            </p>
            <button type="button" on:click=move |_| on_dismiss()>
                "コピーしました — 閉じる"
            </button>
        </div>
    }
}

// ─── Create form ────────────────────────────────────────────────────────────

#[component]
fn CreateClientForm(
    csrf: RwSignal<String>,
    on_created: impl Fn(ClientView, Option<String>) + 'static + Clone,
    on_cancel: impl Fn() + 'static + Clone,
) -> impl IntoView {
    let id_v                = RwSignal::new(String::new());
    let name_v              = RwSignal::new(String::new());
    let client_type_v       = RwSignal::new("public".to_owned());
    let redirect_uris_v     = RwSignal::new(String::new());
    let scopes_v            = RwSignal::new("openid".to_owned());
    let token_auth_method_v = RwSignal::new("none".to_owned());
    let busy                = RwSignal::new(false);
    let error               = RwSignal::new(Option::<String>::None);

    let is_confidential = move || client_type_v.get() == "confidential";

    let on_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        let token = csrf.get_untracked();
        let body = serde_json::json!({
            "id": id_v.get_untracked(),
            "name": name_v.get_untracked(),
            "client_type": client_type_v.get_untracked(),
            "redirect_uris": parse_redirect_uris(&redirect_uris_v.get_untracked()),
            "allowed_scopes": parse_scopes(&scopes_v.get_untracked()),
            "token_auth_method": token_auth_method_v.get_untracked(),
        });
        let on_created = on_created.clone();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match post_with_csrf("/admin/console/clients", &token, &body).await {
                Ok((201, resp_body)) => {
                    match serde_json::from_str::<CreateResponse>(&resp_body) {
                        Ok(r) => on_created(r.client, r.client_secret),
                        Err(_) => error.set(Some("応答の解析に失敗しました。".into())),
                    }
                }
                Ok((_, resp_body)) => error.set(Some(error_message_from_body(&resp_body))),
                Err(e) => error.set(Some(e)),
            }
            busy.set(false);
        });
    };

    view! {
        <form on:submit=on_submit>
            <h2>"新しいクライアントを登録"</h2>
            {move || error.get().map(|e| view! { <p role="alert" class="form-error">{e}</p> })}

            <label for="new-client-id">"クライアントID"</label>
            <input id="new-client-id" type="text" required
                prop:value=move || id_v.get()
                on:input=move |ev| id_v.set(event_target_value(&ev)) />

            <label for="new-client-name">"名前"</label>
            <input id="new-client-name" type="text" required
                prop:value=move || name_v.get()
                on:input=move |ev| name_v.set(event_target_value(&ev)) />

            <label for="new-client-type">"種別"</label>
            <select id="new-client-type"
                on:change=move |ev| {
                    let v = event_target_value(&ev);
                    client_type_v.set(v.clone());
                    token_auth_method_v.set(if v == "confidential" { "client_secret_basic".to_owned() } else { "none".to_owned() });
                }
            >
                <option value="public" selected=move || !is_confidential()>"public"</option>
                <option value="confidential" selected=move || is_confidential()>"confidential"</option>
            </select>

            <Show when=is_confidential>
                <div role="note">
                    <p>
                        "機密クライアント(confidential)を作成すると、シークレットが発行されます。"
                        "シークレットは作成後に一度だけ表示されます — その場で必ずコピーしてください。"
                        "後から再度表示することはできません(再発行は可能です)。"
                    </p>
                    <label for="new-client-tam">"トークン認証方式"</label>
                    <select id="new-client-tam"
                        on:change=move |ev| token_auth_method_v.set(event_target_value(&ev))
                    >
                        <option value="client_secret_basic" selected=move || token_auth_method_v.get() == "client_secret_basic">"client_secret_basic"</option>
                        <option value="client_secret_post" selected=move || token_auth_method_v.get() == "client_secret_post">"client_secret_post"</option>
                    </select>
                </div>
            </Show>

            <label for="new-client-redirects">"リダイレクトURI(1行に1つ)"</label>
            <textarea id="new-client-redirects" required
                prop:value=move || redirect_uris_v.get()
                on:input=move |ev| redirect_uris_v.set(event_target_value(&ev))
            ></textarea>

            <label for="new-client-scopes">"許可スコープ(空白区切り)"</label>
            <input id="new-client-scopes" type="text" required
                prop:value=move || scopes_v.get()
                on:input=move |ev| scopes_v.set(event_target_value(&ev)) />

            <button type="submit" disabled=move || busy.get()>
                {move || if busy.get() { "登録中…" } else { "登録する" }}
            </button>
            <button type="button" disabled=move || busy.get()
                on:click={let on_cancel = on_cancel.clone(); move |_| on_cancel()}>
                "キャンセル"
            </button>
        </form>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_200_is_let_through_to_parse() {
        assert_eq!(classify_list_status(200), Ok(()));
    }

    #[test]
    fn unauthorized_statuses_map_to_the_unauthorized_message() {
        assert_eq!(classify_list_status(401), Err("unauthorized".to_string()));
        assert_eq!(classify_list_status(403), Err("unauthorized".to_string()));
    }

    #[test]
    fn any_other_status_is_witnessed_by_its_own_code() {
        assert_eq!(classify_list_status(500), Err("http 500".to_string()));
    }

    #[test]
    fn unauthorized_error_gets_the_specific_message() {
        assert_eq!(list_error_message("unauthorized"), "権限がありません。再度サインインしてください。");
    }

    #[test]
    fn any_other_error_gets_the_generic_message() {
        assert_eq!(list_error_message("http 500"), "読み込みに失敗しました。再読み込みしてください。");
    }

    // ── error_message_from_body: the three shapes the four write routes
    // actually return (RFC 141 cycle 2's own finding, not hypothetical) ──

    #[test]
    fn json_error_body_extracts_the_message() {
        assert_eq!(
            error_message_from_body(r#"{"error":"id is required"}"#),
            "id is required",
        );
    }

    #[test]
    fn plain_text_error_body_is_used_verbatim() {
        // What the CSRF check and the early field-presence checks return
        // (`Response::error`, not `op_error_response`) -- not JSON at all.
        assert_eq!(
            error_message_from_body("missing or invalid CSRF token"),
            "missing or invalid CSRF token",
        );
    }

    #[test]
    fn empty_body_gets_a_generic_message() {
        assert_eq!(error_message_from_body(""), "エラーが発生しました。");
        assert_eq!(error_message_from_body("   "), "エラーが発生しました。");
    }

    #[test]
    fn json_body_with_no_error_field_falls_back_to_the_raw_text() {
        // Defensive: a shape this cycle's four routes don't actually
        // return, but the parser must not panic or silently swallow it.
        assert_eq!(error_message_from_body(r#"{"ok":true}"#), r#"{"ok":true}"#);
    }

    #[test]
    fn redirect_uris_are_split_on_newlines_and_blank_lines_dropped() {
        assert_eq!(
            parse_redirect_uris("https://a.example/cb\n\nhttps://b.example/cb\n  \n"),
            vec!["https://a.example/cb".to_string(), "https://b.example/cb".to_string()],
        );
    }

    #[test]
    fn scopes_are_split_on_whitespace() {
        assert_eq!(
            parse_scopes("  openid   email  profile "),
            vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
        );
    }

    #[test]
    fn client_label_prefers_the_name_when_present() {
        assert_eq!(client_label("My App", "app-1"), "My App (app-1)");
    }

    #[test]
    fn client_label_falls_back_to_the_id_when_name_is_blank() {
        assert_eq!(client_label("", "app-1"), "app-1");
        assert_eq!(client_label("   ", "app-1"), "app-1");
    }

    #[test]
    fn format_created_at_renders_a_known_timestamp() {
        // 2024-01-01T00:00:00Z
        assert_eq!(format_created_at(1_704_067_200), "2024-01-01 00:00");
    }
}
