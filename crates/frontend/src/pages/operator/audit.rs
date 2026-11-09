//! 監査ログブラウザ (`/admin/console/audit`) — RFC 131 §0 slice 1.
//!
//! ADR-013 準拠: 日本語のみ。ロケールネゴシエーションなし。
//!
//! Reproduces the pre-`580eeba` server-rendered viewer
//! (`crates/frontend/src/admin/audit.rs`'s `audit_page`, 545 lines, no
//! caller — deliberately **not deleted** this slice, see this slice's
//! own handoff §2) as a CSR component against the new
//! `GET /admin/console/audit.json`. Six sections, same order:
//! nav, filter form, export form, schema note, results table, pager.
//!
//! **Stickiness is architectural here, not reconstructed.** The
//! server-rendered version round-tripped the filter state through the
//! URL query string so a fresh request could re-fill the form; this
//! component keeps the filter inputs as local signals that the fetch
//! never resets, so "sticky after submit" falls out of the CSR model
//! for free — no URL-encoding helper needed (`audit_page`'s own
//! `encode_query_string`/`build_filter_url*` have no counterpart here).
//!
//! **The export form carries a `csrf` hidden field; `audit_page`'s
//! never did.** `POST /admin/console/audit/export` requires one
//! (`crate::csrf::verify` against the `__Host-cesauth-csrf` cookie,
//! `audit_export.rs:34`), and the reference implementation's own
//! `render_export_form` has no csrf parameter to embed one with — a
//! gap in the 545-line specification, invisible until this slice
//! actually drives the form (see the implementation report's parity
//! table, "export form" row).

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};

// ─── Data shapes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AuditEntryView {
    ts:      i64,
    kind:    String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    reason:  Option<String>,
    key:     String,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditResponse {
    entries:      Vec<AuditEntryView>,
    csrf_token:   String,
    #[serde(default)]
    older_cursor: Option<String>,
    has_newer:    bool,
}

// ─── Pure decision helpers (host-testable — same reason clients.rs's own
// pulled theirs out: neither a reactive signal nor a gloo_net::http::Response
// is constructable on host) ─────────────────────────────────────────────────

fn classify_status(status: u16) -> Result<(), String> {
    match status {
        200       => Ok(()),
        401 | 403 => Err("unauthorized".into()),
        s         => Err(format!("http {s}")),
    }
}

fn error_message(error: &str) -> &'static str {
    if error == "unauthorized" {
        "権限がありません。再度サインインしてください。"
    } else {
        "読み込みに失敗しました。再読み込みしてください。"
    }
}

/// Build the `audit.json` query string from the current filter + cursor
/// state. Empty fields are omitted, matching `audit_page`'s own
/// `build_filter_url`'s behaviour (an unset filter is absent, not sent
/// as an empty-string match).
fn build_query(actor: &str, event: &str, from: &str, to: &str, cursor: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !actor.is_empty() { parts.push(format!("actor={}", urlencode(actor))); }
    if !event.is_empty() { parts.push(format!("event={}", urlencode(event))); }
    if !from.is_empty()  { parts.push(format!("from={}",  urlencode(from))); }
    if !to.is_empty()    { parts.push(format!("to={}",    urlencode(to))); }
    if let Some(c) = cursor { parts.push(format!("cursor={}", urlencode(c))); }
    if parts.is_empty() {
        "/admin/console/audit.json".to_owned()
    } else {
        format!("/admin/console/audit.json?{}", parts.join("&"))
    }
}

/// Percent-encode the bytes a filter value or cursor can contain.
/// Same restricted safe-set `audit_page`'s own `encode_query_string`
/// uses (alphanumerics, `-_.~:+`); anything else is hex-encoded.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
            b'-' | b'_' | b'.' | b'~' | b':' | b'+' => out.push(*b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ─── Network calls ─────────────────────────────────────────────────────────

async fn fetch_audit(query: &str) -> Result<AuditResponse, String> {
    let resp = gloo_net::http::Request::get(query)
        .header("Accept", "application/json")
        .send().await
        .map_err(|e| format!("network: {e}"))?;
    classify_status(resp.status())?;
    resp.json().await.map_err(|e| format!("parse: {e}"))
}

// ─── Top-level page component ──────────────────────────────────────────────

/// 監査ログブラウザ (`/admin/console/audit`)
#[component]
pub fn ConsoleAudit() -> impl IntoView {
    let actor_v = RwSignal::new(String::new());
    let event_v = RwSignal::new(String::new());
    let from_v  = RwSignal::new(String::new());
    let to_v    = RwSignal::new(String::new());
    let cursor  = RwSignal::new(Option::<String>::None);

    let entries      = RwSignal::new(Vec::<AuditEntryView>::new());
    let csrf         = RwSignal::new(String::new());
    let older_cursor = RwSignal::new(Option::<String>::None);
    let has_newer    = RwSignal::new(false);
    let loading      = RwSignal::new(true);
    let load_error   = RwSignal::new(Option::<String>::None);

    let refresh = move || {
        loading.set(true);
        load_error.set(None);
        let q = build_query(
            &actor_v.get_untracked(), &event_v.get_untracked(),
            &from_v.get_untracked(),  &to_v.get_untracked(),
            cursor.get_untracked().as_deref(),
        );
        spawn_local(async move {
            match fetch_audit(&q).await {
                Ok(r) => {
                    entries.set(r.entries);
                    csrf.set(r.csrf_token);
                    older_cursor.set(r.older_cursor);
                    has_newer.set(r.has_newer);
                }
                Err(e) => load_error.set(Some(e)),
            }
            loading.set(false);
        });
    };

    // Initial load.
    refresh();

    let on_filter_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        cursor.set(None);  // a new filter starts back at the head
        refresh();
    };
    let on_older = move |_| {
        if let Some(c) = older_cursor.get_untracked() {
            cursor.set(Some(c));
            refresh();
        }
    };
    let on_newer = move |_| {
        cursor.set(None);
        refresh();
    };

    view! {
        <main lang="ja" aria-label="監査ログ">
            <h1>"監査ログ"</h1>

            // ── render_nav ──────────────────────────────────────────────
            <p>
                <a href="/admin/console">"← コンソール"</a>
                " · "
                <a href="/admin/console/audit/chain">"チェーン検証状況 →"</a>
            </p>

            {move || load_error.get().map(|e| view! {
                <p role="alert">{error_message(&e)}</p>
            })}

            // ── render_filter_form ──────────────────────────────────────
            <section aria-label="絞り込み">
                <h2>"絞り込み"</h2>
                <form on:submit=on_filter_submit>
                    <table>
                        <tr>
                            <th scope="row"><label for="audit-actor">"実行者"</label></th>
                            <td>
                                <input id="audit-actor" type="text" placeholder="user-id" style="width:100%"
                                    prop:value=move || actor_v.get()
                                    on:input=move |ev| actor_v.set(event_target_value(&ev)) />
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="audit-event">"イベント種別"</label></th>
                            <td>
                                <input id="audit-event" type="text" list="audit-event-kinds" placeholder="(すべて)" style="width:100%"
                                    prop:value=move || event_v.get()
                                    on:input=move |ev| event_v.set(event_target_value(&ev)) />
                                <datalist id="audit-event-kinds">
                                    <option value="auth_success"></option>
                                    <option value="auth_failed"></option>
                                    <option value="session_revoked"></option>
                                    <option value="token_introspected"></option>
                                    <option value="audit_exported"></option>
                                    <option value="admin_console_viewed"></option>
                                </datalist>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">"期間 (UTC)"</th>
                            <td>
                                <label for="audit-from" class="sr-only">"開始"</label>
                                <input id="audit-from" type="text" placeholder="1970-01-01T00:00:00Z" style="width:14em"
                                    prop:value=move || from_v.get()
                                    on:input=move |ev| from_v.set(event_target_value(&ev)) />
                                " — "
                                <label for="audit-to" class="sr-only">"終了"</label>
                                <input id="audit-to" type="text" placeholder="1970-01-01T00:00:00Z" style="width:14em"
                                    prop:value=move || to_v.get()
                                    on:input=move |ev| to_v.set(event_target_value(&ev)) />
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"></th>
                            <td><button type="submit">"絞り込む"</button></td>
                        </tr>
                    </table>
                </form>
            </section>

            // ── render_export_form (csrf field added — see module doc) ──
            <section aria-label="export">
                <form method="post" action="/admin/console/audit/export" style="margin-top:8px">
                    <input type="hidden" name="csrf"    prop:value=move || csrf.get() />
                    <input type="hidden" name="subject" prop:value=move || actor_v.get() />
                    <input type="hidden" name="event"   prop:value=move || event_v.get() />
                    <button type="submit" name="format" value="csv" class="secondary" style="margin-right:4px">"Export CSV"</button>
                    <button type="submit" name="format" value="jsonl" class="secondary">"Export JSONL"</button>
                </form>
            </section>

            // ── render_schema_note ───────────────────────────────────────
            <p class="note">"tenant_id 単位での絞り込みは現在のスキーマでは未提供 (RFC 109 §scope amendments)。"</p>

            // ── render_results ───────────────────────────────────────────
            <Show when=move || loading.get()>
                <p aria-busy="true" aria-live="polite">"読み込み中…"</p>
            </Show>
            <Show when=move || !loading.get() && load_error.get().is_none()>
                <Show
                    when=move || !entries.get().is_empty()
                    fallback=|| view! { <section aria-label="Results"><div class="empty">"条件に合致するイベントはありません。"</div></section> }
                >
                    <section aria-label="Results">
                        <table>
                            <thead>
                                <tr>
                                    <th scope="col" class="num">"時刻"</th>
                                    <th scope="col">"実行者"</th>
                                    <th scope="col">"イベント"</th>
                                    <th scope="col">"詳細"</th>
                                    <th scope="col">"Seq"</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For
                                    each=move || entries.get()
                                    key=|e| e.key.clone()
                                    children=move |e: AuditEntryView| view! {
                                        <tr>
                                            <td class="num muted">{e.ts}</td>
                                            <td class="muted">{e.subject.clone().unwrap_or_else(|| "—".to_owned())}</td>
                                            <td><code>{e.kind.clone()}</code></td>
                                            <td class="muted">{e.reason.clone().unwrap_or_default()}</td>
                                            <td class="muted">{e.key.clone()}</td>
                                        </tr>
                                    }
                                />
                            </tbody>
                        </table>
                    </section>
                </Show>
            </Show>

            // ── render_pager ─────────────────────────────────────────────
            <Show when=move || has_newer.get() || older_cursor.get().is_some()>
                <nav aria-label="pagination">
                    <p>
                        <Show when=move || has_newer.get()>
                            <a href="#" on:click=on_newer>"← 新しい"</a>
                        </Show>
                        <Show when=move || has_newer.get() && older_cursor.get().is_some()>
                            " · "
                        </Show>
                        <Show when=move || older_cursor.get().is_some()>
                            <a href="#" on:click=on_older>"より古い →"</a>
                        </Show>
                    </p>
                </nav>
            </Show>
        </main>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_200_is_let_through() {
        assert_eq!(classify_status(200), Ok(()));
    }

    #[test]
    fn unauthorized_statuses_map_to_the_unauthorized_message() {
        assert_eq!(classify_status(401), Err("unauthorized".to_string()));
        assert_eq!(classify_status(403), Err("unauthorized".to_string()));
    }

    #[test]
    fn any_other_status_is_witnessed_by_its_own_code() {
        assert_eq!(classify_status(500), Err("http 500".to_string()));
    }

    #[test]
    fn unauthorized_error_gets_the_specific_message() {
        assert_eq!(error_message("unauthorized"), "権限がありません。再度サインインしてください。");
    }

    #[test]
    fn any_other_error_gets_the_generic_message() {
        assert_eq!(error_message("http 500"), "読み込みに失敗しました。再読み込みしてください。");
    }

    #[test]
    fn build_query_omits_unset_fields() {
        assert_eq!(build_query("", "", "", "", None), "/admin/console/audit.json");
    }

    #[test]
    fn build_query_includes_only_set_fields() {
        assert_eq!(
            build_query("alice", "", "", "", None),
            "/admin/console/audit.json?actor=alice",
        );
    }

    #[test]
    fn build_query_includes_every_filter_and_the_cursor() {
        let q = build_query("alice", "auth_failed", "2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z", Some("abc123"));
        assert_eq!(
            q,
            "/admin/console/audit.json?actor=alice&event=auth_failed&from=2025-01-01T00:00:00Z&to=2025-01-02T00:00:00Z&cursor=abc123",
        );
    }

    #[test]
    fn urlencode_passes_the_safe_set_through_verbatim() {
        assert_eq!(urlencode("alice-bob_02.test~1:2+3"), "alice-bob_02.test~1:2+3");
    }

    #[test]
    fn urlencode_percent_encodes_everything_else() {
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("a&b"), "a%26b");
    }
}
