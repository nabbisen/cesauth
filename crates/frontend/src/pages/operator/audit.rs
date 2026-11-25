//! Audit log browser (`/admin/console/audit`) — RFC 131 §0 slice 1,
//! converted to a negotiated locale by RFC 185 §5.3 screen 1.
//!
//! **This is the first screen in the project whose language follows the
//! request.** `routes/admin/console/audit.rs::page` resolves `Locale`
//! from `Accept-Language` and emits it as `<html lang>`; this component
//! reads it back once, at mount, via [`crate::app::mounted_locale`] —
//! there is no other channel a CSR component has to learn the locale
//! the server negotiated (D5). `<main lang>` below follows the same
//! value: an element-level `lang` left at a hardcoded `"ja"` would win
//! over `<html lang>` for this component's entire subtree and silently
//! defeat the whole conversion (RFC 185 §5.3 handoff, D4) — there is no
//! build-time signal for that mistake, only a grep for the attribute
//! itself finding nothing hardcoded (§9 assertion 2).
//!
//! Reproduces the pre-`580eeba` server-rendered viewer (`admin/audit.rs`'s
//! `audit_page`, 545 lines, no caller — **deleted at RFC 185 §5.3 screen
//! 1 round 2**, once measured parity closed the gap round 1 found; last
//! present at commit `2ea2758`, `git show 2ea2758:crates/frontend/src/admin/audit.rs`)
//! as a CSR component against `GET /admin/console/audit.json`. Six
//! sections, same order: nav, filter form, export form, schema note,
//! results table, pager.
//!
//! **Stickiness is architectural here, not reconstructed.** The old
//! server-rendered version round-tripped the filter state through the
//! URL query string so a fresh request could re-fill the form; this
//! component keeps the filter inputs as local signals that the fetch
//! never resets, so "sticky after submit" falls out of the CSR model
//! for free — no URL-encoding helper needed (`audit_page`'s own
//! `encode_query_string`/`build_filter_url*` had no counterpart here).
//!
//! **The export form carries a `csrf` hidden field; `audit_page`'s
//! never did.** `POST /admin/console/audit/export` requires one
//! (`crate::csrf::verify` against the `__Host-cesauth-csrf` cookie,
//! `audit_export.rs:34`), and the old template's own `render_export_form`
//! had no csrf parameter to embed one with — a gap in the 545-line
//! specification, invisible until this slice actually drove the form
//! (see the implementation report's parity table, "export form" row).
//!
//! **The export form also carries `since`/`until` as of RFC 131 §0
//! slice 2 deliverable B.** It previously sent only `csrf`/`subject`/
//! `event` — the operator's date-range filter (`from_v`/`to_v`) was
//! silently dropped on export, so "narrow to a period, then export"
//! downloaded everything with nothing on screen saying so. Converted
//! via [`parse_rfc3339_to_unix`] (the same RFC 3339 → Unix-seconds
//! helper the `.json` query already uses) rather than a second parser;
//! an empty or unparseable input omits the field, matching how an
//! unset filter is already treated.
//!
//! **RFC 187 round 2 T6 adds a genuinely new actor filter and column,
//! distinct from the pre-existing (mislabelled) "Subject" one.** The
//! existing `actor_v` signal / `actor=` query parameter / `AuditViewerActorLabel`
//! key have always meant SUBJECT (decision 1, `0.102.0`) — out of this
//! cut's scope to rename (D4/§7). The new filter is `performed_by_v` /
//! `performed_by=` / the freed `AuditViewerActorLabel`/`AuditViewerColActor`
//! names, with the old subject keys renamed to `AuditViewerSubjectLabel`/
//! `AuditViewerColSubject`. **Carried through to the export form too**
//! (`name="performed_by"`) — the same class of bug RFC 131 §0 slice 2
//! deliverable B already found on this exact screen for `since`/`until`:
//! a screen filter missing from the export form downloads silently
//! ignoring it.

use cesauth_core::admin::service::audit_pagination::parse_rfc3339_to_unix;
use cesauth_core::admin::types::PayloadDivergence;
use cesauth_core::i18n::{lookup, Locale, MessageKey};
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};

use crate::app::mounted_locale;

// ─── Data shapes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AuditEntryView {
    ts:      i64,
    kind:    String,
    #[serde(default)]
    subject: Option<String>,
    /// **RFC 187 round 2 T6.** Who performed the action, distinct from
    /// `subject`.
    #[serde(default)]
    actor:   Option<String>,
    #[serde(default)]
    reason:  Option<String>,
    key:     String,
    /// **RFC 188 Phase 2, T4 (G1 ruling, Change 1).** `#[serde(default)]`
    /// guards a transient backend/frontend version skew the same way
    /// `subject`/`actor`/`reason` above do — a brand-new field, same
    /// deployment-rollout concern. Defaults to `PayloadUnreadable`, not
    /// `Clean`: an absent field is missing information, and treating
    /// missing information as "nothing to see" is the sentinel-that-
    /// looks-like-data mistake this project has already ruled against.
    #[serde(default = "default_payload_divergence")]
    diverges_from_payload: PayloadDivergence,
}

fn default_payload_divergence() -> PayloadDivergence {
    PayloadDivergence::PayloadUnreadable
}

#[derive(Debug, Clone, Deserialize)]
struct AuditResponse {
    entries:      Vec<AuditEntryView>,
    csrf_token:   String,
    #[serde(default)]
    older_cursor: Option<String>,
    has_newer:    bool,
    /// **0.110.0-signals-get-readers, F-5.** The deployment's actual
    /// export row cap — `crate::routes::admin::console::resolve_max_rows`,
    /// the same number the export route itself uses. `#[serde(default)]`
    /// guards a transient version-skew response the same way the
    /// tenancy list's new field does; `0` renders no cap line rather
    /// than a wrong one.
    #[serde(default)]
    export_max_rows: u64,
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

fn error_message(error: &str, locale: Locale) -> &'static str {
    if error == "unauthorized" {
        lookup(MessageKey::FetchUnauthorized, locale)
    } else {
        lookup(MessageKey::FetchFailed, locale)
    }
}

/// **0.110.0-signals-get-readers, F-5, required test (4).** `{n}`
/// substitutes the deployment's actual cap — never a literal baked
/// into the string (0.108.0's ruling against copy that restates a
/// code constant).
fn export_cap_note(max_rows: u64, locale: Locale) -> String {
    lookup(MessageKey::AuditViewerExportCapNote, locale).replace("{n}", &max_rows.to_string())
}

/// Build the `audit.json` query string from the current filter + cursor
/// state. Empty fields are omitted, matching the old template's
/// `audit_page::build_filter_url`'s behaviour (an unset filter is
/// absent, not sent as an empty-string match).
///
/// **RFC 187 round 2 T6**: `subject` is the pre-existing filter whose
/// query parameter has always been (mislabelled) `actor` — out of this
/// cut's scope to rename. `performed_by` is the genuinely new filter
/// this round adds, under its own, non-colliding parameter name.
fn build_query(subject: &str, performed_by: &str, event: &str, from: &str, to: &str, cursor: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !subject.is_empty() { parts.push(format!("actor={}", urlencode(subject))); }
    if !performed_by.is_empty() { parts.push(format!("performed_by={}", urlencode(performed_by))); }
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
/// Same restricted safe-set the old template's `audit_page::encode_query_string`
/// used (alphanumerics, `-_.~:+`); anything else is hex-encoded.
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

/// Audit log browser (`/admin/console/audit`)
#[component]
pub fn ConsoleAudit() -> impl IntoView {
    // RFC 185 §5.3 screen 1, D5: read once, at mount, not a reactive
    // signal or context (RFC 180 §5 still bars a reactive locale
    // context) — plain state passed down to every lookup() call below.
    let locale = mounted_locale();

    let actor_v = RwSignal::new(String::new());
    // RFC 187 round 2 T6: the genuinely new actor filter. Named
    // `performed_by_v`, not `actor_v2` or similar — `actor_v` above is
    // the pre-existing SUBJECT filter (its own query parameter has
    // always been, mislabelled, `actor`); this is the real one.
    let performed_by_v = RwSignal::new(String::new());
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
    // F-5: 0 renders no cap line (never a wrong one) until the first
    // successful fetch sets the deployment's real cap.
    let export_max_rows = RwSignal::new(0u64);

    let refresh = move || {
        loading.set(true);
        load_error.set(None);
        let q = build_query(
            &actor_v.get_untracked(), &performed_by_v.get_untracked(), &event_v.get_untracked(),
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
                    export_max_rows.set(r.export_max_rows);
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
        <main lang=locale.bcp47() aria-label=lookup(MessageKey::AuditViewerPageTitle, locale)>
            <h1>{lookup(MessageKey::AuditViewerPageTitle, locale)}</h1>

            // ── render_nav ──────────────────────────────────────────────
            <p>
                <a href="/admin/console">{lookup(MessageKey::OperatorConsoleBackLink, locale)}</a>
                " · "
                <a href="/admin/console/audit/chain">{lookup(MessageKey::AuditViewerChainLink, locale)}</a>
            </p>

            {move || load_error.get().map(|e| view! {
                <p role="alert">{error_message(&e, locale)}</p>
            })}

            // ── render_filter_form ──────────────────────────────────────
            <section aria-label=lookup(MessageKey::AuditViewerSectionTitle, locale)>
                <h2>{lookup(MessageKey::AuditViewerSectionTitle, locale)}</h2>
                <form on:submit=on_filter_submit>
                    <table>
                        <tr>
                            <th scope="row"><label for="audit-subject">{lookup(MessageKey::AuditViewerSubjectLabel, locale)}</label></th>
                            <td>
                                <input id="audit-subject" type="text" placeholder="user-id" style="width:100%"
                                    prop:value=move || actor_v.get()
                                    on:input=move |ev| actor_v.set(event_target_value(&ev)) />
                            </td>
                        </tr>
                        // RFC 187 round 2 T6: the genuinely new actor filter,
                        // its own id/for pair so it cannot be confused with
                        // the subject row above.
                        <tr>
                            <th scope="row"><label for="audit-performed-by">{lookup(MessageKey::AuditViewerActorLabel, locale)}</label></th>
                            <td>
                                <input id="audit-performed-by" type="text" placeholder="user-id" style="width:100%"
                                    prop:value=move || performed_by_v.get()
                                    on:input=move |ev| performed_by_v.set(event_target_value(&ev)) />
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="audit-event">{lookup(MessageKey::AuditViewerEventLabel, locale)}</label></th>
                            <td>
                                <input id="audit-event" type="text" list="audit-event-kinds" placeholder=lookup(MessageKey::AuditViewerEventAny, locale) style="width:100%"
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
                            <th scope="row">{lookup(MessageKey::AuditViewerPeriodLabel, locale)}</th>
                            <td>
                                <label for="audit-from" class="sr-only">{lookup(MessageKey::AuditViewerFromLabel, locale)}</label>
                                <input id="audit-from" type="text" placeholder="1970-01-01T00:00:00Z" style="width:14em"
                                    prop:value=move || from_v.get()
                                    on:input=move |ev| from_v.set(event_target_value(&ev)) />
                                " — "
                                <label for="audit-to" class="sr-only">{lookup(MessageKey::AuditViewerToLabel, locale)}</label>
                                <input id="audit-to" type="text" placeholder="1970-01-01T00:00:00Z" style="width:14em"
                                    prop:value=move || to_v.get()
                                    on:input=move |ev| to_v.set(event_target_value(&ev)) />
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"></th>
                            <td><button type="submit">{lookup(MessageKey::AuditViewerSubmitButton, locale)}</button></td>
                        </tr>
                    </table>
                </form>
            </section>

            // ── render_export_form (csrf field added — see module doc;
            // since/until added RFC 131 §0 slice 2 deliverable B — the
            // operator's date-range filter was silently dropped on export,
            // see this slice's handoff §4) ──
            <section aria-label="export">
                <form method="post" action="/admin/console/audit/export" style="margin-top:8px">
                    <input type="hidden" name="csrf"    prop:value=move || csrf.get() />
                    <input type="hidden" name="subject" prop:value=move || actor_v.get() />
                    // RFC 187 round 2 §4(a): the export form must carry
                    // every screen filter, or the download silently
                    // ignores whichever one is missing — this exact bug
                    // already shipped on this exact screen for
                    // since/until (RFC 131 §0 slice 2 deliverable B, see
                    // this file's own module doc).
                    <input type="hidden" name="performed_by" prop:value=move || performed_by_v.get() />
                    <input type="hidden" name="event"   prop:value=move || event_v.get() />
                    {move || parse_rfc3339_to_unix(&from_v.get())
                        .map(|secs| view! { <input type="hidden" name="since" value=secs.to_string() /> })}
                    {move || parse_rfc3339_to_unix(&to_v.get())
                        .map(|secs| view! { <input type="hidden" name="until" value=secs.to_string() /> })}
                    // "Export CSV"/"Export JSONL" stay English in both
                    // locales deliberately — file-format names, not
                    // natural-language UI (same carve-out as the old
                    // server template's `render_export_form`).
                    // F-5(a): state the cap before the operator clicks,
                    // not after — the best version of "users must not
                    // be confused" is the one where there is nothing to
                    // explain. 0 (not yet fetched) renders nothing.
                    <Show when=move || (export_max_rows.get() > 0)>
                        <p class="note">{move || export_cap_note(export_max_rows.get(), locale)}</p>
                    </Show>
                    <button type="submit" name="format" value="csv" class="secondary" style="margin-right:4px">"Export CSV"</button>
                    <button type="submit" name="format" value="jsonl" class="secondary">"Export JSONL"</button>
                </form>
            </section>

            // ── render_schema_note ───────────────────────────────────────
            <p class="note">{lookup(MessageKey::AuditViewerNoteSchemaTenant, locale)}</p>
            // RFC 188 Phase 2, T4, D4 — the filter residual, read before
            // the results table where a marked row will be seen.
            <p class="note">{lookup(MessageKey::AuditViewerNoteFilterResidual, locale)}</p>

            // ── render_results ───────────────────────────────────────────
            <Show when=move || loading.get()>
                <p aria-busy="true" aria-live="polite">{lookup(MessageKey::FetchLoading, locale)}</p>
            </Show>
            <Show when=move || !loading.get() && load_error.get().is_none()>
                <Show
                    when=move || !entries.get().is_empty()
                    fallback=move || view! { <section aria-label="Results"><div class="empty">{lookup(MessageKey::AuditViewerEmptyState, locale)}</div></section> }
                >
                    <section aria-label="Results">
                        <table>
                            <thead>
                                <tr>
                                    <th scope="col" class="num">{lookup(MessageKey::AuditViewerColTime, locale)}</th>
                                    <th scope="col">{lookup(MessageKey::AuditViewerColSubject, locale)}</th>
                                    <th scope="col">{lookup(MessageKey::AuditViewerColActor, locale)}</th>
                                    <th scope="col">{lookup(MessageKey::AuditViewerColEvent, locale)}</th>
                                    <th scope="col">{lookup(MessageKey::AuditViewerColReason, locale)}</th>
                                    <th scope="col">{lookup(MessageKey::AuditViewerColSeq, locale)}</th>
                                    // RFC 188 Phase 2, T4 (G1-ruled).
                                    <th scope="col">{lookup(MessageKey::AuditViewerColDivergence, locale)}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For
                                    each=move || entries.get()
                                    key=|e| e.key.clone()
                                    children=move |e: AuditEntryView| {
                                        // G1 Change 1: the unreadable marker replaces a
                                        // display field's own value only when the wire
                                        // state says so — never inferred from the field
                                        // being absent (a row that diverges only on a
                                        // column this screen doesn't show can have a
                                        // legitimately-absent subject/actor/reason too).
                                        let unreadable = e.diverges_from_payload == PayloadDivergence::PayloadUnreadable;
                                        let marked = unreadable || e.diverges_from_payload == PayloadDivergence::Diverges;
                                        let field = move |v: Option<String>| if unreadable {
                                            lookup(MessageKey::AuditViewerUnparseableMarker, locale).to_owned()
                                        } else {
                                            v.unwrap_or_else(|| "—".to_owned())
                                        };
                                        view! {
                                            <tr>
                                                <td class="num muted">{cesauth_core::util::format_unix_as_iso8601(e.ts)}</td>
                                                <td class="muted">{field(e.subject.clone())}</td>
                                                <td class="muted">{field(e.actor.clone())}</td>
                                                <td><code>{e.kind.clone()}</code></td>
                                                <td class="muted">{if unreadable { lookup(MessageKey::AuditViewerUnparseableMarker, locale).to_owned() } else { e.reason.clone().unwrap_or_default() }}</td>
                                                <td class="muted">{e.key.clone()}</td>
                                                <td class="muted">
                                                    <Show when=move || marked>
                                                        <span
                                                            title=lookup(MessageKey::AuditViewerDivergenceMarkLabel, locale)
                                                            aria-label=lookup(MessageKey::AuditViewerDivergenceMarkLabel, locale)
                                                        >{lookup(MessageKey::AuditViewerDivergenceMark, locale)}</span>
                                                    </Show>
                                                </td>
                                            </tr>
                                        }
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
                            <a href="#" on:click=on_newer>{lookup(MessageKey::AuditViewerNewerLink, locale)}</a>
                        </Show>
                        <Show when=move || has_newer.get() && older_cursor.get().is_some()>
                            " · "
                        </Show>
                        <Show when=move || older_cursor.get().is_some()>
                            <a href="#" on:click=on_older>{lookup(MessageKey::AuditViewerOlderLink, locale)}</a>
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
        assert_eq!(error_message("unauthorized", Locale::Ja), "権限がありません。再度サインインしてください。");
    }

    #[test]
    fn any_other_error_gets_the_generic_message() {
        assert_eq!(error_message("http 500", Locale::Ja), "読み込みに失敗しました。再読み込みしてください。");
    }

    // RFC 185 §5.3 screen 1 — this screen's own build-time proof that
    // its strings actually come from `lookup(_, locale)` rather than a
    // locale parameter nothing reads: the two locales must disagree.
    // The rendered English screen itself is `observed`/`reviewed`, not
    // `exercised` (no browser here); this is what IS exercised.
    #[test]
    fn export_cap_note_carries_the_actual_cap_not_a_literal() {
        assert!(export_cap_note(10_000, Locale::En).contains("10000"),
            "got: {}", export_cap_note(10_000, Locale::En));
        assert!(export_cap_note(500, Locale::En).contains("500"),
            "a different deployment's cap must render that cap, got: {}", export_cap_note(500, Locale::En));
        assert!(!export_cap_note(500, Locale::En).contains("10000"));
    }

    #[test]
    fn error_message_follows_the_locale_argument() {
        assert_eq!(error_message("unauthorized", Locale::En), "You do not have permission. Please sign in again.");
        assert_eq!(error_message("http 500", Locale::En), "Failed to load. Please reload.");
        assert_ne!(
            error_message("unauthorized", Locale::Ja),
            error_message("unauthorized", Locale::En),
        );
    }

    #[test]
    fn build_query_omits_unset_fields() {
        assert_eq!(build_query("", "", "", "", "", None), "/admin/console/audit.json");
    }

    #[test]
    fn build_query_includes_only_set_fields() {
        assert_eq!(
            build_query("alice", "", "", "", "", None),
            "/admin/console/audit.json?actor=alice",
        );
    }

    #[test]
    fn build_query_includes_the_new_actor_filter_under_its_own_name() {
        // RFC 187 round 2 T6: performed_by is its own parameter, not
        // the pre-existing (mislabelled) "actor" one, which "subject"
        // above already occupies.
        assert_eq!(
            build_query("", "bob", "", "", "", None),
            "/admin/console/audit.json?performed_by=bob",
        );
    }

    #[test]
    fn build_query_includes_every_filter_and_the_cursor() {
        let q = build_query("alice", "bob", "auth_failed", "2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z", Some("abc123"));
        assert_eq!(
            q,
            "/admin/console/audit.json?actor=alice&performed_by=bob&event=auth_failed&from=2025-01-01T00:00:00Z&to=2025-01-02T00:00:00Z&cursor=abc123",
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
