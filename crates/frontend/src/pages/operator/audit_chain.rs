//! 監査チェーン検証状況 (`/admin/console/audit/chain`) — RFC 131 §0 slice 2.
//!
//! ADR-013 準拠: 日本語のみ。ロケールネゴシエーションなし。
//!
//! Reproduces `crates/frontend/src/admin/audit_chain.rs`'s
//! `audit_chain_status_page` (280 lines, 6 tests, no caller since
//! `580eeba`) as a CSR component against the new
//! `GET /admin/console/audit/chain.json`. Four blocks, same order:
//! nav back, summary, checkpoint, verify-now form.
//!
//! **The badge logic is copied verbatim, not re-derived** — `badge_html`
//! and `consistency_badge` below match `render_summary`'s five-arm match
//! and `render_checkpoint`'s three-arm match exactly, kept as pure
//! functions for the same reason `audit.rs`'s `classify_status` is pure:
//! host-testable without a reactive signal or a DOM.
//!
//! **The verify-now form posts and lets the server's 302 drive the
//! refetch** — `POST /admin/console/audit/chain/verify` always redirects
//! to `/admin/console/audit/chain` (a full page navigation, not a fetch),
//! so the browser reloads the component and it refetches on mount. That
//! is the intended flow per this slice's handoff, not a defect to work
//! around with a client-side re-fetch after the POST.

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::Deserialize;

// ─── Data shapes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct ChainStatusView {
    current_chain_length:      i64,
    #[serde(default)]
    last_run_at:                Option<i64>,
    #[serde(default)]
    last_run_valid:             Option<bool>,
    #[serde(default)]
    last_run_first_mismatch:    Option<i64>,
    #[serde(default)]
    last_run_checkpoint_match:  Option<bool>,
    #[serde(default)]
    last_run_rows_walked:       Option<u64>,
    #[serde(default)]
    checkpoint_seq:             Option<i64>,
    #[serde(default)]
    checkpoint_chain_hash:      Option<String>,
    #[serde(default)]
    checkpoint_at:              Option<i64>,
    growth_since_checkpoint:    bool,
    csrf_token:                 String,
}

// ─── Pure decision helpers (host-testable — same reason audit.rs's own
// classify_status/error_message are pulled out) ─────────────────────────────

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

/// Mirrors `admin/audit_chain.rs::render_summary`'s badge match exactly —
/// five states, in the same order. `(valid, first_mismatch, checkpoint_match)`.
fn badge_html(valid: Option<bool>, first_mismatch: Option<i64>, checkpoint_match: Option<bool>) -> String {
    match (valid, first_mismatch, checkpoint_match) {
        (None, _, _) => {
            r##"<span class="badge">no runs yet</span>"##.to_owned()
        }
        (Some(true), _, _) => {
            r##"<span class="badge badge--success">✓ chain valid</span>"##.to_owned()
        }
        (Some(false), Some(seq), _) => {
            format!(r##"<span class="badge badge--danger">⛔ tamper detected at seq={seq}</span>"##)
        }
        (Some(false), None, Some(false)) => {
            r##"<span class="badge badge--danger">⛔ chain history mismatch (checkpoint disagrees with current head)</span>"##.to_owned()
        }
        (Some(false), None, _) => {
            r##"<span class="badge badge--danger">⛔ verification failed</span>"##.to_owned()
        }
    }
}

/// RFC 131 §0 slice 2 follow-up §2 — a deliberate improvement over
/// `admin/audit_chain.rs::render_checkpoint`'s consistency match, which
/// has the same bug: `last_run_checkpoint_match: None` has two distinct
/// causes it conflated into one label. True cold start is no checkpoint
/// has ever been recorded (`checkpoint_seq.is_none()`). But a full
/// re-walk — which is all `verify_now` ever does — deliberately skips
/// the cross-check even when a checkpoint already exists
/// (`cesauth_core::audit::verifier`'s own comment on
/// `checkpoint_consistent: None`), so after pressing "verify now" on a
/// store that is not cold at all, the old label said it was. Telling the
/// two apart needs `checkpoint_seq` alongside `checkpoint_match`, which
/// the old function had available in its caller but never consulted for
/// this label.
fn consistency_badge(checkpoint_seq: Option<i64>, checkpoint_match: Option<bool>) -> &'static str {
    match (checkpoint_seq, checkpoint_match) {
        (_, Some(true))  => r##"<span class="badge badge--success">✓ matches current row at seq</span>"##,
        (_, Some(false)) => r##"<span class="badge badge--danger">✗ does NOT match current row at seq (rewrite)</span>"##,
        (None, None)      => r##"<span class="badge">cold start — no cross-check</span>"##,
        (Some(_), None)   => r##"<span class="badge">not applicable — last run was a full re-walk, which always skips the cross-check</span>"##,
    }
}

// ─── Network calls ─────────────────────────────────────────────────────────

async fn fetch_status() -> Result<ChainStatusView, String> {
    let resp = gloo_net::http::Request::get("/admin/console/audit/chain.json")
        .header("Accept", "application/json")
        .send().await
        .map_err(|e| format!("network: {e}"))?;
    classify_status(resp.status())?;
    resp.json().await.map_err(|e| format!("parse: {e}"))
}

// ─── Top-level page component ──────────────────────────────────────────────

/// 監査チェーン検証状況 (`/admin/console/audit/chain`)
#[component]
pub fn ConsoleAuditChain() -> impl IntoView {
    let status      = RwSignal::new(Option::<ChainStatusView>::None);
    let loading      = RwSignal::new(true);
    let load_error   = RwSignal::new(Option::<String>::None);

    spawn_local(async move {
        match fetch_status().await {
            Ok(s)  => status.set(Some(s)),
            Err(e) => load_error.set(Some(e)),
        }
        loading.set(false);
    });

    view! {
        <main lang="ja" aria-label="監査チェーン検証">
            <h1>"監査チェーン検証"</h1>

            // ── nav back ─────────────────────────────────────────────────
            <p><a href="/admin/console/audit">"← 監査ログ"</a></p>

            {move || load_error.get().map(|e| view! {
                <p role="alert">{error_message(&e)}</p>
            })}

            <Show when=move || loading.get()>
                <p aria-busy="true" aria-live="polite">"読み込み中…"</p>
            </Show>

            <Show when=move || !loading.get() && load_error.get().is_none()>
                {move || status.get().map(|s| {
                    let badge = badge_html(s.last_run_valid, s.last_run_first_mismatch, s.last_run_checkpoint_match);
                    let last_run_at = s.last_run_at
                        .map(cesauth_core::util::format_unix_as_iso8601)
                        .unwrap_or_else(|| "—".to_owned());
                    let rows_walked = s.last_run_rows_walked
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "—".to_owned());
                    let growth_hint = s.growth_since_checkpoint;
                    let current_chain_length = s.current_chain_length;

                    let checkpoint_seq    = s.checkpoint_seq;
                    let checkpoint_hash   = s.checkpoint_chain_hash.clone().unwrap_or_default();
                    let checkpoint_at     = s.checkpoint_at
                        .map(cesauth_core::util::format_unix_as_iso8601)
                        .unwrap_or_else(|| "—".to_owned());
                    let consistency = consistency_badge(checkpoint_seq, s.last_run_checkpoint_match);
                    let csrf = s.csrf_token.clone();

                    view! {
                        // ── summary ──────────────────────────────────────
                        <section aria-label="Verification status">
                            <h2>"Status"</h2>
                            <table>
                                <tr><th scope="row">"Status"</th><td inner_html=badge></td></tr>
                                <tr><th scope="row">"Current chain length"</th><td><code>{current_chain_length}</code>" rows (genesis + events)"</td></tr>
                                <tr><th scope="row">"Last verification"</th><td>{last_run_at}</td></tr>
                                <tr><th scope="row">"Rows walked in last run"</th><td><code>{rows_walked}</code></td></tr>
                            </table>
                            <Show when=move || growth_hint>
                                <p class="note">"⏳ New audit events have been appended since the last verification. The next daily cron at 04:00 UTC will walk them; you can also trigger a full re-verify below."</p>
                            </Show>
                        </section>

                        // ── checkpoint ───────────────────────────────────
                        {if checkpoint_seq.is_none() {
                            view! {
                                <section aria-label="Checkpoint">
                                    <h2>"Checkpoint"</h2>
                                    <div class="empty">"No successful verification has completed yet. The first daily cron run will produce a checkpoint."</div>
                                </section>
                            }.into_any()
                        } else {
                            view! {
                                <section aria-label="Checkpoint">
                                    <h2>"Checkpoint"</h2>
                                    <p class="note">"The verifier records the chain head after each successful run. The next run cross-checks the recorded chain_hash against the current row at the same seq — a mismatch indicates wholesale-rewrite tampering."</p>
                                    <table>
                                        <tr><th scope="row">"Last verified seq"</th><td><code>{checkpoint_seq.unwrap_or_default()}</code></td></tr>
                                        <tr><th scope="row">"Recorded chain_hash"</th><td><code>{checkpoint_hash.clone()}</code></td></tr>
                                        <tr><th scope="row">"Recorded at"</th><td>{checkpoint_at.clone()}</td></tr>
                                        <tr><th scope="row">"Consistency"</th><td inner_html=consistency></td></tr>
                                    </table>
                                </section>
                            }.into_any()
                        }}

                        // ── verify-now form ──────────────────────────────
                        <section aria-label="Trigger verification">
                            <h2>"Trigger verification"</h2>
                            <p class="note">"Run a full re-verification right now. Walks the chain from the genesis row, ignoring the existing checkpoint. On success the checkpoint is replaced with the new head. Use after a deploy or whenever you want immediate confirmation."</p>
                            <form method="post" action="/admin/console/audit/chain/verify">
                                <input type="hidden" name="csrf" value=csrf />
                                <button type="submit" class="warning">"Verify chain now (full re-walk)"</button>
                            </form>
                        </section>
                    }
                })}
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
    fn no_runs_yet_badge() {
        assert!(badge_html(None, None, None).contains("no runs yet"));
    }

    #[test]
    fn valid_chain_badge() {
        assert!(badge_html(Some(true), None, Some(true)).contains("✓ chain valid"));
    }

    #[test]
    fn tamper_at_seq_badge() {
        let html = badge_html(Some(false), Some(17), None);
        assert!(html.contains("tamper detected at seq=17"));
        assert!(html.contains("badge--danger"));
    }

    #[test]
    fn chain_history_mismatch_badge() {
        let html = badge_html(Some(false), None, Some(false));
        assert!(html.contains("chain history mismatch"));
        assert!(html.contains("badge--danger"));
    }

    #[test]
    fn verification_failed_badge() {
        let html = badge_html(Some(false), None, None);
        assert!(html.contains("verification failed"));
        assert!(html.contains("badge--danger"));
    }

    #[test]
    fn consistency_cold_start_no_checkpoint_at_all() {
        assert!(consistency_badge(None, None).contains("cold start"));
    }

    #[test]
    fn consistency_not_applicable_after_a_full_rewalk_with_an_existing_checkpoint() {
        // RFC 131 §0 slice 2 follow-up §2 — the defect this slice fixes:
        // a checkpoint exists (268 on the live instance tested), but the
        // last run was a full re-walk, which always skips the cross-check.
        let html = consistency_badge(Some(268), None);
        assert!(html.contains("not applicable"));
        assert!(!html.contains("cold start"),
            "a checkpoint that exists must never be described as cold");
    }

    #[test]
    fn consistency_match() {
        assert!(consistency_badge(Some(42), Some(true)).contains("matches current row at seq"));
    }

    #[test]
    fn consistency_mismatch() {
        let html = consistency_badge(Some(42), Some(false));
        assert!(html.contains("does NOT match"));
        assert!(html.contains("badge--danger"));
    }
}
