//! Chain verification status (`/admin/console/audit/chain`) — RFC 131 §0
//! slice 2, converted to a negotiated locale by RFC 185 §5.3 screen 2.
//!
//! **This is why the gate was widened in RFC 185 §5.2.** Nine of this
//! screen's Japanese strings sat in raw-string HTML (`status_badge`/
//! `consistency_badge`'s markup fragments below) and had been rendering
//! unconverted since `0.97.0`, through two reviews that counted this
//! file's Japanese with a matcher that could not see them — `0.101.0`
//! closed that gap, and this is the screen that gap exists for.
//!
//! `routes/admin/console/audit_chain.rs::page` resolves `Locale` from
//! `Accept-Language` and emits it as `<html lang>`; this component reads
//! it back once, at mount, via [`crate::app::mounted_locale`], same
//! channel as screen 1. `<main lang>` follows the same value for the
//! same reason screen 1's does: an element-level `lang` left hardcoded
//! would win over `<html lang>` for this component's whole subtree with
//! no build-time signal for the mistake.
//!
//! **`status_badge`/`consistency_badge` return `(class, text)`, not
//! HTML.** The pre-conversion versions built raw `<span>` strings and
//! injected them through a raw-markup sink attribute (two of them, on
//! the audit-tamper screen) — not exploitable (the only interpolation was `{seq}`, an
//! `i64`), but removed anyway while every line of both functions was
//! already being touched for i18n, rather than left as the smaller
//! change. The `view!` macro pairs the class with the text natively, so
//! both sinks disappear with no runtime-string HTML left to parse back
//! out of.
//!
//! **The five/four-arm matches are load-bearing and were kept in exact
//! correspondence with the pre-`580eeba` server-rendered template's own
//! `render_summary`/`render_checkpoint`.** `consistency_badge`'s fourth
//! arm (`NotApplicable`, distinct from genuine `ColdStart`) has no
//! template counterpart — it is the `0.97.0` bug fix described on the
//! variant itself: the old single `None` arm conflated "no checkpoint
//! has ever existed" with "a full re-walk always skips the cross-check,"
//! so a non-cold store that had just been fully re-verified was
//! mislabelled as a cold start.
//!
//! Reproduces `admin/audit_chain.rs`'s `audit_chain_status_page` (281
//! lines, 6 tests, no caller since `580eeba` by its own module doc) —
//! **deleted at RFC 185 §5.3 screen 2**, once measured region-by-region
//! parity held; last present at commit `f82122b`,
//! `git show f82122b:crates/frontend/src/admin/audit_chain.rs`.
//! Four blocks, same order: nav back, summary, checkpoint, verify-now
//! form. RFC 184 adds a fifth between summary and checkpoint: an
//! acknowledgement form, shown only while `alarm_needs_acknowledgement`
//! is true.
//!
//! **The verify-now and acknowledge forms post and let the server's 302
//! drive the refetch** — both always redirect back to this page (a full
//! navigation, not a fetch), so the browser reloads the component and it
//! refetches on mount. Intended flow, not a defect to work around with a
//! client-side re-fetch after the POST.
//!
//! `chain_hash` and `seq` stay in English in both locales deliberately —
//! identifiers from the data/API, not prose, the same carve-out slice 1
//! made for `Export CSV`/`Export JSONL`.

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::Deserialize;

use cesauth_core::i18n::{lookup, Locale, MessageKey};

use crate::app::mounted_locale;

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
    last_run_acknowledged:      Option<bool>,
    #[serde(default)]
    checkpoint_seq:             Option<i64>,
    #[serde(default)]
    checkpoint_chain_hash:      Option<String>,
    #[serde(default)]
    checkpoint_at:              Option<i64>,
    growth_since_checkpoint:    bool,
    #[serde(default)]
    column_check_performed:            bool,
    #[serde(default)]
    column_divergence_count:           usize,
    #[serde(default)]
    column_divergences:                Vec<cesauth_core::ports::audit_chain::ColumnDivergence>,
    #[serde(default)]
    column_divergences_acknowledged:   Option<bool>,
    /// **0.110.0-signals-get-readers, F-6.** `Some(run_at)` when a
    /// later walk found the chain clean but was refused permission to
    /// clear the standing alarm above because it is unacknowledged.
    #[serde(default)]
    clean_walk_refused_at:     Option<i64>,
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

fn error_message(error: &str, locale: Locale) -> &'static str {
    if error == "unauthorized" {
        lookup(MessageKey::FetchUnauthorized, locale)
    } else {
        lookup(MessageKey::FetchFailed, locale)
    }
}

/// Mirrors `admin/audit_chain.rs::render_summary`'s badge match exactly —
/// five states, in the same order. `(valid, first_mismatch, checkpoint_match)`.
/// Returns `(css class, text)` rather than an HTML string (RFC 185 §5.3
/// screen 2, D2 — removes the raw-markup sink this function used to
/// feed). `seq` stays as the identifier, not translated.
fn status_badge(valid: Option<bool>, first_mismatch: Option<i64>, checkpoint_match: Option<bool>, locale: Locale) -> (&'static str, String) {
    match (valid, first_mismatch, checkpoint_match) {
        (None, _, _) => {
            ("badge", lookup(MessageKey::AuditChainStatusNoRuns, locale).to_owned())
        }
        (Some(true), _, _) => {
            ("badge badge--success", lookup(MessageKey::AuditChainStatusValid, locale).to_owned())
        }
        (Some(false), Some(seq), _) => {
            ("badge badge--danger", lookup(MessageKey::AuditChainStatusTamperAtSeq, locale).replace("{seq}", &seq.to_string()))
        }
        (Some(false), None, Some(false)) => {
            ("badge badge--danger", lookup(MessageKey::AuditChainStatusHistoryMismatch, locale).to_owned())
        }
        (Some(false), None, _) => {
            ("badge badge--danger", lookup(MessageKey::AuditChainStatusVerificationFailed, locale).to_owned())
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
/// this label. Returns `(css class, text)`, same reason as `status_badge`
/// above (D2). `seq` stays as the identifier, not translated.
fn consistency_badge(checkpoint_seq: Option<i64>, checkpoint_match: Option<bool>, locale: Locale) -> (&'static str, String) {
    match (checkpoint_seq, checkpoint_match) {
        (_, Some(true))  => ("badge badge--success", lookup(MessageKey::AuditChainConsistencyMatch, locale).to_owned()),
        (_, Some(false)) => ("badge badge--danger", lookup(MessageKey::AuditChainConsistencyMismatch, locale).to_owned()),
        (None, None)      => ("badge", lookup(MessageKey::AuditChainConsistencyColdStart, locale).to_owned()),
        (Some(_), None)   => ("badge", lookup(MessageKey::AuditChainConsistencyNotApplicable, locale).to_owned()),
    }
}

/// RFC 184 §3.3 — the console must offer an acknowledgement control
/// exactly when a detected mismatch has not yet been dealt with.
/// `acknowledged` is only meaningful alongside `valid: Some(false)`;
/// any other combination (no run yet, or the chain is currently
/// valid) has nothing to acknowledge.
fn alarm_needs_acknowledgement(valid: Option<bool>, acknowledged: Option<bool>) -> bool {
    valid == Some(false) && acknowledged != Some(true)
}

/// RFC 188 Phase 1, S5's three states for the column cross-check line:
/// not yet checked (this run predates cross-checking, or hasn't reached
/// this row yet), checked and clean, or checked and `n` columns diverge.
/// `performed=false` must win regardless of `divergence_count` — an old
/// stored blob deserializes `column_check_performed` as `false` via
/// `#[serde(default)]`, and an empty divergence list on such a blob must
/// never render as "clean" (the state it would be confused with is the
/// opposite of what happened: no claim was made, not a claim of zero).
/// Returns `(css class, text)`, same reason as `status_badge` above (D2).
fn columns_status_badge(performed: bool, divergence_count: usize, locale: Locale) -> (&'static str, String) {
    match (performed, divergence_count) {
        (false, _) => ("badge", lookup(MessageKey::AuditChainColumnsStatusNotChecked, locale).to_owned()),
        (true, 0)  => ("badge badge--success", lookup(MessageKey::AuditChainColumnsStatusClean, locale).to_owned()),
        (true, n)  => ("badge badge--danger", lookup(MessageKey::AuditChainColumnsStatusDiverging, locale).replace("{n}", &n.to_string())),
    }
}

/// S3's column-class analogue of `alarm_needs_acknowledgement` above —
/// independent of it: a standing chain alarm must not gate whether the
/// columns-class control shows, and vice versa.
fn columns_divergence_needs_acknowledgement(divergence_count: usize, acknowledged: Option<bool>) -> bool {
    divergence_count > 0 && acknowledged != Some(true)
}

/// **0.110.0-signals-get-readers, F-6, required test (3).** Renders
/// only when `refused_at` is `Some` — the standing alarm already has
/// its own badge and acknowledgement control; this is a sentence
/// attached to it, not a state of its own. `{ts}` substitutes the
/// canonical-formatted timestamp, same convention
/// `AuditChainStatusTamperAtSeq`'s `{seq}` already uses.
fn clean_walk_refused_note(refused_at: Option<i64>, locale: Locale) -> Option<String> {
    refused_at.map(|ts| {
        let formatted = cesauth_core::util::format_unix_as_iso8601(ts);
        lookup(MessageKey::AuditChainCleanWalkRefusedNote, locale).replace("{ts}", &formatted)
    })
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

/// Chain verification status (`/admin/console/audit/chain`)
#[component]
pub fn ConsoleAuditChain() -> impl IntoView {
    let locale = mounted_locale();

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
        <main lang=locale.bcp47() aria-label=lookup(MessageKey::AuditChainHeading, locale)>
            <h1>{lookup(MessageKey::AuditChainHeading, locale)}</h1>

            // ── nav back ─────────────────────────────────────────────────
            <p><a href="/admin/console/audit">{lookup(MessageKey::AuditChainNavBack, locale)}</a></p>

            {move || load_error.get().map(|e| view! {
                <p role="alert">{error_message(&e, locale)}</p>
            })}

            <Show when=move || loading.get()>
                <p aria-busy="true" aria-live="polite">{lookup(MessageKey::FetchLoading, locale)}</p>
            </Show>

            <Show when=move || !loading.get() && load_error.get().is_none()>
                {move || status.get().map(|s| {
                    let (status_class, status_text) = status_badge(s.last_run_valid, s.last_run_first_mismatch, s.last_run_checkpoint_match, locale);
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
                    let (consistency_class, consistency_text) = consistency_badge(checkpoint_seq, s.last_run_checkpoint_match, locale);
                    let needs_ack = alarm_needs_acknowledgement(s.last_run_valid, s.last_run_acknowledged);
                    let refused_note = clean_walk_refused_note(s.clean_walk_refused_at, locale);
                    let csrf_verify = s.csrf_token.clone();
                    let csrf_ack    = s.csrf_token.clone();

                    let columns_performed = s.column_check_performed;
                    let columns_count     = s.column_divergence_count;
                    let (columns_class, columns_text) = columns_status_badge(columns_performed, columns_count, locale);
                    let divergences_shown = s.column_divergences.clone();
                    let divergences_more  = columns_count.saturating_sub(divergences_shown.len());
                    let columns_needs_ack = columns_divergence_needs_acknowledgement(columns_count, s.column_divergences_acknowledged);
                    let csrf_columns_ack  = s.csrf_token.clone();

                    view! {
                        // ── summary ──────────────────────────────────────
                        <section aria-label=lookup(MessageKey::AuditChainSummaryTitle, locale)>
                            <h2>{lookup(MessageKey::AuditChainSummaryTitle, locale)}</h2>
                            <table>
                                <tr><th scope="row">{lookup(MessageKey::Status, locale)}</th><td><span class=status_class>{status_text}</span></td></tr>
                                <tr><th scope="row">{lookup(MessageKey::AuditChainColChainLength, locale)}</th><td><code>{current_chain_length}</code>{lookup(MessageKey::AuditChainChainLengthUnit, locale)}</td></tr>
                                <tr><th scope="row">{lookup(MessageKey::AuditChainColLastVerification, locale)}</th><td>{last_run_at}</td></tr>
                                <tr><th scope="row">{lookup(MessageKey::AuditChainColRowsWalked, locale)}</th><td><code>{rows_walked}</code></td></tr>
                            </table>
                            // F-6: beside the standing alarm, not its own
                            // section — renders only when a later clean
                            // walk was refused permission to clear it.
                            {refused_note.clone().map(|note| view! {
                                <p class="note" role="alert">{note}</p>
                            })}
                            <Show when=move || growth_hint>
                                <p class="note">{lookup(MessageKey::AuditChainGrowthHint, locale)}</p>
                            </Show>
                        </section>

                        // ── acknowledgement (RFC 184 §3.3) ───────────────
                        <Show when=move || needs_ack>
                            <section aria-label=lookup(MessageKey::AuditChainAckTitle, locale)>
                                <h2>{lookup(MessageKey::AuditChainAckTitle, locale)}</h2>
                                <p class="note">{lookup(MessageKey::AuditChainAckNote, locale)}</p>
                                <form method="post" action="/admin/console/audit/chain/acknowledge">
                                    <input type="hidden" name="csrf" value=csrf_ack.clone() />
                                    <input type="hidden" name="class" value="chain" />
                                    <button type="submit" class="warning">{lookup(MessageKey::AuditChainAckButton, locale)}</button>
                                </form>
                            </section>
                        </Show>

                        // ── column cross-check (RFC 188 Phase 1) ─────────
                        <section aria-label=lookup(MessageKey::AuditChainColumnsSectionTitle, locale)>
                            <h2>{lookup(MessageKey::AuditChainColumnsSectionTitle, locale)}</h2>
                            <p class="note">{lookup(MessageKey::AuditChainColumnsNote, locale)}</p>
                            <table>
                                <tr><th scope="row">{lookup(MessageKey::Status, locale)}</th><td><span class=columns_class>{columns_text}</span></td></tr>
                            </table>
                            <Show when=move || (columns_count > 0)>
                                <table>
                                    <thead>
                                        <tr>
                                            <th scope="col">{lookup(MessageKey::AuditChainColumnsColRow, locale)}</th>
                                            <th scope="col">{lookup(MessageKey::AuditChainColumnsColColumn, locale)}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {divergences_shown.clone().into_iter().map(|d| view! {
                                            <tr><td><code>{d.seq}</code></td><td><code>{d.column}</code></td></tr>
                                        }).collect_view()}
                                    </tbody>
                                </table>
                                <Show when=move || (divergences_more > 0)>
                                    <p class="note">{lookup(MessageKey::AuditChainColumnsMoreNote, locale).replace("{n}", &divergences_more.to_string())}</p>
                                </Show>
                            </Show>
                            <Show when=move || columns_needs_ack>
                                <section aria-label=lookup(MessageKey::AuditChainColumnsAckTitle, locale)>
                                    <h3>{lookup(MessageKey::AuditChainColumnsAckTitle, locale)}</h3>
                                    <p class="note">{lookup(MessageKey::AuditChainColumnsAckNote, locale)}</p>
                                    <form method="post" action="/admin/console/audit/chain/acknowledge">
                                        <input type="hidden" name="csrf" value=csrf_columns_ack.clone() />
                                        <input type="hidden" name="class" value="columns" />
                                        <button type="submit" class="warning">{lookup(MessageKey::AuditChainColumnsAckButton, locale)}</button>
                                    </form>
                                </section>
                            </Show>
                        </section>

                        // ── checkpoint ───────────────────────────────────
                        {if checkpoint_seq.is_none() {
                            view! {
                                <section aria-label=lookup(MessageKey::AuditChainCheckpointTitle, locale)>
                                    <h2>{lookup(MessageKey::AuditChainCheckpointTitle, locale)}</h2>
                                    <div class="empty">{lookup(MessageKey::AuditChainCheckpointEmpty, locale)}</div>
                                </section>
                            }.into_any()
                        } else {
                            view! {
                                <section aria-label=lookup(MessageKey::AuditChainCheckpointTitle, locale)>
                                    <h2>{lookup(MessageKey::AuditChainCheckpointTitle, locale)}</h2>
                                    <p class="note">{lookup(MessageKey::AuditChainCheckpointNote, locale)}</p>
                                    <table>
                                        <tr><th scope="row">{lookup(MessageKey::AuditChainColLastVerifiedSeq, locale)}</th><td><code>{checkpoint_seq.unwrap_or_default()}</code></td></tr>
                                        <tr><th scope="row">{lookup(MessageKey::AuditChainColRecordedChainHash, locale)}</th><td><code>{checkpoint_hash.clone()}</code></td></tr>
                                        <tr><th scope="row">{lookup(MessageKey::AuditChainColRecordedAt, locale)}</th><td>{checkpoint_at.clone()}</td></tr>
                                        <tr><th scope="row">{lookup(MessageKey::AuditChainColConsistency, locale)}</th><td><span class=consistency_class>{consistency_text}</span></td></tr>
                                    </table>
                                </section>
                            }.into_any()
                        }}

                        // ── verify-now form ──────────────────────────────
                        <section aria-label=lookup(MessageKey::AuditChainVerifyTitle, locale)>
                            <h2>{lookup(MessageKey::AuditChainVerifyTitle, locale)}</h2>
                            <p class="note">{lookup(MessageKey::AuditChainVerifyNote, locale)}</p>
                            <form method="post" action="/admin/console/audit/chain/verify">
                                <input type="hidden" name="csrf" value=csrf_verify />
                                <button type="submit" class="warning">{lookup(MessageKey::AuditChainVerifyButton, locale)}</button>
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

    // ── 0.110.0-signals-get-readers, required test (3): the refusal
    // line renders only when the field is `Some`, and the timestamp
    // substitutes in place ───────────────────────────────────────────

    #[test]
    fn clean_walk_refused_note_is_none_when_nothing_was_refused() {
        assert_eq!(clean_walk_refused_note(None, Locale::En), None);
    }

    #[test]
    fn clean_walk_refused_note_renders_the_timestamp_in_place() {
        let note = clean_walk_refused_note(Some(1_700_000_000), Locale::En).unwrap();
        assert!(note.contains("2023-11-14T22:13:20Z"), "got: {note}");
        assert!(!note.contains("{ts}"), "placeholder must be substituted, got: {note}");
    }

    #[test]
    fn clean_walk_refused_note_says_the_chain_was_clean_not_broken() {
        // The literal fact ("a clean walk was refused") reads as
        // "verification is broken" unless the copy says the opposite
        // explicitly: the walk found the chain CLEAN.
        let note = clean_walk_refused_note(Some(1_700_000_000), Locale::En).unwrap();
        assert!(note.contains("found the chain clean"), "got: {note}");
        assert!(note.contains("not allowed to clear this alarm"), "got: {note}");
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
    fn error_message_follows_the_locale_argument() {
        assert_eq!(error_message("unauthorized", Locale::En), "You do not have permission. Please sign in again.");
        assert_eq!(error_message("http 500", Locale::En), "Failed to load. Please reload.");
        assert_ne!(
            error_message("unauthorized", Locale::Ja),
            error_message("unauthorized", Locale::En),
        );
    }

    #[test]
    fn no_runs_yet_badge() {
        let (_, text) = status_badge(None, None, None, Locale::Ja);
        assert!(text.contains("検証未実行"));
    }

    #[test]
    fn valid_chain_badge() {
        let (_, text) = status_badge(Some(true), None, Some(true), Locale::Ja);
        assert!(text.contains("✓ チェーン正常"));
    }

    #[test]
    fn tamper_at_seq_badge() {
        let (class, text) = status_badge(Some(false), Some(17), None, Locale::Ja);
        assert!(text.contains("seq=17 で改ざんを検出"));
        assert_eq!(class, "badge badge--danger");
    }

    #[test]
    fn chain_history_mismatch_badge() {
        let (class, text) = status_badge(Some(false), None, Some(false), Locale::Ja);
        assert!(text.contains("チェーン履歴の不一致"));
        assert_eq!(class, "badge badge--danger");
    }

    #[test]
    fn verification_failed_badge() {
        let (class, text) = status_badge(Some(false), None, None, Locale::Ja);
        assert!(text.contains("検証失敗"));
        assert_eq!(class, "badge badge--danger");
    }

    #[test]
    fn status_badge_follows_the_locale_argument() {
        let (_, ja) = status_badge(None, None, None, Locale::Ja);
        let (_, en) = status_badge(None, None, None, Locale::En);
        assert_eq!(en, "Not yet verified");
        assert_ne!(ja, en);
    }

    #[test]
    fn consistency_cold_start_no_checkpoint_at_all() {
        let (_, text) = consistency_badge(None, None, Locale::Ja);
        assert!(text.contains("初回実行"));
    }

    #[test]
    fn consistency_not_applicable_after_a_full_rewalk_with_an_existing_checkpoint() {
        // RFC 131 §0 slice 2 follow-up §2 — the defect this slice fixes:
        // a checkpoint exists (268 on the live instance tested), but the
        // last run was a full re-walk, which always skips the cross-check.
        let (_, text) = consistency_badge(Some(268), None, Locale::Ja);
        assert!(text.contains("対象外"));
        assert!(!text.contains("初回実行"),
            "a checkpoint that exists must never be described as a cold start");
    }

    #[test]
    fn consistency_match() {
        let (class, text) = consistency_badge(Some(42), Some(true), Locale::Ja);
        assert!(text.contains("seq の現在行と一致"));
        assert_eq!(class, "badge badge--success");
    }

    #[test]
    fn consistency_mismatch() {
        let (class, text) = consistency_badge(Some(42), Some(false), Locale::Ja);
        assert!(text.contains("不一致"));
        assert_eq!(class, "badge badge--danger");
    }

    #[test]
    fn consistency_badge_follows_the_locale_argument() {
        let (_, ja) = consistency_badge(None, None, Locale::Ja);
        let (_, en) = consistency_badge(None, None, Locale::En);
        assert_eq!(en, "First run — no cross-check");
        assert_ne!(ja, en);
    }

    // ── alarm_needs_acknowledgement (RFC 184 §3.3) ──────────────────────

    #[test]
    fn an_unacknowledged_mismatch_needs_acknowledgement() {
        assert!(alarm_needs_acknowledgement(Some(false), Some(false)));
    }

    #[test]
    fn an_acknowledged_mismatch_does_not_need_it_again() {
        assert!(!alarm_needs_acknowledgement(Some(false), Some(true)));
    }

    #[test]
    fn a_valid_chain_never_needs_acknowledgement() {
        assert!(!alarm_needs_acknowledgement(Some(true), Some(false)));
        assert!(!alarm_needs_acknowledgement(Some(true), None));
    }

    #[test]
    fn no_run_yet_needs_no_acknowledgement() {
        assert!(!alarm_needs_acknowledgement(None, None));
    }

    // ── columns_status_badge / columns_divergence_needs_acknowledgement
    // (RFC 188 Phase 1, S5/S3) ───────────────────────────────────────────

    #[test]
    fn columns_not_checked_badge_wins_regardless_of_count() {
        let (class, text) = columns_status_badge(false, 0, Locale::Ja);
        assert_eq!(class, "badge");
        assert!(text.contains("未チェック"));
        // An old stored blob with no RFC 188 fields deserializes
        // `column_check_performed` as `false` via `#[serde(default)]`
        // and an empty divergence list — must not read as "clean".
        let (class2, text2) = columns_status_badge(false, 0, Locale::En);
        assert_eq!(class2, "badge");
        assert!(text2.contains("Not yet checked"));
    }

    #[test]
    fn columns_clean_badge() {
        let (class, text) = columns_status_badge(true, 0, Locale::En);
        assert_eq!(class, "badge badge--success");
        assert!(text.contains("Columns match payload"));
    }

    #[test]
    fn columns_diverging_badge_substitutes_n() {
        let (class, text) = columns_status_badge(true, 3, Locale::En);
        assert_eq!(class, "badge badge--danger");
        assert!(text.contains("3 column(s) diverge from payload"));
    }

    #[test]
    fn columns_divergence_needing_acknowledgement() {
        assert!(columns_divergence_needs_acknowledgement(1, Some(false)));
        assert!(columns_divergence_needs_acknowledgement(1, None));
        assert!(!columns_divergence_needs_acknowledgement(1, Some(true)));
        assert!(!columns_divergence_needs_acknowledgement(0, None),
            "nothing standing -- nothing to acknowledge");
    }
}
