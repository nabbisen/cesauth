//! Admin console — Audit chain status page (Phase 2 of
//! ADR-010, v0.33.0).
//!
//! `GET /admin/console/audit/chain` renders this. Shows:
//!
//! - The current chain head (length).
//! - The most-recent verification result with status badge
//!   (✓ valid / ⚠ tamper / no runs yet).
//! - The recorded checkpoint (last verified seq + chain_hash
//!   + when).
//! - "Growth since checkpoint" hint if rows have been appended
//!   since the last verification.
//! - A POST form to `/admin/console/audit/chain/verify` for an
//!   operator-triggered full re-verify.
//!
//! Tamper alarms render with the `flash--danger` token so the
//! visual treatment matches the rest of the admin surface.

use crate::escape;
use cesauth_core::admin::types::{AdminPrincipal, AuditChainStatus};

use super::frame::{admin_frame, Tab};

pub fn audit_chain_status_page(
    principal: &AdminPrincipal,
    status:    &AuditChainStatus,
    csrf:      &str,
) -> String {
    let body = format!(
        "{nav_back}\n{summary}\n{checkpoint}\n{verify_form}",
        nav_back    = nav_back(),
        summary     = render_summary(status),
        checkpoint  = render_checkpoint(status),
        verify_form = render_verify_form(csrf),
    );
    admin_frame(
        "Audit chain — verification status",
        principal.role,
        principal.name.as_deref(),
        Tab::Audit,
        &body,
    )
}

fn nav_back() -> String {
    r##"<p><a href="/admin/console/audit">← Audit log search</a></p>"##.to_owned()
}

fn render_summary(s: &AuditChainStatus) -> String {
    let badge = match (s.last_run_valid, s.last_run_first_mismatch, s.last_run_checkpoint_match) {
        (None, _, _) => {
            r##"<span class="badge">no runs yet</span>"##.to_owned()
        }
        (Some(true), _, _) => {
            r##"<span class="badge badge--success">✓ chain valid</span>"##.to_owned()
        }
        (Some(false), Some(seq), _) => {
            format!(
                r##"<span class="badge badge--danger">⛔ tamper detected at seq={seq}</span>"##,
            )
        }
        (Some(false), None, Some(false)) => {
            // Wholesale rewrite — no internal mismatch but the
            // checkpoint cross-check failed. The verifier has no
            // single seq to point at, so we phrase this as a
            // chain-history mismatch.
            r##"<span class="badge badge--danger">⛔ chain history mismatch (checkpoint disagrees with current head)</span>"##.to_owned()
        }
        (Some(false), None, _) => {
            r##"<span class="badge badge--danger">⛔ verification failed</span>"##.to_owned()
        }
    };

    let last_run_at = s.last_run_at
        .map(|t| escape(&format_unix(t)))
        .unwrap_or_else(|| "—".to_owned());

    let rows_walked = s.last_run_rows_walked
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".to_owned());

    let growth_hint = if s.growth_since_checkpoint {
        r##"<p class="note">⏳ New audit events have been appended since the last verification. The next daily cron at 04:00 UTC will walk them; you can also trigger a full re-verify below.</p>"##
    } else {
        ""
    };

    format!(
        r##"<section aria-label="Verification status">
  <h2>Status</h2>
  <table>
    <tr><th scope="row">Status</th><td>{badge}</td></tr>
    <tr><th scope="row">Current chain length</th><td><code>{len}</code> rows (genesis + events)</td></tr>
    <tr><th scope="row">Last verification</th><td>{last_run_at}</td></tr>
    <tr><th scope="row">Rows walked in last run</th><td><code>{rows_walked}</code></td></tr>
  </table>
  {growth_hint}
</section>"##,
        len = s.current_chain_length,
    )
}

fn render_checkpoint(s: &AuditChainStatus) -> String {
    if s.checkpoint_seq.is_none() {
        return r##"<section aria-label="Checkpoint">
  <h2>Checkpoint</h2>
  <div class="empty">No successful verification has completed yet. The first daily cron run will produce a checkpoint.</div>
</section>"##.to_owned();
    }
    let seq        = s.checkpoint_seq.unwrap();
    let chain_hash = s.checkpoint_chain_hash.as_deref().unwrap_or("");
    let at         = s.checkpoint_at
        .map(format_unix)
        .unwrap_or_else(|| "—".to_owned());
    let consistency = match s.last_run_checkpoint_match {
        Some(true)  => r##"<span class="badge badge--success">✓ matches current row at seq</span>"##,
        Some(false) => r##"<span class="badge badge--danger">✗ does NOT match current row at seq (rewrite)</span>"##,
        None        => r##"<span class="badge">cold start — no cross-check</span>"##,
    };
    format!(
        r##"<section aria-label="Checkpoint">
  <h2>Checkpoint</h2>
  <p class="note">The verifier records the chain head after each successful run. The next run cross-checks the recorded chain_hash against the current row at the same seq — a mismatch indicates wholesale-rewrite tampering.</p>
  <table>
    <tr><th scope="row">Last verified seq</th><td><code>{seq}</code></td></tr>
    <tr><th scope="row">Recorded chain_hash</th><td><code>{hash}</code></td></tr>
    <tr><th scope="row">Recorded at</th><td>{at_str}</td></tr>
    <tr><th scope="row">Consistency</th><td>{consistency}</td></tr>
  </table>
</section>"##,
        hash = escape(chain_hash),
        at_str = escape(&at),
    )
}

fn render_verify_form(csrf: &str) -> String {
    format!(
        r##"<section aria-label="Trigger verification">
  <h2>Trigger verification</h2>
  <p class="note">Run a full re-verification right now. Walks the chain from the genesis row, ignoring the existing checkpoint. On success the checkpoint is replaced with the new head. Use after a deploy or whenever you want immediate confirmation.</p>
  <form method="post" action="/admin/console/audit/chain/verify">
    <input type="hidden" name="csrf" value="{csrf}">
    <button type="submit" class="warning">Verify chain now (full re-walk)</button>
  </form>
</section>"##,
        csrf = escape(csrf),
    )
}

/// Format a Unix-seconds timestamp as ISO-8601 UTC. We avoid
/// pulling a localization helper because the admin console is
/// operator-facing English/numeric only.
fn format_unix(unix: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    let dt = time::OffsetDateTime::from_unix_timestamp(unix).unwrap_or_else(|_| time::OffsetDateTime::UNIX_EPOCH);
    dt.format(&Rfc3339).unwrap_or_else(|_| unix.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;

    fn principal() -> AdminPrincipal {
        AdminPrincipal {
            id:      "test".to_owned(),
            name:    Some("Operator".to_owned()),
            role:    Role::ReadOnly,
            user_id: None,
        }
    }

    fn empty_status() -> AuditChainStatus {
        AuditChainStatus {
            current_chain_length:      0,
            last_run_at:               None,
            last_run_valid:            None,
            last_run_first_mismatch:   None,
            last_run_checkpoint_match: None,
            last_run_rows_walked:      None,
            checkpoint_seq:            None,
            checkpoint_chain_hash:     None,
            checkpoint_at:             None,
            growth_since_checkpoint:   false,
        }
    }

    #[test]
    fn empty_chain_renders_no_runs_yet_badge() {
        let html = audit_chain_status_page(&principal(), &empty_status(), "csrf");
        assert!(html.contains("no runs yet"));
        assert!(html.contains("No successful verification has completed yet"));
    }

    #[test]
    fn valid_chain_renders_success_badge_and_checkpoint_metadata() {
        let mut s = empty_status();
        s.current_chain_length      = 42;
        s.last_run_at               = Some(1_700_000_000);
        s.last_run_valid            = Some(true);
        s.last_run_rows_walked      = Some(40);
        s.checkpoint_seq            = Some(42);
        s.checkpoint_chain_hash     = Some("a".repeat(64));
        s.checkpoint_at             = Some(1_700_000_000);
        s.last_run_checkpoint_match = Some(true);
        let html = audit_chain_status_page(&principal(), &s, "csrf");
        assert!(html.contains("✓ chain valid"),
            "valid chain must render the success badge");
        assert!(html.contains(&"a".repeat(64)),
            "the checkpoint chain_hash must appear in the rendered status");
        assert!(html.contains("42"),
            "the checkpoint seq must appear");
        assert!(html.contains("matches current row at seq"),
            "checkpoint cross-check success must be rendered");
    }

    #[test]
    fn tamper_at_seq_renders_danger_badge_with_seq() {
        let mut s = empty_status();
        s.current_chain_length    = 42;
        s.last_run_at             = Some(1_700_000_000);
        s.last_run_valid          = Some(false);
        s.last_run_first_mismatch = Some(17);
        s.last_run_rows_walked    = Some(42);
        let html = audit_chain_status_page(&principal(), &s, "csrf");
        assert!(html.contains("tamper detected at seq=17"),
            "first_mismatch_seq must surface in the badge");
        assert!(html.contains("badge--danger"),
            "tamper must use the danger token");
    }

    #[test]
    fn wholesale_rewrite_renders_chain_history_mismatch() {
        let mut s = empty_status();
        s.current_chain_length      = 5;
        s.last_run_at               = Some(1_700_000_000);
        s.last_run_valid            = Some(false);
        s.last_run_first_mismatch   = None;       // no internal mismatch
        s.last_run_checkpoint_match = Some(false); // but checkpoint disagrees
        s.checkpoint_seq            = Some(3);
        s.checkpoint_chain_hash     = Some("b".repeat(64));
        let html = audit_chain_status_page(&principal(), &s, "csrf");
        assert!(html.contains("chain history mismatch"),
            "wholesale-rewrite alarm must use the chain-history phrasing");
        assert!(html.contains("badge--danger"));
    }

    #[test]
    fn growth_since_checkpoint_renders_hint() {
        let mut s = empty_status();
        s.current_chain_length      = 100;
        s.last_run_at               = Some(1_700_000_000);
        s.last_run_valid            = Some(true);
        s.last_run_rows_walked      = Some(60);
        s.checkpoint_seq            = Some(80);
        s.checkpoint_chain_hash     = Some("c".repeat(64));
        s.checkpoint_at             = Some(1_700_000_000);
        s.last_run_checkpoint_match = Some(true);
        s.growth_since_checkpoint   = true;
        let html = audit_chain_status_page(&principal(), &s, "csrf");
        assert!(html.contains("New audit events have been appended"),
            "growth hint must render when growth_since_checkpoint is true");
    }

    #[test]
    fn verify_now_form_carries_csrf_token() {
        let html = audit_chain_status_page(&principal(), &empty_status(), "csrf-abc");
        assert!(html.contains(r#"action="/admin/console/audit/chain/verify""#));
        assert!(html.contains(r#"name="csrf""#));
        assert!(html.contains(r#"value="csrf-abc""#));
    }
}
