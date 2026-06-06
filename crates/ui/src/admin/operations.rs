//! `/admin/console/operations` — cron pass status surface (RFC 081).

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use super::frame::{admin_frame, Tab};

/// One cron pass display record.
#[derive(Debug)]
pub struct CronPassDisplay {
    pub name:      &'static str,
    pub label:     &'static str,
    pub last_run:  Option<String>,   // ISO-8601 UTC
    pub success:   Option<bool>,
    pub processed: Option<u64>,
    pub mode:      &'static str,     // "Apply" | "Dry-run"
    pub error:     Option<String>,
}

impl CronPassDisplay {
    pub const fn placeholder(name: &'static str, label: &'static str, mode: &'static str) -> Self {
        Self {
            name,
            label,
            last_run:  None,
            success:   None,
            processed: None,
            mode,
            error:     None,
        }
    }
}

/// Render the operations / cron status page.
pub fn operations_page(
    principal: &AdminPrincipal,
    passes:    &[CronPassDisplay],
) -> String {
    let rows: String = passes.iter().map(|p| {
        let status = match p.success {
            None        => "<span class=\"badge\">No recent run</span>".to_owned(),
            Some(true)  => "<span class=\"badge ok\">✓ Success</span>".to_owned(),
            Some(false) => "<span class=\"badge critical\">✗ Failed</span>".to_owned(),
        };
        let processed = p.processed.map(|n| n.to_string()).unwrap_or_else(|| "—".to_owned());
        let last_run  = p.last_run.as_deref().unwrap_or("—");
        let error_row = match &p.error {
            None    => String::new(),
            Some(e) => format!(
                "<tr><td colspan=\"5\" class=\"error-detail\"><code>{}</code></td></tr>",
                escape(e)
            ),
        };
        format!(
            "<tr>\
              <td><strong>{label}</strong><br><code style=\"font-size:0.8em\">{name}</code></td>\
              <td>{status}</td>\
              <td>{mode}</td>\
              <td>{processed}</td>\
              <td>{last_run}</td>\
            </tr>{error_row}",
            label     = escape(p.label),
            name      = escape(p.name),
            status    = status,
            mode      = escape(p.mode),
            processed = escape(&processed),
            last_run  = escape(last_run),
            error_row = error_row,
        )
    }).collect::<Vec<_>>().join("\n");

    let body = format!(
        "<h2>Daily cron passes</h2>\
        <p class=\"muted\">Scheduled at 04:00 UTC. Last-run state is stored in KV (TTL 8 days); \
        a missing row means no recent run was recorded.</p>\
        <table>\
          <thead>\
            <tr><th>Pass</th><th>Status</th><th>Mode</th><th>Processed</th><th>Last run</th></tr>\
          </thead>\
          <tbody>{rows}</tbody>\
        </table>\
        <p class=\"note\" style=\"margin-top:16px\">\
          <strong>Dry-run</strong> passes perform no mutations — they only log what would be done. \
          Enable via environment variables (e.g. <code>SESSION_INDEX_AUTO_REPAIR=true</code>).\
        </p>",
        rows = rows,
    );

    admin_frame("Operations", principal.role, principal.name.as_deref(), Tab::Operations, &cesauth_core::admin::scope::ScopeBadge::System, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::{AdminPrincipal, Role};

    fn principal() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None, role: Role::Operations, user_id: None }
    }

    fn default_passes() -> Vec<CronPassDisplay> {
        vec![
            CronPassDisplay::placeholder("sweep",                  "Sweep",                  "Apply"),
            CronPassDisplay::placeholder("audit_chain",            "Audit chain verify",     "Apply"),
            CronPassDisplay::placeholder("session_index_audit",    "Session index audit",    "Apply"),
            CronPassDisplay::placeholder("audit_retention",        "Audit retention prune",  "Dry-run"),
            CronPassDisplay::placeholder("session_index_repair",   "Session index repair",   "Dry-run"),
        ]
    }

    #[test]
    fn operations_page_renders_all_5_passes() {
        let html = operations_page(&principal(), &default_passes());
        assert!(html.contains("sweep"),                "sweep pass");
        assert!(html.contains("audit_chain"),          "audit chain pass");
        assert!(html.contains("session_index_audit"),  "session index audit pass");
        assert!(html.contains("audit_retention"),      "audit retention pass");
        assert!(html.contains("session_index_repair"), "session index repair pass");
    }

    #[test]
    fn operations_page_shows_dryrun_for_repair() {
        let html = operations_page(&principal(), &default_passes());
        // Should contain Dry-run at least twice (retention + repair)
        let dry_count = html.matches("Dry-run").count();
        assert!(dry_count >= 2, "expected 2+ Dry-run badges, got {dry_count}");
    }

    #[test]
    fn operations_page_no_recent_run_when_placeholder() {
        let html = operations_page(&principal(), &default_passes());
        assert!(html.contains("No recent run"), "placeholder passes show no-recent-run badge");
    }

    #[test]
    fn operations_page_shows_success_badge() {
        let mut passes = default_passes();
        passes[0].success   = Some(true);
        passes[0].processed = Some(42);
        passes[0].last_run  = Some("2026-05-12T04:00:00Z".to_owned());
        let html = operations_page(&principal(), &passes);
        assert!(html.contains("✓ Success"), "success badge");
        assert!(html.contains("42"),        "processed count");
        assert!(html.contains("2026-"),     "last run timestamp");
    }

    #[test]
    fn operations_page_shows_failure_badge() {
        let mut passes = default_passes();
        passes[0].success = Some(false);
        passes[0].error   = Some("D1 connection timeout".to_owned());
        let html = operations_page(&principal(), &passes);
        assert!(html.contains("✗ Failed"),           "failure badge");
        assert!(html.contains("D1 connection timeout"), "error message");
    }
}
