//! Preview-and-apply template helper — RFC 018.
//!
//! Renders the standard preview page for any admin operation. The
//! operation-specific handler provides `diff`, `impact`, and the signed
//! `preview_token`; this module handles the HTML.
//!
//! The operator sees:
//!
//! ```text
//! ┌─ [ impact banner: severity colour ] ──────────────────────────┐
//! │  Title                                                         │
//! │  • bullet 1                                                    │
//! │  • bullet 2                                                    │
//! │  Rollback: how to reverse                                      │
//! └────────────────────────────────────────────────────────────────┘
//!
//! Changes
//! ┌──────────┬─────────────────┬───────────────────┐
//! │ Field    │ Current value   │ After             │
//! ├──────────┼─────────────────┼───────────────────┤
//! │ LOG_LEVEL│ info            │ debug             │
//! └──────────┴─────────────────┴───────────────────┘
//!
//! [ Cancel ]                           [ Apply ]
//! ```

use crate::escape;
use cesauth_core::admin::preview::{DiffEntry, ImpactSeverity, ImpactStatement};

/// Render the preview page body fragment (NOT the full page — pass to a frame function).
///
/// `apply_action` is the POST URL, e.g. `/admin/console/config_edit/apply`.
/// `cancel_url`  is the URL for the Cancel link.
/// `preview_token` is the HMAC-signed wire-form token to embed in the hidden field.
/// `can_apply` controls whether the apply button is rendered or disabled.
pub fn preview_body(
    diff:          &[DiffEntry],
    impact:        &ImpactStatement,
    apply_action:  &str,
    cancel_url:    &str,
    preview_token: &str,
    csrf_token:    &str,
    can_apply:     bool,
) -> String {
    let banner_class = impact.severity.banner_css_class();

    let no_apply_notice = if !can_apply {
        r#"<p class="preview-notice-readonly">You don't have permission to apply this change.</p>"#
    } else {
        ""
    };

    // Impact banner.
    let destructive_notice = if impact.severity == ImpactSeverity::High {
        r#"<p class="preview-destructive">⛔ DESTRUCTIVE — this change cannot be undone.</p>"#
    } else {
        ""
    };

    let bullets_html: String = impact.bullets.iter()
        .map(|b| format!("<li>{}</li>", escape(b)))
        .collect::<Vec<_>>()
        .join("\n");

    // Diff table.
    let diff_rows: String = diff.iter().map(|e| {
        let changed_class = if e.is_unchanged() { "" } else { " class=\"diff-changed\"" };
        format!(
            r#"<tr{changed_class}><td>{field}</td><td class="diff-before">{before}</td><td class="diff-after">{after}</td></tr>"#,
            changed_class = changed_class,
            field  = escape(&e.field),
            before = escape(&e.before),
            after  = escape(&e.after),
        )
    }).collect::<Vec<_>>().join("\n");

    let apply_button = if can_apply {
        format!(
            r#"<button type="submit" class="button danger">Apply</button>"#
        )
    } else {
        r#"<button type="submit" disabled aria-disabled="true" class="button">Apply (no permission)</button>"#.to_owned()
    };

    format!(
        r##"
<div class="{banner_class}">
  {destructive_notice}
  <h2 class="preview-title">{title}</h2>
  <ul class="preview-bullets">
{bullets_html}
  </ul>
  <p class="preview-rollback"><strong>How to reverse:</strong> {rollback}</p>
  {no_apply_notice}
</div>

<section>
  <h2>Changes</h2>
  <table>
    <thead><tr><th>Field</th><th>Current value</th><th>After apply</th></tr></thead>
    <tbody>
{diff_rows}
    </tbody>
  </table>
</section>

<form method="POST" action="{apply_action}">
  <input type="hidden" name="csrf_token"    value="{csrf_token}">
  <input type="hidden" name="preview_token" value="{preview_token}">
  <div class="preview-actions">
    <a href="{cancel_url}" class="button secondary">Cancel</a>
    {apply_button}
  </div>
</form>
"##,
        banner_class    = banner_class,
        title           = escape(&impact.title),
        bullets_html    = bullets_html,
        rollback        = escape(&impact.rollback),
        no_apply_notice = no_apply_notice,
        destructive_notice = destructive_notice,
        diff_rows       = diff_rows,
        apply_action    = escape(apply_action),
        cancel_url      = escape(cancel_url),
        csrf_token      = escape(csrf_token),
        preview_token   = escape(preview_token),
        apply_button    = apply_button,
    )
}

/// Convenience: render a "no change" preview (both before and after are identical).
pub fn preview_body_noop(
    apply_action: &str,
    cancel_url:   &str,
    csrf_token:   &str,
    preview_token: &str,
) -> String {
    format!(
        r##"
<div class="preview-banner preview-banner--info">
  <h2 class="preview-title">No change</h2>
  <p>The submitted values are identical to the current configuration. Apply will be a no-op.</p>
</div>
<form method="POST" action="{apply_action}">
  <input type="hidden" name="csrf_token"    value="{csrf_token}">
  <input type="hidden" name="preview_token" value="{preview_token}">
  <div class="preview-actions">
    <a href="{cancel_url}" class="button secondary">Cancel</a>
    <button type="submit" class="button">Apply (no-op)</button>
  </div>
</form>
"##,
        apply_action  = escape(apply_action),
        cancel_url    = escape(cancel_url),
        csrf_token    = escape(csrf_token),
        preview_token = escape(preview_token),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::preview::{DiffEntry, ImpactSeverity, ImpactStatement};

    fn sample_impact(severity: ImpactSeverity) -> ImpactStatement {
        ImpactStatement::new(
            "Test operation",
            vec!["Effect 1".to_owned(), "Effect 2".to_owned()],
            "How to undo this.",
            severity,
        )
    }

    fn sample_diff() -> Vec<DiffEntry> {
        vec![DiffEntry::new("LOG_LEVEL", "info", "debug")]
    }

    #[test]
    fn preview_high_severity_renders_danger_banner() {
        let body = preview_body(
            &sample_diff(),
            &sample_impact(ImpactSeverity::High),
            "/apply", "/cancel", "tok", "csrf", true,
        );
        assert!(body.contains("preview-banner--danger"),
            "high severity must render danger banner: {body}");
    }

    #[test]
    fn preview_high_severity_renders_destructive_notice() {
        let body = preview_body(
            &sample_diff(),
            &sample_impact(ImpactSeverity::High),
            "/apply", "/cancel", "tok", "csrf", true,
        );
        assert!(body.contains("DESTRUCTIVE"),
            "high severity must include DESTRUCTIVE notice: {body}");
    }

    #[test]
    fn preview_medium_severity_renders_warning_banner() {
        let body = preview_body(
            &sample_diff(),
            &sample_impact(ImpactSeverity::Medium),
            "/apply", "/cancel", "tok", "csrf", true,
        );
        assert!(body.contains("preview-banner--warning"),
            "medium severity must render warning banner");
        assert!(!body.contains("DESTRUCTIVE"),
            "medium severity must NOT include DESTRUCTIVE notice");
    }

    #[test]
    fn preview_low_severity_renders_info_banner() {
        let body = preview_body(
            &sample_diff(),
            &sample_impact(ImpactSeverity::Low),
            "/apply", "/cancel", "tok", "csrf", true,
        );
        assert!(body.contains("preview-banner--info"),
            "low severity must render info banner");
    }

    #[test]
    fn preview_includes_rollback_hint() {
        let body = preview_body(
            &sample_diff(),
            &sample_impact(ImpactSeverity::Low),
            "/apply", "/cancel", "tok", "csrf", true,
        );
        assert!(body.contains("How to undo this."),
            "preview must include rollback text");
    }

    #[test]
    fn preview_read_only_shows_no_permission_notice() {
        let body = preview_body(
            &sample_diff(),
            &sample_impact(ImpactSeverity::Low),
            "/apply", "/cancel", "tok", "csrf", false,
        );
        assert!(body.contains("don't have permission"),
            "read-only preview must show no-permission notice");
    }

    #[test]
    fn preview_noop_shows_no_change_message() {
        let body = preview_body_noop("/apply", "/cancel", "csrf", "tok");
        assert!(body.contains("No change"), "noop preview must say no change");
        assert!(body.contains("no-op"), "noop preview must say no-op");
    }
}
