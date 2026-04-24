//! Overview page (§4.1).

use crate::escape;
use cesauth_core::admin::types::OverviewSummary;

use super::frame::{admin_frame, Tab};

pub fn overview_page(s: &OverviewSummary) -> String {
    let body = format!(
        "{alerts}\n{recent_alerts}\n{recent_audit}\n{last_verified}",
        alerts         = render_alert_counts(s),
        recent_alerts  = render_recent_alerts(s),
        recent_audit   = render_recent_audit(s),
        last_verified  = render_last_verified(s),
    );
    admin_frame(
        "Overview",
        s.principal.role,
        s.principal.name.as_deref(),
        Tab::Overview,
        &body,
    )
}

fn render_alert_counts(s: &OverviewSummary) -> String {
    let c = &s.alert_counts;
    let total = c.critical + c.warn + c.info;
    if total == 0 {
        return r#"<section aria-label="Alert summary">
  <h2>Alerts</h2>
  <p class="muted">No alerts raised. Safety attestations are fresh and no cost thresholds were exceeded.</p>
</section>"#.to_owned();
    }
    format!(
        r##"<section aria-label="Alert summary">
  <h2>Alerts <a href="/admin/console/alerts" class="muted" style="font-weight:normal; font-size:13px;">(all →)</a></h2>
  <p role="status">
    <span class="badge critical">{crit} critical</span>
    &nbsp;<span class="badge warn">{warn} warn</span>
    &nbsp;<span class="badge muted">{info} info</span>
  </p>
</section>"##,
        crit = c.critical,
        warn = c.warn,
        info = c.info,
    )
}

fn render_recent_alerts(s: &OverviewSummary) -> String {
    if s.recent_alerts.is_empty() {
        return String::new();
    }
    let rows: String = s.recent_alerts.iter().map(|a| {
        let (cls, level) = match a.level {
            cesauth_core::admin::types::AlertLevel::Critical => ("critical", "critical"),
            cesauth_core::admin::types::AlertLevel::Warn     => ("warn",     "warn"),
            cesauth_core::admin::types::AlertLevel::Info     => ("muted",    "info"),
        };
        format!(
            r#"<tr>
  <td><span class="badge {cls}">{level}</span></td>
  <td>{title}</td>
  <td class="muted">{detail}</td>
</tr>"#,
            cls    = cls,
            level  = level,
            title  = escape(&a.title),
            detail = escape(&a.detail),
        )
    }).collect::<Vec<_>>().join("\n");
    format!(
        r##"<section aria-label="Recent alerts">
  <h2>Recent alerts</h2>
  <table><thead>
    <tr><th scope="col">Level</th><th scope="col">Title</th><th scope="col">Detail</th></tr>
  </thead><tbody>
{rows}
  </tbody></table>
</section>"##
    )
}

fn render_recent_audit(s: &OverviewSummary) -> String {
    let inner = if s.last_audit_events.is_empty() {
        r#"<div class="empty">No audit events in today's log (or log unavailable).</div>"#.to_owned()
    } else {
        let rows: String = s.last_audit_events.iter().map(|e| {
            format!(
                r#"<tr>
  <td class="num muted">{ts}</td>
  <td><code>{kind}</code></td>
  <td class="muted">{subject}</td>
  <td class="muted">{reason}</td>
</tr>"#,
                ts      = e.ts,
                kind    = escape(&e.kind),
                subject = escape(e.subject.as_deref().unwrap_or("—")),
                reason  = escape(e.reason.as_deref().unwrap_or("")),
            )
        }).collect::<Vec<_>>().join("\n");
        format!(
            r#"<table><thead>
  <tr><th scope="col" class="num">ts</th><th scope="col">kind</th><th scope="col">subject</th><th scope="col">reason</th></tr>
</thead><tbody>
{rows}
</tbody></table>"#
        )
    };
    format!(
        r##"<section aria-label="Recent audit events">
  <h2>Recent audit events <a href="/admin/console/audit" class="muted" style="font-weight:normal; font-size:13px;">(search →)</a></h2>
  {inner}
</section>"##
    )
}

fn render_last_verified(s: &OverviewSummary) -> String {
    let inner = if s.last_verified_buckets.is_empty() {
        r#"<div class="empty">No bucket attestations recorded.</div>"#.to_owned()
    } else {
        let rows: String = s.last_verified_buckets.iter().map(|b| {
            let verified = match b.last_verified_at {
                Some(ts) => format!(r#"<td class="num">{ts}</td>"#),
                None     => r#"<td class="warn">never</td>"#.to_owned(),
            };
            format!(
                r#"<tr>
  <td><code>{bucket}</code></td>
  {verified}
  <td class="muted">{by}</td>
</tr>"#,
                bucket   = escape(&b.bucket),
                verified = verified,
                by       = escape(b.last_verified_by.as_deref().unwrap_or("—")),
            )
        }).collect::<Vec<_>>().join("\n");
        format!(
            r#"<table><thead>
  <tr><th scope="col">bucket</th><th scope="col" class="num">last_verified_at</th><th scope="col">by</th></tr>
</thead><tbody>
{rows}
</tbody></table>"#
        )
    };
    format!(
        r##"<section aria-label="Recently verified buckets">
  <h2>Recently verified buckets <a href="/admin/console/safety" class="muted" style="font-weight:normal; font-size:13px;">(safety →)</a></h2>
  {inner}
</section>"##
    )
}
