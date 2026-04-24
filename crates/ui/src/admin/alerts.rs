//! Alert Center page (§4.6).

use crate::escape;
use cesauth_core::admin::types::{Alert, AlertLevel, Role};

use super::frame::{admin_frame, Tab};

pub fn alerts_page(now_unix: i64, alerts: &[Alert]) -> String {
    let body = if alerts.is_empty() {
        format!(
            r##"<section aria-label="All clear">
  <p role="status" class="ok">
    <span class="badge ok">all clear</span>
    No alerts at unix {now_unix}. Safety attestations are fresh, no cost thresholds exceeded.
  </p>
</section>"##,
            now_unix = now_unix,
        )
    } else {
        let (critical, warn, info) = split_by_level(alerts);
        format!(
            "{summary}\n{c}\n{w}\n{i}",
            summary = render_summary(alerts.len(), critical.len(), warn.len(), info.len(), now_unix),
            c = render_block("Critical", "critical", &critical),
            w = render_block("Warn",     "warn",     &warn),
            i = render_block("Info",     "muted",    &info),
        )
    };
    admin_frame("Alert center", Role::ReadOnly, None, Tab::Alerts, &body)
}

fn split_by_level<'a>(alerts: &'a [Alert]) -> (Vec<&'a Alert>, Vec<&'a Alert>, Vec<&'a Alert>) {
    let mut c = Vec::new(); let mut w = Vec::new(); let mut i = Vec::new();
    for a in alerts {
        match a.level {
            AlertLevel::Critical => c.push(a),
            AlertLevel::Warn     => w.push(a),
            AlertLevel::Info     => i.push(a),
        }
    }
    (c, w, i)
}

fn render_summary(total: usize, critical: usize, warn: usize, info: usize, now_unix: i64) -> String {
    format!(
        r##"<section aria-label="Summary">
  <p role="status">
    {total} alerts as of unix {now_unix} —
    <span class="badge critical">{critical} critical</span>
    &nbsp;<span class="badge warn">{warn} warn</span>
    &nbsp;<span class="badge muted">{info} info</span>
  </p>
</section>"##
    )
}

fn render_block(title: &str, cls: &str, alerts: &[&Alert]) -> String {
    if alerts.is_empty() {
        return String::new();
    }
    let rows: String = alerts.iter().map(|a| {
        format!(
            r#"<tr>
  <td><span class="badge {cls}">{level}</span></td>
  <td>{title}</td>
  <td class="muted">{detail}</td>
  <td class="num muted">{ts}</td>
</tr>"#,
            cls    = cls,
            level  = a.level.label(),
            title  = escape(&a.title),
            detail = escape(&a.detail),
            ts     = a.raised_at,
        )
    }).collect::<Vec<_>>().join("\n");
    format!(
        r##"<section aria-label="{title} alerts">
  <h2>{title}</h2>
  <table><thead>
    <tr><th scope="col">Level</th><th scope="col">Title</th><th scope="col">Detail</th><th scope="col" class="num">Raised (unix)</th></tr>
  </thead><tbody>
{rows}
  </tbody></table>
</section>"##,
        title = escape(title),
    )
}
