//! Cost Dashboard page (§4.2).

use crate::escape;
use cesauth_core::admin::policy::{format_change, format_metric};
use cesauth_core::admin::types::{CostTrend, Role, ServiceId};

use super::frame::{admin_frame, Tab};

/// Render the dashboard. Each entry is `(service, Ok(trend) | Err(msg))`
/// so one service's failure doesn't erase the rest.
pub fn cost_page(
    now_unix: i64,
    results:  &[(ServiceId, Result<CostTrend, String>)],
) -> String {
    let body: String = results.iter().map(|(svc, res)| render_service(*svc, res)).collect();
    let body = format!(
        r##"<p class="muted">Taken at unix {now_unix}.
  Snapshots are persisted at most once per hour per service; repeated views do not inflate cost.
  See <a href="/admin/console/config">Configuration Review</a> to tune thresholds.</p>
{body}"##,
        now_unix = now_unix,
        body = body,
    );
    admin_frame("Cost dashboard", Role::ReadOnly, None, Tab::Cost, &body)
}

fn render_service(service: ServiceId, res: &Result<CostTrend, String>) -> String {
    let label = service.label();
    match res {
        Ok(trend) => render_ok(label, trend),
        Err(msg)  => format!(
            r##"<section aria-label="{label} metrics">
  <h2>{label}</h2>
  <div class="empty warn">Metrics read failed: {msg}</div>
</section>"##,
            label = escape(label),
            msg   = escape(msg),
        ),
    }
}

fn render_ok(label: &str, t: &CostTrend) -> String {
    let rows: String = if t.current.metrics.is_empty() {
        r#"<tr><td colspan="3" class="empty">No metrics reported for this service (see note).</td></tr>"#.to_owned()
    } else {
        t.current.metrics.iter().map(|m| {
            let delta = t.changes_permille.iter()
                .find(|(k, _)| k == &m.key)
                .and_then(|(_, d)| *d);
            let delta_cls = match delta {
                Some(d) if d > 0  => "warn",
                Some(d) if d < 0  => "ok",
                _                 => "muted",
            };
            format!(
                r#"<tr>
  <td><code>{key}</code></td>
  <td class="num">{value}</td>
  <td class="num {cls}">{delta}</td>
</tr>"#,
                key   = escape(&m.key),
                value = escape(&format_metric(m.value, m.unit)),
                cls   = delta_cls,
                delta = escape(&format_change(delta)),
            )
        }).collect::<Vec<_>>().join("\n")
    };

    let banner = if t.breaches_threshold {
        r#"<p role="status"><span class="badge warn">threshold exceeded</span> See the Alert Center for detail.</p>"#
    } else { "" };
    let note = match t.note {
        Some(n) => format!(r#"<p class="note">{}</p>"#, escape(n)),
        None    => String::new(),
    };
    let baseline = match t.previous_taken_at {
        Some(ts) => format!(r#"<p class="note">Previous baseline taken at unix {ts}.</p>"#),
        None     => r#"<p class="note">First snapshot — trend available from next view onward.</p>"#.to_owned(),
    };

    format!(
        r##"<section aria-label="{label} metrics">
  <h2>{label}</h2>
  {banner}
  <table><thead>
    <tr><th scope="col">Metric</th><th scope="col" class="num">Value</th><th scope="col" class="num">vs previous</th></tr>
  </thead><tbody>
{rows}
  </tbody></table>
  {baseline}
  {note}
</section>"##,
        label = escape(label),
        banner = banner,
        rows = rows,
        baseline = baseline,
        note = note,
    )
}
