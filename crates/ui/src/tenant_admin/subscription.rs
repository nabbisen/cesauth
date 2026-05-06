//! `/admin/t/<slug>/subscription` — the tenant's subscription
//! history.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::billing::types::{SubscriptionHistoryEntry, SubscriptionStatus};
use cesauth_core::tenancy::types::Tenant;

use super::frame::{tenant_admin_frame, TenantAdminTab};

pub fn subscription_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    entries:   &[SubscriptionHistoryEntry],
) -> String {
    let body = render_table(entries);
    tenant_admin_frame(
        "Subscription history",
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::Subscription,
        &body,
    )
}

fn render_table(entries: &[SubscriptionHistoryEntry]) -> String {
    if entries.is_empty() {
        return r##"<p class="empty">No subscription history yet.</p>"##.into();
    }
    // Reverse-chronological: most recent at top.
    let mut sorted: Vec<&SubscriptionHistoryEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at));

    let rows: String = sorted.iter().map(|e| {
        format!(
            r#"<tr>
  <td>{when}</td>
  <td><code>{event}</code></td>
  <td>{plan_change}</td>
  <td>{status_change}</td>
  <td>{actor}</td>
</tr>"#,
            when          = e.occurred_at,
            event         = escape(&e.event),
            plan_change   = render_plan_change(e.from_plan_id.as_deref(), e.to_plan_id.as_deref()),
            status_change = render_status_change(e.from_status, e.to_status),
            actor         = escape(&e.actor),
        )
    }).collect::<Vec<_>>().join("\n");
    format!(
        r##"<table>
  <thead><tr>
    <th scope="col">When (unix)</th>
    <th scope="col">Event</th>
    <th scope="col">Plan change</th>
    <th scope="col">Status change</th>
    <th scope="col">Actor</th>
  </tr></thead>
  <tbody>
{rows}
  </tbody>
</table>"##
    )
}

fn render_plan_change(from: Option<&str>, to: Option<&str>) -> String {
    match (from, to) {
        (Some(f), Some(t)) =>
            format!("<code>{}</code> → <code>{}</code>", escape(f), escape(t)),
        (None,    Some(t)) => format!("→ <code>{}</code>", escape(t)),
        (Some(f), None)    => format!("<code>{}</code> →", escape(f)),
        (None,    None)    => r#"<span class="muted">—</span>"#.into(),
    }
}

fn render_status_change(from: Option<SubscriptionStatus>, to: Option<SubscriptionStatus>) -> String {
    match (from, to) {
        (Some(f), Some(t)) => format!("{} → {}", status_label(f), status_label(t)),
        (None,    Some(t)) => format!("→ {}", status_label(t)),
        (Some(f), None)    => format!("{} →", status_label(f)),
        (None,    None)    => r#"<span class="muted">—</span>"#.into(),
    }
}

fn status_label(s: SubscriptionStatus) -> &'static str {
    match s {
        SubscriptionStatus::Active    => r#"<span class="badge ok">active</span>"#,
        SubscriptionStatus::PastDue   => r#"<span class="badge warn">past_due</span>"#,
        SubscriptionStatus::Cancelled => r#"<span class="badge critical">cancelled</span>"#,
        SubscriptionStatus::Expired   => r#"<span class="badge critical">expired</span>"#,
    }
}
