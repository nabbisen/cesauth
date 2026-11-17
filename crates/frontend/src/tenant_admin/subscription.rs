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
            when          = cesauth_core::util::format_unix_as_iso8601(e.occurred_at),
            event         = escape(&e.event),
            plan_change   = render_plan_change(e.from_plan_id.as_deref(), e.to_plan_id.as_deref()),
            status_change = render_status_change(e.from_status, e.to_status),
            actor         = escape(&e.actor),
        )
    }).collect::<Vec<_>>().join("\n");
    format!(
        r##"<table>
  <thead><tr>
    <th scope="col">When</th>
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

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;
    use cesauth_core::tenancy::types::TenantStatus;

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "admin".into(), name: None, role: Role::ReadOnly, user_id: None }
    }

    fn tenant() -> Tenant {
        Tenant {
            id: "t-acme".into(), slug: "acme".into(), display_name: "Acme".into(),
            status: TenantStatus::Active, created_at: 0, updated_at: 0,
        }
    }

    /// RFC 111 slice A, T5. Anchor shared with `admin/tests.rs`'s
    /// `rfc_111`/`rfc_111_callers` modules: `1_704_067_200` →
    /// `2024-01-01T00:00:00Z`.
    #[test]
    fn occurred_at_renders_through_the_canonical_formatter() {
        let entries = vec![SubscriptionHistoryEntry {
            id: "h1".into(), subscription_id: "s".into(), tenant_id: "t-acme".into(),
            event: "plan_changed".into(),
            from_plan_id: None, to_plan_id: None,
            from_status: None, to_status: None,
            actor: "alice".into(), occurred_at: 1_704_067_200,
        }];
        let html = subscription_page(&p(), &tenant(), &entries);
        assert!(html.contains("2024-01-01T00:00:00Z"),
            "occurred_at must render through format_unix_as_iso8601, got:\n{html}");
        assert!(!html.contains("1704067200"),
            "the raw epoch integer must not appear beside its formatted form");
    }
}
