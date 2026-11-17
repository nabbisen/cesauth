//! `/admin/tenancy/tenants/:tid/subscription/history` — the
//! append-only change log for a tenant's subscription.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::billing::types::{SubscriptionHistoryEntry, SubscriptionStatus};
use cesauth_core::routes::tenancy_console as routes;

use super::frame::{tenancy_console_frame, TenancyConsoleTab};

pub fn subscription_history_page(
    principal: &AdminPrincipal,
    tenant_id: &str,
    tenant_slug: &str,
    entries:   &[SubscriptionHistoryEntry],
) -> String {
    let title = format!("Subscription history: {tenant_slug}");
    let body = format!(
        r##"<p class="muted"><a href="{tenant_url}">← Back to tenant</a></p>
{table}"##,
        tenant_url = escape(&routes::tenant(tenant_id)),
        table = render_table(entries),
    );
    tenancy_console_frame(&title, principal.role, principal.name.as_deref(), TenancyConsoleTab::Tenants, &body)
}

fn render_table(entries: &[SubscriptionHistoryEntry]) -> String {
    let body: String = if entries.is_empty() {
        r#"<tr><td colspan="6" class="empty">No history entries.</td></tr>"#.to_owned()
    } else {
        // Reverse-chronological — most recent at top, since "what
        // changed last" is the operator's most common question.
        let mut rows: Vec<&SubscriptionHistoryEntry> = entries.iter().collect();
        rows.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at));
        rows.iter().map(|e| {
            let plan_change = match (&e.from_plan_id, &e.to_plan_id) {
                (Some(from), Some(to)) => format!(
                    "<code>{}</code> → <code>{}</code>", escape(from), escape(to)
                ),
                _ => "—".to_owned(),
            };
            let status_change = match (e.from_status, e.to_status) {
                (Some(from), Some(to)) => format!(
                    "<code>{}</code> → <code>{}</code>", status_str(from), status_str(to)
                ),
                _ => "—".to_owned(),
            };
            format!(
                r##"<tr>
  <td class="muted">{ts}</td>
  <td><code>{event}</code></td>
  <td>{plan}</td>
  <td>{status}</td>
  <td><code>{actor}</code></td>
</tr>"##,
                ts     = cesauth_core::util::format_unix_as_iso8601(e.occurred_at),
                event  = escape(&e.event),
                plan   = plan_change,
                status = status_change,
                actor  = escape(&e.actor),
            )
        }).collect::<Vec<_>>().join("\n")
    };
    format!(
        r##"<section aria-label="History">
  <table><thead>
    <tr>
      <th scope="col">Occurred</th>
      <th scope="col">Event</th>
      <th scope="col">Plan change</th>
      <th scope="col">Status change</th>
      <th scope="col">Actor</th>
    </tr>
  </thead><tbody>
{body}
  </tbody></table>
  <p class="muted">Events are append-only: each plan or status change
    inserts one row in <code>subscription_history</code> via the
    <code>POST /api/v1/tenants/:tid/subscription/...</code> handlers.
    Reverse-chronological — newest first.</p>
</section>"##
    )
}

fn status_str(s: SubscriptionStatus) -> &'static str {
    match s {
        SubscriptionStatus::Active    => "active",
        SubscriptionStatus::PastDue   => "past_due",
        SubscriptionStatus::Cancelled => "cancelled",
        SubscriptionStatus::Expired   => "expired",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "admin".into(), name: None,role: Role::ReadOnly, user_id: None }
    }

    #[test]
    fn empty_history_renders_empty_state() {
        let html = subscription_history_page(&p(), "t-acme", "acme", &[]);
        assert!(html.contains("No history entries"));
    }

    #[test]
    fn history_renders_in_reverse_chronological_order() {
        let entries = vec![
            SubscriptionHistoryEntry {
                id: "h1".into(), subscription_id: "s".into(), tenant_id: "t".into(),
                event: "plan_changed".into(),
                from_plan_id: Some("plan-trial".into()),
                to_plan_id:   Some("plan-pro".into()),
                from_status: None, to_status: None,
                actor: "alice".into(), occurred_at: 100,
            },
            SubscriptionHistoryEntry {
                id: "h2".into(), subscription_id: "s".into(), tenant_id: "t".into(),
                event: "status_changed".into(),
                from_plan_id: None, to_plan_id: None,
                from_status: Some(SubscriptionStatus::Active),
                to_status:   Some(SubscriptionStatus::PastDue),
                actor: "system".into(), occurred_at: 200,
            },
        ];
        let html = subscription_history_page(&p(), "t-acme", "acme", &entries);
        // Both events present.
        assert!(html.contains("plan_changed"));
        assert!(html.contains("status_changed"));
        // Newest (occurred_at=200) appears before oldest (=100).
        let pos_status = html.find("status_changed").unwrap();
        let pos_plan   = html.find("plan_changed").unwrap();
        assert!(pos_status < pos_plan,
            "newer event must render first; got status@{pos_status} plan@{pos_plan}");
    }

    #[test]
    fn back_link_points_to_tenant_detail() {
        let html = subscription_history_page(&p(), "t-acme", "acme", &[]);
        assert!(html.contains(r#"href="/admin/tenancy/tenants/t-acme""#));
    }

    /// RFC 111 slice A, T5. Anchor shared with `admin/tests.rs`'s
    /// `rfc_111`/`rfc_111_callers` modules: `1_704_067_200` →
    /// `2024-01-01T00:00:00Z`.
    #[test]
    fn occurred_at_renders_through_the_canonical_formatter() {
        let entries = vec![SubscriptionHistoryEntry {
            id: "h1".into(), subscription_id: "s".into(), tenant_id: "t".into(),
            event: "plan_changed".into(),
            from_plan_id: None, to_plan_id: None,
            from_status: None, to_status: None,
            actor: "alice".into(), occurred_at: 1_704_067_200,
        }];
        let html = subscription_history_page(&p(), "t-acme", "acme", &entries);
        assert!(html.contains("2024-01-01T00:00:00Z"),
            "occurred_at must render through format_unix_as_iso8601, got:\n{html}");
        assert!(!html.contains("1704067200"),
            "the raw epoch integer must not appear beside its formatted form");
    }
}
