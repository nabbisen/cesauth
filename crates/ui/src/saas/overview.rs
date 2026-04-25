//! `/admin/saas` — overview page.
//!
//! Deployment-wide counters: total tenants, organizations, groups,
//! plus a breakdown of subscriptions by plan. Reads from the same
//! D1 tables the API surface uses; renders entirely server-side.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;

use super::frame::{saas_frame, SaasTab};

/// Per-plan breakdown row. Built by the route handler from a single
/// SQL aggregate; the UI just renders.
#[derive(Debug, Clone)]
pub struct PlanBreakdownRow {
    pub plan_slug:      String,
    pub plan_label:     String,
    pub subscriber_count: i64,
}

/// Top-level counter set.
#[derive(Debug, Clone, Default)]
pub struct OverviewCounts {
    pub tenants_active:    i64,
    pub tenants_suspended: i64,
    pub tenants_deleted:   i64,
    pub organizations:     i64,
    pub groups:            i64,
    pub plans_active:      i64,
}

pub fn overview_page(
    principal:  &AdminPrincipal,
    counts:     &OverviewCounts,
    by_plan:    &[PlanBreakdownRow],
) -> String {
    let body = format!(
        "{counters}\n{plans}\n{howto}",
        counters = render_counters(counts),
        plans    = render_plan_breakdown(by_plan),
        howto    = render_howto(),
    );
    saas_frame(
        "Overview",
        principal.role,
        principal.name.as_deref(),
        SaasTab::Overview,
        &body,
    )
}

fn render_counters(c: &OverviewCounts) -> String {
    format!(
        r##"<section aria-label="Counters">
  <h2>Counters</h2>
  <table>
    <thead><tr><th scope="col">Metric</th><th scope="col">Count</th></tr></thead>
    <tbody>
      <tr><td>Tenants — active</td><td>{a}</td></tr>
      <tr><td>Tenants — suspended</td><td>{s}</td></tr>
      <tr><td>Tenants — deleted (soft)</td><td>{d}</td></tr>
      <tr><td>Organizations</td><td>{o}</td></tr>
      <tr><td>Groups</td><td>{g}</td></tr>
      <tr><td>Active plans</td><td>{p}</td></tr>
    </tbody>
  </table>
</section>"##,
        a = c.tenants_active, s = c.tenants_suspended, d = c.tenants_deleted,
        o = c.organizations, g = c.groups, p = c.plans_active,
    )
}

fn render_plan_breakdown(rows: &[PlanBreakdownRow]) -> String {
    let body: String = if rows.is_empty() {
        r#"<tr><td colspan="3" class="empty">No subscriptions yet.</td></tr>"#.to_owned()
    } else {
        rows.iter().map(|r| format!(
            "<tr><td><code>{slug}</code></td><td>{label}</td><td>{n}</td></tr>",
            slug  = escape(&r.plan_slug),
            label = escape(&r.plan_label),
            n     = r.subscriber_count,
        )).collect::<Vec<_>>().join("\n")
    };
    format!(
        r##"<section aria-label="Subscriptions by plan">
  <h2>Subscriptions by plan</h2>
  <table><thead>
    <tr><th scope="col">Slug</th><th scope="col">Plan</th><th scope="col">Subscribers</th></tr>
  </thead><tbody>
{body}
  </tbody></table>
</section>"##
    )
}

fn render_howto() -> String {
    r##"<section aria-label="How to mutate">
  <h2>Making changes</h2>
  <p class="muted">This console is <strong>read-only</strong>. Tenant
    / organization / group / role-assignment / subscription mutations
    go through the JSON API at <code>/api/v1/...</code> (v0.4.2). The
    HTML preview/confirm flow that wraps those calls is slated for
    v0.4.4 — see the changelog and roadmap.</p>
  <p class="muted">For the full operator runbook
    (<code>wrangler</code> recipes for promoting a system_admin,
    re-grading account types, etc.), see the
    <em>Tenancy &amp; tenancy service</em> chapter of the operator
    documentation.</p>
</section>"##.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;

    fn test_principal() -> AdminPrincipal {
        AdminPrincipal {
            id: "admin-1".into(),
            name: Some("alice".into()),
            role: Role::ReadOnly,
        }
    }

    #[test]
    fn overview_renders_all_counters() {
        let counts = OverviewCounts {
            tenants_active: 3, tenants_suspended: 1, tenants_deleted: 0,
            organizations: 5, groups: 12, plans_active: 4,
        };
        let html = overview_page(&test_principal(), &counts, &[]);
        for needle in ["Tenants — active", ">3<", ">5<", ">12<"] {
            assert!(html.contains(needle), "expected {needle:?} in overview HTML");
        }
    }

    #[test]
    fn empty_plan_breakdown_renders_empty_state() {
        let html = overview_page(&test_principal(), &OverviewCounts::default(), &[]);
        assert!(html.contains("No subscriptions yet"));
    }

    #[test]
    fn plan_breakdown_renders_each_row() {
        let rows = vec![
            PlanBreakdownRow {
                plan_slug: "free".into(), plan_label: "Free".into(),
                subscriber_count: 10,
            },
            PlanBreakdownRow {
                plan_slug: "pro".into(), plan_label: "Pro".into(),
                subscriber_count: 3,
            },
        ];
        let html = overview_page(&test_principal(), &OverviewCounts::default(), &rows);
        assert!(html.contains("free"));
        assert!(html.contains("Pro"));
        assert!(html.contains(">10<"));
        assert!(html.contains(">3<"));
    }

    #[test]
    fn read_only_disclaimer_is_present() {
        let html = overview_page(&test_principal(), &OverviewCounts::default(), &[]);
        assert!(html.contains("read-only"),
            "0.4.3 console must clearly mark itself as read-only");
    }
}
