//! Subscription set-plan form. Two-step preview/confirm because
//! plan changes affect billing and may shift quota limits.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::billing::types::{Plan, Subscription};

use super::super::frame::{saas_frame, SaasTab};

pub fn form_page(
    principal:    &AdminPrincipal,
    tenant_id:    &str,
    tenant_slug:  &str,
    current:      &Subscription,
    current_plan: Option<&Plan>,
    available:    &[Plan],
    selected_id:  &str,
    error:        Option<&str>,
) -> String {
    let title = format!("Change plan: {}", tenant_slug);
    let current_label = current_plan
        .map(|p| format!("{} (<code>{}</code>)", escape(&p.display_name), escape(&p.slug)))
        .unwrap_or_else(|| format!("<code>{}</code>", escape(&current.plan_id)));
    let options: String = available.iter().map(|p| {
        let s = if p.id == selected_id { " selected" } else { "" };
        format!(
            r#"<option value="{id}"{s}>{name} ({slug})</option>"#,
            id = escape(&p.id), s = s,
            name = escape(&p.display_name),
            slug = escape(&p.slug),
        )
    }).collect();
    let body = format!(
        r##"<p><a href="/admin/saas/tenants/{tid}">← Back to tenant</a></p>
{error}
<section aria-label="Current">
  <table><tbody>
    <tr><th scope="row">Tenant</th>       <td><code>{slug}</code></td></tr>
    <tr><th scope="row">Current plan</th> <td>{current}</td></tr>
  </tbody></table>
</section>
<section aria-label="Plan picker">
  <form method="post" action="/admin/saas/tenants/{tid}/subscription/plan">
    <p>
      <label for="plan_id">Target plan</label>
      <select id="plan_id" name="plan_id" required>
        {options}
      </select>
    </p>
    <p><button type="submit">Preview change</button></p>
  </form>
</section>"##,
        tid     = escape(tenant_id),
        slug    = escape(tenant_slug),
        current = current_label,
        error   = match error {
            None    => String::new(),
            Some(m) => format!(
                r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {m}</p></section>"#,
                m = escape(m),
            ),
        },
    );
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

pub fn confirm_page(
    principal:    &AdminPrincipal,
    tenant_id:    &str,
    tenant_slug:  &str,
    current_plan: Option<&Plan>,
    target_plan:  &Plan,
) -> String {
    let title = format!("Confirm plan change: {}", tenant_slug);
    let same = current_plan.map(|p| p.id == target_plan.id).unwrap_or(false);
    let warning = if same {
        r##"<p class="muted">No change — current and target plan are the same. Submitting will be a no-op.</p>"##.to_owned()
    } else if !target_plan.active {
        r##"<p role="status" class="critical"><span class="badge critical">danger</span> Target plan is marked inactive. Submission will be rejected by the server.</p>"##.to_owned()
    } else {
        // Show quota delta when both plans have the same quota name —
        // this is the operator's most-asked question on plan change.
        if let Some(cur) = current_plan {
            render_quota_delta(cur, target_plan)
        } else {
            r##"<p role="status" class="critical"><span class="badge warn">caution</span> Subscription is moving from no plan to a plan; new quotas take effect immediately.</p>"##.to_owned()
        }
    };
    let body = format!(
        r##"<p><a href="/admin/saas/tenants/{tid}">← Back to tenant</a></p>
<section aria-label="Diff">
  <h2>Change to apply</h2>
  <table><tbody>
    <tr><th scope="row">Tenant</th>       <td><code>{slug}</code></td></tr>
    <tr><th scope="row">Plan (current)</th><td>{cur}</td></tr>
    <tr><th scope="row">Plan (target)</th> <td>{tgt}</td></tr>
  </tbody></table>
  {warning}
</section>
<section aria-label="Apply">
  <form class="danger" method="post" action="/admin/saas/tenants/{tid}/subscription/plan">
    <input type="hidden" name="plan_id" value="{plan_id}">
    <input type="hidden" name="confirm" value="yes">
    <p><button type="submit">Apply plan change</button></p>
  </form>
</section>"##,
        tid     = escape(tenant_id),
        slug    = escape(tenant_slug),
        cur     = current_plan.map(|p| format!("{} (<code>{}</code>)", escape(&p.display_name), escape(&p.slug))).unwrap_or_else(|| "<em class=\"muted\">none</em>".to_owned()),
        tgt     = format!("{} (<code>{}</code>)", escape(&target_plan.display_name), escape(&target_plan.slug)),
        plan_id = escape(&target_plan.id),
    );
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

fn render_quota_delta(cur: &Plan, tgt: &Plan) -> String {
    let mut rows: Vec<String> = Vec::new();
    for q_target in &tgt.quotas {
        let from = cur.quotas.iter().find(|q| q.name == q_target.name).map(|q| q.value);
        let to   = q_target.value;
        let same = from == Some(to);
        let from_label = from.map(|v| if v < 0 { "unlimited".to_owned() } else { v.to_string() }).unwrap_or_else(|| "(unset)".to_owned());
        let to_label   = if to < 0 { "unlimited".to_owned() } else { to.to_string() };
        let icon = if same { "" } else if to < from.unwrap_or(0) && to >= 0 { " ⚠" } else { "" };
        rows.push(format!(
            "<tr><td><code>{name}</code></td><td>{from}</td><td>{to}{icon}</td></tr>",
            name = escape(&q_target.name), from = from_label, to = to_label, icon = icon,
        ));
    }
    if rows.is_empty() {
        return r##"<p class="muted">Target plan has no quotas — no quota change.</p>"##.to_owned();
    }
    format!(
        r##"<section aria-label="Quota delta">
  <h3>Quota delta</h3>
  <table><thead><tr><th scope="col">Quota</th><th scope="col">From</th><th scope="col">To</th></tr></thead>
  <tbody>
{rows}
  </tbody></table>
  <p class="muted">⚠ marks quotas that decrease — existing usage above the new limit
    will <strong>not</strong> be auto-pruned, but new creates will be refused with 409.</p>
</section>"##,
        rows = rows.join("\n"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;
    use cesauth_core::billing::types::{
        FeatureFlag, Plan, Quota, Subscription, SubscriptionLifecycle, SubscriptionStatus,
    };

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None, role: Role::Operations }
    }

    fn plan(id: &str, slug: &str, active: bool, quotas: Vec<Quota>) -> Plan {
        Plan {
            id: id.into(), slug: slug.into(), display_name: slug.to_uppercase(),
            active, features: vec![FeatureFlag::new("core")],
            quotas, price_description: None,
            created_at: 0, updated_at: 0,
        }
    }
    fn s(plan_id: &str) -> Subscription {
        Subscription {
            id: "s".into(), tenant_id: "t".into(), plan_id: plan_id.into(),
            lifecycle: SubscriptionLifecycle::Paid, status: SubscriptionStatus::Active,
            started_at: 0, current_period_end: None, trial_ends_at: None,
            status_changed_at: 0, updated_at: 0,
        }
    }

    #[test]
    fn confirm_warns_when_target_is_inactive() {
        let cur = plan("plan-pro", "pro", true, vec![]);
        let tgt = plan("plan-archived", "archived", false, vec![]);
        let html = confirm_page(&p(), "t", "acme", Some(&cur), &tgt);
        assert!(html.contains("Target plan is marked inactive"));
    }

    #[test]
    fn confirm_renders_quota_delta_with_arrow_marker_for_decrease() {
        let cur = plan("p1", "old", true, vec![Quota { name: "max_users".into(), value: 100 }]);
        let tgt = plan("p2", "new", true, vec![Quota { name: "max_users".into(), value: 10 }]);
        let html = confirm_page(&p(), "t", "acme", Some(&cur), &tgt);
        assert!(html.contains("max_users"));
        assert!(html.contains("100"));
        assert!(html.contains(">10"));
        assert!(html.contains("⚠"), "decrease must be marked");
    }

    #[test]
    fn confirm_no_op_on_same_plan() {
        let same = plan("p1", "pro", true, vec![]);
        let html = confirm_page(&p(), "t", "acme", Some(&same), &same);
        assert!(html.contains("No change"));
    }

    #[test]
    fn form_marks_currently_selected_plan() {
        let plans = vec![
            plan("p1", "free", true, vec![]),
            plan("p2", "pro",  true, vec![]),
        ];
        let html = form_page(&p(), "t", "acme", &s("p2"), Some(&plans[1]), &plans, "p2", None);
        // The selected option must carry the "selected" attribute.
        assert!(html.contains(r#"value="p2" selected"#));
    }
}
