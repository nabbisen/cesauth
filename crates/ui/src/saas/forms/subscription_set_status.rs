//! Subscription status change form with preview/confirm.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::billing::types::{Subscription, SubscriptionStatus};

use super::super::frame::{saas_frame, SaasTab};

pub fn form_page(
    principal:   &AdminPrincipal,
    tenant_id:   &str,
    tenant_slug: &str,
    current:     &Subscription,
    selected:    Option<SubscriptionStatus>,
    error:       Option<&str>,
) -> String {
    let s = selected.unwrap_or(current.status);
    let title = format!("Subscription status: {tenant_slug}");
    let body = format!(
        r##"<p><a href="/admin/saas/tenants/{tid}">← Back to tenant</a></p>
{error}
<section aria-label="Current">
  <table><tbody>
    <tr><th scope="row">Tenant</th>           <td><code>{slug}</code></td></tr>
    <tr><th scope="row">Current status</th>   <td>{cur}</td></tr>
  </tbody></table>
</section>
<section aria-label="Status change form">
  <form method="post" action="/admin/saas/tenants/{tid}/subscription/status">
    <fieldset>
      <legend>Target status</legend>
      <p><input type="radio" id="s_active"    name="status" value="active"    {ca}> <label for="s_active">    <code>active</code></label></p>
      <p><input type="radio" id="s_past_due"  name="status" value="past_due"  {cp}> <label for="s_past_due">  <code>past_due</code> — billing failed; usage continues</label></p>
      <p><input type="radio" id="s_cancelled" name="status" value="cancelled" {cc}> <label for="s_cancelled"> <code>cancelled</code> — operator-initiated; final period continues</label></p>
      <p><input type="radio" id="s_expired"   name="status" value="expired"   {ce}> <label for="s_expired">   <code>expired</code> — final-period end reached</label></p>
    </fieldset>
    <p><button type="submit">Preview change</button></p>
  </form>
</section>"##,
        tid   = escape(tenant_id),
        slug  = escape(tenant_slug),
        cur   = render_status_badge(current.status),
        ca    = if s == SubscriptionStatus::Active    { "checked" } else { "" },
        cp    = if s == SubscriptionStatus::PastDue   { "checked" } else { "" },
        cc    = if s == SubscriptionStatus::Cancelled { "checked" } else { "" },
        ce    = if s == SubscriptionStatus::Expired   { "checked" } else { "" },
        error = match error {
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
    principal:   &AdminPrincipal,
    tenant_id:   &str,
    tenant_slug: &str,
    current:     &Subscription,
    target:      SubscriptionStatus,
) -> String {
    let title = format!("Confirm subscription status: {tenant_slug}");
    let warning = match (current.status == target, target) {
        (true,  _)                         => r##"<p class="muted">No change — current and target are the same.</p>"##.to_owned(),
        (false, SubscriptionStatus::Cancelled) => r##"<p role="status" class="critical"><span class="badge warn">caution</span> Cancelling marks the subscription as cancelled. The current period continues to be honored; behavior at period end depends on the integration.</p>"##.to_owned(),
        (false, SubscriptionStatus::Expired)   => r##"<p role="status" class="critical"><span class="badge critical">danger</span> Marking expired causes plan-quota enforcement to fall through to "no plan" allow-all. Confirm only if you intend the tenant to no longer be subject to its plan limits.</p>"##.to_owned(),
        _                                  => String::new(),
    };
    let target_str = match target {
        SubscriptionStatus::Active    => "active",
        SubscriptionStatus::PastDue   => "past_due",
        SubscriptionStatus::Cancelled => "cancelled",
        SubscriptionStatus::Expired   => "expired",
    };
    let body = format!(
        r##"<p><a href="/admin/saas/tenants/{tid}">← Back to tenant</a></p>
<section aria-label="Diff">
  <h2>Change to apply</h2>
  <table><tbody>
    <tr><th scope="row">Tenant</th>            <td><code>{slug}</code></td></tr>
    <tr><th scope="row">Status (current)</th>  <td>{from}</td></tr>
    <tr><th scope="row">Status (target)</th>   <td>{to}</td></tr>
  </tbody></table>
  {warning}
</section>
<section aria-label="Apply">
  <form class="danger" method="post" action="/admin/saas/tenants/{tid}/subscription/status">
    <input type="hidden" name="status"  value="{target}">
    <input type="hidden" name="confirm" value="yes">
    <p><button type="submit">Apply status change</button></p>
  </form>
</section>"##,
        tid    = escape(tenant_id),
        slug   = escape(tenant_slug),
        from   = render_status_badge(current.status),
        to     = render_status_badge(target),
        target = target_str,
    );
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

fn render_status_badge(s: SubscriptionStatus) -> &'static str {
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
    use cesauth_core::billing::types::{Subscription, SubscriptionLifecycle, SubscriptionStatus};

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None, role: Role::Operations }
    }
    fn s(status: SubscriptionStatus) -> Subscription {
        Subscription {
            id: "s".into(), tenant_id: "t".into(), plan_id: "p".into(),
            lifecycle: SubscriptionLifecycle::Paid, status,
            started_at: 0, current_period_end: None, trial_ends_at: None,
            status_changed_at: 0, updated_at: 0,
        }
    }

    #[test]
    fn confirm_warns_on_expire() {
        let html = confirm_page(&p(), "t", "acme", &s(SubscriptionStatus::Active), SubscriptionStatus::Expired);
        assert!(html.contains("plan-quota enforcement to fall through"));
    }

    #[test]
    fn confirm_warns_on_cancel() {
        let html = confirm_page(&p(), "t", "acme", &s(SubscriptionStatus::Active), SubscriptionStatus::Cancelled);
        assert!(html.contains("current period continues"));
    }

    #[test]
    fn confirm_no_op_on_same_status() {
        let html = confirm_page(&p(), "t", "acme", &s(SubscriptionStatus::Active), SubscriptionStatus::Active);
        assert!(html.contains("No change"));
    }
}
