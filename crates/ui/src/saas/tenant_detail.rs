//! `/admin/saas/tenants/:tid` — one tenant's full picture.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::billing::types::{Plan, Subscription, SubscriptionStatus};
use cesauth_core::tenancy::types::{
    Organization, Tenant, TenantMembership, TenantMembershipRole,
};

use super::frame::{saas_frame, SaasTab};
use super::tenants::render_status_badge;

/// Inputs needed to render a single tenant page. The route handler
/// builds this from a fan-out of D1 reads; we keep the type here so
/// the call shape stays explicit.
#[derive(Debug, Clone)]
pub struct TenantDetailInput<'a> {
    pub tenant:        &'a Tenant,
    pub members:       &'a [TenantMembership],
    pub organizations: &'a [Organization],
    pub subscription:  Option<&'a Subscription>,
    /// Looked up from `subscription.plan_id`; passed in separately
    /// because the plan catalog has its own lifetime.
    pub plan:          Option<&'a Plan>,
}

pub fn tenant_detail_page(principal: &AdminPrincipal, input: &TenantDetailInput<'_>) -> String {
    let title = format!("Tenant: {}", input.tenant.slug);
    let actions = render_actions(principal, &input.tenant.id, input.subscription.is_some());
    let body = format!(
        "{actions}\n{summary}\n{subscription}\n{orgs}\n{members}",
        summary      = render_summary(input.tenant),
        subscription = render_subscription(input.subscription, input.plan, &input.tenant.id),
        orgs         = render_organizations_section(principal, &input.tenant.id, input.organizations),
        members      = render_members_with_actions(Some(principal), &input.tenant.id, input.members),
    );
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

fn render_actions(principal: &AdminPrincipal, tenant_id: &str, has_subscription: bool) -> String {
    if !principal.role.can_manage_tenancy() {
        return String::new();
    }
    let tid = escape(tenant_id);
    let sub_actions = if has_subscription {
        format!(
            r##"
  <a class="action" href="/admin/saas/tenants/{tid}/subscription/plan">Change plan</a>
  <a class="action" href="/admin/saas/tenants/{tid}/subscription/status">Change subscription status</a>"##,
        )
    } else {
        String::new()
    };
    format!(
        r##"<section aria-label="Actions">
  <p class="muted">Mutations available to your role:</p>
  <div class="action-row">
    <a class="action" href="/admin/saas/tenants/{tid}/organizations/new">+ New organization</a>
    <a class="action" href="/admin/saas/tenants/{tid}/groups/new">+ New tenant-scoped group</a>
    <a class="action" href="/admin/saas/tenants/{tid}/memberships/new">+ Add tenant member</a>
    <a class="action danger" href="/admin/saas/tenants/{tid}/status">Change tenant status</a>{sub_actions}
  </div>
</section>"##,
    )
}

fn render_summary(t: &Tenant) -> String {
    format!(
        r##"<section aria-label="Tenant summary">
  <h2>Summary</h2>
  <table>
    <tbody>
      <tr><th scope="row">Id</th>            <td><code>{id}</code></td></tr>
      <tr><th scope="row">Slug</th>          <td><code>{slug}</code></td></tr>
      <tr><th scope="row">Display name</th>  <td>{name}</td></tr>
      <tr><th scope="row">Status</th>        <td>{status}</td></tr>
      <tr><th scope="row">Created (unix)</th><td>{created}</td></tr>
      <tr><th scope="row">Updated (unix)</th><td>{updated}</td></tr>
    </tbody>
  </table>
</section>"##,
        id      = escape(&t.id),
        slug    = escape(&t.slug),
        name    = escape(&t.display_name),
        status  = render_status_badge(t.status),
        created = t.created_at,
        updated = t.updated_at,
    )
}

fn render_subscription(s: Option<&Subscription>, p: Option<&Plan>, tenant_id: &str) -> String {
    match (s, p) {
        (None, _) => format!(
            r##"<section aria-label="Subscription">
  <h2>Subscription</h2>
  <p class="muted">No subscription on file. Provision one with
    <code>POST /api/v1/tenants/{tid}/subscription</code> (route lands
    in 0.9.0) or insert a row directly in <code>subscriptions</code>.</p>
</section>"##,
            tid = escape(tenant_id)),
        (Some(s), p) => {
            let status_badge = match s.status {
                SubscriptionStatus::Active    => r#"<span class="badge ok">active</span>"#,
                SubscriptionStatus::PastDue   => r#"<span class="badge warn">past_due</span>"#,
                SubscriptionStatus::Cancelled => r#"<span class="badge critical">cancelled</span>"#,
                SubscriptionStatus::Expired   => r#"<span class="badge critical">expired</span>"#,
            };
            let plan_label = p.map(|x| escape(&x.display_name)).unwrap_or_else(|| "(unknown)".to_owned());
            let plan_slug  = p.map(|x| escape(&x.slug)).unwrap_or_else(|| escape(&s.plan_id));
            let trial_row = match s.trial_ends_at {
                Some(t) => format!(r#"<tr><th scope="row">Trial ends (unix)</th><td>{t}</td></tr>"#),
                None    => String::new(),
            };
            let period_row = match s.current_period_end {
                Some(t) => format!(r#"<tr><th scope="row">Current period end (unix)</th><td>{t}</td></tr>"#),
                None    => r#"<tr><th scope="row">Current period end</th><td class="muted">none (evergreen)</td></tr>"#.to_owned(),
            };
            format!(
                r##"<section aria-label="Subscription">
  <h2>Subscription</h2>
  <table>
    <tbody>
      <tr><th scope="row">Plan</th>      <td>{plan_label} (<code>{plan_slug}</code>)</td></tr>
      <tr><th scope="row">Lifecycle</th> <td><code>{lifecycle}</code></td></tr>
      <tr><th scope="row">Status</th>    <td>{status_badge}</td></tr>
      <tr><th scope="row">Started (unix)</th><td>{started}</td></tr>
      {period_row}
      {trial_row}
    </tbody>
  </table>
  <p class="muted"><a href="/admin/saas/tenants/{tid}/subscription/history">View change history →</a></p>
</section>"##,
                lifecycle = match s.lifecycle {
                    cesauth_core::billing::types::SubscriptionLifecycle::Trial => "trial",
                    cesauth_core::billing::types::SubscriptionLifecycle::Paid  => "paid",
                    cesauth_core::billing::types::SubscriptionLifecycle::Grace => "grace",
                },
                started = s.started_at,
                tid     = escape(tenant_id),
            )
        }
    }
}

fn render_organizations_section(_principal: &AdminPrincipal, _tenant_id: &str, orgs: &[Organization]) -> String {
    // _principal is reserved here for future per-row actions; the
    // "+ New organization" button is rendered by render_actions
    // above so this function stays read-only.
    render_organizations(orgs)
}

fn render_organizations(orgs: &[Organization]) -> String {
    let body: String = if orgs.is_empty() {
        r#"<tr><td colspan="3" class="empty">No organizations.</td></tr>"#.to_owned()
    } else {
        orgs.iter().map(|o| format!(
            r##"<tr>
  <td><a href="/admin/saas/organizations/{id}"><code>{slug}</code></a></td>
  <td>{name}</td>
  <td>{status}</td>
</tr>"##,
            id   = escape(&o.id),
            slug = escape(&o.slug),
            name = escape(&o.display_name),
            status = format!("{:?}", o.status).to_lowercase(),
        )).collect::<Vec<_>>().join("\n")
    };
    format!(
        r##"<section aria-label="Organizations">
  <h2>Organizations</h2>
  <table><thead>
    <tr><th scope="col">Slug</th><th scope="col">Display name</th><th scope="col">Status</th></tr>
  </thead><tbody>
{body}
  </tbody></table>
</section>"##
    )
}

fn render_members_with_actions(
    principal: Option<&AdminPrincipal>,
    tenant_id: &str,
    members:   &[TenantMembership],
) -> String {
    let manage = principal.map(|p| p.role.can_manage_tenancy()).unwrap_or(false);
    let body: String = if members.is_empty() {
        let cols = if manage { 4 } else { 3 };
        format!(r#"<tr><td colspan="{cols}" class="empty">No members.</td></tr>"#)
    } else {
        members.iter().map(|m| {
            let role_badge = match m.role {
                TenantMembershipRole::Owner => r#"<span class="badge critical">owner</span>"#,
                TenantMembershipRole::Admin => r#"<span class="badge warn">admin</span>"#,
                TenantMembershipRole::Member => r#"<span class="badge">member</span>"#,
            };
            let action_cell = if manage {
                format!(
                    r##"<td><a class="action danger" href="/admin/saas/tenants/{tid}/memberships/{uid}/delete" style="font-size: 0.85em; padding: 4px 10px;">Remove</a></td>"##,
                    tid = escape(tenant_id),
                    uid = escape(&m.user_id),
                )
            } else {
                String::new()
            };
            format!(
                r##"<tr>
  <td><a href="/admin/saas/users/{uid}/role_assignments"><code>{uid_short}</code></a></td>
  <td>{badge}</td>
  <td class="muted">{joined}</td>
  {action_cell}
</tr>"##,
                uid       = escape(&m.user_id),
                uid_short = escape(&m.user_id),
                badge     = role_badge,
                joined    = m.joined_at,
            )
        }).collect::<Vec<_>>().join("\n")
    };
    let action_th = if manage { r#"<th scope="col"></th>"# } else { "" };
    format!(
        r##"<section aria-label="Members">
  <h2>Tenant members</h2>
  <table><thead>
    <tr>
      <th scope="col">User id</th>
      <th scope="col">Role</th>
      <th scope="col">Joined (unix)</th>
      {action_th}
    </tr>
  </thead><tbody>
{body}
  </tbody></table>
  <p class="muted">Click a user id to view that user's role assignments across every scope.</p>
</section>"##
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;
    use cesauth_core::billing::types::{
        FeatureFlag, Plan, Quota, SubscriptionLifecycle, SubscriptionStatus,
    };
    use cesauth_core::tenancy::types::{
        Organization, OrganizationStatus, Tenant, TenantStatus,
    };

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "admin".into(), name: None,role: Role::ReadOnly, user_id: None }
    }
    fn t() -> Tenant {
        Tenant {
            id: "t-acme".into(), slug: "acme".into(),
            display_name: "Acme Corp".into(),
            status: TenantStatus::Active, created_at: 0, updated_at: 0,
        }
    }
    fn input<'a>(t: &'a Tenant, members: &'a [TenantMembership], orgs: &'a [Organization]) -> TenantDetailInput<'a> {
        TenantDetailInput {
            tenant: t, members, organizations: orgs,
            subscription: None, plan: None,
        }
    }

    #[test]
    fn detail_page_shows_summary_and_no_subscription() {
        let html = tenant_detail_page(&p(), &input(&t(), &[], &[]));
        assert!(html.contains("acme"));
        assert!(html.contains("Acme Corp"));
        assert!(html.contains("No subscription on file"));
    }

    #[test]
    fn detail_page_lists_organizations() {
        let tenant = t();
        let orgs = vec![Organization {
            id: "o-eng".into(), tenant_id: tenant.id.clone(),
            slug: "engineering".into(), display_name: "Engineering".into(),
            status: OrganizationStatus::Active, parent_organization_id: None,
            created_at: 0, updated_at: 0,
        }];
        let html = tenant_detail_page(&p(), &input(&tenant, &[], &orgs));
        assert!(html.contains("/admin/saas/organizations/o-eng"));
        assert!(html.contains("engineering"));
    }

    #[test]
    fn detail_page_renders_subscription_with_plan() {
        let tenant = t();
        let sub = Subscription {
            id: "s1".into(), tenant_id: tenant.id.clone(), plan_id: "plan-pro".into(),
            lifecycle: SubscriptionLifecycle::Paid, status: SubscriptionStatus::Active,
            started_at: 100, current_period_end: Some(200), trial_ends_at: None,
            status_changed_at: 100, updated_at: 100,
        };
        let plan = Plan {
            id: "plan-pro".into(), slug: "pro".into(), display_name: "Pro Plan".into(),
            active: true,
            features: vec![FeatureFlag::new("core")],
            quotas: vec![Quota { name: "max_users".into(), value: 100 }],
            price_description: None, created_at: 0, updated_at: 0,
        };
        let inp = TenantDetailInput {
            tenant: &tenant, members: &[], organizations: &[],
            subscription: Some(&sub), plan: Some(&plan),
        };
        let html = tenant_detail_page(&p(), &inp);
        assert!(html.contains("Pro Plan"));
        assert!(html.contains("active"));
        assert!(html.contains("paid"));
    }

    #[test]
    fn member_link_points_to_user_role_assignments() {
        let tenant = t();
        let members = vec![TenantMembership {
            tenant_id: tenant.id.clone(), user_id: "u-alice".into(),
            role: TenantMembershipRole::Owner, joined_at: 0,
        }];
        let html = tenant_detail_page(&p(), &input(&tenant, &members, &[]));
        assert!(html.contains("/admin/saas/users/u-alice/role_assignments"));
        assert!(html.contains("owner"));
    }

    #[test]
    fn read_only_role_does_not_see_action_buttons() {
        let html = tenant_detail_page(&p(), &input(&t(), &[], &[]));
        // ReadOnly: no /new, no /status, no subscription/plan links.
        assert!(!html.contains(r#"href="/admin/saas/tenants/t-acme/organizations/new""#),
            "ReadOnly must not see + New organization");
        assert!(!html.contains(r#"href="/admin/saas/tenants/t-acme/status""#),
            "ReadOnly must not see Change tenant status");
        assert!(!html.contains(r#"href="/admin/saas/tenants/t-acme/groups/new""#),
            "ReadOnly must not see + New tenant-scoped group");
    }

    #[test]
    fn operations_role_sees_action_buttons() {
        let p = AdminPrincipal { id: "x".into(), name: None,role: Role::Operations, user_id: None };
        let html = tenant_detail_page(&p, &input(&t(), &[], &[]));
        assert!(html.contains(r#"href="/admin/saas/tenants/t-acme/organizations/new""#));
        assert!(html.contains(r#"href="/admin/saas/tenants/t-acme/status""#));
        assert!(html.contains(r#"href="/admin/saas/tenants/t-acme/groups/new""#));
    }

    #[test]
    fn subscription_actions_appear_only_when_subscription_present() {
        // Without a subscription, the "Change plan" / "Change
        // subscription status" buttons should not render — there's
        // nothing to change yet.
        let p = AdminPrincipal { id: "x".into(), name: None,role: Role::Operations, user_id: None };
        let tenant = t();
        let html_no_sub = tenant_detail_page(&p, &input(&tenant, &[], &[]));
        assert!(!html_no_sub.contains(r#"/subscription/plan""#),
            "no subscription -> no Change plan button");

        // With a subscription, buttons appear.
        let sub = cesauth_core::billing::types::Subscription {
            id: "s".into(), tenant_id: tenant.id.clone(), plan_id: "plan-pro".into(),
            lifecycle: cesauth_core::billing::types::SubscriptionLifecycle::Paid,
            status: cesauth_core::billing::types::SubscriptionStatus::Active,
            started_at: 0, current_period_end: None, trial_ends_at: None,
            status_changed_at: 0, updated_at: 0,
        };
        let inp = TenantDetailInput {
            tenant: &tenant, members: &[], organizations: &[],
            subscription: Some(&sub), plan: None,
        };
        let html_with_sub = tenant_detail_page(&p, &inp);
        assert!(html_with_sub.contains(r#"/subscription/plan""#),
            "with subscription -> Change plan button");
        assert!(html_with_sub.contains(r#"/subscription/status""#),
            "with subscription -> Change subscription status button");
    }
}
