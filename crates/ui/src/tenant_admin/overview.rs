//! `/admin/t/<slug>` — tenant-scoped overview.
//!
//! Counters scoped to one tenant: organizations, users, groups,
//! current subscription plan + status. The route handler builds
//! `TenantOverviewCounts` from a few SQL aggregates filtered to
//! `tenant_id = ?` and hands it here for rendering.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::{Tenant, TenantStatus};

use super::affordances::Affordances;
use super::frame::{tenant_admin_frame, TenantAdminTab};

/// Per-tenant counters, scoped to `tenant.id`.
#[derive(Debug, Clone, Default)]
pub struct TenantOverviewCounts {
    pub organizations: i64,
    pub users:         i64,
    pub groups:        i64,
    /// Current plan slug (e.g. "starter", "pro"), if a subscription
    /// row exists. None means "no active subscription" — possible
    /// for newly created tenants.
    pub current_plan:  Option<String>,
}

pub fn overview_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    counts:    &TenantOverviewCounts,
    aff:       &Affordances,
) -> String {
    let body = format!(
        "{tenant_card}\n{counters}\n{actions}\n{howto}",
        tenant_card = render_tenant_card(tenant),
        counters    = render_counters(counts),
        actions     = render_quick_actions(tenant, aff),
        howto       = render_howto(),
    );
    tenant_admin_frame(
        "Overview",
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::Overview,
        &body,
    )
}

/// Quick-action buttons surfaced on the overview page. Only the
/// affordances the current user has at tenant scope appear.
fn render_quick_actions(tenant: &Tenant, aff: &Affordances) -> String {
    let mut buttons: Vec<String> = Vec::new();
    if aff.can_create_organization {
        buttons.push(format!(
            r#"<a href="/admin/t/{slug}/organizations/new" class="button">+ New organization</a>"#,
            slug = escape(&tenant.slug),
        ));
    }
    if aff.can_add_tenant_member {
        buttons.push(format!(
            r#"<a href="/admin/t/{slug}/memberships/new" class="button">+ Add tenant member</a>"#,
            slug = escape(&tenant.slug),
        ));
    }
    if buttons.is_empty() {
        return String::new();
    }
    format!(
        r#"<section aria-label="Quick actions"><h2>Quick actions</h2><p>{}</p></section>"#,
        buttons.join(" "),
    )
}

fn render_tenant_card(t: &Tenant) -> String {
    let status_badge = match t.status {
        TenantStatus::Active     => r#"<span class="badge ok">active</span>"#,
        TenantStatus::Suspended  => r#"<span class="badge warn">suspended</span>"#,
        TenantStatus::Deleted    => r#"<span class="badge critical">deleted</span>"#,
        TenantStatus::Pending    => r#"<span class="badge warn">pending</span>"#,
    };
    format!(
        r##"<section aria-label="Tenant">
  <h2>This tenant</h2>
  <table>
    <tbody>
      <tr><th scope="row">Display name</th><td>{name}</td></tr>
      <tr><th scope="row">Slug</th><td><code>{slug}</code></td></tr>
      <tr><th scope="row">Status</th><td>{status}</td></tr>
    </tbody>
  </table>
</section>"##,
        name   = escape(&t.display_name),
        slug   = escape(&t.slug),
        status = status_badge,
    )
}

fn render_counters(c: &TenantOverviewCounts) -> String {
    let plan_html = match &c.current_plan {
        Some(p) => format!("<code>{}</code>", escape(p)),
        None    => r#"<span class="muted">none</span>"#.into(),
    };
    format!(
        r##"<section aria-label="Counters">
  <h2>Counters</h2>
  <table>
    <thead><tr><th scope="col">Metric</th><th scope="col">Count</th></tr></thead>
    <tbody>
      <tr><td>Organizations</td><td>{orgs}</td></tr>
      <tr><td>Users</td><td>{users}</td></tr>
      <tr><td>Groups</td><td>{groups}</td></tr>
      <tr><td>Current plan</td><td>{plan}</td></tr>
    </tbody>
  </table>
</section>"##,
        orgs   = c.organizations,
        users  = c.users,
        groups = c.groups,
        plan   = plan_html,
    )
}

fn render_howto() -> String {
    r##"<section aria-label="What's here">
  <h2>About this surface</h2>
  <p class="muted">This is the tenant-scoped admin surface — every page is
  filtered to your tenant. To do system-admin operations across all tenants,
  visit <code>/admin/tenancy/</code> instead (system-admin tokens only).</p>
  <p class="muted">v0.15.0 adds tenant-scoped membership forms (add/remove
  for tenant, organization, and group memberships) and affordance gating —
  buttons surface only when the current operator has permission to use them.</p>
</section>"##.into()
}
