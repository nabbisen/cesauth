//! `/admin/t/<slug>/organizations` and
//! `/admin/t/<slug>/organizations/:oid` — list and detail.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::{Group, Organization, OrganizationStatus, Tenant};

use super::frame::{tenant_admin_frame, TenantAdminTab};

pub fn organizations_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    orgs:      &[Organization],
) -> String {
    let body = if orgs.is_empty() {
        r#"<p class="empty">No organizations under this tenant yet.</p>"#.to_owned()
    } else {
        render_org_table(tenant, orgs)
    };
    tenant_admin_frame(
        "Organizations",
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::Organizations,
        &body,
    )
}

pub fn organization_detail_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    org:       &Organization,
    groups:    &[Group],
) -> String {
    let body = format!(
        "{card}\n{groups}",
        card   = render_org_card(org),
        groups = render_groups_section(groups),
    );
    let title = format!("Organization — {}", org.display_name);
    tenant_admin_frame(
        &title,
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::OrganizationDetail,
        &body,
    )
}

fn render_org_table(tenant: &Tenant, orgs: &[Organization]) -> String {
    let rows: String = orgs.iter().map(|o| {
        format!(
            r#"<tr>
  <td><a href="/admin/t/{slug}/organizations/{oid}">{name}</a></td>
  <td><code>{org_slug}</code></td>
  <td>{status}</td>
</tr>"#,
            slug     = escape(&tenant.slug),
            oid      = escape(&o.id),
            name     = escape(&o.display_name),
            org_slug = escape(&o.slug),
            status   = render_org_status_badge(o.status),
        )
    }).collect::<Vec<_>>().join("\n");
    format!(
        r##"<table>
  <thead><tr><th scope="col">Display name</th><th scope="col">Slug</th><th scope="col">Status</th></tr></thead>
  <tbody>
{rows}
  </tbody>
</table>"##,
    )
}

fn render_org_card(o: &Organization) -> String {
    format!(
        r##"<section aria-label="Organization">
  <table>
    <tbody>
      <tr><th scope="row">Display name</th><td>{name}</td></tr>
      <tr><th scope="row">Slug</th><td><code>{slug}</code></td></tr>
      <tr><th scope="row">Status</th><td>{status}</td></tr>
    </tbody>
  </table>
</section>"##,
        name   = escape(&o.display_name),
        slug   = escape(&o.slug),
        status = render_org_status_badge(o.status),
    )
}

fn render_groups_section(groups: &[Group]) -> String {
    if groups.is_empty() {
        return r##"<section aria-label="Groups"><h2>Groups</h2>
<p class="empty">No groups in this organization.</p></section>"##.into();
    }
    let rows: String = groups.iter().map(|g| {
        format!(
            r#"<tr><td>{name}</td><td><code>{slug}</code></td></tr>"#,
            name = escape(&g.display_name),
            slug = escape(&g.slug),
        )
    }).collect::<Vec<_>>().join("\n");
    format!(
        r##"<section aria-label="Groups">
  <h2>Groups</h2>
  <table>
    <thead><tr><th scope="col">Display name</th><th scope="col">Slug</th></tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
</section>"##
    )
}

fn render_org_status_badge(s: OrganizationStatus) -> &'static str {
    match s {
        OrganizationStatus::Active    => r#"<span class="badge ok">active</span>"#,
        OrganizationStatus::Suspended => r#"<span class="badge warn">suspended</span>"#,
        OrganizationStatus::Deleted   => r#"<span class="badge critical">deleted</span>"#,
    }
}
