//! `/admin/t/<slug>/organizations` and
//! `/admin/t/<slug>/organizations/:oid` — list and detail.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::routes::tenant_admin as routes;
use cesauth_core::tenancy::types::{Group, Organization, OrganizationStatus, Tenant};

use super::affordances::Affordances;
use super::frame::{tenant_admin_frame, TenantAdminTab};

pub fn organizations_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    orgs:      &[Organization],
    aff:       &Affordances,
) -> String {
    let create_button = if aff.can_create_organization {
        format!(
            r#"<p><a href="{url}" class="button">+ New organization</a></p>"#,
            // RFC 108 escape contract.
            url = escape(&routes::organizations_new(&tenant.slug)),
        )
    } else { String::new() };
    let table = if orgs.is_empty() {
        r#"<p class="empty">No organizations under this tenant yet.</p>"#.to_owned()
    } else {
        render_org_table(tenant, orgs, aff)
    };
    let body = format!("{create_button}\n{table}");
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
    aff:       &Affordances,
) -> String {
    let actions = render_org_actions(tenant, org, aff);
    let body = format!(
        "{actions}\n{card}\n{groups}",
        actions = actions,
        card    = render_org_card(org),
        groups  = render_groups_section(tenant, groups, aff),
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

fn render_org_actions(tenant: &Tenant, org: &Organization, aff: &Affordances) -> String {
    let mut buttons: Vec<String> = Vec::new();
    if aff.can_update_organization {
        buttons.push(format!(
            r#"<a href="{url}" class="button">Change status</a>"#,
            // RFC 108 escape contract.
            url = escape(&routes::org_status(&tenant.slug, &org.id)),
        ));
    }
    if aff.can_create_group {
        buttons.push(format!(
            r#"<a href="{url}" class="button">+ New group</a>"#,
            url = escape(&routes::org_groups_new(&tenant.slug, &org.id)),
        ));
    }
    if aff.can_add_org_member {
        buttons.push(format!(
            r#"<a href="{url}" class="button">+ Add member</a>"#,
            url = escape(&routes::org_memberships_new(&tenant.slug, &org.id)),
        ));
    }
    if buttons.is_empty() {
        return String::new();
    }
    format!(r#"<p>{}</p>"#, buttons.join(" "))
}

fn render_org_table(tenant: &Tenant, orgs: &[Organization], _aff: &Affordances) -> String {
    let rows: String = orgs.iter().map(|o| {
        format!(
            r#"<tr>
  <td><a href="{url}">{name}</a></td>
  <td><code>{org_slug}</code></td>
  <td>{status}</td>
</tr>"#,
            url      = escape(&routes::org_detail(&tenant.slug, &o.id)),
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

fn render_groups_section(
    tenant: &Tenant, groups: &[Group], aff: &Affordances,
) -> String {
    if groups.is_empty() {
        return r##"<section aria-label="Groups"><h2>Groups</h2>
<p class="empty">No groups in this organization.</p></section>"##.into();
    }
    let rows: String = groups.iter().map(|g| {
        let mut actions: Vec<String> = Vec::new();
        if aff.can_delete_group {
            actions.push(format!(
                r#"<a href="{url}">delete</a>"#,
                url = escape(&routes::group_delete(&tenant.slug, &g.id)),
            ));
        }
        if aff.can_add_group_member {
            actions.push(format!(
                r#"<a href="{url}">+ member</a>"#,
                url = escape(&routes::group_memberships_new(&tenant.slug, &g.id)),
            ));
        }
        let actions_html = if actions.is_empty() {
            String::new()
        } else {
            format!("<td>{}</td>", actions.join(" · "))
        };
        format!(
            r#"<tr><td>{name}</td><td><code>{slug}</code></td>{actions}</tr>"#,
            name = escape(&g.display_name),
            slug = escape(&g.slug),
            actions = actions_html,
        )
    }).collect::<Vec<_>>().join("\n");
    let header_action = if aff.can_delete_group || aff.can_add_group_member {
        r#"<th scope="col">Actions</th>"#
    } else { "" };
    format!(
        r##"<section aria-label="Groups">
  <h2>Groups</h2>
  <table>
    <thead><tr><th scope="col">Display name</th><th scope="col">Slug</th>{header_action}</tr></thead>
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
