//! `/admin/tenancy/organizations/:oid` — one organization's full picture.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::{
    Group, Organization, OrganizationMembership, OrganizationRole, OrganizationStatus,
};

use super::frame::{tenancy_console_frame, TenancyConsoleTab};

#[derive(Debug, Clone)]
pub struct OrganizationDetailInput<'a> {
    pub organization: &'a Organization,
    /// The org-scoped groups (`parent_kind = 'organization'`).
    pub groups:       &'a [Group],
    pub members:      &'a [OrganizationMembership],
}

pub fn organization_detail_page(
    principal: &AdminPrincipal,
    input:     &OrganizationDetailInput<'_>,
) -> String {
    let title = format!("Organization: {}", input.organization.slug);
    let actions = render_actions(principal, &input.organization.id);
    let body = format!(
        "{actions}\n{summary}\n{groups}\n{members}",
        summary = render_summary(input.organization),
        groups  = render_groups_section(principal, &input.organization.id, input.groups),
        members = render_members_with_actions(Some(principal), &input.organization.id, input.members),
    );
    tenancy_console_frame(&title, principal.role, principal.name.as_deref(), TenancyConsoleTab::Tenants, &body)
}

fn render_actions(principal: &AdminPrincipal, org_id: &str) -> String {
    if !principal.role.can_manage_tenancy() {
        return String::new();
    }
    let oid = escape(org_id);
    format!(
        r##"<section aria-label="Actions">
  <p class="muted">Mutations available to your role:</p>
  <div class="action-row">
    <a class="action" href="/admin/tenancy/organizations/{oid}/groups/new">+ New group</a>
    <a class="action" href="/admin/tenancy/organizations/{oid}/memberships/new">+ Add organization member</a>
    <a class="action danger" href="/admin/tenancy/organizations/{oid}/status">Change organization status</a>
  </div>
</section>"##,
    )
}

fn render_groups_section(principal: &AdminPrincipal, _org_id: &str, groups: &[Group]) -> String {
    // Per-row delete affordance.
    let body: String = if groups.is_empty() {
        r#"<tr><td colspan="4" class="empty">No groups in this organization.</td></tr>"#.to_owned()
    } else {
        groups.iter().map(|g| {
            let delete_link = if principal.role.can_manage_tenancy() {
                format!(
                    r##"<a class="action danger" href="/admin/tenancy/groups/{id}/delete" style="font-size: 0.85em; padding: 4px 10px;">Delete</a>"##,
                    id = escape(&g.id),
                )
            } else {
                String::new()
            };
            format!(
                r##"<tr>
  <td><code>{slug}</code></td>
  <td>{name}</td>
  <td class="muted">{id}</td>
  <td>{delete_link}</td>
</tr>"##,
                slug = escape(&g.slug),
                name = escape(&g.display_name),
                id   = escape(&g.id),
            )
        }).collect::<Vec<_>>().join("\n")
    };
    format!(
        r##"<section aria-label="Groups">
  <h2>Groups</h2>
  <table><thead>
    <tr>
      <th scope="col">Slug</th>
      <th scope="col">Display name</th>
      <th scope="col">Id</th>
      <th scope="col"></th>
    </tr>
  </thead><tbody>
{body}
  </tbody></table>
</section>"##
    )
}

fn render_summary(o: &Organization) -> String {
    let status_badge = match o.status {
        OrganizationStatus::Active    => r#"<span class="badge ok">active</span>"#,
        OrganizationStatus::Suspended => r#"<span class="badge warn">suspended</span>"#,
        OrganizationStatus::Deleted   => r#"<span class="badge critical">deleted</span>"#,
    };
    format!(
        r##"<section aria-label="Summary">
  <h2>Summary</h2>
  <table>
    <tbody>
      <tr><th scope="row">Id</th>          <td><code>{id}</code></td></tr>
      <tr><th scope="row">Tenant</th>      <td><a href="/admin/tenancy/tenants/{tid}"><code>{tid_short}</code></a></td></tr>
      <tr><th scope="row">Slug</th>        <td><code>{slug}</code></td></tr>
      <tr><th scope="row">Display name</th><td>{name}</td></tr>
      <tr><th scope="row">Status</th>      <td>{status}</td></tr>
      <tr><th scope="row">Created (unix)</th><td>{created}</td></tr>
    </tbody>
  </table>
</section>"##,
        id        = escape(&o.id),
        tid       = escape(&o.tenant_id),
        tid_short = escape(&o.tenant_id),
        slug      = escape(&o.slug),
        name      = escape(&o.display_name),
        status    = status_badge,
        created   = o.created_at,
    )
}

fn render_members_with_actions(
    principal: Option<&AdminPrincipal>,
    org_id:    &str,
    members:   &[OrganizationMembership],
) -> String {
    let manage = principal.map(|p| p.role.can_manage_tenancy()).unwrap_or(false);
    let body: String = if members.is_empty() {
        let cols = if manage { 4 } else { 3 };
        format!(r#"<tr><td colspan="{cols}" class="empty">No members.</td></tr>"#)
    } else {
        members.iter().map(|m| {
            let badge = match m.role {
                OrganizationRole::Admin  => r#"<span class="badge warn">admin</span>"#,
                OrganizationRole::Member => r#"<span class="badge">member</span>"#,
            };
            let action_cell = if manage {
                format!(
                    r##"<td><a class="action danger" href="/admin/tenancy/organizations/{oid}/memberships/{uid}/delete" style="font-size: 0.85em; padding: 4px 10px;">Remove</a></td>"##,
                    oid = escape(org_id),
                    uid = escape(&m.user_id),
                )
            } else {
                String::new()
            };
            format!(
                r##"<tr>
  <td><a href="/admin/tenancy/users/{uid}/role_assignments"><code>{uid}</code></a></td>
  <td>{badge}</td>
  <td class="muted">{joined}</td>
  {action_cell}
</tr>"##,
                uid    = escape(&m.user_id),
                badge  = badge,
                joined = m.joined_at,
            )
        }).collect::<Vec<_>>().join("\n")
    };
    let action_th = if manage { r#"<th scope="col"></th>"# } else { "" };
    format!(
        r##"<section aria-label="Members">
  <h2>Members</h2>
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
</section>"##
    )
}
