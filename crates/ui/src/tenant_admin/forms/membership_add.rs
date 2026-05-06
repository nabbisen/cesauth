//! Tenant-scoped membership add forms (additive, one-click).
//!
//! Three URL entry points, mirroring the v0.10.0 system-admin
//! shape but slug-relative:
//! - `POST /admin/t/:slug/memberships` (tenant-scope)
//! - `POST /admin/t/:slug/organizations/:oid/memberships`
//! - `POST /admin/t/:slug/groups/:gid/memberships`
//!
//! Memberships do not grant permissions on their own (that's the
//! role-assignment forms' job); adding the same user twice is a
//! no-op. So no preview/confirm step.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::Tenant;

use super::super::frame::{tenant_admin_frame, TenantAdminTab};

/// Tenant-scope membership add. Renders a select for `role`
/// (owner / admin / member).
pub fn for_tenant(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    user_id:   &str,
    role:      &str,
    error:     Option<&str>,
) -> String {
    let title = format!("Add tenant member: {}", tenant.slug);
    render(
        principal, tenant, &title,
        &format!("/admin/t/{}", escape(&tenant.slug)),
        &format!("/admin/t/{}/memberships", escape(&tenant.slug)),
        &format!("tenant <code>{}</code>", escape(&tenant.slug)),
        TenantAdminTab::Overview,
        user_id,
        Some(("role", &[
            ("owner",  "Owner — top-level control of the tenant"),
            ("admin",  "Admin — manage organizations, groups, members"),
            ("member", "Member — basic access to tenant resources"),
        ], role)),
        error,
    )
}

/// Organization-scope membership add.
pub fn for_organization(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    org_id:    &str,
    org_slug:  &str,
    user_id:   &str,
    role:      &str,
    error:     Option<&str>,
) -> String {
    let title = format!("Add organization member: {org_slug}");
    render(
        principal, tenant, &title,
        &format!("/admin/t/{}/organizations/{}", escape(&tenant.slug), escape(org_id)),
        &format!("/admin/t/{}/organizations/{}/memberships", escape(&tenant.slug), escape(org_id)),
        &format!("organization <code>{}</code>", escape(org_slug)),
        TenantAdminTab::OrganizationDetail,
        user_id,
        Some(("role", &[
            ("admin",  "Admin — manage groups and members"),
            ("member", "Member — basic access to org resources"),
        ], role)),
        error,
    )
}

/// Group-scope membership add. No role select — group memberships
/// don't carry a role variant in the existing schema.
pub fn for_group(
    principal:  &AdminPrincipal,
    tenant:     &Tenant,
    group_id:   &str,
    group_slug: &str,
    org_id:     &str,
    user_id:    &str,
    error:      Option<&str>,
) -> String {
    let title = format!("Add group member: {group_slug}");
    let back = if org_id.is_empty() {
        format!("/admin/t/{}/organizations", escape(&tenant.slug))
    } else {
        format!("/admin/t/{}/organizations/{}", escape(&tenant.slug), escape(org_id))
    };
    render(
        principal, tenant, &title,
        &back,
        &format!("/admin/t/{}/groups/{}/memberships", escape(&tenant.slug), escape(group_id)),
        &format!("group <code>{}</code>", escape(group_slug)),
        TenantAdminTab::OrganizationDetail,
        user_id,
        None,
        error,
    )
}

#[allow(clippy::too_many_arguments)]
fn render(
    principal:   &AdminPrincipal,
    tenant:      &Tenant,
    title:       &str,
    back_href:   &str,
    form_action: &str,
    parent_html: &str,
    active_tab:  TenantAdminTab,
    user_id:     &str,
    role_select: Option<(&str, &[(&str, &str)], &str)>,
    error:       Option<&str>,
) -> String {
    let role_field = match role_select {
        None => String::new(),
        Some((name, options, selected)) => {
            let opts: String = options.iter().map(|(value, label)| {
                let s = if *value == selected { " selected" } else { "" };
                format!(
                    r#"<option value="{v}"{s}>{l}</option>"#,
                    v = escape(value), s = s, l = escape(label),
                )
            }).collect();
            format!(
                r##"<tr>
  <th scope="row"><label for="{name}">Role</label></th>
  <td><select id="{name}" name="{name}" required>{opts}</select></td>
</tr>"##,
            )
        }
    };
    let body = format!(
        r##"<p><a href="{back}">← Back</a></p>
{error}
<section aria-label="Add member form">
  <p>Adding a member to {parent_html}.</p>
  <form method="post" action="{action}">
    <table><tbody>
      <tr>
        <th scope="row"><label for="user_id">User id</label></th>
        <td><input id="user_id" name="user_id" type="text" required value="{uid}"></td>
      </tr>
      {role_field}
    </tbody></table>
    <p><button type="submit">Add member</button></p>
  </form>
</section>
<section aria-label="Help" class="muted">
  <h3>Notes</h3>
  <ul>
    <li>The user id must already exist in <code>users</code> within this tenant. This form does not auto-provision users.</li>
    <li>Memberships are additive — adding the same user twice is a no-op (the existing row is preserved).</li>
    <li>Membership alone does not grant permissions. Use the role-assignment forms to grant capabilities.</li>
  </ul>
</section>"##,
        back   = back_href,
        action = form_action,
        uid    = escape(user_id),
        error  = match error {
            None    => String::new(),
            Some(m) => format!(
                r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {m}</p></section>"#,
                m = escape(m),
            ),
        },
    );
    tenant_admin_frame(
        title, &tenant.slug, &tenant.display_name,
        principal.role, principal.name.as_deref(),
        active_tab, &body,
    )
}
