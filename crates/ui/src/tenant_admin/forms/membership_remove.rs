//! Tenant-scoped membership remove (one-step confirm).
//!
//! Mildly destructive — cuts off the user from anything they were
//! getting via that membership. One-step confirm between the click
//! and the commit (no diff page, just a yes/no).

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::Tenant;

use super::super::frame::{tenant_admin_frame, TenantAdminTab};

pub fn for_tenant(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    user_id:   &str,
    role:      &str,
) -> String {
    let title = format!("Remove tenant member: {user_id}");
    let body = render_body(
        &format!("/admin/t/{}", escape(&tenant.slug)),
        &format!("/admin/t/{}/memberships/{}/delete", escape(&tenant.slug), escape(user_id)),
        &format!("Remove user <code>{}</code> from tenant <code>{}</code>?",
            escape(user_id), escape(&tenant.slug)),
        Some(("Role being removed", role)),
        "tenant",
    );
    tenant_admin_frame(
        &title, &tenant.slug, &tenant.display_name,
        principal.role, principal.name.as_deref(),
        TenantAdminTab::Overview, &body,
    )
}

pub fn for_organization(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    org_id:    &str,
    org_slug:  &str,
    user_id:   &str,
    role:      &str,
) -> String {
    let title = format!("Remove org member: {user_id}");
    let body = render_body(
        &format!("/admin/t/{}/organizations/{}", escape(&tenant.slug), escape(org_id)),
        &format!("/admin/t/{}/organizations/{}/memberships/{}/delete",
            escape(&tenant.slug), escape(org_id), escape(user_id)),
        &format!("Remove user <code>{}</code> from organization <code>{}</code>?",
            escape(user_id), escape(org_slug)),
        Some(("Role being removed", role)),
        "organization",
    );
    tenant_admin_frame(
        &title, &tenant.slug, &tenant.display_name,
        principal.role, principal.name.as_deref(),
        TenantAdminTab::OrganizationDetail, &body,
    )
}

pub fn for_group(
    principal:  &AdminPrincipal,
    tenant:     &Tenant,
    group_id:   &str,
    group_slug: &str,
    org_id:     &str,
    user_id:    &str,
) -> String {
    let title = format!("Remove group member: {user_id}");
    let back = if org_id.is_empty() {
        format!("/admin/t/{}/organizations", escape(&tenant.slug))
    } else {
        format!("/admin/t/{}/organizations/{}", escape(&tenant.slug), escape(org_id))
    };
    let body = render_body(
        &back,
        &format!("/admin/t/{}/groups/{}/memberships/{}/delete",
            escape(&tenant.slug), escape(group_id), escape(user_id)),
        &format!("Remove user <code>{}</code> from group <code>{}</code>?",
            escape(user_id), escape(group_slug)),
        None,
        "group",
    );
    tenant_admin_frame(
        &title, &tenant.slug, &tenant.display_name,
        principal.role, principal.name.as_deref(),
        TenantAdminTab::OrganizationDetail, &body,
    )
}

fn render_body(
    back_href:    &str,
    form_action:  &str,
    headline:     &str,
    role_row:     Option<(&str, &str)>,
    parent_kind:  &str,
) -> String {
    let role_html = match role_row {
        None    => String::new(),
        Some((label, role)) => format!(
            r#"<tr><th scope="row">{l}</th><td><code>{r}</code></td></tr>"#,
            l = escape(label), r = escape(role),
        ),
    };
    format!(
        r##"<p><a href="{back}">← Back</a></p>
<section aria-label="Confirm">
  <h3>Remove member</h3>
  <p>{headline}</p>
  <table><tbody>{role_html}</tbody></table>
  <p class="muted">After remove, the user immediately loses any access tied to this {kind} membership.
     Other memberships at broader scopes may continue to grant access.</p>
</section>
<section aria-label="Apply or cancel">
  <form method="post" action="{action}">
    <input type="hidden" name="confirm" value="yes">
    <p>
      <button type="submit" class="critical">Remove member</button>
      <a href="{back}">Cancel</a>
    </p>
  </form>
</section>"##,
        back   = back_href,
        action = form_action,
        kind   = escape(parent_kind),
    )
}
