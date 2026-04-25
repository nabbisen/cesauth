//! Group create form (one-click).
//!
//! `parent_kind` is fixed by the URL: tenant-scoped groups under
//! `/admin/saas/tenants/:tid/groups/new`, organization-scoped groups
//! under `/admin/saas/organizations/:oid/groups/new`. The HTML form
//! itself doesn't ask for parent_kind because it's already encoded
//! in the URL.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;

use super::super::frame::{saas_frame, SaasTab};

/// Render a tenant-scoped group create form.
pub fn for_tenant(
    principal:    &AdminPrincipal,
    tenant_id:    &str,
    tenant_slug:  &str,
    slug:         &str,
    display_name: &str,
    error:        Option<&str>,
) -> String {
    render(principal,
        &format!("New group in tenant: {tenant_slug}"),
        &format!("/admin/saas/tenants/{}", escape(tenant_id)),
        &format!("/admin/saas/tenants/{}/groups/new", escape(tenant_id)),
        "tenant", &format!("tenant <code>{}</code>", escape(tenant_slug)),
        slug, display_name, error,
    )
}

/// Render an org-scoped group create form.
pub fn for_organization(
    principal:    &AdminPrincipal,
    org_id:       &str,
    org_slug:     &str,
    slug:         &str,
    display_name: &str,
    error:        Option<&str>,
) -> String {
    render(principal,
        &format!("New group in organization: {org_slug}"),
        &format!("/admin/saas/organizations/{}", escape(org_id)),
        &format!("/admin/saas/organizations/{}/groups/new", escape(org_id)),
        "organization", &format!("organization <code>{}</code>", escape(org_slug)),
        slug, display_name, error,
    )
}

fn render(
    principal:   &AdminPrincipal,
    title:       &str,
    back_href:   &str,
    form_action: &str,
    parent_kind: &str,
    parent_html: &str,
    slug:        &str,
    display_name:&str,
    error:       Option<&str>,
) -> String {
    let _ = parent_kind;  // hidden field intentionally omitted; the URL carries it
    let body = format!(
        r##"<p><a href="{back}">← Back</a></p>
{error}
<section aria-label="New group form">
  <p>Creating in {parent_html}.</p>
  <form method="post" action="{action}">
    <table><tbody>
      <tr>
        <th scope="row"><label for="slug">Slug</label></th>
        <td><input id="slug" name="slug" type="text" required pattern="[a-z0-9][a-z0-9-]*" value="{slug}"></td>
      </tr>
      <tr>
        <th scope="row"><label for="display_name">Display name</label></th>
        <td><input id="display_name" name="display_name" type="text" required value="{name}"></td>
      </tr>
    </tbody></table>
    <p><button type="submit">Create group</button></p>
  </form>
</section>
<section aria-label="Help" class="muted">
  <h3>Notes</h3>
  <ul>
    <li>The slug is unique within the tenant. It cannot be changed later.</li>
    <li>The new group has no members. Add memberships via
        <code>POST /api/v1/groups/:gid/memberships</code>.</li>
    <li>Quota: this tenant's plan caps the total group count.
        Hitting the limit returns 409.</li>
  </ul>
</section>"##,
        back   = back_href,
        action = form_action,
        slug   = escape(slug),
        name   = escape(display_name),
        error  = match error {
            None    => String::new(),
            Some(m) => format!(
                r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {m}</p></section>"#,
                m = escape(m),
            ),
        },
    );
    saas_frame(title, principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None, role: Role::Operations }
    }

    #[test]
    fn tenant_form_action_is_tenant_scoped() {
        let html = for_tenant(&p(), "t-acme", "acme", "", "", None);
        assert!(html.contains(r#"action="/admin/saas/tenants/t-acme/groups/new""#));
        assert!(html.contains("acme"));
    }

    #[test]
    fn organization_form_action_is_org_scoped() {
        let html = for_organization(&p(), "o-eng", "engineering", "", "", None);
        assert!(html.contains(r#"action="/admin/saas/organizations/o-eng/groups/new""#));
        assert!(html.contains("engineering"));
    }
}
