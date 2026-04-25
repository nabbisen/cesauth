//! `GET /admin/saas/tenants/:tid/organizations/new` — create-organization form.
//!
//! One-click submit (no preview). The destructive operation is
//! organization status change, which has its own preview/confirm flow.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::Tenant;

use super::super::frame::{saas_frame, SaasTab};

pub fn organization_create_form(
    principal:    &AdminPrincipal,
    tenant:       &Tenant,
    slug:         &str,
    display_name: &str,
    error:        Option<&str>,
) -> String {
    let title = format!("New organization in: {}", tenant.slug);
    let body = format!(
        r##"<p><a href="/admin/saas/tenants/{tid}">← Back to tenant detail</a></p>
{error}
<section aria-label="New organization form">
  <form method="post" action="/admin/saas/tenants/{tid}/organizations/new">
    <table>
      <tbody>
        <tr>
          <th scope="row"><label for="slug">Slug</label></th>
          <td><input id="slug" name="slug" type="text" required pattern="[a-z0-9][a-z0-9-]*" value="{slug}"></td>
        </tr>
        <tr>
          <th scope="row"><label for="display_name">Display name</label></th>
          <td><input id="display_name" name="display_name" type="text" required value="{name}"></td>
        </tr>
      </tbody>
    </table>
    <p><button type="submit">Create organization</button></p>
  </form>
</section>
<section aria-label="Help" class="muted">
  <h3>Notes</h3>
  <ul>
    <li>The slug is unique within the tenant. It cannot be changed later.</li>
    <li>The new organization starts in <code>active</code> status with no members.
        Memberships are added via <code>POST /api/v1/organizations/:oid/memberships</code>.</li>
    <li>Quota: this tenant's plan caps the number of organizations.
        If you hit the limit, the create returns 409.</li>
  </ul>
</section>"##,
        tid   = escape(&tenant.id),
        error = match error {
            None => String::new(),
            Some(msg) => format!(
                r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {msg}</p></section>"#,
                msg = escape(msg),
            ),
        },
        slug  = escape(slug),
        name  = escape(display_name),
    );
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;
    use cesauth_core::tenancy::types::{Tenant, TenantStatus};

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None, role: Role::Operations }
    }
    fn t() -> Tenant {
        Tenant {
            id: "t-acme".into(), slug: "acme".into(),
            display_name: "Acme".into(),
            status: TenantStatus::Active, created_at: 0, updated_at: 0,
        }
    }

    #[test]
    fn form_action_includes_tenant_id() {
        let html = organization_create_form(&p(), &t(), "", "", None);
        assert!(html.contains(r#"action="/admin/saas/tenants/t-acme/organizations/new""#));
    }

    #[test]
    fn quota_is_mentioned_in_help() {
        let html = organization_create_form(&p(), &t(), "", "", None);
        assert!(html.contains("Quota"));
    }
}
