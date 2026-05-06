//! `GET/POST /admin/t/:slug/organizations/new` — create an
//! organization within the current tenant. One-click submit
//! (additive, low risk). Tenant identity comes from the URL
//! slug, not a hidden field, so tenant boundary is enforced by
//! the route gate.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::Tenant;

use super::super::frame::{tenant_admin_frame, TenantAdminTab};

pub fn organization_create_form(
    principal:    &AdminPrincipal,
    tenant:       &Tenant,
    slug:         &str,
    display_name: &str,
    error:        Option<&str>,
) -> String {
    let title = format!("New organization in: {}", tenant.slug);
    let body = format!(
        r##"<p><a href="/admin/t/{tslug}/organizations">← Back to organizations</a></p>
{error}
<section aria-label="New organization form">
  <form method="post" action="/admin/t/{tslug}/organizations/new">
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
    <li>The slug is unique within this tenant. It cannot be changed later.</li>
    <li>The new organization starts in <code>active</code> status with no members.
        Add memberships via the organization detail page (forms ship in 0.15.0).</li>
    <li>Quota: this tenant's plan caps the number of organizations.
        If you hit the limit, the create returns 409.</li>
  </ul>
</section>"##,
        tslug = escape(&tenant.slug),
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
    tenant_admin_frame(
        &title,
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::Organizations,
        &body,
    )
}
