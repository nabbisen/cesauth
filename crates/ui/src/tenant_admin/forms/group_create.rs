//! `GET/POST /admin/t/:slug/organizations/:oid/groups/new` —
//! create a group within an organization in the current tenant.
//! One-click submit (additive, low risk).

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::{Organization, Tenant};

use super::super::frame::{tenant_admin_frame, TenantAdminTab};

pub fn group_create_form(
    principal:    &AdminPrincipal,
    tenant:       &Tenant,
    org:          &Organization,
    slug:         &str,
    display_name: &str,
    error:        Option<&str>,
) -> String {
    let title = format!("New group in: {}", org.slug);
    let body = format!(
        r##"<p><a href="/admin/t/{tslug}/organizations/{oid}">← Back to organization</a></p>
{error}
<section aria-label="New group form">
  <form method="post" action="/admin/t/{tslug}/organizations/{oid}/groups/new">
    <table>
      <tbody>
        <tr><th scope="row">Organization</th><td><code>{oslug}</code></td></tr>
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
    <p><button type="submit">Create group</button></p>
  </form>
</section>
<section aria-label="Help" class="muted">
  <h3>Notes</h3>
  <ul>
    <li>The slug is unique within this organization. It cannot be changed later.</li>
    <li>Groups are the finest-grained scope cesauth manages.
        Permissions assigned at group scope override broader scopes.</li>
  </ul>
</section>"##,
        tslug = escape(&tenant.slug),
        oid   = escape(&org.id),
        oslug = escape(&org.slug),
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
        TenantAdminTab::OrganizationDetail,
        &body,
    )
}
