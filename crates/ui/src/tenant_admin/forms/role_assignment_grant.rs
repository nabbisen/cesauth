//! `GET/POST /admin/t/:slug/users/:uid/role_assignments/new` —
//! grant a role to a user within the current tenant. Preview/confirm
//! pattern (changing authorization is medium-risk).
//!
//! Differences from the v0.9.0 system-admin equivalent:
//! - Scope picker omits `system`. A tenant admin cannot grant
//!   cesauth-wide roles (ADR-003 separation: only the system-admin
//!   surface can do that).
//! - The `tenant` scope option is implicit — its scope_id is
//!   pre-filled with the current tenant's id and not editable.
//!   This prevents a tenant admin from typing in a different
//!   tenant's id and granting against it.
//! - Visible roles come from the tenant's role catalog
//!   (`RoleRepository::list_visible_to_tenant`).

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::authz::types::Role;
use cesauth_core::tenancy::types::Tenant;
use cesauth_core::types::User;

use super::super::frame::{tenant_admin_frame, TenantAdminTab};

#[derive(Debug, Clone)]
pub struct GrantInput<'a> {
    pub subject_user:    &'a User,
    pub available_roles: &'a [Role],
    /// Sticky values on re-render after a failed submit.
    pub role_id:         &'a str,
    pub scope_type:      &'a str,  // "tenant" / "organization" / "group" / "user"
    pub scope_id:        &'a str,
    pub expires_at:      &'a str,
    pub error:           Option<&'a str>,
}

pub fn grant_form(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    input:     &GrantInput<'_>,
) -> String {
    let user_label = input.subject_user.display_name.as_deref()
        .unwrap_or(&input.subject_user.id);
    let title = format!("Grant role to user: {}", user_label);
    let role_options = render_role_options(input.available_roles, input.role_id);
    let body = format!(
        r##"<p><a href="/admin/t/{tslug}/users/{uid}/role_assignments">← Back to user's role assignments</a></p>
{error}
<section aria-label="Grant role form">
  <form method="post" action="/admin/t/{tslug}/users/{uid}/role_assignments/new">
    <table>
      <tbody>
        <tr><th scope="row">User</th><td>{uname} <code>{uid}</code></td></tr>
        <tr>
          <th scope="row"><label for="role_id">Role</label></th>
          <td><select id="role_id" name="role_id" required>{role_options}</select></td>
        </tr>
      </tbody>
    </table>

    <fieldset>
      <legend>Scope</legend>
      <p class="muted">Tenant scope grants the role across this entire tenant.
         Narrower scopes restrict it to one organization or group.</p>
      <p><input type="radio" id="sc_tenant" name="scope_type" value="tenant" {ct}>
         <label for="sc_tenant"><code>tenant</code> — scope_id is fixed to <code>{tid}</code></label></p>
      <p><input type="radio" id="sc_org"    name="scope_type" value="organization" {co}>
         <label for="sc_org"><code>organization</code></label></p>
      <p><input type="radio" id="sc_group"  name="scope_type" value="group" {cg}>
         <label for="sc_group"><code>group</code></label></p>
      <p><input type="radio" id="sc_user"   name="scope_type" value="user" {cu}>
         <label for="sc_user"><code>user</code> (rare — for self-service grants)</label></p>
    </fieldset>

    <p>
      <label for="scope_id">Scope id</label> — the organization/group/user id.
        For <code>tenant</code> scope, leave blank; the route handler will
        substitute this tenant's id.<br>
      <input id="scope_id" name="scope_id" type="text" value="{scope_id}" style="width: 30em;">
    </p>

    <p>
      <label for="expires_at">Expires at (unix seconds, optional)</label><br>
      <input id="expires_at" name="expires_at" type="number" value="{exp}" style="width: 16em;">
    </p>

    <p><button type="submit">Preview grant</button></p>
  </form>
</section>"##,
        tslug    = escape(&tenant.slug),
        tid      = escape(&tenant.id),
        uid      = escape(&input.subject_user.id),
        uname    = escape(user_label),
        ct = if input.scope_type == "tenant"       { "checked" } else { "" },
        co = if input.scope_type == "organization" { "checked" } else { "" },
        cg = if input.scope_type == "group"        { "checked" } else { "" },
        cu = if input.scope_type == "user"         { "checked" } else { "" },
        scope_id = escape(input.scope_id),
        exp      = escape(input.expires_at),
        error    = render_error(input.error),
    );
    tenant_admin_frame(
        &title,
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::UserRoleAssignments,
        &body,
    )
}

#[derive(Debug, Clone)]
pub struct PreviewInput<'a> {
    pub subject_user: &'a User,
    pub role_label:   &'a str,    // "name (slug)"
    pub scope_label:  &'a str,    // "tenant t-123" / "organization o-456"
    pub expires_at:   Option<&'a str>,
}

pub fn preview_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    role_id:   &str,
    scope_type: &str,
    scope_id:   &str,
    expires_at_raw: &str,
    input:      &PreviewInput<'_>,
) -> String {
    let user_label = input.subject_user.display_name.as_deref()
        .unwrap_or(&input.subject_user.id);
    let title = format!("Confirm grant: {}", user_label);
    let body = format!(
        r##"<p><a href="/admin/t/{tslug}/users/{uid}/role_assignments/new">← Back to form</a></p>
<section aria-label="Diff">
  <h3>Proposed grant</h3>
  <table><tbody>
    <tr><th scope="row">User</th><td>{uname} <code>{uid}</code></td></tr>
    <tr><th scope="row">Role</th><td>{role}</td></tr>
    <tr><th scope="row">Scope</th><td>{scope}</td></tr>
    <tr><th scope="row">Expires at</th><td>{exp}</td></tr>
  </tbody></table>
</section>
<section aria-label="Apply or cancel">
  <form method="post" action="/admin/t/{tslug}/users/{uid}/role_assignments/new">
    <input type="hidden" name="role_id" value="{role_id}">
    <input type="hidden" name="scope_type" value="{scope_type}">
    <input type="hidden" name="scope_id" value="{scope_id}">
    <input type="hidden" name="expires_at" value="{exp_raw}">
    <input type="hidden" name="confirm" value="yes">
    <p>
      <button type="submit" class="critical">Apply grant</button>
      <a href="/admin/t/{tslug}/users/{uid}/role_assignments">Cancel</a>
    </p>
  </form>
</section>"##,
        tslug      = escape(&tenant.slug),
        uid        = escape(&input.subject_user.id),
        uname      = escape(user_label),
        role       = escape(input.role_label),
        scope      = escape(input.scope_label),
        exp        = match input.expires_at {
            Some(s) => format!("<code>{}</code>", escape(s)),
            None    => r#"<span class="muted">never</span>"#.into(),
        },
        role_id    = escape(role_id),
        scope_type = escape(scope_type),
        scope_id   = escape(scope_id),
        exp_raw    = escape(expires_at_raw),
    );
    tenant_admin_frame(
        &title,
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::UserRoleAssignments,
        &body,
    )
}

fn render_role_options(roles: &[Role], selected: &str) -> String {
    if roles.is_empty() {
        return r#"<option value="" disabled>(no roles available)</option>"#.into();
    }
    let mut out = String::new();
    if selected.is_empty() {
        out.push_str(r#"<option value="" disabled selected>Select a role…</option>"#);
    }
    for r in roles {
        let sel = if r.id == selected { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{name} ({slug})</option>"#,
            id   = escape(&r.id),
            sel  = sel,
            name = escape(&r.display_name),
            slug = escape(&r.slug),
        ));
    }
    out
}

fn render_error(e: Option<&str>) -> String {
    match e {
        None    => String::new(),
        Some(m) => format!(
            r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {m}</p></section>"#,
            m = escape(m),
        ),
    }
}
