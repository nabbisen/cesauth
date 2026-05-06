//! `GET/POST /admin/t/:slug/role_assignments/:id/delete` — revoke
//! a role assignment from a user. Preview/confirm — pulling
//! authorization is medium-risk.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::authz::types::{RoleAssignment, Scope};
use cesauth_core::tenancy::types::Tenant;
use cesauth_core::types::User;

use super::super::frame::{tenant_admin_frame, TenantAdminTab};

#[derive(Debug, Clone)]
pub struct RevokeInput<'a> {
    pub assignment:   &'a RoleAssignment,
    pub subject_user: &'a User,
    pub role_label:   &'a str,
    pub error:        Option<&'a str>,
}

pub fn form_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    input:     &RevokeInput<'_>,
) -> String {
    let user_label = input.subject_user.display_name.as_deref()
        .unwrap_or(&input.subject_user.id);
    let title = format!("Revoke role from: {}", user_label);
    let body = format!(
        r##"<p><a href="/admin/t/{tslug}/users/{uid}/role_assignments">← Back to user's role assignments</a></p>
{error}
<section aria-label="Assignment">
  <table><tbody>
    <tr><th scope="row">User</th><td>{uname} <code>{uid}</code></td></tr>
    <tr><th scope="row">Role</th><td>{role}</td></tr>
    <tr><th scope="row">Scope</th><td>{scope}</td></tr>
  </tbody></table>
</section>
<section aria-label="Revoke form">
  <form method="post" action="/admin/t/{tslug}/role_assignments/{aid}/delete">
    <p class="muted">After revoke, the user immediately loses any access this assignment granted.
       Other assignments at broader scopes may continue to grant access.</p>
    <p><button type="submit">Preview revoke</button></p>
  </form>
</section>"##,
        tslug = escape(&tenant.slug),
        aid   = escape(&input.assignment.id),
        uid   = escape(&input.subject_user.id),
        uname = escape(user_label),
        role  = escape(input.role_label),
        scope = render_scope_inline(&input.assignment.scope),
        error = render_error(input.error),
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

pub fn preview_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    input:     &RevokeInput<'_>,
) -> String {
    let user_label = input.subject_user.display_name.as_deref()
        .unwrap_or(&input.subject_user.id);
    let title = format!("Confirm revoke: {}", user_label);
    let body = format!(
        r##"<p><a href="/admin/t/{tslug}/role_assignments/{aid}/delete">← Back to form</a></p>
<section aria-label="Diff">
  <h3>What will be revoked</h3>
  <table><tbody>
    <tr><th scope="row">User</th><td>{uname} <code>{uid}</code></td></tr>
    <tr><th scope="row">Role</th><td>{role}</td></tr>
    <tr><th scope="row">Scope</th><td>{scope}</td></tr>
  </tbody></table>
</section>
<section aria-label="Apply or cancel">
  <form method="post" action="/admin/t/{tslug}/role_assignments/{aid}/delete">
    <input type="hidden" name="confirm" value="yes">
    <p>
      <button type="submit" class="critical">Apply revoke</button>
      <a href="/admin/t/{tslug}/users/{uid}/role_assignments">Cancel</a>
    </p>
  </form>
</section>"##,
        tslug = escape(&tenant.slug),
        aid   = escape(&input.assignment.id),
        uid   = escape(&input.subject_user.id),
        uname = escape(user_label),
        role  = escape(input.role_label),
        scope = render_scope_inline(&input.assignment.scope),
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

fn render_scope_inline(s: &Scope) -> String {
    match s {
        Scope::System => r#"<span class="muted">system</span>"#.into(),
        Scope::Tenant       { tenant_id }       => format!(r#"tenant <code>{}</code>"#, escape(tenant_id)),
        Scope::Organization { organization_id } => format!(r#"organization <code>{}</code>"#, escape(organization_id)),
        Scope::Group        { group_id }        => format!(r#"group <code>{}</code>"#, escape(group_id)),
        Scope::User         { user_id }         => format!(r#"user <code>{}</code>"#, escape(user_id)),
    }
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
