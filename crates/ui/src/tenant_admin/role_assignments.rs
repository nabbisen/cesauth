//! `/admin/t/<slug>/users/:uid/role_assignments` — every role
//! assignment a single user holds, scoped to the current tenant
//! context.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::authz::types::{RoleAssignment, Scope};
use cesauth_core::tenancy::types::Tenant;
use cesauth_core::types::User;

use super::frame::{tenant_admin_frame, TenantAdminTab};

/// Inputs the route handler assembles. The route already enforces
/// that `subject_user.tenant_id == tenant.id` (cross-tenant lookups
/// are blocked at the adapter layer), so the template trusts that
/// every assignment passed in is in-scope for the current tenant.
#[derive(Debug, Clone)]
pub struct TenantUserRoleAssignmentsInput<'a> {
    pub subject_user: &'a User,
    pub assignments:  &'a [RoleAssignment],
    /// Map from `role_id` to `(slug, display_name)`. The route
    /// does one bulk SELECT and feeds the dictionary in. Missing
    /// keys render as the bare id; that should not happen in
    /// well-formed data but we defend.
    pub role_labels:  &'a [(String, String, String)],   // (id, slug, display_name)
}

pub fn role_assignments_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    input:     &TenantUserRoleAssignmentsInput<'_>,
) -> String {
    let user_label = input.subject_user.display_name.as_deref()
        .unwrap_or(&input.subject_user.id);
    let title = format!("Role assignments — {}", user_label);
    let body  = render_table(input);
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

fn render_table(input: &TenantUserRoleAssignmentsInput<'_>) -> String {
    if input.assignments.is_empty() {
        return r#"<p class="empty">No role assignments for this user.</p>"#.into();
    }
    let rows: String = input.assignments.iter().map(|a| {
        let role_html = render_role_label(input.role_labels, &a.role_id);
        let scope_html = render_scope(&a.scope);
        format!(
            r#"<tr><td>{role}</td><td>{scope}</td></tr>"#,
            role  = role_html,
            scope = scope_html,
        )
    }).collect::<Vec<_>>().join("\n");
    format!(
        r##"<table>
  <thead><tr><th scope="col">Role</th><th scope="col">Scope</th></tr></thead>
  <tbody>
{rows}
  </tbody>
</table>"##
    )
}

fn render_role_label(labels: &[(String, String, String)], role_id: &str) -> String {
    if let Some((_, slug, name)) = labels.iter().find(|(id, _, _)| id == role_id) {
        format!(
            r#"{name} <span class="muted">(<code>{slug}</code>)</span>"#,
            name = escape(name),
            slug = escape(slug),
        )
    } else {
        format!(r#"<code>{}</code>"#, escape(role_id))
    }
}

fn render_scope(s: &Scope) -> String {
    match s {
        Scope::System => r#"<span class="muted">system</span>"#.into(),
        Scope::Tenant { tenant_id } =>
            format!(r#"tenant <code>{}</code>"#, escape(tenant_id)),
        Scope::Organization { organization_id } =>
            format!(r#"organization <code>{}</code>"#, escape(organization_id)),
        Scope::Group { group_id } =>
            format!(r#"group <code>{}</code>"#, escape(group_id)),
        Scope::User { user_id } =>
            format!(r#"user <code>{}</code>"#, escape(user_id)),
    }
}
