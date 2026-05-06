//! Role assignment revoke (one-step confirm).
//!
//! Reachable from the user's role-assignments drill-in page where
//! each row grows a "Revoke" link.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::authz::types::{RoleAssignment, Scope};

use super::super::frame::{tenancy_console_frame, TenancyConsoleTab};

pub fn confirm_page(
    principal:   &AdminPrincipal,
    user_id:     &str,
    assignment:  &RoleAssignment,
    role_label:  &str,
) -> String {
    let title = "Revoke role assignment".to_owned();
    let scope_html = render_scope(&assignment.scope);
    let body = format!(
        r##"<p><a href="/admin/tenancy/users/{uid}/role_assignments">← Back to user's role assignments</a></p>
<section aria-label="Revoke confirmation">
  <h2>Revoke this role assignment?</h2>
  <table><tbody>
    <tr><th scope="row">User</th>      <td><code>{uid}</code></td></tr>
    <tr><th scope="row">Role</th>      <td>{role_label}</td></tr>
    <tr><th scope="row">Scope</th>     <td>{scope}</td></tr>
    <tr><th scope="row">Granted by</th><td><code>{granted_by}</code></td></tr>
    <tr><th scope="row">Granted (unix)</th><td>{granted_at}</td></tr>
    <tr><th scope="row">Assignment id</th><td><code>{aid}</code></td></tr>
  </tbody></table>
  <p role="status" class="critical">
    <span class="badge warn">caution</span>
    The user immediately loses any permission granted by this assignment. Their session is not invalidated; ongoing sessions retain whatever they cached, but new <code>check_permission</code> calls return Denied.
  </p>
</section>
<section aria-label="Apply">
  <form class="danger" method="post" action="/admin/tenancy/role_assignments/{aid}/delete">
    <input type="hidden" name="user_id" value="{uid}">
    <input type="hidden" name="confirm" value="yes">
    <p><button type="submit">Revoke role assignment</button></p>
  </form>
</section>"##,
        uid        = escape(user_id),
        role_label = role_label,           // already escaped by caller
        scope      = scope_html,
        granted_by = escape(&assignment.granted_by),
        granted_at = assignment.granted_at,
        aid        = escape(&assignment.id),
    );
    tenancy_console_frame(&title, principal.role, principal.name.as_deref(), TenancyConsoleTab::UserRoleAssignments, &body)
}

fn render_scope(s: &Scope) -> String {
    match s {
        Scope::System => r#"<span class="badge critical">system</span>"#.to_owned(),
        Scope::Tenant { tenant_id } => format!(
            r#"<span class="badge">tenant</span> <code>{}</code>"#, escape(tenant_id),
        ),
        Scope::Organization { organization_id } => format!(
            r#"<span class="badge">organization</span> <code>{}</code>"#, escape(organization_id),
        ),
        Scope::Group { group_id } => format!(
            r#"<span class="badge">group</span> <code>{}</code>"#, escape(group_id),
        ),
        Scope::User { user_id } => format!(
            r#"<span class="badge">user</span> <code>{}</code>"#, escape(user_id),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None,role: Role::Operations, user_id: None }
    }

    #[test]
    fn confirm_carries_assignment_id_in_action() {
        let a = RoleAssignment {
            id: "a-1".into(), user_id: "u".into(), role_id: "r".into(),
            scope: Scope::System,
            granted_by: "x".into(), granted_at: 0, expires_at: None,
        };
        let html = confirm_page(&p(), "u-alice", &a, "<code>system_admin</code>");
        assert!(html.contains(r#"action="/admin/tenancy/role_assignments/a-1/delete""#));
        assert!(html.contains(r#"name="confirm" value="yes""#));
    }

    #[test]
    fn system_scope_badge_renders_critical_color() {
        let a = RoleAssignment {
            id: "a".into(), user_id: "u".into(), role_id: "r".into(),
            scope: Scope::System,
            granted_by: "x".into(), granted_at: 0, expires_at: None,
        };
        let html = confirm_page(&p(), "u", &a, "system_admin");
        // System scope is the most-impactful — must call attention.
        assert!(html.contains(r#"badge critical">system"#));
    }

    #[test]
    fn warning_explains_session_handoff_semantics() {
        let a = RoleAssignment {
            id: "a".into(), user_id: "u".into(), role_id: "r".into(),
            scope: Scope::Tenant { tenant_id: "t".into() },
            granted_by: "x".into(), granted_at: 0, expires_at: None,
        };
        let html = confirm_page(&p(), "u", &a, "tenant_admin");
        assert!(html.contains("session is not invalidated"));
    }
}
