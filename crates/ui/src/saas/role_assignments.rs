//! `/admin/saas/users/:uid/role_assignments` — every role assignment
//! a single user holds, across every scope.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::authz::types::{RoleAssignment, Scope};

use super::frame::{saas_frame, SaasTab};

/// Inputs the route handler assembles. The role-display map lets us
/// show a nice "tenant_admin" label instead of just the opaque
/// `role-tenant-admin` id; the route does one bulk SELECT and feeds
/// the dictionary in.
#[derive(Debug, Clone)]
pub struct UserRoleAssignmentsInput<'a> {
    pub user_id:     &'a str,
    pub assignments: &'a [RoleAssignment],
    /// Map from `role_id` to a `(slug, display_name)` pair. Missing
    /// keys render as the bare id; this should not happen in
    /// well-formed data but we defend.
    pub role_labels: &'a [(String, String, String)],   // (id, slug, display_name)
}

pub fn user_role_assignments_page(
    principal: &AdminPrincipal,
    input:     &UserRoleAssignmentsInput<'_>,
) -> String {
    let title = format!("Role assignments: user {}", input.user_id);
    let body = render_table(input);
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::UserRoleAssignments, &body)
}

fn render_table(input: &UserRoleAssignmentsInput<'_>) -> String {
    let body: String = if input.assignments.is_empty() {
        r#"<tr><td colspan="5" class="empty">No role assignments.</td></tr>"#.to_owned()
    } else {
        input.assignments.iter().map(|a| {
            let role_label = input.role_labels.iter()
                .find(|(id, _, _)| id == &a.role_id)
                .map(|(_, slug, name)| format!(
                    "{name} (<code>{slug}</code>)",
                    name = escape(name), slug = escape(slug),
                ))
                .unwrap_or_else(|| format!("<code>{}</code>", escape(&a.role_id)));
            let scope_html = render_scope(&a.scope);
            let expires = match a.expires_at {
                Some(t) => format!("{t}"),
                None    => r#"<span class="muted">none</span>"#.to_owned(),
            };
            format!(
                r##"<tr>
  <td>{role_label}</td>
  <td>{scope}</td>
  <td><code>{granted_by}</code></td>
  <td class="muted">{granted}</td>
  <td>{expires}</td>
</tr>"##,
                role_label = role_label,
                scope      = scope_html,
                granted_by = escape(&a.granted_by),
                granted    = a.granted_at,
                expires    = expires,
            )
        }).collect::<Vec<_>>().join("\n")
    };
    format!(
        r##"<section aria-label="Assignments">
  <p class="muted"><a href="/admin/saas/tenants">← Back to tenants</a></p>
  <table><thead>
    <tr>
      <th scope="col">Role</th>
      <th scope="col">Scope</th>
      <th scope="col">Granted by</th>
      <th scope="col">Granted (unix)</th>
      <th scope="col">Expires</th>
    </tr>
  </thead><tbody>
{body}
  </tbody></table>
</section>"##
    )
}

fn render_scope(s: &Scope) -> String {
    match s {
        Scope::System => r#"<span class="badge critical">system</span>"#.to_owned(),
        Scope::Tenant { tenant_id } => format!(
            r#"<span class="badge">tenant</span> <a href="/admin/saas/tenants/{id}"><code>{id_short}</code></a>"#,
            id = escape(tenant_id), id_short = escape(tenant_id),
        ),
        Scope::Organization { organization_id } => format!(
            r#"<span class="badge">organization</span> <a href="/admin/saas/organizations/{id}"><code>{id_short}</code></a>"#,
            id = escape(organization_id), id_short = escape(organization_id),
        ),
        Scope::Group { group_id } => format!(
            r#"<span class="badge">group</span> <code>{id}</code>"#, id = escape(group_id),
        ),
        Scope::User { user_id } => format!(
            r#"<span class="badge">user</span> <code>{id}</code>"#, id = escape(user_id),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "admin".into(), name: None, role: Role::ReadOnly }
    }

    #[test]
    fn empty_assignments_render_empty_state() {
        let input = UserRoleAssignmentsInput {
            user_id: "u-alice", assignments: &[], role_labels: &[],
        };
        let html = user_role_assignments_page(&p(), &input);
        assert!(html.contains("No role assignments"));
    }

    #[test]
    fn scope_renders_with_drill_links() {
        let assignments = vec![
            RoleAssignment {
                id: "a1".into(), user_id: "u".into(), role_id: "role-tenant-admin".into(),
                scope: Scope::Tenant { tenant_id: "t-acme".into() },
                granted_by: "system".into(), granted_at: 0, expires_at: None,
            },
            RoleAssignment {
                id: "a2".into(), user_id: "u".into(), role_id: "role-system-admin".into(),
                scope: Scope::System,
                granted_by: "wrangler".into(), granted_at: 0, expires_at: None,
            },
        ];
        let labels = vec![
            ("role-tenant-admin".into(), "tenant_admin".into(), "Tenant admin".into()),
            ("role-system-admin".into(), "system_admin".into(), "System admin".into()),
        ];
        let input = UserRoleAssignmentsInput {
            user_id: "u-alice", assignments: &assignments, role_labels: &labels,
        };
        let html = user_role_assignments_page(&p(), &input);
        assert!(html.contains(r#"href="/admin/saas/tenants/t-acme""#));
        assert!(html.contains("Tenant admin"));
        assert!(html.contains("System admin"));
        assert!(html.contains(r#"badge critical">system"#));
    }

    #[test]
    fn unknown_role_id_renders_as_bare_id() {
        // Defensive case: assignment references a role row that
        // doesn't exist (or wasn't joined). Render the id rather
        // than panic.
        let assignments = vec![RoleAssignment {
            id: "a".into(), user_id: "u".into(), role_id: "role-ghost".into(),
            scope: Scope::System,
            granted_by: "x".into(), granted_at: 0, expires_at: None,
        }];
        let input = UserRoleAssignmentsInput {
            user_id: "u-alice", assignments: &assignments, role_labels: &[],
        };
        let html = user_role_assignments_page(&p(), &input);
        assert!(html.contains("role-ghost"));
    }
}
