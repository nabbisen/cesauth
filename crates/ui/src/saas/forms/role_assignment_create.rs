//! Role assignment grant form (one-click).
//!
//! Reachable from the user's role-assignments drill-in page:
//! `GET /admin/saas/users/:uid/role_assignments/new`.
//!
//! The form asks for:
//! - role_id (select populated from the visible role catalog)
//! - scope_type (radio: system / tenant / organization / group / user)
//! - scope_id (text, required for non-system scopes)
//! - expires_at (optional unix timestamp)
//!
//! The scope picker is the form's interesting part — `Scope` is a
//! sum type and the v0.4.2 JSON API takes a structured value. The
//! form encodes it as `(scope_type, scope_id?)` and the route
//! handler reconstructs the `Scope` enum.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::authz::types::Role;

use super::super::frame::{saas_frame, SaasTab};

/// Inputs needed to render the form. The role catalog drives the
/// role-id select; the route handler reads it once with
/// `RoleRepository::list_visible_to_tenant` (or `list_system_roles`
/// for a deployment with no tenant context).
#[derive(Debug, Clone)]
pub struct RoleAssignmentCreateInput<'a> {
    pub user_id:        &'a str,
    /// Available roles for the role-id select. Each entry is
    /// `(id, slug, display_name)` — id is the form value, the rest
    /// build the visible label.
    pub available_roles: &'a [Role],
    /// Sticky values on re-render after a failed submit.
    pub role_id:         &'a str,
    pub scope_type:      &'a str,
    pub scope_id:        &'a str,
    pub expires_at:      &'a str,
    pub error:           Option<&'a str>,
}

pub fn role_assignment_create_form(
    principal: &AdminPrincipal,
    input:     &RoleAssignmentCreateInput<'_>,
) -> String {
    let title = format!("Grant role to user: {}", input.user_id);
    let body = format!(
        r##"<p><a href="/admin/saas/users/{uid}/role_assignments">← Back to user's role assignments</a></p>
{error}
<section aria-label="Grant role form">
  <form method="post" action="/admin/saas/users/{uid}/role_assignments/new">
    <table><tbody>
      <tr>
        <th scope="row"><label for="role_id">Role</label></th>
        <td>
          <select id="role_id" name="role_id" required>
            <option value="">— pick a role —</option>
            {role_options}
          </select>
        </td>
      </tr>
      <tr>
        <th scope="row">Scope</th>
        <td>{scope_radios}</td>
      </tr>
      <tr>
        <th scope="row"><label for="scope_id">Scope id</label></th>
        <td>
          <input id="scope_id" name="scope_id" type="text" value="{scope_id}">
          <p class="muted">Required for tenant / organization / group / user scopes. Leave blank for system scope.</p>
        </td>
      </tr>
      <tr>
        <th scope="row"><label for="expires_at">Expires (unix seconds)</label></th>
        <td>
          <input id="expires_at" name="expires_at" type="text" value="{expires}">
          <p class="muted">Leave blank for no expiry. Past values are still recorded but the assignment is immediately purged by the next sweep.</p>
        </td>
      </tr>
    </tbody></table>
    <p><button type="submit">Grant role</button></p>
  </form>
</section>
<section aria-label="Help" class="muted">
  <h3>Notes</h3>
  <ul>
    <li>System-scope grants apply across every tenant. Use sparingly.</li>
    <li>The role catalog includes both system roles
        (<code>tenant_id IS NULL</code>) and any tenant-local roles
        the deployment has provisioned.</li>
    <li>Granting the same role to the same user at the same scope
        twice creates a second row — that is intentional, since
        each row carries its own granted_by/granted_at audit lineage.
        The duplicate has no additional effect on
        <code>check_permission</code>.</li>
  </ul>
</section>"##,
        uid          = escape(input.user_id),
        scope_id     = escape(input.scope_id),
        expires      = escape(input.expires_at),
        role_options = render_role_options(input.available_roles, input.role_id),
        scope_radios = render_scope_radios(input.scope_type),
        error        = match input.error {
            None    => String::new(),
            Some(m) => format!(
                r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {m}</p></section>"#,
                m = escape(m),
            ),
        },
    );
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::UserRoleAssignments, &body)
}

fn render_role_options(roles: &[Role], selected: &str) -> String {
    roles.iter().map(|r| {
        let is_selected = r.id == selected;
        let s = if is_selected { " selected" } else { "" };
        let scope_kind = if r.tenant_id.is_some() { " (tenant-local)" } else { " (system)" };
        format!(
            r#"<option value="{id}"{s}>{name} ({slug}){scope_kind}</option>"#,
            id   = escape(&r.id),
            s    = s,
            name = escape(&r.display_name),
            slug = escape(&r.slug),
        )
    }).collect()
}

fn render_scope_radios(selected: &str) -> String {
    [
        ("system",       "system — every tenant"),
        ("tenant",       "tenant — one specific tenant"),
        ("organization", "organization — one specific organization"),
        ("group",        "group — one specific group"),
        ("user",         "user — applies to operations on a specific other user"),
    ].iter().enumerate().map(|(i, (value, label))| {
        let checked = if *value == selected || (selected.is_empty() && i == 0) { " checked" } else { "" };
        format!(
            r##"<p><input type="radio" id="st_{v}" name="scope_type" value="{v}"{c}> <label for="st_{v}">{l}</label></p>"##,
            v = value, c = checked, l = escape(label),
        )
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role as AdminRole;

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None, role: AdminRole::Operations }
    }
    fn role(id: &str, slug: &str, tenant: Option<&str>) -> Role {
        Role {
            id: id.into(), tenant_id: tenant.map(str::to_owned),
            slug: slug.into(), display_name: format!("{slug} role"),
            permissions: Vec::new(),
            created_at: 0, updated_at: 0,
        }
    }

    fn input<'a>(uid: &'a str, roles: &'a [Role]) -> RoleAssignmentCreateInput<'a> {
        RoleAssignmentCreateInput {
            user_id: uid, available_roles: roles,
            role_id: "", scope_type: "tenant", scope_id: "", expires_at: "",
            error: None,
        }
    }

    #[test]
    fn form_action_includes_user_id() {
        let html = role_assignment_create_form(&p(), &input("u-alice", &[]));
        assert!(html.contains(r#"action="/admin/saas/users/u-alice/role_assignments/new""#));
    }

    #[test]
    fn role_options_distinguish_system_from_tenant_local() {
        let roles = vec![
            role("r-sys", "system_admin", None),
            role("r-loc", "tenant_member", Some("t-acme")),
        ];
        let html = role_assignment_create_form(&p(), &input("u", &roles));
        assert!(html.contains("(system)"), "system role must be labelled");
        assert!(html.contains("(tenant-local)"), "tenant-local role must be labelled");
    }

    #[test]
    fn all_five_scope_radios_render() {
        let html = role_assignment_create_form(&p(), &input("u", &[]));
        for s in ["system", "tenant", "organization", "group", "user"] {
            assert!(html.contains(&format!(r#"value="{s}""#)),
                "scope radio for {s:?} must render");
        }
    }

    #[test]
    fn selected_scope_is_marked_checked() {
        let mut inp = input("u", &[]);
        inp.scope_type = "organization";
        let html = role_assignment_create_form(&p(), &inp);
        // The organization radio gets " checked".
        assert!(html.contains(r#"value="organization" checked"#));
    }

    #[test]
    fn sticky_values_preserved_on_rerender() {
        let mut inp = input("u-alice", &[]);
        inp.scope_id   = "t-acme";
        inp.expires_at = "1735689600";
        inp.error      = Some("scope id required");
        let html = role_assignment_create_form(&p(), &inp);
        assert!(html.contains(r#"value="t-acme""#));
        assert!(html.contains(r#"value="1735689600""#));
        assert!(html.contains("scope id required"));
    }
}
