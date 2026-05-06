//! Membership add form (one-click).
//!
//! Three URL entry points, one shared rendering shape:
//! - `POST /admin/tenancy/tenants/:tid/memberships`
//! - `POST /admin/tenancy/organizations/:oid/memberships`
//! - `POST /admin/tenancy/groups/:gid/memberships`
//!
//! Memberships are additive and cheap — joining a group does not
//! grant any permission by itself; permissions are conferred by
//! `role_assignments`, which is its own form. So we don't put a
//! preview/confirm step in the membership flow.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;

use super::super::frame::{tenancy_console_frame, TenancyConsoleTab};

/// Tenant-scoped membership add form. Renders a select for `role`
/// (owner / admin / member).
pub fn for_tenant(
    principal:    &AdminPrincipal,
    tenant_id:    &str,
    tenant_slug:  &str,
    user_id:      &str,
    role:         &str,
    error:        Option<&str>,
) -> String {
    let title = format!("Add tenant member: {tenant_slug}");
    render(
        principal, &title,
        &format!("/admin/tenancy/tenants/{}", escape(tenant_id)),
        &format!("/admin/tenancy/tenants/{}/memberships", escape(tenant_id)),
        &format!("tenant <code>{}</code>", escape(tenant_slug)),
        user_id,
        Some(("role", &[
            ("owner",  "Owner — top-level control of the tenant"),
            ("admin",  "Admin — manage organizations, groups, members"),
            ("member", "Member — basic access to tenant resources"),
        ], role)),
        error,
    )
}

/// Organization-scoped membership add form. Renders a select for
/// `role` (admin / member).
pub fn for_organization(
    principal:  &AdminPrincipal,
    org_id:     &str,
    org_slug:   &str,
    user_id:    &str,
    role:       &str,
    error:      Option<&str>,
) -> String {
    let title = format!("Add organization member: {org_slug}");
    render(
        principal, &title,
        &format!("/admin/tenancy/organizations/{}", escape(org_id)),
        &format!("/admin/tenancy/organizations/{}/memberships", escape(org_id)),
        &format!("organization <code>{}</code>", escape(org_slug)),
        user_id,
        Some(("role", &[
            ("admin",  "Admin — manage groups + members in this org"),
            ("member", "Member — basic access to org resources"),
        ], role)),
        error,
    )
}

/// Group-scoped membership add form. Group memberships have no
/// role (the group itself is what's queried).
pub fn for_group(
    principal:  &AdminPrincipal,
    group_id:   &str,
    group_slug: &str,
    tenant_id:  &str,
    user_id:    &str,
    error:      Option<&str>,
) -> String {
    let title = format!("Add group member: {group_slug}");
    // Group's "back" target is the owning tenant — there is no
    // standalone /admin/tenancy/groups/:gid page in 0.9.0.
    render(
        principal, &title,
        &format!("/admin/tenancy/tenants/{}", escape(tenant_id)),
        &format!("/admin/tenancy/groups/{}/memberships", escape(group_id)),
        &format!("group <code>{}</code>", escape(group_slug)),
        user_id,
        None,
        error,
    )
}

fn render(
    principal:   &AdminPrincipal,
    title:       &str,
    back_href:   &str,
    form_action: &str,
    parent_html: &str,
    user_id:     &str,
    role_select: Option<(&str, &[(&str, &str)], &str)>,
    error:       Option<&str>,
) -> String {
    let role_field = match role_select {
        None => String::new(),
        Some((name, options, selected)) => {
            let opts: String = options.iter().map(|(value, label)| {
                let s = if *value == selected { " selected" } else { "" };
                format!(
                    r#"<option value="{v}"{s}>{l}</option>"#,
                    v = escape(value), s = s, l = escape(label),
                )
            }).collect();
            format!(
                r##"<tr>
  <th scope="row"><label for="{name}">Role</label></th>
  <td><select id="{name}" name="{name}" required>{opts}</select></td>
</tr>"##,
            )
        }
    };
    let body = format!(
        r##"<p><a href="{back}">← Back</a></p>
{error}
<section aria-label="Add member form">
  <p>Adding a member to {parent_html}.</p>
  <form method="post" action="{action}">
    <table><tbody>
      <tr>
        <th scope="row"><label for="user_id">User id</label></th>
        <td><input id="user_id" name="user_id" type="text" required value="{uid}"></td>
      </tr>
      {role_field}
    </tbody></table>
    <p><button type="submit">Add member</button></p>
  </form>
</section>
<section aria-label="Help" class="muted">
  <h3>Notes</h3>
  <ul>
    <li>The user id must already exist in <code>users</code>. This form does not auto-provision users.</li>
    <li>Memberships are additive — adding the same user twice is a no-op (the existing row is preserved).</li>
    <li>Membership alone does not grant permissions. Use the role-assignment forms to grant capabilities.</li>
  </ul>
</section>"##,
        back   = back_href,
        action = form_action,
        uid    = escape(user_id),
        error  = match error {
            None    => String::new(),
            Some(m) => format!(
                r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {m}</p></section>"#,
                m = escape(m),
            ),
        },
    );
    tenancy_console_frame(title, principal.role, principal.name.as_deref(), TenancyConsoleTab::Tenants, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None,role: Role::Operations, user_id: None }
    }

    #[test]
    fn tenant_form_action_is_tenant_scoped() {
        let html = for_tenant(&p(), "t-acme", "acme", "", "member", None);
        assert!(html.contains(r#"action="/admin/tenancy/tenants/t-acme/memberships""#));
    }

    #[test]
    fn tenant_form_renders_three_role_options() {
        let html = for_tenant(&p(), "t", "x", "", "member", None);
        assert!(html.contains(r#"value="owner""#));
        assert!(html.contains(r#"value="admin""#));
        assert!(html.contains(r#"value="member""#));
    }

    #[test]
    fn org_form_renders_two_role_options_only() {
        let html = for_organization(&p(), "o", "x", "", "member", None);
        // Org-level membership has no "owner" — that's tenant-scope.
        assert!(html.contains(r#"value="admin""#));
        assert!(html.contains(r#"value="member""#));
        assert!(!html.contains(r#"value="owner""#),
            "org membership has no owner role");
    }

    #[test]
    fn group_form_omits_role_field() {
        // Group membership has no role.
        let html = for_group(&p(), "g", "x", "t-acme", "", None);
        assert!(!html.contains(r#"name="role""#),
            "group membership form must not have a role field");
    }

    #[test]
    fn form_preserves_user_id_on_rerender() {
        let html = for_tenant(&p(), "t", "x", "u-alice", "admin", Some("user not found"));
        assert!(html.contains(r#"value="u-alice""#));
        assert!(html.contains("user not found"));
    }

    #[test]
    fn untrusted_user_id_is_html_escaped() {
        let html = for_tenant(&p(), "t", "x", r#"<script>alert(1)</script>"#, "member", None);
        assert!(!html.contains("<script>"), "user_id must be escaped");
        assert!(html.contains("&lt;script&gt;"));
    }
}
