//! Membership remove (one-step confirm).
//!
//! Removing a membership is mildly destructive — it cuts off the
//! user from anything they were getting via that membership. We
//! show a small confirm screen between the click and the commit
//! (no diff to render, just yes/no).

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;

use super::super::frame::{tenancy_console_frame, TenancyConsoleTab};

/// Tenant-membership remove confirm page.
pub fn for_tenant(
    principal:    &AdminPrincipal,
    tenant_id:    &str,
    tenant_slug:  &str,
    user_id:      &str,
    role:         &str,
) -> String {
    let title = format!("Remove tenant member: {user_id}");
    let body = render_body(
        &format!("/admin/tenancy/tenants/{}", escape(tenant_id)),
        &format!("/admin/tenancy/tenants/{}/memberships/{}/delete", escape(tenant_id), escape(user_id)),
        &format!("Remove user <code>{}</code> from tenant <code>{}</code>?",
            escape(user_id), escape(tenant_slug)),
        Some(("Role being removed", role)),
        "tenant",
    );
    tenancy_console_frame(&title, principal.role, principal.name.as_deref(), TenancyConsoleTab::Tenants, &body)
}

/// Organization-membership remove confirm page.
pub fn for_organization(
    principal:  &AdminPrincipal,
    org_id:     &str,
    org_slug:   &str,
    user_id:    &str,
    role:       &str,
) -> String {
    let title = format!("Remove org member: {user_id}");
    let body = render_body(
        &format!("/admin/tenancy/organizations/{}", escape(org_id)),
        &format!("/admin/tenancy/organizations/{}/memberships/{}/delete", escape(org_id), escape(user_id)),
        &format!("Remove user <code>{}</code> from organization <code>{}</code>?",
            escape(user_id), escape(org_slug)),
        Some(("Role being removed", role)),
        "organization",
    );
    tenancy_console_frame(&title, principal.role, principal.name.as_deref(), TenancyConsoleTab::Tenants, &body)
}

/// Group-membership remove confirm page.
pub fn for_group(
    principal:  &AdminPrincipal,
    group_id:   &str,
    group_slug: &str,
    tenant_id:  &str,
    user_id:    &str,
) -> String {
    let title = format!("Remove group member: {user_id}");
    let body = render_body(
        &format!("/admin/tenancy/tenants/{}", escape(tenant_id)),
        &format!("/admin/tenancy/groups/{}/memberships/{}/delete", escape(group_id), escape(user_id)),
        &format!("Remove user <code>{}</code> from group <code>{}</code>?",
            escape(user_id), escape(group_slug)),
        None,
        "group",
    );
    tenancy_console_frame(&title, principal.role, principal.name.as_deref(), TenancyConsoleTab::Tenants, &body)
}

fn render_body(
    back_href:    &str,
    action_href:  &str,
    confirm_q:    &str,
    role_row:     Option<(&str, &str)>,
    scope_label:  &str,
) -> String {
    let role_html = match role_row {
        None => String::new(),
        Some((label, value)) => format!(
            r##"<tr><th scope="row">{label}</th><td><code>{v}</code></td></tr>"##,
            label = escape(label), v = escape(value),
        ),
    };
    format!(
        r##"<p><a href="{back}">← Back</a></p>
<section aria-label="Remove confirmation">
  <h2>{q}</h2>
  <table><tbody>
    {role_html}
    <tr><th scope="row">Scope</th><td>{scope}</td></tr>
  </tbody></table>
  <p role="status" class="critical">
    <span class="badge warn">caution</span>
    The user loses access to anything conferred by this {scope} membership. Re-adding restores it; data is not destroyed.
  </p>
</section>
<section aria-label="Apply">
  <form class="danger" method="post" action="{action}">
    <input type="hidden" name="confirm" value="yes">
    <p><button type="submit">Remove member</button></p>
  </form>
</section>"##,
        back   = back_href,
        action = action_href,
        q      = confirm_q,
        scope  = scope_label,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None,role: Role::Operations, user_id: None }
    }

    #[test]
    fn tenant_remove_action_includes_user_id() {
        let html = for_tenant(&p(), "t-acme", "acme", "u-alice", "owner");
        assert!(html.contains(r#"action="/admin/tenancy/tenants/t-acme/memberships/u-alice/delete""#));
        assert!(html.contains("owner"));
    }

    #[test]
    fn group_remove_omits_role_row() {
        let html = for_group(&p(), "g-1", "all-staff", "t-acme", "u-alice");
        assert!(!html.contains("Role being removed"),
            "group membership has no role field");
    }

    #[test]
    fn untrusted_user_id_is_html_escaped() {
        let html = for_tenant(&p(), "t", "x", "<script>alert(1)</script>", "member");
        assert!(!html.contains("<script>"), "user_id must be escaped");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn confirm_form_carries_confirm_yes_hidden_field() {
        let html = for_tenant(&p(), "t", "x", "u", "member");
        assert!(html.contains(r#"name="confirm" value="yes""#));
    }
}
