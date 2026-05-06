//! Organization status change form. Same shape as tenant_set_status.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::{Organization, OrganizationStatus};

use super::super::frame::{saas_frame, SaasTab};

pub fn form_page(
    principal: &AdminPrincipal,
    org:       &Organization,
    selected:  Option<OrganizationStatus>,
    reason_default: &str,
    error:     Option<&str>,
) -> String {
    let s = selected.unwrap_or(org.status);
    let title = format!("Organization status: {}", org.slug);
    let body = format!(
        r##"<p><a href="/admin/saas/organizations/{oid}">← Back to organization</a></p>
{error}
<section aria-label="Organization">
  <table><tbody>
    <tr><th scope="row">Slug</th><td><code>{slug}</code></td></tr>
    <tr><th scope="row">Tenant</th><td><code>{tid}</code></td></tr>
    <tr><th scope="row">Current status</th><td>{cur}</td></tr>
  </tbody></table>
</section>
<section aria-label="Status change form">
  <form method="post" action="/admin/saas/organizations/{oid}/status">
    <fieldset>
      <legend>Target status</legend>
      <p><input type="radio" id="s_active"    name="status" value="active"   {ca}> <label for="s_active">    <code>active</code></label></p>
      <p><input type="radio" id="s_suspended" name="status" value="suspended"{cs}> <label for="s_suspended"> <code>suspended</code> — preserves data; users in this org cannot use it</label></p>
      <p><input type="radio" id="s_deleted"   name="status" value="deleted"  {cd}> <label for="s_deleted">   <code>deleted</code> — soft delete, hidden from active list</label></p>
    </fieldset>
    <p>
      <label for="reason">Reason (recorded in audit log)</label><br>
      <input id="reason" name="reason" type="text" required maxlength="200" value="{reason}" style="width: 30em;">
    </p>
    <p><button type="submit">Preview change</button></p>
  </form>
</section>"##,
        oid    = escape(&org.id),
        slug   = escape(&org.slug),
        tid    = escape(&org.tenant_id),
        cur    = render_status_badge(org.status),
        ca     = if s == OrganizationStatus::Active    { "checked" } else { "" },
        cs     = if s == OrganizationStatus::Suspended { "checked" } else { "" },
        cd     = if s == OrganizationStatus::Deleted   { "checked" } else { "" },
        reason = escape(reason_default),
        error  = match error {
            None => String::new(),
            Some(m) => format!(
                r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {m}</p></section>"#,
                m = escape(m),
            ),
        },
    );
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

pub fn confirm_page(
    principal: &AdminPrincipal,
    org:       &Organization,
    target:    OrganizationStatus,
    reason:    &str,
) -> String {
    let title = format!("Confirm organization status: {}", org.slug);
    let warning = match (org.status == target, target) {
        (true,  _)                              => r##"<p class="muted">No change — current and target status are the same.</p>"##.to_owned(),
        (false, OrganizationStatus::Suspended) => r##"<p role="status" class="critical"><span class="badge warn">caution</span> Suspending the organization makes it unreachable for its members. Existing tenant-level memberships are unaffected.</p>"##.to_owned(),
        (false, OrganizationStatus::Deleted)   => r##"<p role="status" class="critical"><span class="badge critical">danger</span> Soft-deleting the organization hides it from the active list. Recovery requires manual SQL.</p>"##.to_owned(),
        (false, OrganizationStatus::Active)    => String::new(),
    };
    let target_str = match target {
        OrganizationStatus::Active    => "active",
        OrganizationStatus::Suspended => "suspended",
        OrganizationStatus::Deleted   => "deleted",
    };
    let body = format!(
        r##"<p><a href="/admin/saas/organizations/{oid}">← Back to organization</a></p>
<section aria-label="Diff">
  <h2>Change to apply</h2>
  <table><tbody>
    <tr><th scope="row">Slug</th>             <td><code>{slug}</code></td></tr>
    <tr><th scope="row">Status (current)</th> <td>{from}</td></tr>
    <tr><th scope="row">Status (target)</th>  <td>{to}</td></tr>
    <tr><th scope="row">Reason</th>           <td>{reason}</td></tr>
  </tbody></table>
  {warning}
</section>
<section aria-label="Apply">
  <form class="danger" method="post" action="/admin/saas/organizations/{oid}/status">
    <input type="hidden" name="status"  value="{target}">
    <input type="hidden" name="reason"  value="{reason}">
    <input type="hidden" name="confirm" value="yes">
    <p><button type="submit">Apply change</button></p>
  </form>
</section>"##,
        oid    = escape(&org.id),
        slug   = escape(&org.slug),
        from   = render_status_badge(org.status),
        to     = render_status_badge(target),
        reason = escape(reason),
        target = target_str,
    );
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

fn render_status_badge(s: OrganizationStatus) -> &'static str {
    match s {
        OrganizationStatus::Active    => r#"<span class="badge ok">active</span>"#,
        OrganizationStatus::Suspended => r#"<span class="badge warn">suspended</span>"#,
        OrganizationStatus::Deleted   => r#"<span class="badge critical">deleted</span>"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;
    use cesauth_core::tenancy::types::{Organization, OrganizationStatus};

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None,role: Role::Operations, user_id: None }
    }
    fn o() -> Organization {
        Organization {
            id: "o-eng".into(), tenant_id: "t-acme".into(),
            slug: "engineering".into(), display_name: "Engineering".into(),
            status: OrganizationStatus::Active, parent_organization_id: None,
            created_at: 0, updated_at: 0,
        }
    }

    #[test]
    fn confirm_warns_on_suspend() {
        let html = confirm_page(&p(), &o(), OrganizationStatus::Suspended, "off-boarding");
        assert!(html.contains("unreachable for its members"));
    }

    #[test]
    fn confirm_no_op_on_same_status() {
        let html = confirm_page(&p(), &o(), OrganizationStatus::Active, "x");
        assert!(html.contains("No change"));
    }
}
