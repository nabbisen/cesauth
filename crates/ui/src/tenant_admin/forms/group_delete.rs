//! `GET/POST /admin/t/:slug/groups/:gid/delete` —
//! delete (soft) a group. Preview/confirm pattern.
//!
//! Group delete cascades: any role assignment scoped to the group
//! becomes orphaned (the spec §9.4 garbage-collection step picks
//! these up). The preview spells this out.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::routes::tenant_admin as routes;
use cesauth_core::tenancy::types::{Group, Tenant};

use super::super::frame::{tenant_admin_frame, TenantAdminTab};

pub fn form_page(
    principal:      &AdminPrincipal,
    tenant:         &Tenant,
    group:          &Group,
    org_slug:       &str,
    org_id:         &str,
    reason_default: &str,
    error:          Option<&str>,
) -> String {
    let title = format!("Delete group: {}", group.slug);
    let body = format!(
        r##"<p><a href="{back_url}">← Back to organization</a></p>
{error}
<section aria-label="Group">
  <table><tbody>
    <tr><th scope="row">Slug</th><td><code>{gslug}</code></td></tr>
    <tr><th scope="row">Display name</th><td>{gname}</td></tr>
    <tr><th scope="row">Organization</th><td><code>{org_slug}</code></td></tr>
  </tbody></table>
</section>
<section aria-label="Delete form">
  <form method="post" action="{action_url}">
    <p class="critical"><strong>Warning.</strong> Group delete is a soft delete (the row remains)
       but role assignments scoped to this group become orphaned and stop granting access.
       Memberships of users in this group are also removed.</p>
    <p>
      <label for="reason">Reason (recorded in audit log)</label><br>
      <input id="reason" name="reason" type="text" required maxlength="200" value="{reason}" style="width: 30em;">
    </p>
    <p><button type="submit">Preview delete</button></p>
  </form>
</section>"##,
        // RFC 108 escape contract.
        back_url   = escape(&routes::org_detail(&tenant.slug, org_id)),
        action_url = escape(&routes::group_delete(&tenant.slug, &group.id)),
        gslug    = escape(&group.slug),
        gname    = escape(&group.display_name),
        org_slug = escape(org_slug),
        reason   = escape(reason_default),
        error    = render_error(error),
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

pub fn preview_page(
    principal:      &AdminPrincipal,
    tenant:         &Tenant,
    group:          &Group,
    org_id:         &str,
    reason:         &str,
    affected_assignments: usize,
    affected_memberships: usize,
) -> String {
    let title = format!("Confirm delete: {}", group.slug);
    let body = format!(
        r##"<p><a href="{back_url}">← Back to form</a></p>
<section aria-label="Diff">
  <h3>What will be deleted</h3>
  <table><tbody>
    <tr><th scope="row">Group</th><td><code>{gslug}</code> ({gid})</td></tr>
    <tr><th scope="row">Affected role assignments</th><td>{n_assignments}</td></tr>
    <tr><th scope="row">Affected memberships</th><td>{n_memberships}</td></tr>
    <tr><th scope="row">Reason</th><td>{reason}</td></tr>
  </tbody></table>
  <p class="muted">After delete, the group row is marked deleted (soft delete).
     Assignments and memberships scoped to it are removed; users in this group
     lose any access that depended on it.</p>
</section>
<section aria-label="Apply or cancel">
  <form method="post" action="{action_url}">
    <input type="hidden" name="reason" value="{reason}">
    <input type="hidden" name="confirm" value="yes">
    <p>
      <button type="submit" class="critical">Apply delete</button>
      <a href="{cancel_url}">Cancel</a>
    </p>
  </form>
</section>"##,
        // RFC 108 escape contract.
        back_url   = escape(&routes::group_delete(&tenant.slug, &group.id)),
        action_url = escape(&routes::group_delete(&tenant.slug, &group.id)),
        cancel_url = escape(&routes::org_detail(&tenant.slug, org_id)),
        gid           = escape(&group.id),
        gslug         = escape(&group.slug),
        n_assignments = affected_assignments,
        n_memberships = affected_memberships,
        reason        = escape(reason),
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

fn render_error(e: Option<&str>) -> String {
    match e {
        None    => String::new(),
        Some(m) => format!(
            r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {m}</p></section>"#,
            m = escape(m),
        ),
    }
}
