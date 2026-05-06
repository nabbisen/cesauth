//! `GET/POST /admin/t/:slug/organizations/:oid/status` —
//! status change for an organization. Preview/confirm pattern: the
//! first POST renders a diff, the second (with `confirm=yes`)
//! applies it. Same shape as the v0.9.0 system-admin equivalent.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::{Organization, OrganizationStatus, Tenant};

use super::super::frame::{tenant_admin_frame, TenantAdminTab};

/// Initial form (status picker + reason).
pub fn form_page(
    principal:      &AdminPrincipal,
    tenant:         &Tenant,
    org:            &Organization,
    selected:       Option<OrganizationStatus>,
    reason_default: &str,
    error:          Option<&str>,
) -> String {
    let s = selected.unwrap_or(org.status);
    let title = format!("Organization status: {}", org.slug);
    let body = format!(
        r##"<p><a href="/admin/t/{tslug}/organizations/{oid}">← Back to organization</a></p>
{error}
<section aria-label="Organization">
  <table><tbody>
    <tr><th scope="row">Slug</th><td><code>{oslug}</code></td></tr>
    <tr><th scope="row">Tenant</th><td><code>{tslug}</code></td></tr>
    <tr><th scope="row">Current status</th><td>{cur}</td></tr>
  </tbody></table>
</section>
<section aria-label="Status change form">
  <form method="post" action="/admin/t/{tslug}/organizations/{oid}/status">
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
        tslug  = escape(&tenant.slug),
        oid    = escape(&org.id),
        oslug  = escape(&org.slug),
        cur    = render_status_badge(org.status),
        ca     = if s == OrganizationStatus::Active    { "checked" } else { "" },
        cs     = if s == OrganizationStatus::Suspended { "checked" } else { "" },
        cd     = if s == OrganizationStatus::Deleted   { "checked" } else { "" },
        reason = escape(reason_default),
        error  = render_error(error),
    );
    tenant_admin_frame(
        &title,
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::Organizations,
        &body,
    )
}

/// Preview render. Diff-and-confirm: shows current → target,
/// re-renders the form with a hidden `confirm=yes` for the apply.
pub fn preview_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    org:       &Organization,
    target:    OrganizationStatus,
    reason:    &str,
) -> String {
    let title = format!("Confirm status change: {}", org.slug);
    let body = format!(
        r##"<p><a href="/admin/t/{tslug}/organizations/{oid}/status">← Back to form</a></p>
<section aria-label="Diff">
  <h3>Proposed change</h3>
  <table><tbody>
    <tr><th scope="row">Organization</th><td><code>{oslug}</code> ({oid})</td></tr>
    <tr><th scope="row">Status</th><td>{cur} → {tgt}</td></tr>
    <tr><th scope="row">Reason</th><td>{reason}</td></tr>
  </tbody></table>
</section>
<section aria-label="Apply or cancel">
  <form method="post" action="/admin/t/{tslug}/organizations/{oid}/status">
    <input type="hidden" name="status" value="{tgt_value}">
    <input type="hidden" name="reason" value="{reason}">
    <input type="hidden" name="confirm" value="yes">
    <p>
      <button type="submit" class="critical">Apply</button>
      <a href="/admin/t/{tslug}/organizations/{oid}">Cancel</a>
    </p>
  </form>
</section>"##,
        tslug     = escape(&tenant.slug),
        oid       = escape(&org.id),
        oslug     = escape(&org.slug),
        cur       = render_status_badge(org.status),
        tgt       = render_status_badge(target),
        tgt_value = status_value(target),
        reason    = escape(reason),
    );
    tenant_admin_frame(
        &title,
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::Organizations,
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

fn render_status_badge(s: OrganizationStatus) -> &'static str {
    match s {
        OrganizationStatus::Active    => r#"<span class="badge ok">active</span>"#,
        OrganizationStatus::Suspended => r#"<span class="badge warn">suspended</span>"#,
        OrganizationStatus::Deleted   => r#"<span class="badge critical">deleted</span>"#,
    }
}

fn status_value(s: OrganizationStatus) -> &'static str {
    match s {
        OrganizationStatus::Active    => "active",
        OrganizationStatus::Suspended => "suspended",
        OrganizationStatus::Deleted   => "deleted",
    }
}
