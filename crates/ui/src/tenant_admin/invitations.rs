//! `/admin/t/<slug>/invitations` — invitation management page (RFC 066).

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::invitation::Invitation;
use cesauth_core::tenancy::types::Tenant;

use super::frame::{tenant_admin_frame, TenantAdminTab};

/// Render the invitation list page for a tenant admin.
pub fn invitations_page(
    principal:   &AdminPrincipal,
    tenant:      &Tenant,
    invitations: &[Invitation],
    now_unix:    i64,
) -> String {
    let csrf = ""; // CSRF token injected by the worker handler at render time

    let issue_form = format!(
        r#"<section class="card mb-4">
  <h2 class="card-title">Invite a user</h2>
  <form method="POST" action="/admin/t/{slug}/invitations">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <div class="form-row">
      <label for="email">Email address</label>
      <input type="email" id="email" name="email" required placeholder="user@example.com">
    </div>
    <div class="form-row">
      <label for="role">Initial role</label>
      <select id="role" name="role">
        <option value="tenant_member">Tenant Member</option>
        <option value="tenant_admin">Tenant Admin</option>
      </select>
    </div>
    <button type="submit" class="btn-primary">Send invitation</button>
  </form>
</section>"#,
        slug = escape(&tenant.slug),
        csrf = escape(csrf),
    );

    let table = if invitations.is_empty() {
        r#"<p class="empty">No pending invitations.</p>"#.to_owned()
    } else {
        let rows: String = invitations.iter().map(|inv| {
            let expires_in_h = (inv.expires_at - now_unix).max(0) / 3600;
            let status = if inv.revoked_at.is_some() {
                "<span class=\"badge badge-error\">revoked</span>"
            } else if now_unix > inv.expires_at {
                "<span class=\"badge badge-warn\">expired</span>"
            } else {
                "<span class=\"badge badge-ok\">pending</span>"
            };
            format!(
                r#"<tr>
  <td>{email}</td>
  <td>{role}</td>
  <td>{status}</td>
  <td>{expires}</td>
  <td>
    <form method="POST" action="/admin/t/{slug}/invitations/{id}/revoke" style="display:inline">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <button type="submit" class="btn-sm btn-danger"
              onclick="return confirm('Revoke this invitation?')">Revoke</button>
    </form>
  </td>
</tr>"#,
                email   = escape(&inv.email),
                role    = escape(&inv.role),
                status  = status,
                expires = if inv.revoked_at.is_none() && now_unix <= inv.expires_at {
                    format!("{}h remaining", expires_in_h)
                } else {
                    "—".to_owned()
                },
                slug    = escape(&tenant.slug),
                id      = escape(&inv.id),
                csrf    = escape(csrf),
            )
        }).collect::<Vec<_>>().join("\n");

        format!(
            r#"<table class="data-table">
  <thead>
    <tr>
      <th>Email</th><th>Role</th><th>Status</th><th>Expires</th><th></th>
    </tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>"#
        )
    };

    let body = format!("{issue_form}\n<section class=\"card\">\n<h2 class=\"card-title\">Pending invitations</h2>\n{table}\n</section>");

    tenant_admin_frame(
        "Invitations",
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::Invitations,
        &body,
    )
}
