//! `/admin/t/<slug>/deletion-requests` — deletion request queue (RFC 067).

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::deletion::{DeletionRequest, DeletionStatus};
use cesauth_core::tenancy::types::Tenant;

use super::frame::{tenant_admin_frame, TenantAdminTab};

/// Render the deletion request queue for a tenant admin.
pub fn deletion_requests_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    requests:  &[DeletionRequest],
    now_unix:  i64,
) -> String {
    let csrf = ""; // CSRF injected by worker handler

    let table = if requests.is_empty() {
        r#"<p class="empty">No pending deletion requests.</p>"#.to_owned()
    } else {
        let rows: String = requests.iter().map(|req| {
            let status_badge = match req.status {
                DeletionStatus::Pending   => "<span class=\"badge badge-warn\">pending</span>",
                DeletionStatus::Executed  => "<span class=\"badge badge-ok\">executed</span>",
                DeletionStatus::Cancelled => "<span class=\"badge badge-gray\">cancelled</span>",
            };

            let days_until = (req.scheduled_at - now_unix).max(0) / 86400;

            let actions = if req.status == DeletionStatus::Pending {
                format!(
                    r#"<form method="POST" action="/admin/t/{slug}/deletion-requests/{id}/cancel" style="display:inline">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <button type="submit" class="btn-sm btn-secondary">Cancel</button>
</form>
<form method="POST" action="/admin/t/{slug}/deletion-requests/{id}/execute" style="display:inline; margin-left:4px">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <button type="submit" class="btn-sm btn-danger"
          onclick="return confirm('Execute this deletion immediately? This is irreversible.')">Execute now</button>
</form>"#,
                    slug = escape(&tenant.slug),
                    id   = escape(&req.id),
                    csrf = escape(csrf),
                )
            } else {
                "—".to_owned()
            };

            format!(
                r#"<tr>
  <td><code>{user_id}</code></td>
  <td>{status}</td>
  <td>{scheduled}</td>
  <td>{actions}</td>
</tr>"#,
                user_id   = escape(&req.user_id),
                status    = status_badge,
                scheduled = if req.status == DeletionStatus::Pending {
                    format!("{}d remaining", days_until)
                } else {
                    "—".to_owned()
                },
                actions   = actions,
            )
        }).collect::<Vec<_>>().join("\n");

        format!(
            r#"<table class="data-table">
  <thead>
    <tr>
      <th>User ID</th><th>Status</th><th>Scheduled</th><th>Actions</th>
    </tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>"#
        )
    };

    let body = format!(
        r#"<div class="alert alert-info mb-4">
  <strong>Grace period:</strong> Deletion requests execute after the scheduled date (default: 30 days).
  Cancel before execution to prevent data loss. Executed deletions are <strong>irreversible</strong>.
</div>
<section class="card">
  <h2 class="card-title">Deletion requests</h2>
  {table}
</section>"#
    );

    tenant_admin_frame(
        "Deletion Requests",
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::DeletionRequests,
        &body,
    )
}
