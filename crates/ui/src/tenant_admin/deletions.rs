//! `/admin/t/<slug>/deletion-requests` — deletion request queue (RFC 067).
//!
//! RFC 078: All visible strings use MessageKey / JA-only locale (admin policy).

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::deletion::{DeletionRequest, DeletionStatus};
use cesauth_core::i18n::{lookup, Locale, MessageKey};
use cesauth_core::tenancy::types::Tenant;

use super::frame::{tenant_admin_frame, TenantAdminTab};

/// Render the deletion request queue for a tenant admin.
pub fn deletion_requests_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    requests:  &[DeletionRequest],
    now_unix:  i64,
) -> String {
    let l    = Locale::Ja; // admin is JA-only (ADR-013 / RFC 078)
    let csrf = "";

    let notice = format!(
        "<div class=\"alert alert-info mb-4\">{}</div>",
        escape(lookup(MessageKey::TenantDeletionGracePeriodNotice, l)),
    );

    let table = if requests.is_empty() {
        format!("<p class=\"empty\">{}</p>",
            escape(lookup(MessageKey::TenantDeletionEmpty, l)))
    } else {
        let rows: String = requests.iter().map(|req| {
            let status_badge = match req.status {
                DeletionStatus::Pending   => format!("<span class=\"badge badge-warn\">{}</span>",
                    escape(lookup(MessageKey::TenantDeletionStatusPending, l))),
                DeletionStatus::Executed  => format!("<span class=\"badge badge-ok\">{}</span>",
                    escape(lookup(MessageKey::TenantDeletionStatusExecuted, l))),
                DeletionStatus::Cancelled => format!("<span class=\"badge badge-gray\">{}</span>",
                    escape(lookup(MessageKey::TenantDeletionStatusCancelled, l))),
            };

            let days_until = (req.scheduled_at - now_unix).max(0) / 86400;
            let scheduled_label = if req.status == DeletionStatus::Pending {
                lookup(MessageKey::TenantDeletionScheduledInDays, l)
                    .replace("{n}", &days_until.to_string())
            } else {
                "\u{2014}".to_owned()
            };

            let actions = if req.status == DeletionStatus::Pending {
                let cancel_btn      = escape(lookup(MessageKey::TenantDeletionCancelButton,  l));
                let execute_btn     = escape(lookup(MessageKey::TenantDeletionExecuteButton, l));
                let execute_confirm = escape(lookup(MessageKey::TenantDeletionExecuteConfirm, l));
                format!(
                    "<form method=\"POST\" action=\"/admin/t/{slug}/deletion-requests/{id}/cancel\" style=\"display:inline\">\n\
  <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\n\
  <button type=\"submit\" class=\"btn-sm btn-secondary\">{cancel}</button>\n\
</form>\n\
<form method=\"POST\" action=\"/admin/t/{slug}/deletion-requests/{id}/execute\" style=\"display:inline; margin-left:4px\">\n\
  <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\n\
  <button type=\"submit\" class=\"btn-sm btn-danger\"\n\
          onclick=\"return confirm('{confirm}')\">{execute}</button>\n\
</form>",
                    slug    = escape(&tenant.slug),
                    id      = escape(&req.id),
                    csrf    = escape(csrf),
                    cancel  = cancel_btn,
                    execute = execute_btn,
                    confirm = execute_confirm,
                )
            } else {
                "\u{2014}".to_owned()
            };

            format!(
                "<tr>\n  <td><code>{user_id}</code></td>\n  <td>{status}</td>\n\
  <td>{scheduled}</td>\n  <td>{actions}</td>\n</tr>",
                user_id   = escape(&req.user_id),
                status    = status_badge,
                scheduled = escape(&scheduled_label),
                actions   = actions,
            )
        }).collect::<Vec<_>>().join("\n");

        format!(
            "<table class=\"data-table\">\n  <thead>\n    <tr>\n\
      <th>{uid}</th><th>{status}</th><th>{scheduled}</th><th>{actions}</th>\n\
    </tr>\n  </thead>\n  <tbody>\n{rows}\n  </tbody>\n</table>",
            uid       = escape(lookup(MessageKey::TenantDeletionColUserId,    l)),
            status    = escape(lookup(MessageKey::TenantDeletionColStatus,    l)),
            scheduled = escape(lookup(MessageKey::TenantDeletionColScheduled, l)),
            actions   = escape(lookup(MessageKey::TenantDeletionColActions,   l)),
            rows      = rows,
        )
    };

    let heading = escape(lookup(MessageKey::TenantDeletionTableHeading, l));
    let body = format!("{notice}\n<section class=\"card\">\n<h2 class=\"card-title\">{heading}</h2>\n{table}\n</section>",
        notice = notice, heading = heading, table = table);

    tenant_admin_frame(
        lookup(MessageKey::TenantDeletionPageTitle, l),
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::DeletionRequests,
        &body,
    )
}
