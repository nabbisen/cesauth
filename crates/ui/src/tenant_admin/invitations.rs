//! `/admin/t/<slug>/invitations` — invitation management page (RFC 066).
//!
//! RFC 078: All visible strings use MessageKey / JA-only locale (admin policy).

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::i18n::{lookup, Locale, MessageKey};
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
    let l    = Locale::Ja; // admin is JA-only (ADR-013 / RFC 078)
    let csrf = "";

    let issue_form = format!(
        "<section class=\"card mb-4\">\n\
  <h2 class=\"card-title\">{section_title}</h2>\n\
  <form method=\"POST\" action=\"/admin/t/{slug}/invitations\">\n\
    <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\n\
    <div class=\"form-row\">\n\
      <label for=\"email\">{email_label}</label>\n\
      <input type=\"email\" id=\"email\" name=\"email\" required placeholder=\"user@example.com\">\n\
    </div>\n\
    <div class=\"form-row\">\n\
      <label for=\"role\">{role_label}</label>\n\
      <select id=\"role\" name=\"role\">\n\
        <option value=\"tenant_member\">{role_member}</option>\n\
        <option value=\"tenant_admin\">{role_admin}</option>\n\
      </select>\n\
    </div>\n\
    <button type=\"submit\" class=\"btn-primary\">{submit_btn}</button>\n\
  </form>\n\
</section>",
        slug          = escape(&tenant.slug),
        csrf          = escape(csrf),
        section_title = escape(lookup(MessageKey::TenantInviteSectionTitle, l)),
        email_label   = escape(lookup(MessageKey::TenantInviteEmailLabel,   l)),
        role_label    = escape(lookup(MessageKey::TenantInviteRoleLabel,    l)),
        role_member   = escape(lookup(MessageKey::TenantInviteRoleMember,   l)),
        role_admin    = escape(lookup(MessageKey::TenantInviteRoleAdmin,    l)),
        submit_btn    = escape(lookup(MessageKey::TenantInviteSubmitButton, l)),
    );

    let table = if invitations.is_empty() {
        format!("<p class=\"empty\">{}</p>",
            escape(lookup(MessageKey::TenantInviteEmpty, l)))
    } else {
        let rows: String = invitations.iter().map(|inv| {
            let expires_in_h = (inv.expires_at - now_unix).max(0) / 3600;
            let status = if inv.revoked_at.is_some() {
                format!("<span class=\"badge badge-error\">{}</span>",
                    escape(lookup(MessageKey::TenantInviteStatusRevoked, l)))
            } else if now_unix > inv.expires_at {
                format!("<span class=\"badge badge-warn\">{}</span>",
                    escape(lookup(MessageKey::TenantInviteStatusExpired, l)))
            } else {
                format!("<span class=\"badge badge-ok\">{}</span>",
                    escape(lookup(MessageKey::TenantInviteStatusPending, l)))
            };
            let expires_label = if inv.revoked_at.is_none() && now_unix <= inv.expires_at {
                lookup(MessageKey::TenantInviteExpiresInHours, l)
                    .replace("{n}", &expires_in_h.to_string())
            } else {
                "\u{2014}".to_owned() // em dash
            };
            let confirm_msg = escape(lookup(MessageKey::TenantInviteRevokeConfirm, l));
            let revoke_btn  = escape(lookup(MessageKey::TenantInviteRevokeButton,  l));
            format!(
                "<tr>\n  <td>{email}</td>\n  <td>{role}</td>\n  <td>{status}</td>\n\
  <td>{expires}</td>\n  <td>\n\
    <form method=\"POST\" action=\"/admin/t/{slug}/invitations/{id}/revoke\" style=\"display:inline\">\n\
      <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\n\
      <button type=\"submit\" class=\"btn-sm btn-danger\"\n\
              onclick=\"return confirm('{confirm}')\">{revoke}</button>\n\
    </form>\n  </td>\n</tr>",
                email   = escape(&inv.email),
                role    = escape(&inv.role),
                status  = status,
                expires = escape(&expires_label),
                slug    = escape(&tenant.slug),
                id      = escape(&inv.id),
                csrf    = escape(csrf),
                confirm = confirm_msg,
                revoke  = revoke_btn,
            )
        }).collect::<Vec<_>>().join("\n");

        format!(
            "<table class=\"data-table\">\n  <thead>\n    <tr>\n\
      <th>{email}</th><th>{role}</th><th>{status}</th><th>{expires}</th><th></th>\n\
    </tr>\n  </thead>\n  <tbody>\n{rows}\n  </tbody>\n</table>",
            email   = escape(lookup(MessageKey::TenantInviteColEmail,   l)),
            role    = escape(lookup(MessageKey::TenantInviteColRole,    l)),
            status  = escape(lookup(MessageKey::TenantInviteColStatus,  l)),
            expires = escape(lookup(MessageKey::TenantInviteColExpires, l)),
            rows    = rows,
        )
    };

    let heading = escape(lookup(MessageKey::TenantInvitePendingHeading, l));
    let body    = format!("{issue_form}\n<section class=\"card\">\n<h2 class=\"card-title\">{heading}</h2>\n{table}\n</section>");

    tenant_admin_frame(
        lookup(MessageKey::TenantInvitePageTitle, l),
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::Invitations,
        &body,
    )
}
