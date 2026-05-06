//! `/admin/t/<slug>/users` — list of users belonging to this tenant.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::Tenant;
use cesauth_core::tenancy::AccountType;
use cesauth_core::types::{User, UserStatus};

use super::frame::{tenant_admin_frame, TenantAdminTab};

pub fn users_page(
    principal: &AdminPrincipal,
    tenant:    &Tenant,
    users:     &[User],
) -> String {
    let body = if users.is_empty() {
        r#"<p class="empty">No users in this tenant yet.</p>"#.to_owned()
    } else {
        render_user_table(tenant, users)
    };
    tenant_admin_frame(
        "Users",
        &tenant.slug,
        &tenant.display_name,
        principal.role,
        principal.name.as_deref(),
        TenantAdminTab::Users,
        &body,
    )
}

fn render_user_table(tenant: &Tenant, users: &[User]) -> String {
    let rows: String = users.iter().map(|u| {
        let display = u.display_name.as_deref().unwrap_or("—");
        let email   = u.email.as_deref().unwrap_or("—");
        format!(
            r#"<tr>
  <td><a href="/admin/t/{slug}/users/{uid}/role_assignments">{name}</a></td>
  <td>{email}</td>
  <td>{kind}</td>
  <td>{status}</td>
</tr>"#,
            slug   = escape(&tenant.slug),
            uid    = escape(&u.id),
            name   = escape(display),
            email  = escape(email),
            kind   = render_account_type(u.account_type),
            status = render_user_status_badge(u.status),
        )
    }).collect::<Vec<_>>().join("\n");
    format!(
        r##"<table>
  <thead><tr>
    <th scope="col">Display name</th>
    <th scope="col">Email</th>
    <th scope="col">Account type</th>
    <th scope="col">Status</th>
  </tr></thead>
  <tbody>
{rows}
  </tbody>
</table>"##
    )
}

fn render_user_status_badge(s: UserStatus) -> &'static str {
    match s {
        UserStatus::Active    => r#"<span class="badge ok">active</span>"#,
        UserStatus::Disabled  => r#"<span class="badge warn">disabled</span>"#,
        UserStatus::Deleted   => r#"<span class="badge critical">deleted</span>"#,
    }
}

fn render_account_type(t: AccountType) -> &'static str {
    match t {
        AccountType::Anonymous            => "anonymous",
        AccountType::HumanUser            => "human",
        AccountType::ServiceAccount       => "service account",
        AccountType::SystemOperator       => "system operator",
        AccountType::ExternalFederatedUser => "federated",
    }
}
