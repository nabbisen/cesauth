//! `/admin/saas/tenants` — list of every non-deleted tenant.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::{Tenant, TenantStatus};

use super::frame::{saas_frame, SaasTab};

pub fn tenants_page(principal: &AdminPrincipal, rows: &[Tenant]) -> String {
    let actions = if principal.role.can_manage_tenancy() {
        r##"<p><a class="action" href="/admin/saas/tenants/new">+ New tenant</a></p>"##
    } else {
        ""
    };
    let body = format!("{actions}\n{table}", table = render_table(rows));
    saas_frame("Tenants", principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

fn render_table(rows: &[Tenant]) -> String {
    let body: String = if rows.is_empty() {
        r#"<tr><td colspan="5" class="empty">No tenants — provision one via <code>POST /api/v1/tenants</code>.</td></tr>"#
            .to_owned()
    } else {
        rows.iter().map(|t| format!(
            r##"<tr>
  <td><a href="/admin/saas/tenants/{id}"><code>{slug}</code></a></td>
  <td>{name}</td>
  <td>{status_badge}</td>
  <td class="muted">{created}</td>
  <td class="muted">{id_short}</td>
</tr>"##,
            id    = escape(&t.id),
            slug  = escape(&t.slug),
            name  = escape(&t.display_name),
            status_badge = render_status_badge(t.status),
            created  = t.created_at,
            id_short = escape(&t.id),
        )).collect::<Vec<_>>().join("\n")
    };
    format!(
        r##"<section aria-label="Tenant catalogue">
  <p class="muted">Showing all non-deleted tenants. Click a slug to drill in.</p>
  <table><thead>
    <tr>
      <th scope="col">Slug</th>
      <th scope="col">Display name</th>
      <th scope="col">Status</th>
      <th scope="col">Created (unix)</th>
      <th scope="col">Id</th>
    </tr>
  </thead><tbody>
{body}
  </tbody></table>
</section>"##
    )
}

pub(super) fn render_status_badge(s: TenantStatus) -> &'static str {
    match s {
        TenantStatus::Active    => r#"<span class="badge ok">active</span>"#,
        TenantStatus::Suspended => r#"<span class="badge warn">suspended</span>"#,
        TenantStatus::Pending   => r#"<span class="badge">pending</span>"#,
        TenantStatus::Deleted   => r#"<span class="badge critical">deleted</span>"#,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "admin".into(), name: None, role: Role::ReadOnly }
    }

    fn tenant(slug: &str, status: TenantStatus) -> Tenant {
        Tenant {
            id: format!("t-{slug}"), slug: slug.into(),
            display_name: format!("{slug} corp"),
            status, created_at: 100, updated_at: 200,
        }
    }

    #[test]
    fn empty_list_renders_call_to_action() {
        let html = tenants_page(&p(), &[]);
        assert!(html.contains("/api/v1/tenants"),
            "empty state must point at the JSON API");
    }

    #[test]
    fn each_tenant_row_links_to_detail() {
        let rows = vec![tenant("acme", TenantStatus::Active)];
        let html = tenants_page(&p(), &rows);
        assert!(html.contains(r#"href="/admin/saas/tenants/t-acme""#));
        assert!(html.contains("acme"));
    }

    #[test]
    fn suspended_tenant_shows_warn_badge() {
        let rows = vec![tenant("foo", TenantStatus::Suspended)];
        let html = tenants_page(&p(), &rows);
        assert!(html.contains(r#"badge warn">suspended"#));
    }

    #[test]
    fn untrusted_slug_is_html_escaped() {
        // Slugs validate to [a-z0-9-] in the service layer, but the
        // display_name does not — defend in depth.
        let mut t = tenant("acme", TenantStatus::Active);
        t.display_name = "<script>alert(1)</script>".into();
        let html = tenants_page(&p(), &[t]);
        assert!(!html.contains("<script>"),
            "display_name must be escaped; got {html:?}");
        assert!(html.contains("&lt;script&gt;"),
            "expected escaped form");
    }

    #[test]
    fn read_only_role_does_not_see_new_tenant_button() {
        // ReadOnly cannot mutate; the affordance must be hidden so
        // a click doesn't lead to a blank 403 page.
        let p = AdminPrincipal { id: "x".into(), name: None, role: Role::ReadOnly };
        let html = tenants_page(&p, &[]);
        assert!(!html.contains(r#"href="/admin/saas/tenants/new""#),
            "ReadOnly must not see the New tenant link");
    }

    #[test]
    fn operations_role_sees_new_tenant_button() {
        let p = AdminPrincipal { id: "x".into(), name: None, role: Role::Operations };
        let html = tenants_page(&p, &[]);
        assert!(html.contains(r#"href="/admin/saas/tenants/new""#),
            "Operations must see the New tenant link");
    }
}
