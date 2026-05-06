//! Page chrome for the tenant-scoped admin surface.
//!
//! Mirrors the visual style of `tenancy_console::frame` but is
//! a separate code path. Per ADR-003, no chrome (header, nav,
//! footer) is shared between the system-admin and tenant-admin
//! surfaces — that separation is the structural defense against
//! tenant-boundary leakage. If a future change to the system-admin
//! frame should also apply here, both files have to be updated.
//!
//! ## What's distinctive
//!
//! - **Tenant identity is in the header.** The slug and display
//!   name appear next to the "tenant admin" label so an operator
//!   never has to guess which tenant they're looking at.
//! - **Nav links are slug-relative.** Every link is built off
//!   `/admin/t/<slug>/...` so the user doesn't accidentally
//!   navigate out of their tenant context.
//! - **No "operator mode" affordance.** Per ADR-003. To do
//!   system-admin work, leave this surface entirely.

use crate::escape;
use cesauth_core::admin::types::Role;

/// Tabs in the tenant-admin nav. All hrefs are built per-render
/// because they include the tenant slug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantAdminTab {
    /// `/admin/t/<slug>` — landing page, tenant's own counters.
    Overview,
    /// `/admin/t/<slug>/organizations`.
    Organizations,
    /// `/admin/t/<slug>/users`.
    Users,
    /// `/admin/t/<slug>/subscription`.
    Subscription,
    /// Drill-in destination from a user row. No top-level tab.
    UserRoleAssignments,
    /// Drill-in destination from an organizations row. No
    /// top-level tab.
    OrganizationDetail,
}

impl TenantAdminTab {
    /// Build the href for this tab, using the tenant's slug.
    /// Drill-in tabs return `None` because the URL needs an id
    /// the frame doesn't know about.
    fn href(self, slug: &str) -> Option<String> {
        match self {
            TenantAdminTab::Overview      => Some(format!("/admin/t/{slug}")),
            TenantAdminTab::Organizations => Some(format!("/admin/t/{slug}/organizations")),
            TenantAdminTab::Users         => Some(format!("/admin/t/{slug}/users")),
            TenantAdminTab::Subscription  => Some(format!("/admin/t/{slug}/subscription")),
            TenantAdminTab::UserRoleAssignments
            | TenantAdminTab::OrganizationDetail => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            TenantAdminTab::Overview            => "Overview",
            TenantAdminTab::Organizations       => "Organizations",
            TenantAdminTab::Users               => "Users",
            TenantAdminTab::Subscription        => "Subscription",
            TenantAdminTab::UserRoleAssignments => "User roles",
            TenantAdminTab::OrganizationDetail  => "Organization",
        }
    }
}

/// The four tabs that appear in the nav bar. Drill-in tabs are
/// not navigated to from the bar.
const NAV_TABS: [TenantAdminTab; 4] = [
    TenantAdminTab::Overview,
    TenantAdminTab::Organizations,
    TenantAdminTab::Users,
    TenantAdminTab::Subscription,
];

/// Render a tenant-admin page.
///
/// `tenant_slug` and `tenant_display_name` are surfaced in the
/// header so the tenant identity is unambiguous in screenshots
/// and bug reports. `role` and `role_name` mirror the
/// system-admin frame's contract.
pub fn tenant_admin_frame(
    title:               &str,
    tenant_slug:         &str,
    tenant_display_name: &str,
    role:                Role,
    role_name:           Option<&str>,
    active_tab:          TenantAdminTab,
    body:                &str,
) -> String {
    let title_esc        = escape(title);
    let slug_esc         = escape(tenant_slug);
    let tenant_name_esc  = escape(tenant_display_name);
    let role_label       = role.label();
    let role_badge = match role {
        Role::ReadOnly   => "readonly",
        Role::Security   => "security",
        Role::Operations => "operations",
        Role::Super      => "super",
    };
    let name_esc = role_name.map(escape).unwrap_or_default();

    let nav: String = NAV_TABS.iter().map(|t| {
        let current = if *t == active_tab { r#" aria-current="page""# } else { "" };
        // Safe: slug came from a TenantRepository row, validated at
        // creation time. We still escape it inside attributes for
        // defense in depth.
        let href = t.href(tenant_slug).unwrap_or_else(|| "#".into());
        format!(
            r#"<li><a href="{href}"{current}>{label}</a></li>"#,
            href    = escape(&href),
            current = current,
            label   = t.label(),
        )
    }).collect::<Vec<_>>().join("");

    format!(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title_esc} — {tenant_name_esc} — cesauth tenant admin</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; margin: 0; color: #222; }}
    header {{ background: #1e3a5f; color: #fff; padding: 12px 24px; display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap; }}
    header h1 {{ margin: 0; font-size: 1.2em; }}
    header .tenant-name {{ font-size: 1em; opacity: 0.9; }}
    header .tenant-slug {{ font-family: ui-monospace, 'SF Mono', Consolas, monospace; font-size: 0.85em; opacity: 0.7; }}
    header .badge {{ font-size: 0.75em; padding: 2px 8px; border-radius: 3px; background: rgba(255,255,255,0.15); }}
    header .badge.readonly   {{ background: #34495e; }}
    header .badge.security   {{ background: #d35400; }}
    header .badge.operations {{ background: #2980b9; }}
    header .badge.super      {{ background: #c0392b; }}
    nav {{ background: #e3eaf2; padding: 0 24px; }}
    nav ul {{ list-style: none; margin: 0; padding: 0; display: flex; gap: 0; flex-wrap: wrap; }}
    nav li a {{ display: block; padding: 10px 16px; color: #1e3a5f; text-decoration: none; border-bottom: 2px solid transparent; }}
    nav li a:hover {{ background: rgba(0,0,0,0.05); }}
    nav li a[aria-current="page"] {{ border-bottom-color: #1e3a5f; font-weight: 600; }}
    main {{ max-width: 1200px; margin: 24px auto; padding: 0 24px; }}
    main h2 {{ margin-top: 32px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
    table th, table td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #ddd; }}
    table th {{ background: #f5f5f5; font-weight: 600; }}
    .muted {{ color: #777; }}
    .empty {{ text-align: center; color: #999; padding: 24px; }}
    .badge {{ font-size: 0.8em; padding: 2px 8px; border-radius: 3px; background: #ecf0f1; }}
    .badge.ok       {{ background: #d4edda; color: #155724; }}
    .badge.warn     {{ background: #fff3cd; color: #856404; }}
    .badge.critical {{ background: #f8d7da; color: #721c24; }}
    code {{ font-family: ui-monospace, 'SF Mono', Consolas, monospace; font-size: 0.9em; background: #f5f5f5; padding: 1px 4px; border-radius: 2px; }}
    footer {{ text-align: center; color: #999; font-size: 0.8em; padding: 24px; }}
  </style>
</head>
<body>
  <header>
    <h1>cesauth tenant admin</h1>
    <span class="tenant-name">{tenant_name_esc}</span>
    <span class="tenant-slug">{slug_esc}</span>
    <span class="badge {role_badge}">{role_label}</span>
    {name_html}
  </header>
  <nav><ul>{nav}</ul></nav>
  <main>
    <h2>{title_esc}</h2>
{body}
  </main>
  <footer>cesauth tenant admin — v0.41.0 (mutations + affordance gating)</footer>
</body>
</html>"##,
        name_html = if name_esc.is_empty() {
            String::new()
        } else {
            format!(r#"<span class="muted">{name_esc}</span>"#)
        },
    )
}
