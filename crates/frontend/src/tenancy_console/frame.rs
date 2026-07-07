//! Page chrome for the tenancy console.
//!
//! Deliberately distinct from `crate::admin::frame::admin_frame` —
//! the two surfaces serve different mental models and we don't want
//! tab bleed between them. They share visual styling (link colors,
//! header hierarchy) so an operator who knows one can navigate the
//! other, but the navbar is its own concern.

use crate::escape;
use cesauth_core::admin::scope::ScopeBadge;
use cesauth_core::admin::types::Role;
use cesauth_core::i18n::Locale;
use cesauth_core::routes::tenancy_console as routes;

/// Tabs in the tenancy console nav.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenancyConsoleTab {
    /// `/admin/tenancy` — landing page, deployment-wide counters.
    Overview,
    /// `/admin/tenancy/tenants` — tenant catalogue.
    Tenants,
    /// `/admin/tenancy/users/:id/role_assignments` — drill-in destination.
    /// Has no top-level tab; "current" only when navigated from a
    /// detail page.
    UserRoleAssignments,
}

impl TenancyConsoleTab {
    fn href(self) -> Option<&'static str> {
        match self {
            TenancyConsoleTab::Overview            => Some(routes::ROOT),
            TenancyConsoleTab::Tenants             => Some(routes::TENANTS),
            // Drill-in only — no top-level entry.
            TenancyConsoleTab::UserRoleAssignments => None,
        }
    }
    fn label(self) -> &'static str {
        match self {
            TenancyConsoleTab::Overview            => "Overview",
            TenancyConsoleTab::Tenants             => "Tenants",
            TenancyConsoleTab::UserRoleAssignments => "User roles",
        }
    }
}

/// The four tabs that appear in the nav bar. `UserRoleAssignments`
/// is reachable via drill-through, not nav, and is therefore
/// excluded.
const NAV_TABS: [TenancyConsoleTab; 2] = [TenancyConsoleTab::Overview, TenancyConsoleTab::Tenants];

/// Render a tenancy console page.
///
/// `role`/`role_name` mirror the admin-frame contract — surface the
/// caller's identity in the header so screenshots in support tickets
/// have an unambiguous "this was operator X looking" attestation.
pub fn tenancy_console_frame(
    title:      &str,
    role:       Role,
    role_name:  Option<&str>,
    active_tab: TenancyConsoleTab,
    body:       &str,
) -> String {
    tenancy_console_frame_for(title, role, role_name, active_tab, Locale::default(), body)
}

/// Locale-aware variant of [`tenancy_console_frame`].
pub fn tenancy_console_frame_for(
    title:      &str,
    role:       Role,
    role_name:  Option<&str>,
    active_tab: TenancyConsoleTab,
    locale:     Locale,
    body:       &str,
) -> String {
    let scope = ScopeBadge::Tenancy;
    let nonce = crate::render_nonce();
    let title_esc  = escape(title);
    let role_label = role.label();
    let role_badge = match role {
        Role::ReadOnly   => "readonly",
        Role::Security   => "security",
        Role::Operations => "operations",
        Role::Super      => "super",
    };
    let name_esc = role_name.map(escape).unwrap_or_default();
    let scope_class = scope.css_class();
    let scope_label = scope.label_for(locale);
    let scope_aria  = scope.aria_label_for(locale);

    let nav: String = NAV_TABS.iter().map(|t| {
        let current = if *t == active_tab { r#" aria-current="page""# } else { "" };
        format!(
            r#"<li><a href="{href}"{current}>{label}</a></li>"#,
            href    = t.href().unwrap_or("#"),
            current = current,
            label   = t.label(),
        )
    }).collect::<Vec<_>>().join("");

    format!(
        r##"<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title_esc} — cesauth tenancy console</title>
  <style nonce="{nonce}">
    /* RFC 105: semantic + scope tokens injected from crates/ui/src/design_tokens.rs.
       Single source of truth — do not duplicate values here. */
    {tokens}
    {scope_tokens}
    body {{ font-family: system-ui, -apple-system, sans-serif; margin: 0; color: #222; }}
    header {{ background: #2c3e50; color: #fff; padding: 12px 24px; display: flex; align-items: baseline; gap: 16px; }}
    header h1 {{ margin: 0; font-size: 1.2em; }}
    header .badge {{ font-size: 0.75em; padding: 2px 8px; border-radius: 3px; background: rgba(255,255,255,0.15); }}
    header .badge.readonly   {{ background: #34495e; }}
    header .badge.security   {{ background: #d35400; }}
    header .badge.operations {{ background: #2980b9; }}
    header .badge.super      {{ background: #c0392b; }}
    /* RFC 016 / 073 scope badge (tenancy-console dark-header variant) — same
       palette and treatment as the tenant_admin frame's scope badge so a
       scope-aware operator sees consistent visual language. */
    header .scope-badge {{ font-size: 0.75em; padding: 2px 8px; border-radius: 10px; font-weight: 500;
                           border: 1px solid rgba(255,255,255,0.5); color: #fff; }}
    header .scope-badge.scope-tenant  {{ background: var(--scope-tenant); }}
    header .scope-badge.scope-system  {{ background: var(--scope-system); }}
    header .scope-badge.scope-tenancy {{ background: var(--scope-tenancy); }}
    nav {{ background: #ecf0f1; padding: 0 24px; }}
    nav ul {{ list-style: none; margin: 0; padding: 0; display: flex; gap: 0; }}
    nav li a {{ display: block; padding: 10px 16px; color: #2c3e50; text-decoration: none; border-bottom: 2px solid transparent; }}
    nav li a:hover {{ background: rgba(0,0,0,0.05); }}
    nav li a[aria-current="page"] {{ border-bottom-color: #2c3e50; font-weight: 600; }}
    main {{ max-width: 1200px; margin: 24px auto; padding: 0 24px; }}
    main h2 {{ margin-top: 32px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
    table th, table td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #ddd; }}
    table th {{ background: #f5f5f5; font-weight: 600; }}
    .muted {{ color: #777; }}
    .empty {{ text-align: center; color: #999; padding: 24px; }}
    .badge {{ font-size: 0.8em; padding: 2px 8px; border-radius: 3px; background: #ecf0f1; }}
    /* Legacy .badge.ok/.warn/.critical (RFC 082): now point to shared semantic tokens
       so all three admin frames share the same state palette (RFC 105). */
    .badge.ok       {{ background: var(--success-bg); color: var(--success); }}
    .badge.warn     {{ background: var(--warning-bg); color: var(--warning); }}
    .badge.critical {{ background: var(--danger-bg);  color: var(--danger);  }}
    /* RFC 082: CSS-variable-based badge aliases matching end-user tokens */
    .badge--success {{ background: var(--success-bg); color: var(--success); }}
    .badge--warning {{ background: var(--warning-bg); color: var(--warning); }}
    .badge--danger  {{ background: var(--danger-bg);  color: var(--danger);  }}
    .badge--info    {{ background: var(--info-bg);    color: var(--info);    }}
    code {{ font-family: ui-monospace, 'SF Mono', Consolas, monospace; font-size: 0.9em; background: #f5f5f5; padding: 1px 4px; border-radius: 2px; }}
    .action {{ display: inline-block; padding: 6px 14px; background: #2980b9; color: #fff; text-decoration: none; border-radius: 3px; font-weight: 600; }}
    .action:hover {{ background: #1f6391; }}
    .action.danger {{ background: #c0392b; }}
    .action.danger:hover {{ background: #922b21; }}
    .action-row {{ margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap; }}
    form.danger button {{ background: #c0392b; color: #fff; border: none; padding: 8px 16px; border-radius: 3px; cursor: pointer; font-weight: 600; }}
    form.danger button:hover {{ background: #922b21; }}
    button {{ background: #2980b9; color: #fff; border: none; padding: 8px 16px; border-radius: 3px; cursor: pointer; font-weight: 600; }}
    button:hover {{ background: #1f6391; }}
    input[type="text"], select {{ padding: 6px 10px; border: 1px solid #ccc; border-radius: 3px; font-size: 1em; }}
    fieldset {{ border: 1px solid #ddd; padding: 12px 16px; }}
    footer {{ text-align: center; color: #999; font-size: 0.8em; padding: 24px; }}
  /* RFC 077: skip-to-content link */
  .skip-link {{ position: absolute; top: -100px; left: 0; padding: 4px 12px;
               background: #fff; color: var(--accent, #2753c8); text-decoration: underline; z-index: 1000; }}
  .skip-link:focus {{ top: 0; outline: 2px solid #2753c8; }}
  </style>
</head>
<body>
<a href="#main" class="skip-link">メインコンテンツへスキップ</a>
  <header>
    <h1>cesauth tenancy console</h1>
    <span class="{scope_class}" aria-label="{scope_aria}">{scope_label}</span>
    <span class="badge {role_badge}">{role_label}</span>
    {name_html}
  </header>
  <nav><ul>{nav}</ul></nav>
  <main id="main">
    <h2>{title_esc}</h2>
{body}
  </main>
  <footer>cesauth tenancy console</footer>
</body>
</html>"##,
        scope_class = scope_class,
        scope_label = scope_label,
        scope_aria  = scope_aria,
        name_html = if name_esc.is_empty() {
            String::new()
        } else {
            format!(r#"<span class="muted">{name_esc}</span>"#)
        },
        tokens       = crate::design_tokens::DESIGN_TOKENS_FMT,
        scope_tokens = crate::design_tokens::SCOPE_TOKENS_FMT,
    )
}
