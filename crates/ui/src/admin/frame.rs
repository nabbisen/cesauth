//! Shared chrome for every admin-console page.
//!
//! Every page's handler builds its body fragment then calls
//! [`admin_frame`] with a page title, the current principal's role
//! label, and the active nav tab.
//!
//! Inline CSS is intentional. A separate stylesheet would require a
//! `style-src 'self'` that ultimately points at another Workers asset,
//! and the CSS is small enough that duplicating it on each page costs
//! almost nothing. The tri-state color palette (`--ok`, `--warn`,
//! `--critical`) matches the alert severity cue shown on the Overview
//! and Alert Center pages.

use crate::escape;
use cesauth_core::admin::types::Role;

/// Nav-tab identifier. Used by the frame to render the active link
/// with `aria-current="page"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Cost,
    Safety,
    Audit,
    Config,
    Alerts,
}

impl Tab {
    fn href(self) -> &'static str {
        match self {
            Tab::Overview => "/admin/console",
            Tab::Cost     => "/admin/console/cost",
            Tab::Safety   => "/admin/console/safety",
            Tab::Audit    => "/admin/console/audit",
            Tab::Config   => "/admin/console/config",
            Tab::Alerts   => "/admin/console/alerts",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Cost     => "Cost",
            Tab::Safety   => "Safety",
            Tab::Audit    => "Audit",
            Tab::Config   => "Config",
            Tab::Alerts   => "Alerts",
        }
    }
}

const TABS_ORDER: [Tab; 6] = [
    Tab::Overview, Tab::Cost, Tab::Safety, Tab::Audit, Tab::Config, Tab::Alerts,
];

/// Top-level admin page scaffold.
///
/// `title` is used verbatim inside `<title>` and `<h1>`; it is
/// HTML-escaped here so callers may pass untrusted strings (bucket
/// names, etc.) without double-escaping.
pub fn admin_frame(
    title:       &str,
    role:        Role,
    role_name:   Option<&str>,
    active_tab:  Tab,
    body:        &str,
) -> String {
    let title_esc = escape(title);
    let role_label = role.label();
    let role_badge = match role {
        Role::ReadOnly   => "readonly",
        Role::Security   => "security",
        Role::Operations => "operations",
        Role::Super      => "super",
    };
    let name_esc = role_name.map(escape).unwrap_or_default();

    let nav: String = TABS_ORDER.iter().map(|t| {
        let current = if *t == active_tab { r#" aria-current="page""# } else { "" };
        format!(
            r#"<li><a href="{href}"{current}>{label}</a></li>"#,
            href    = t.href(),
            current = current,
            label   = t.label(),
        )
    }).collect::<Vec<_>>().join("");

    format!(r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title_esc} — cesauth admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {{
    --bg:       #fafafa;
    --fg:       #111;
    --muted:    #666;
    --border:   #ddd;
    --accent:   #1d4ed8;
    --ok:       #0a8f4e;
    --warn:     #c67a00;
    --critical: #a6261d;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font: 14px/1.5 system-ui, sans-serif; color: var(--fg); background: var(--bg); }}
  header.site {{
    padding: 12px 20px; background: #fff; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 20px;
  }}
  header.site .brand {{ font-weight: 600; letter-spacing: 0.05em; }}
  header.site .role-badge {{
    margin-left: auto; padding: 3px 8px; border-radius: 3px;
    background: #eee; color: var(--muted); font-size: 12px;
  }}
  header.site .role-badge.super      {{ background: #6d28d9; color: #fff; }}
  header.site .role-badge.operations {{ background: #1d4ed8; color: #fff; }}
  header.site .role-badge.security   {{ background: #0a8f4e; color: #fff; }}
  header.site .role-badge.readonly   {{ background: #6b7280; color: #fff; }}
  nav.tabs {{
    background: #fff; border-bottom: 1px solid var(--border);
    padding: 0 20px;
  }}
  nav.tabs ul {{ margin: 0; padding: 0; list-style: none; display: flex; gap: 4px; }}
  nav.tabs li a {{
    display: block; padding: 10px 14px; color: var(--muted); text-decoration: none;
  }}
  nav.tabs li a[aria-current="page"] {{
    color: var(--fg); border-bottom: 2px solid var(--accent);
  }}
  main {{ max-width: 1100px; margin: 0 auto; padding: 24px 20px; }}
  h1 {{ font-size: 22px; margin: 0 0 16px; }}
  h2 {{ font-size: 16px; margin: 28px 0 8px; }}
  section {{ background: #fff; border: 1px solid var(--border); border-radius: 6px;
            padding: 16px 20px; margin: 0 0 20px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }}
  th {{ background: #f4f4f4; font-weight: 600; font-size: 13px; }}
  tbody tr:last-child td {{ border-bottom: 0; }}
  .muted    {{ color: var(--muted); }}
  .num      {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .ok       {{ color: var(--ok); }}
  .warn     {{ color: var(--warn); }}
  .critical {{ color: var(--critical); font-weight: 600; }}
  .badge {{ display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px; }}
  .badge.ok       {{ background: #e0f3e7; color: var(--ok); }}
  .badge.warn     {{ background: #fdf0e0; color: var(--warn); }}
  .badge.critical {{ background: #fde0dc; color: var(--critical); }}
  .badge.muted    {{ background: #eee;    color: var(--muted); }}
  form.danger {{
    border: 1px solid var(--critical); padding: 12px; border-radius: 4px; background: #fff7f7;
  }}
  form.danger button {{ background: var(--critical); color: #fff; border: 0;
                        padding: 6px 12px; border-radius: 3px; cursor: pointer; }}
  form.inline {{ display: inline; }}
  form.inline button {{ background: transparent; color: var(--accent); border: 0;
                        padding: 0; cursor: pointer; text-decoration: underline; font-size: 13px; }}
  details {{ margin-top: 4px; }}
  details summary {{ cursor: pointer; color: var(--muted); font-size: 12px; }}
  footer {{ color: var(--muted); font-size: 12px; text-align: center; padding: 20px; }}
  .empty {{ color: var(--muted); font-style: italic; padding: 12px 0; }}
  .note  {{ color: var(--muted); font-size: 12px; font-style: italic; margin-top: 4px; }}
</style>
</head>
<body>
<header class="site">
  <span class="brand">cesauth admin</span>
  <span class="role-badge {role_badge}" aria-label="Current admin role: {role_label}">{role_label}{name_suffix}</span>
</header>
<nav class="tabs" aria-label="Console sections"><ul>{nav}</ul></nav>
<main>
<h1>{title_esc}</h1>
{body}
</main>
<footer>cesauth Cost &amp; Data Safety Admin Console — v0.3.0</footer>
</body>
</html>
"##,
        title_esc = title_esc,
        role_label = role_label,
        role_badge = role_badge,
        name_suffix = if name_esc.is_empty() { String::new() } else { format!(" · {name_esc}") },
        nav = nav,
        body = body,
    )
}
