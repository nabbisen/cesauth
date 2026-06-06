//! Audit Log search page (§4.4).

use crate::escape;
use cesauth_core::admin::scope::ScopeBadge;
use cesauth_core::admin::types::{AdminAuditEntry, AdminPrincipal, AuditQuery};
use cesauth_core::routes::admin as routes;

use super::frame::{admin_frame, Tab};

pub fn audit_page(principal: &AdminPrincipal, q: &AuditQuery, entries: &[AdminAuditEntry]) -> String {
    let body = format!(
        "{nav}\n{form}\n{results}",
        nav     = render_nav(),
        form    = render_search_form(q),
        results = render_results(entries),
    );
    admin_frame(
        "Audit log",
        principal.role,
        principal.name.as_deref(),
        Tab::Audit,
        &ScopeBadge::System,
        &body,
    )
}

fn render_nav() -> String {
    format!(
        r##"<p><a href="{chain_url}">Chain verification status →</a></p>"##,
        chain_url = routes::AUDIT_CHAIN,
    )
}

fn render_search_form(q: &AuditQuery) -> String {
    let kind    = escape(q.kind_contains.as_deref().unwrap_or(""));
    let subject = escape(q.subject_contains.as_deref().unwrap_or(""));
    let limit   = q.limit.unwrap_or(50);
    format!(
        r##"<section aria-label="Search filters">
  <h2>Filters</h2>
  <form method="get" action="{audit_url}">
    <table>
      <tr>
        <th scope="row"><label for="kind">kind contains</label></th>
        <td><input id="kind" name="kind" type="text" value="{kind}" placeholder="auth_failed" style="width:100%"></td>
      </tr>
      <tr>
        <th scope="row"><label for="subject">subject contains</label></th>
        <td><input id="subject" name="subject" type="text" value="{subject}" placeholder="user-id or session-id substring" style="width:100%"></td>
      </tr>
      <tr>
        <th scope="row"><label for="limit">limit</label></th>
        <td><input id="limit" name="limit" type="number" value="{limit}" min="1" max="200" style="width:6em"></td>
      </tr>
      <tr>
        <th scope="row"></th>
        <td><button type="submit">Search</button></td>
      </tr>
    </table>
  </form>
  <form method="post" action="{export_url}" style="margin-top:8px">
    <input type="hidden" name="kind"    value="{kind}">
    <input type="hidden" name="subject" value="{subject}">
    <input type="hidden" name="limit"   value="{limit}">
    <button type="submit" name="format" value="csv"  class="secondary" style="margin-right:4px">Export CSV</button>
    <button type="submit" name="format" value="jsonl" class="secondary">Export JSONL</button>
  </form>
  <p class="note">Audit events live in the D1 <code>audit_events</code> table (v0.32.0+, ADR-010). The <em>Chain verification status</em> link above shows whether the SHA-256 chain over those rows is intact.</p>
</section>"##,
        audit_url  = routes::AUDIT,
        export_url = routes::AUDIT_EXPORT,
        kind       = kind,
        subject    = subject,
        limit      = limit,
    )
}

fn render_results(entries: &[AdminAuditEntry]) -> String {
    if entries.is_empty() {
        return r#"<section aria-label="Results">
  <h2>Results</h2>
  <div class="empty">No events matched.</div>
</section>"#.to_owned();
    }
    let rows: String = entries.iter().map(|e| format!(
        r##"<tr>
  <td class="num muted">{ts}</td>
  <td><code>{kind}</code></td>
  <td class="muted">{subject}</td>
  <td class="muted">{reason}</td>
  <td><details><summary>key</summary><code>{key}</code></details></td>
</tr>"##,
        ts      = e.ts,
        kind    = escape(&e.kind),
        subject = escape(e.subject.as_deref().unwrap_or("—")),
        reason  = escape(e.reason.as_deref().unwrap_or("")),
        key     = escape(&e.key),
    )).collect::<Vec<_>>().join("\n");
    format!(
        r##"<section aria-label="Results">
  <h2>Results ({n} events)</h2>
  <table><thead>
    <tr><th scope="col" class="num">ts</th><th scope="col">kind</th><th scope="col">subject</th><th scope="col">reason</th><th scope="col">key</th></tr>
  </thead><tbody>
{rows}
  </tbody></table>
</section>"##,
        n    = entries.len(),
        rows = rows,
    )
}
