//! Audit Log search page (§4.4).

use crate::escape;
use cesauth_core::admin::types::{AdminAuditEntry, AuditQuery, Role};

use super::frame::{admin_frame, Tab};

pub fn audit_page(q: &AuditQuery, entries: &[AdminAuditEntry]) -> String {
    let body = format!(
        "{form}\n{results}",
        form    = render_search_form(q),
        results = render_results(entries),
    );
    admin_frame("Audit log", Role::ReadOnly, None, Tab::Audit, &body)
}

fn render_search_form(q: &AuditQuery) -> String {
    let prefix  = escape(q.prefix.as_deref().unwrap_or(""));
    let kind    = escape(q.kind_contains.as_deref().unwrap_or(""));
    let subject = escape(q.subject_contains.as_deref().unwrap_or(""));
    let limit   = q.limit.unwrap_or(50);
    format!(
        r##"<section aria-label="Search filters">
  <h2>Filters</h2>
  <form method="get" action="/admin/console/audit">
    <table>
      <tr>
        <th scope="row"><label for="prefix">R2 prefix</label></th>
        <td><input id="prefix" name="prefix" type="text" value="{prefix}" placeholder="audit/YYYY/MM/DD/" style="width:100%"></td>
      </tr>
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
  <p class="note">Prefix defaults to today's UTC day. Widen with <code>audit/2026/04/</code> for the month; narrow with <code>audit/2026/04/24/</code> for a day.</p>
</section>"##
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
