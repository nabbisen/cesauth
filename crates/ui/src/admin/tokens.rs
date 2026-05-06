//! Admin-token management UI (v0.4.0, Super-only).
//!
//! Three screens:
//!
//!   * [`list_page`] — table of active tokens (id, role, name) with a
//!     per-row "Disable" form and a top-right "Create new token" link.
//!   * [`new_form`] — role + name form that POSTs to the create route.
//!   * [`created_page`] — shown exactly once after a successful create:
//!     the plaintext bearer is displayed with a prominent "copy it now,
//!     it won't be shown again" warning.
//!
//! Per spec §14 this surface is provisional. The list does NOT show
//! `created_at` / `last_used_at` / `disabled_at` because the port's
//! [`AdminTokenRepository::list`] returns only `AdminPrincipal`; extending
//! that is a post-tenant-boundaries decision.

use crate::escape;
use cesauth_core::admin::types::{AdminPrincipal, Role};

use super::frame::{admin_frame, Tab};

// -------------------------------------------------------------------------
// List
// -------------------------------------------------------------------------

pub fn list_page(principal: &AdminPrincipal, tokens: &[AdminPrincipal]) -> String {
    let rows = if tokens.is_empty() {
        r#"<tr><td colspan="4" class="empty">No active admin tokens. Only the <code>ADMIN_API_KEY</code> bootstrap bearer will resolve.</td></tr>"#.to_owned()
    } else {
        tokens.iter().map(|t| {
            let role_badge = match t.role {
                Role::Super      => r#"<span class="badge critical">super</span>"#,
                Role::Operations => r#"<span class="badge warn">operations</span>"#,
                Role::Security   => r#"<span class="badge ok">security</span>"#,
                Role::ReadOnly   => r#"<span class="badge muted">read_only</span>"#,
            };
            format!(
                r##"<tr>
  <td><code>{id}</code></td>
  <td>{role_badge}</td>
  <td class="muted">{name}</td>
  <td>
    <form class="inline" method="post" action="/admin/console/tokens/{id}/disable">
      <button type="submit" aria-label="Disable token {name_aria}">Disable</button>
    </form>
  </td>
</tr>"##,
                id         = escape(&t.id),
                role_badge = role_badge,
                name       = escape(t.name.as_deref().unwrap_or("—")),
                name_aria  = escape(t.name.as_deref().unwrap_or(&t.id)),
            )
        }).collect::<Vec<_>>().join("\n")
    };

    let body = format!(
        r##"<section aria-label="Active tokens">
  <h2>Active tokens <a href="/admin/console/tokens/new" style="font-weight:normal; font-size:13px;">(+ create new)</a></h2>
  <p class="muted">These are every non-disabled row in <code>admin_tokens</code>. The
    <code>ADMIN_API_KEY</code> bootstrap bearer is not listed here — it lives in
    Workers Secrets, has id <code>super-bootstrap</code>, and cannot be disabled from this UI.</p>
  <table><thead>
    <tr>
      <th scope="col">ID</th>
      <th scope="col">Role</th>
      <th scope="col">Name</th>
      <th scope="col">Action</th>
    </tr>
  </thead><tbody>
{rows}
  </tbody></table>
  <p class="note">Disabling a token keeps the row (so the audit trail stays intact) and sets
    <code>disabled_at</code>. The resolver will treat subsequent uses as unknown (401 with
    reason <code>disabled_token</code>). Re-enabling is not supported from the UI —
    create a new token instead.</p>
</section>"##
    );

    admin_frame(
        "Admin tokens",
        principal.role,
        principal.name.as_deref(),
        Tab::Tokens,
        &body,
    )
}

// -------------------------------------------------------------------------
// New form
// -------------------------------------------------------------------------

pub fn new_form(principal: &AdminPrincipal, error: Option<&str>) -> String {
    let error_section = match error {
        None      => String::new(),
        Some(msg) => format!(
            r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {msg}</p></section>"#,
            msg = escape(msg),
        ),
    };

    let body = format!(
        r##"{error_section}
<section aria-label="Create new admin token">
  <h2>Create new admin token</h2>
  <form method="post" action="/admin/console/tokens">
    <table>
      <tr>
        <th scope="row"><label for="role">Role</label></th>
        <td>
          <select id="role" name="role" required>
            <option value="read_only">ReadOnly — view only</option>
            <option value="security">Security — view + re-verify bucket safety, revoke sessions</option>
            <option value="operations" selected>Operations — + edit bucket safety, edit thresholds, create users</option>
            <option value="super">Super — + manage admin tokens</option>
          </select>
        </td>
      </tr>
      <tr>
        <th scope="row"><label for="name">Label</label></th>
        <td>
          <input id="name" name="name" type="text" maxlength="128" placeholder="e.g. alice@example, incident-responder, cron-bot" style="width:100%">
          <p class="note">Optional. Appears in the role badge and in audit events (<code>subject=&lt;id&gt;</code>). Use something you'll recognize later.</p>
        </td>
      </tr>
      <tr>
        <th scope="row"></th>
        <td>
          <p class="muted">The server will mint a 256-bit random bearer, SHA-256-hash it for storage, and show you the plaintext exactly once on the next page.</p>
          <button type="submit">Mint token</button>
          &nbsp;<a href="/admin/console/tokens">Cancel</a>
        </td>
      </tr>
    </table>
  </form>
</section>"##
    );

    admin_frame(
        "Create admin token",
        principal.role,
        principal.name.as_deref(),
        Tab::Tokens,
        &body,
    )
}

// -------------------------------------------------------------------------
// Created (one-shot)
// -------------------------------------------------------------------------

/// One-shot display of a freshly-minted plaintext bearer. After this
/// page, the plaintext is never retrievable again.
pub fn created_page(
    principal: &AdminPrincipal,
    minted:    &AdminPrincipal,
    plaintext: &str,
) -> String {
    let role_label = minted.role.label();
    let body = format!(
        r##"<section aria-label="New token" class="danger-section">
  <h2>Token created</h2>
  <p role="status"><span class="badge warn">write this down NOW</span>
     This plaintext is displayed once. There is no way to retrieve it again — cesauth stores only its SHA-256 hash. If you close this tab without copying, disable the token and create a new one.</p>
  <table>
    <tr><th scope="row">ID</th><td><code>{id}</code></td></tr>
    <tr><th scope="row">Role</th><td>{role}</td></tr>
    <tr><th scope="row">Label</th><td class="muted">{name}</td></tr>
    <tr><th scope="row">Bearer (plaintext)</th>
        <td><code style="background:#fff7f7; padding:8px; display:block; border:1px solid #a6261d; border-radius:3px; word-break:break-all; font-size:15px;">{plaintext}</code></td></tr>
  </table>
  <h2>How to use it</h2>
  <pre style="background:#f4f4f4; padding:12px; border-radius:4px; overflow-x:auto;"><code>curl -H "Authorization: Bearer {plaintext_short}..." \
     https://cesauth.example/admin/console</code></pre>
  <p><a href="/admin/console/tokens">← Back to token list (this page will not display the plaintext again)</a></p>
</section>"##,
        id              = escape(&minted.id),
        role            = escape(role_label),
        name            = escape(minted.name.as_deref().unwrap_or("—")),
        plaintext       = escape(plaintext),
        plaintext_short = escape(&plaintext.chars().take(8).collect::<String>()),
    );

    admin_frame(
        "Token created",
        principal.role,
        principal.name.as_deref(),
        Tab::Tokens,
        &body,
    )
}
