//! `GET/POST /admin/tenancy/users/:uid/tokens/new` —
//! mint a user-bound admin token for a tenant admin.
//!
//! High-risk operation: the resulting token grants its bearer
//! the role's permissions at the user's tenant scope. Preview/
//! confirm pattern, with one extra wrinkle: the **plaintext
//! token is shown once on the apply page**, after which it
//! cannot be retrieved (only the hash is stored). The preview
//! page makes this lifecycle clear so an operator who clicks
//! Apply has plenty of warning to copy the result.
//!
//! Only system-admins reach this form (it lives on the
//! `/admin/tenancy/...` surface, gated by `ManageAdminTokens` per
//! v0.4.0's existing flow). Tenant admins cannot self-mint per
//! ADR-002 / ADR-003.

use crate::escape;
use cesauth_core::admin::types::{AdminPrincipal, Role as AdminRole};
use cesauth_core::types::User;

use super::super::frame::{tenancy_console_frame, TenancyConsoleTab};

/// Form-render input. Sticky values plus the user the token
/// will bind to.
#[derive(Debug, Clone)]
pub struct MintInput<'a> {
    pub subject_user: &'a User,
    /// Sticky on re-render after a failed submit.
    pub role:         &'a str,   // "read_only" / "security" / "operations" / "super"
    pub name:         &'a str,
    pub error:        Option<&'a str>,
}

pub fn form_page(
    principal: &AdminPrincipal,
    input:     &MintInput<'_>,
) -> String {
    let user_label = input.subject_user.display_name.as_deref()
        .unwrap_or(&input.subject_user.id);
    let title = format!("Mint user-bound admin token: {}", user_label);
    let body = format!(
        r##"<p><a href="/admin/tenancy/users/{uid}/role_assignments">← Back to user's role assignments</a></p>
{error}
<section aria-label="Subject">
  <table><tbody>
    <tr><th scope="row">Subject user</th><td>{uname} <code>{uid}</code></td></tr>
    <tr><th scope="row">User's tenant</th><td><code>{tid}</code></td></tr>
  </tbody></table>
</section>
<section aria-label="Mint form">
  <form method="post" action="/admin/tenancy/users/{uid}/tokens/new">
    <fieldset>
      <legend>Admin role for the resulting token</legend>
      <p class="muted">The role applies to the token itself (operator
         affordances on the tenant-admin surface). Distinct from this
         user's role assignments, which gate <code>check_permission</code>
         decisions on the tenant-scoped HTTP API.</p>
      <p><input type="radio" id="r_readonly"   name="role" value="read_only"  {cr}> <label for="r_readonly">  <code>read_only</code></label></p>
      <p><input type="radio" id="r_security"   name="role" value="security"   {cs}> <label for="r_security">  <code>security</code></label></p>
      <p><input type="radio" id="r_operations" name="role" value="operations" {co}> <label for="r_operations"><code>operations</code></label></p>
      <p><input type="radio" id="r_super"      name="role" value="super"      {cu}> <label for="r_super">     <code>super</code></label></p>
    </fieldset>
    <p>
      <label for="name">Token nickname (recorded in audit log)</label><br>
      <input id="name" name="name" type="text" required maxlength="80" value="{name}" style="width: 30em;">
    </p>
    <p><button type="submit">Preview mint</button></p>
  </form>
</section>"##,
        uid   = escape(&input.subject_user.id),
        uname = escape(user_label),
        tid   = escape(&input.subject_user.tenant_id),
        cr    = if input.role == "read_only"  { "checked" } else { "" },
        cs    = if input.role == "security"   { "checked" } else { "" },
        co    = if input.role == "operations" { "checked" } else { "" },
        cu    = if input.role == "super"      { "checked" } else { "" },
        name  = escape(input.name),
        error = render_error(input.error),
    );
    tenancy_console_frame(&title, principal.role, principal.name.as_deref(),
                          TenancyConsoleTab::UserRoleAssignments, &body)
}

#[derive(Debug, Clone)]
pub struct MintPreviewInput<'a> {
    pub subject_user: &'a User,
    pub role:         AdminRole,
    pub name:         &'a str,
}

pub fn preview_page(
    principal: &AdminPrincipal,
    input:     &MintPreviewInput<'_>,
) -> String {
    let user_label = input.subject_user.display_name.as_deref()
        .unwrap_or(&input.subject_user.id);
    let title = format!("Confirm mint: {}", user_label);
    let body = format!(
        r##"<p><a href="/admin/tenancy/users/{uid}/tokens/new">← Back to form</a></p>
<section aria-label="Diff">
  <h3>Proposed mint</h3>
  <table><tbody>
    <tr><th scope="row">Subject user</th><td>{uname} <code>{uid}</code></td></tr>
    <tr><th scope="row">User's tenant</th><td><code>{tid}</code></td></tr>
    <tr><th scope="row">Token role</th><td><code>{role}</code></td></tr>
    <tr><th scope="row">Token nickname</th><td>{name}</td></tr>
  </tbody></table>
  <p class="critical"><strong>Important.</strong> The plaintext token
     is shown <em>once</em> after Apply. cesauth stores only its hash;
     there is no way to recover the plaintext later. Be ready to copy
     it before clicking Apply.</p>
</section>
<section aria-label="Apply or cancel">
  <form method="post" action="/admin/tenancy/users/{uid}/tokens/new">
    <input type="hidden" name="role" value="{role_value}">
    <input type="hidden" name="name" value="{name}">
    <input type="hidden" name="confirm" value="yes">
    <p>
      <button type="submit" class="critical">Apply mint</button>
      <a href="/admin/tenancy/users/{uid}/role_assignments">Cancel</a>
    </p>
  </form>
</section>"##,
        uid        = escape(&input.subject_user.id),
        uname      = escape(user_label),
        tid        = escape(&input.subject_user.tenant_id),
        role       = role_label(input.role),
        role_value = role_value(input.role),
        name       = escape(input.name),
    );
    tenancy_console_frame(&title, principal.role, principal.name.as_deref(),
                          TenancyConsoleTab::UserRoleAssignments, &body)
}

/// Apply page — shown once after the mint succeeds. Carries the
/// plaintext token (which the caller must copy now). Refresh
/// loses it.
pub fn applied_page(
    principal:    &AdminPrincipal,
    subject_user: &User,
    tenant_slug:  &str,
    role:         AdminRole,
    plaintext:    &str,
) -> String {
    let user_label = subject_user.display_name.as_deref()
        .unwrap_or(&subject_user.id);
    let title = format!("Token minted for: {}", user_label);
    let body = format!(
        r##"<section aria-label="Result" class="ok">
  <h3>Mint succeeded</h3>
  <p>The user-bound admin token below grants its bearer
     <code>{role}</code> affordances at this user's tenant.
     <strong>Copy it now</strong> — cesauth stores only its hash;
     refreshing this page loses the plaintext for good.</p>
  <p>
    <code style="display: block; padding: 12px; background: #f5f5f5; word-break: break-all;">{token}</code>
  </p>
  <p class="muted">Hand it to the tenant admin via a secure channel.
     They present it as <code>Authorization: Bearer &lt;token&gt;</code>
     at <code>/admin/t/{tslug}/...</code>.</p>
  <p>
    <a href="/admin/tenancy/users/{uid}/role_assignments">Done — back to user's role assignments</a>
  </p>
</section>"##,
        token  = escape(plaintext),
        role   = role_label(role),
        uid    = escape(&subject_user.id),
        tslug  = escape(tenant_slug),
    );
    tenancy_console_frame(&title, principal.role, principal.name.as_deref(),
                          TenancyConsoleTab::UserRoleAssignments, &body)
}

fn render_error(e: Option<&str>) -> String {
    match e {
        None    => String::new(),
        Some(m) => format!(
            r#"<section aria-label="Error"><p role="status" class="critical"><span class="badge critical">error</span> {m}</p></section>"#,
            m = escape(m),
        ),
    }
}

fn role_label(r: AdminRole) -> &'static str {
    match r {
        AdminRole::ReadOnly   => "read_only",
        AdminRole::Security   => "security",
        AdminRole::Operations => "operations",
        AdminRole::Super      => "super",
    }
}

fn role_value(r: AdminRole) -> &'static str { role_label(r) }
