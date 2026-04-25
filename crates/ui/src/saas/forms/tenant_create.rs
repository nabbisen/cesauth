//! `GET /admin/saas/tenants/new` — create-tenant form.
//!
//! One-click submit (no preview): creating a new tenant is additive
//! and isolated. The destructive operations are status changes,
//! which have their own preview/confirm flow.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;

use super::super::frame::{saas_frame, SaasTab};

/// Render the form. `error` is set on a re-render after a failed
/// submit (validation, slug collision, unknown owner_user_id) so the
/// operator sees what went wrong without losing their inputs.
///
/// Sticky values (`slug`, `display_name`, `owner_user_id`) are
/// preserved across the re-render so the operator only fixes the
/// failed field.
pub fn tenant_create_form(
    principal:     &AdminPrincipal,
    slug:          &str,
    display_name:  &str,
    owner_user_id: &str,
    error:         Option<&str>,
) -> String {
    let body = format!(
        "{back}\n{error}\n{form}\n{help}",
        back  = r##"<p><a href="/admin/saas/tenants">← Back to tenants list</a></p>"##,
        error = render_error(error),
        form  = render_form(slug, display_name, owner_user_id),
        help  = render_help(),
    );
    saas_frame("New tenant", principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

fn render_error(error: Option<&str>) -> String {
    match error {
        None => String::new(),
        Some(msg) => format!(
            r#"<section aria-label="Error">
  <p role="status" class="critical"><span class="badge critical">error</span> {msg}</p>
</section>"#,
            msg = escape(msg),
        ),
    }
}

fn render_form(slug: &str, display_name: &str, owner_user_id: &str) -> String {
    format!(
        r##"<section aria-label="New tenant form">
  <form method="post" action="/admin/saas/tenants/new">
    <table>
      <tbody>
        <tr>
          <th scope="row"><label for="slug">Slug</label></th>
          <td><input id="slug" name="slug" type="text" required pattern="[a-z0-9][a-z0-9-]*" value="{slug}"></td>
        </tr>
        <tr>
          <th scope="row"><label for="display_name">Display name</label></th>
          <td><input id="display_name" name="display_name" type="text" required value="{name}"></td>
        </tr>
        <tr>
          <th scope="row"><label for="owner_user_id">Owner user id</label></th>
          <td><input id="owner_user_id" name="owner_user_id" type="text" required value="{owner}"></td>
        </tr>
      </tbody>
    </table>
    <p><button type="submit">Create tenant</button></p>
  </form>
</section>"##,
        slug  = escape(slug),
        name  = escape(display_name),
        owner = escape(owner_user_id),
    )
}

fn render_help() -> String {
    r##"<section aria-label="Help" class="muted">
  <h3>Notes</h3>
  <ul>
    <li>Slug must be lowercase letters, digits, and hyphens. It cannot be changed later.</li>
    <li>The owner user id must already exist in <code>users</code>. The
        operator-driven create flow does not auto-provision users.</li>
    <li>The new tenant starts in <code>active</code> status with the
        owner as a single tenant member with role <code>owner</code>.
        It has no subscription on file; provision one with
        <code>POST /api/v1/tenants/:tid/subscription</code> if you
        need plan-quota enforcement.</li>
  </ul>
</section>"##.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None, role: Role::Operations }
    }

    #[test]
    fn form_is_post_to_new_endpoint() {
        let html = tenant_create_form(&p(), "", "", "", None);
        assert!(html.contains(r#"action="/admin/saas/tenants/new""#));
        assert!(html.contains(r#"method="post""#));
    }

    #[test]
    fn form_preserves_sticky_values_on_rerender() {
        let html = tenant_create_form(&p(), "acme", "Acme Corp", "u-alice", None);
        assert!(html.contains(r#"value="acme""#));
        assert!(html.contains(r#"value="Acme Corp""#));
        assert!(html.contains(r#"value="u-alice""#));
    }

    #[test]
    fn error_renders_above_form_when_present() {
        let html = tenant_create_form(&p(), "x", "", "", Some("slug already taken"));
        // Error section appears before the form section.
        let pos_error = html.find("slug already taken").expect("error message visible");
        let pos_form  = html.find(r#"<form method="post""#).expect("form rendered");
        assert!(pos_error < pos_form, "error must render above form, got error@{pos_error} form@{pos_form}");
    }

    #[test]
    fn untrusted_input_is_html_escaped() {
        // Display name is operator-supplied; a hostile re-render
        // payload must not break out into HTML.
        let html = tenant_create_form(&p(), "x", "<script>alert(1)</script>", "u", None);
        assert!(!html.contains("<script>"), "display_name must be escaped");
        assert!(html.contains("&lt;script&gt;"));
    }
}
