//! `GET /admin/tenancy/tenants/new` — create-tenant form.
//!
//! One-click submit (no preview): creating a new tenant is additive
//! and isolated. The destructive operations are status changes,
//! which have their own preview/confirm flow.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::routes::tenancy_console as routes;
use cesauth_core::tenancy::service::OwnerHomeOutcome;

use super::super::frame::{tenancy_console_frame, TenancyConsoleTab};

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
        back  = format!(
            r##"<p><a href="{url}">← Back to tenants list</a></p>"##,
            url = routes::TENANTS,
        ),
        error = render_error(error),
        form  = render_form(slug, display_name, owner_user_id),
        help  = render_help(),
    );
    tenancy_console_frame("New tenant", principal.role, principal.name.as_deref(), TenancyConsoleTab::Tenants, &body)
}

/// **RFC 158 §5.6.** The tenant was created — `Assigned` still redirects
/// straight to the tenant detail page, same as before this RFC — but
/// `KeptExistingHome` and `Failed` render this page instead, because a
/// `303` to an ordinary-looking success page is exactly how the gap
/// this RFC closed stayed invisible for as long as it did: the operator
/// who just named an owner has no other way to learn that owner cannot
/// open the console they were just given.
///
/// Must not be called with `Assigned` — there is nothing for this page
/// to say in that case, and the caller still redirects for it.
pub fn tenant_created_owner_home_notice(
    principal:     &AdminPrincipal,
    tenant_id:     &str,
    tenant_slug:   &str,
    owner_user_id: &str,
    owner_home:    OwnerHomeOutcome,
) -> String {
    let explanation = match owner_home {
        OwnerHomeOutcome::KeptExistingHome => format!(
            "The owner (<code>{owner}</code>) already administers a different \
             tenant. Moving their home tenant here would have taken away their \
             access to that tenant, so it was left alone.",
            owner = escape(owner_user_id),
        ),
        OwnerHomeOutcome::Failed => format!(
            "The owner's (<code>{owner}</code>) home tenant could not be \
             assigned — a storage error, recorded in the audit log and the \
             server log.",
            owner = escape(owner_user_id),
        ),
        OwnerHomeOutcome::Assigned => unreachable!(
            "tenant_created_owner_home_notice must not be called for Assigned — \
             that outcome still redirects"
        ),
    };
    let body = format!(
        r#"<section aria-label="Tenant created">
  <p role="status"><span class="badge ok">created</span> Tenant <code>{slug}</code> was created.</p>
  <p>{explanation}</p>
  <p><strong>As a result, <code>{owner}</code> cannot open this tenant's
     console yet.</strong></p>
  <p><a href="{detail_url}">Continue to the tenant detail page →</a></p>
</section>"#,
        slug        = escape(tenant_slug),
        explanation = explanation,
        owner       = escape(owner_user_id),
        detail_url  = routes::tenant(tenant_id),
    );
    tenancy_console_frame("Tenant created", principal.role, principal.name.as_deref(), TenancyConsoleTab::Tenants, &body)
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
  <form method="post" action="{action_url}">
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
        action_url = routes::TENANTS_NEW,
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
        AdminPrincipal { id: "x".into(), name: None,role: Role::Operations, user_id: None }
    }

    #[test]
    fn form_is_post_to_new_endpoint() {
        let html = tenant_create_form(&p(), "", "", "", None);
        assert!(html.contains(r#"action="/admin/tenancy/tenants/new""#));
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

    // ── RFC 158 §5.6: tenant_created_owner_home_notice ───────────────────

    #[test]
    fn kept_existing_home_notice_says_created_and_explains_why() {
        let html = tenant_created_owner_home_notice(
            &p(), "t-1", "acme", "u-owner", OwnerHomeOutcome::KeptExistingHome,
        );
        assert!(html.contains("was created"), "must say the tenant was created");
        assert!(html.contains("already administers a different"),
            "must explain why the home was left alone");
        assert!(html.contains("cannot open this tenant's"),
            "must say the owner cannot open the console");
        assert!(html.contains(r#"href="/admin/tenancy/tenants/t-1""#),
            "must link on to the tenant detail page");
    }

    #[test]
    fn failed_notice_says_created_and_names_a_storage_error() {
        let html = tenant_created_owner_home_notice(
            &p(), "t-2", "beta", "u-owner", OwnerHomeOutcome::Failed,
        );
        assert!(html.contains("was created"));
        assert!(html.contains("storage error"));
        assert!(html.contains("cannot open this tenant's"));
        assert!(html.contains(r#"href="/admin/tenancy/tenants/t-2""#));
    }

    #[test]
    #[should_panic(expected = "must not be called for Assigned")]
    fn notice_panics_if_called_for_assigned() {
        tenant_created_owner_home_notice(&p(), "t-3", "gamma", "u-owner", OwnerHomeOutcome::Assigned);
    }

    #[test]
    fn notice_escapes_a_hostile_owner_user_id() {
        let html = tenant_created_owner_home_notice(
            &p(), "t-1", "acme", "<script>alert(1)</script>", OwnerHomeOutcome::KeptExistingHome,
        );
        assert!(!html.contains("<script>"), "owner_user_id must be escaped");
        assert!(html.contains("&lt;script&gt;"));
    }
}
