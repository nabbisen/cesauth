//! Tenant status change form with preview/confirm.
//!
//! Two phases:
//!
//! 1. **Form** — `GET /admin/saas/tenants/:tid/status` shows
//!    radio buttons for the target status (active / suspended /
//!    deleted) and a free-text reason. Submitting POSTs to the
//!    same URL.
//!
//! 2. **Confirm** — the POST handler (without `confirm=yes`) renders
//!    the same page with a diff banner ("change FROM `active` TO
//!    `suspended` because <reason>") and an Apply button. The
//!    Apply button POSTs again with `confirm=yes`, which commits.
//!
//! The confirm step is mandatory because status changes affect every
//! user in the tenant and the v0.4.2 audit trail records who made
//! the change. We want operators to read what they're about to do
//! before they click.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::{Tenant, TenantStatus};

use super::super::frame::{saas_frame, SaasTab};
use super::super::tenants::render_status_badge;

/// Stage 1: empty form. `reason_default` lets us pre-fill on
/// re-render after a validation error.
pub fn form_page(
    principal:      &AdminPrincipal,
    tenant:         &Tenant,
    selected_status: Option<TenantStatus>,
    reason_default: &str,
    error:          Option<&str>,
) -> String {
    let title = format!("Tenant status: {}", tenant.slug);
    let body = format!(
        "{back}\n{summary}\n{error}\n{form}",
        back    = back_link(&tenant.id),
        summary = render_summary(tenant),
        error   = render_error(error),
        form    = render_form(tenant, selected_status, reason_default),
    );
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

/// Stage 2: confirm page after the operator picked a target.
pub fn confirm_page(
    principal:   &AdminPrincipal,
    tenant:      &Tenant,
    target:      TenantStatus,
    reason:      &str,
) -> String {
    let title = format!("Confirm tenant status: {}", tenant.slug);
    let body = format!(
        "{back}\n{diff}\n{apply}",
        back  = back_link(&tenant.id),
        diff  = render_diff(tenant, target, reason),
        apply = render_apply_form(&tenant.id, target, reason),
    );
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

// -------------------------------------------------------------------------
// Fragments
// -------------------------------------------------------------------------

fn back_link(tenant_id: &str) -> String {
    format!(
        r#"<p><a href="/admin/saas/tenants/{id}">← Back to tenant detail</a></p>"#,
        id = escape(tenant_id),
    )
}

fn render_summary(t: &Tenant) -> String {
    format!(
        r##"<section aria-label="Tenant">
  <table>
    <tbody>
      <tr><th scope="row">Slug</th><td><code>{slug}</code></td></tr>
      <tr><th scope="row">Current status</th><td>{badge}</td></tr>
    </tbody>
  </table>
</section>"##,
        slug  = escape(&t.slug),
        badge = render_status_badge(t.status),
    )
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

fn render_form(t: &Tenant, selected: Option<TenantStatus>, reason: &str) -> String {
    let s = selected.unwrap_or(t.status);
    format!(
        r##"<section aria-label="Status change form">
  <form method="post" action="/admin/saas/tenants/{tid}/status">
    <fieldset>
      <legend>Target status</legend>
      <p>{ra} <label for="s_active">    <code>active</code> — visible and usable</label></p>
      <p>{rs} <label for="s_suspended"> <code>suspended</code> — preserves data; sign-ins refused</label></p>
      <p>{rd} <label for="s_deleted">   <code>deleted</code> — soft delete; row preserved for audit/recovery</label></p>
    </fieldset>
    <p>
      <label for="reason">Reason (recorded in audit log)</label><br>
      <input id="reason" name="reason" type="text" required maxlength="200" value="{reason}" style="width: 30em;">
    </p>
    <p><button type="submit">Preview change</button></p>
  </form>
</section>"##,
        tid    = escape(&t.id),
        reason = escape(reason),
        ra = radio("status", "active",    s == TenantStatus::Active,    "s_active"),
        rs = radio("status", "suspended", s == TenantStatus::Suspended, "s_suspended"),
        rd = radio("status", "deleted",   s == TenantStatus::Deleted,   "s_deleted"),
    )
}

fn radio(name: &str, value: &str, checked: bool, id: &str) -> String {
    let c = if checked { " checked" } else { "" };
    format!(
        r#"<input type="radio" id="{id}" name="{name}" value="{value}"{c}>"#
    )
}

fn render_diff(t: &Tenant, target: TenantStatus, reason: &str) -> String {
    let same = t.status == target;
    let warning = if same {
        r##"<p class="muted">No change — current and target status are the same. Submitting will be a no-op.</p>"##.to_owned()
    } else {
        match target {
            TenantStatus::Active    => String::new(),
            TenantStatus::Suspended => r##"<p role="status" class="critical"><span class="badge warn">caution</span> Suspending the tenant <strong>refuses sign-ins</strong> for every user in this tenant. Existing sessions remain until they expire on their own.</p>"##.to_owned(),
            TenantStatus::Deleted   => r##"<p role="status" class="critical"><span class="badge critical">danger</span> Soft-deleting the tenant hides it from the active list. Data is preserved but the tenant becomes unreachable through normal flows. Recovery requires manual SQL.</p>"##.to_owned(),
            TenantStatus::Pending   => String::new(),
        }
    };
    format!(
        r##"<section aria-label="Diff">
  <h2>Change to apply</h2>
  <table>
    <tbody>
      <tr><th scope="row">Tenant</th>          <td><code>{slug}</code></td></tr>
      <tr><th scope="row">Status (current)</th><td>{from_badge}</td></tr>
      <tr><th scope="row">Status (target)</th> <td>{to_badge}</td></tr>
      <tr><th scope="row">Reason</th>          <td>{reason}</td></tr>
    </tbody>
  </table>
  {warning}
</section>"##,
        slug       = escape(&t.slug),
        from_badge = render_status_badge(t.status),
        to_badge   = render_status_badge(target),
        reason     = escape(reason),
    )
}

fn render_apply_form(tenant_id: &str, target: TenantStatus, reason: &str) -> String {
    let target_str = match target {
        TenantStatus::Active    => "active",
        TenantStatus::Suspended => "suspended",
        TenantStatus::Deleted   => "deleted",
        TenantStatus::Pending   => "pending",
    };
    format!(
        r##"<section aria-label="Apply">
  <form class="danger" method="post" action="/admin/saas/tenants/{tid}/status">
    <input type="hidden" name="status" value="{target}">
    <input type="hidden" name="reason" value="{reason}">
    <input type="hidden" name="confirm" value="yes">
    <p><button type="submit">Apply change</button></p>
  </form>
</section>"##,
        tid    = escape(tenant_id),
        target = target_str,
        reason = escape(reason),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;
    use cesauth_core::tenancy::types::{Tenant, TenantStatus};

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None, role: Role::Operations }
    }
    fn t() -> Tenant {
        Tenant {
            id: "t-acme".into(), slug: "acme".into(),
            display_name: "Acme Corp".into(),
            status: TenantStatus::Active, created_at: 0, updated_at: 0,
        }
    }

    #[test]
    fn form_renders_three_target_options() {
        let html = form_page(&p(), &t(), None, "", None);
        assert!(html.contains(r#"value="active""#));
        assert!(html.contains(r#"value="suspended""#));
        assert!(html.contains(r#"value="deleted""#));
    }

    #[test]
    fn confirm_page_warns_on_suspend() {
        let html = confirm_page(&p(), &t(), TenantStatus::Suspended, "policy violation");
        assert!(html.contains("refuses sign-ins"));
        assert!(html.contains("policy violation"));
        assert!(html.contains(r#"value="confirm" value="yes""#) ||
                html.contains(r#"name="confirm" value="yes""#),
            "apply form must carry confirm=yes hidden field");
    }

    #[test]
    fn confirm_page_warns_on_delete() {
        let html = confirm_page(&p(), &t(), TenantStatus::Deleted, "wind-down");
        assert!(html.contains("Soft-deleting"));
        assert!(html.contains("Recovery requires manual SQL"));
    }

    #[test]
    fn confirm_page_no_op_on_same_status() {
        // Operator picks "active" while current is already "active":
        // the page must render a "no change" notice rather than
        // imply something destructive will happen.
        let html = confirm_page(&p(), &t(), TenantStatus::Active, "x");
        assert!(html.contains("No change"));
    }

    #[test]
    fn reason_is_html_escaped_on_confirm_page() {
        let html = confirm_page(&p(), &t(), TenantStatus::Suspended, "<b>bad</b>");
        assert!(!html.contains("<b>bad</b>"),
            "raw HTML in reason must be escaped");
        assert!(html.contains("&lt;b&gt;bad&lt;/b&gt;"));
    }
}
