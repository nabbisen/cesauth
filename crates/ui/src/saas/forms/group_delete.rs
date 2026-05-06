//! Group delete (soft) with confirm.
//!
//! Single-step confirm — there's no "preview" because there's no
//! data to preview, just a yes/no. We still show a confirm page
//! between the click and the commit because the operation is
//! destructive.

use crate::escape;
use cesauth_core::admin::types::AdminPrincipal;
use cesauth_core::tenancy::types::Group;

use super::super::frame::{saas_frame, SaasTab};

pub fn confirm_page(principal: &AdminPrincipal, group: &Group) -> String {
    let title = format!("Delete group: {}", group.slug);
    let body = format!(
        r##"<p><a href="javascript:history.back()">← Back</a></p>
<section aria-label="Delete confirmation">
  <h2>Delete this group?</h2>
  <table><tbody>
    <tr><th scope="row">Slug</th>        <td><code>{slug}</code></td></tr>
    <tr><th scope="row">Display name</th><td>{name}</td></tr>
    <tr><th scope="row">Tenant</th>      <td><code>{tid}</code></td></tr>
    <tr><th scope="row">Id</th>          <td><code>{id}</code></td></tr>
  </tbody></table>
  <p role="status" class="critical">
    <span class="badge critical">danger</span>
    Deleting marks the group as <code>deleted</code> and hides it from the active list. Existing memberships are preserved as rows but the group is unreachable through normal flows. Recovery requires manual SQL.
  </p>
</section>
<section aria-label="Apply">
  <form class="danger" method="post" action="/admin/saas/groups/{id}/delete">
    <input type="hidden" name="confirm" value="yes">
    <p><button type="submit">Delete group</button></p>
  </form>
</section>"##,
        slug = escape(&group.slug),
        name = escape(&group.display_name),
        tid  = escape(&group.tenant_id),
        id   = escape(&group.id),
    );
    saas_frame(&title, principal.role, principal.name.as_deref(), SaasTab::Tenants, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::admin::types::Role;
    use cesauth_core::tenancy::types::{Group, GroupParent, GroupStatus};

    fn p() -> AdminPrincipal {
        AdminPrincipal { id: "x".into(), name: None,role: Role::Operations, user_id: None }
    }
    fn g() -> Group {
        Group {
            id: "g-1".into(), tenant_id: "t".into(),
            parent: GroupParent::Tenant,
            slug: "all-staff".into(), display_name: "All staff".into(),
            status: GroupStatus::Active, parent_group_id: None,
            created_at: 0, updated_at: 0,
        }
    }

    #[test]
    fn confirm_page_carries_apply_form() {
        let html = confirm_page(&p(), &g());
        assert!(html.contains(r#"name="confirm" value="yes""#));
        assert!(html.contains(r#"action="/admin/saas/groups/g-1/delete""#));
    }

    #[test]
    fn confirm_page_warns_recovery_requires_sql() {
        let html = confirm_page(&p(), &g());
        assert!(html.contains("Recovery requires manual SQL"));
    }
}
