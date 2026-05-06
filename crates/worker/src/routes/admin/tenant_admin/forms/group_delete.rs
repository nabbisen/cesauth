//! `GET/POST /admin/t/:slug/groups/:gid/delete` —
//! tenant-scoped group delete. Preview/confirm.

use cesauth_cf::authz::CloudflareRoleAssignmentRepository;
use cesauth_cf::tenancy::{
    CloudflareGroupRepository, CloudflareMembershipRepository,
    CloudflareOrganizationRepository,
};
use cesauth_core::authz::ports::RoleAssignmentRepository;
use cesauth_core::authz::types::{PermissionCatalog, Scope, ScopeRef};
use cesauth_core::tenancy::ports::{GroupRepository, MembershipRepository, OrganizationRepository};
use cesauth_core::tenancy::types::{Group, GroupParent};
use cesauth_ui::tenant_admin::forms::group_delete::{form_page, preview_page};
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{confirmed, parse_form, redirect_303};
use crate::routes::admin::tenant_admin::gate;

async fn gate_and_load_group<D>(
    req: &Request,
    ctx: &RouteContext<D>,
) -> Result<std::result::Result<(cesauth_core::tenant_admin::TenantAdminContext, Group, String, String), Response>> {
    let principal = match auth::resolve_or_respond(req, &ctx.env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(Err(resp)),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, ctx).await? {
        Ok(c)     => c,
        Err(resp) => return Ok(Err(resp)),
    };
    if let Err(resp) = gate::check_action(
        &ctx_ta,
        PermissionCatalog::GROUP_DELETE,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id },
        ctx,
    ).await? {
        return Ok(Err(resp));
    }

    let gid = match ctx.param("gid") {
        Some(s) => s.clone(),
        None    => return Ok(Err(Response::error("missing group id", 400)?)),
    };
    let groups = CloudflareGroupRepository::new(&ctx.env);
    let group = match groups.get(&gid).await {
        Ok(Some(g)) => g,
        Ok(None)    => return Ok(Err(Response::error("group not found", 404)?)),
        Err(_)      => return Ok(Err(Response::error("storage error", 500)?)),
    };

    // Defense in depth: verify the group belongs to the user's
    // tenant. The `:gid` is a global identifier, not slug-scoped.
    let (org_id, org_slug) = match &group.parent {
        GroupParent::Tenant => {
            // Tenant-scoped group: tenant_id field on Group is the
            // anchor. We cross-check it directly.
            if group.tenant_id != ctx_ta.tenant.id {
                return Ok(Err(Response::error(
                    "group belongs to a different tenant", 403)?));
            }
            (String::new(), String::new())
        }
        GroupParent::Organization { organization_id } => {
            let orgs = CloudflareOrganizationRepository::new(&ctx.env);
            let org = match orgs.get(organization_id).await {
                Ok(Some(o)) => o,
                _ => return Ok(Err(Response::error("organization not found", 404)?)),
            };
            if org.tenant_id != ctx_ta.tenant.id {
                return Ok(Err(Response::error(
                    "group belongs to a different tenant", 403)?));
            }
            (org.id, org.slug)
        }
    };

    Ok(Ok((ctx_ta, group, org_id, org_slug)))
}

pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, group, org_id, org_slug) = match gate_and_load_group(&req, &ctx).await? {
        Ok(t)     => t,
        Err(resp) => return Ok(resp),
    };
    render::html_response(form_page(
        &ctx_ta.principal, &ctx_ta.tenant, &group, &org_slug, &org_id, "", None,
    ))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let (ctx_ta, group, org_id, org_slug) = match gate_and_load_group(&req, &ctx).await? {
        Ok(t)     => t,
        Err(resp) => return Ok(resp),
    };

    let form = parse_form(&mut req).await?;
    let reason = form.get("reason").cloned().unwrap_or_default();
    if reason.trim().is_empty() {
        return render::html_response(form_page(
            &ctx_ta.principal, &ctx_ta.tenant, &group, &org_slug, &org_id, "",
            Some("Reason is required"),
        ));
    }

    if !confirmed(&form) {
        // Count what would be affected. Best-effort: storage failure
        // here means we render with 0/0 — better than refusing the
        // preview. The actual delete is gated on the apply step.
        let assignments = CloudflareRoleAssignmentRepository::new(&ctx.env);
        let n_assignments = assignments
            .list_in_scope(&Scope::Group { group_id: group.id.clone() })
            .await.map(|v| v.len()).unwrap_or(0);
        let memberships = CloudflareMembershipRepository::new(&ctx.env);
        let n_memberships = memberships
            .list_group_members(&group.id)
            .await.map(|v| v.len()).unwrap_or(0);

        return render::html_response(preview_page(
            &ctx_ta.principal, &ctx_ta.tenant, &group, &org_id,
            &reason, n_assignments, n_memberships,
        ));
    }

    let groups_repo = CloudflareGroupRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = groups_repo.delete(&group.id, now).await {
        worker::console_error!("group delete failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::GroupDeleted,
        Some(ctx_ta.principal.id.clone()), Some(group.id.clone()),
        Some(format!("via=tenant-admin,tenant={},group={},reason={}",
            ctx_ta.tenant.id, group.slug, reason)),
    ).await.ok();

    let return_to = if org_id.is_empty() {
        format!("/admin/t/{}/organizations", ctx_ta.tenant.slug)
    } else {
        format!("/admin/t/{}/organizations/{}", ctx_ta.tenant.slug, org_id)
    };
    redirect_303(&return_to)
}
