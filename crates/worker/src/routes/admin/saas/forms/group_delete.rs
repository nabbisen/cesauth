//! `GET/POST /admin/saas/groups/:gid/delete` — group soft delete.

use cesauth_cf::tenancy::CloudflareGroupRepository;
use cesauth_core::tenancy::ports::GroupRepository;
use cesauth_ui::saas::forms::group_delete::confirm_page;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::saas::forms::common::{
    confirmed, parse_form, redirect_303, require_manage,
};
use cesauth_core::tenancy::types::GroupParent;

pub async fn confirm<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(gid) = ctx.param("gid") else { return Response::error("not found", 404); };
    let groups = CloudflareGroupRepository::new(&ctx.env);
    let group = match groups.get(gid).await {
        Ok(Some(g)) => g, _ => return Response::error("not found", 404),
    };
    render::html_response(confirm_page(&principal, &group))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(gid) = ctx.param("gid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };

    let form = parse_form(&mut req).await?;
    if !confirmed(&form) {
        // No confirm field; bounce back to the confirm page.
        let groups = CloudflareGroupRepository::new(&ctx.env);
        let group = match groups.get(&gid).await {
            Ok(Some(g)) => g, _ => return Response::error("not found", 404),
        };
        return render::html_response(confirm_page(&principal, &group));
    }

    let groups = CloudflareGroupRepository::new(&ctx.env);
    let group = match groups.get(&gid).await {
        Ok(Some(g)) => g, _ => return Response::error("not found", 404),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = groups.delete(&gid, now).await {
        worker::console_error!("group delete failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::GroupDeleted,
        Some(principal.id.clone()), Some(gid.clone()),
        Some(format!("via=saas-console,slug={}", group.slug)),
    ).await.ok();

    // Bounce back to whichever parent the group lived under.
    match group.parent {
        GroupParent::Tenant =>
            redirect_303(&format!("/admin/saas/tenants/{}", group.tenant_id)),
        GroupParent::Organization { organization_id } =>
            redirect_303(&format!("/admin/saas/organizations/{organization_id}")),
    }
}
