//! Group create form handlers. Two URL roots:
//! - `/admin/saas/tenants/:tid/groups/new`         → tenant-scoped group
//! - `/admin/saas/organizations/:oid/groups/new`   → org-scoped group

use cesauth_cf::tenancy::{
    CloudflareGroupRepository, CloudflareOrganizationRepository,
    CloudflareTenantRepository,
};
use cesauth_core::tenancy::ports::{NewGroupInput, OrganizationRepository, TenantRepository};
use cesauth_core::tenancy::service::create_group;
use cesauth_core::tenancy::types::GroupParent;
use cesauth_ui::saas::forms::group_create as ui;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::saas::forms::common::{parse_form, redirect_303, require_manage};
use crate::routes::api_v1::quota;

// -----------------------------------------------------------------
// Tenant-scoped
// -----------------------------------------------------------------

pub async fn form_tenant<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid") else { return Response::error("not found", 404); };
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(tid).await {
        Ok(Some(t)) => t, _ => return Response::error("not found", 404),
    };
    render::html_response(ui::for_tenant(&principal, &tenant.id, &tenant.slug, "", "", None))
}

pub async fn submit_tenant<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let form = parse_form(&mut req).await?;
    let slug         = form.get("slug").cloned().unwrap_or_default();
    let display_name = form.get("display_name").cloned().unwrap_or_default();

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(&tid).await {
        Ok(Some(t)) => t, _ => return Response::error("not found", 404),
    };

    if slug.trim().is_empty() || display_name.trim().is_empty() {
        return render::html_response(ui::for_tenant(
            &principal, &tenant.id, &tenant.slug, &slug, &display_name,
            Some("Slug and display name are required"),
        ));
    }

    let parent = GroupParent::Tenant;
    create_and_redirect(&ctx.env, &principal, &tid, parent, &slug, &display_name,
        |err| ui::for_tenant(&principal, &tenant.id, &tenant.slug, &slug, &display_name, Some(err)),
    ).await
}

// -----------------------------------------------------------------
// Organization-scoped
// -----------------------------------------------------------------

pub async fn form_org<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid") else { return Response::error("not found", 404); };
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(oid).await {
        Ok(Some(o)) => o, _ => return Response::error("not found", 404),
    };
    render::html_response(ui::for_organization(&principal, &org.id, &org.slug, "", "", None))
}

pub async fn submit_org<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let form = parse_form(&mut req).await?;
    let slug         = form.get("slug").cloned().unwrap_or_default();
    let display_name = form.get("display_name").cloned().unwrap_or_default();

    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(&oid).await {
        Ok(Some(o)) => o, _ => return Response::error("not found", 404),
    };

    if slug.trim().is_empty() || display_name.trim().is_empty() {
        return render::html_response(ui::for_organization(
            &principal, &org.id, &org.slug, &slug, &display_name,
            Some("Slug and display name are required"),
        ));
    }

    let parent = GroupParent::Organization { organization_id: org.id.clone() };
    create_and_redirect(&ctx.env, &principal, &org.tenant_id, parent, &slug, &display_name,
        |err| ui::for_organization(&principal, &org.id, &org.slug, &slug, &display_name, Some(err)),
    ).await
}

// -----------------------------------------------------------------

async fn create_and_redirect<F: FnOnce(&str) -> String>(
    env:           &worker::Env,
    principal:     &cesauth_core::admin::types::AdminPrincipal,
    tenant_id:     &str,
    parent:        GroupParent,
    slug:          &str,
    display_name:  &str,
    rerender:      F,
) -> Result<Response> {
    // Plan-quota: max_groups, counted across the whole tenant.
    let current = quota::count_groups(env, tenant_id).await.unwrap_or(0);
    let outcome = match quota::check_quota(env, tenant_id, "max_groups", current).await {
        Ok(o) => o, Err(_) => return Response::error("storage error", 500),
    };
    if let Some(_) = quota::into_response_if_exceeded(outcome) {
        return render::html_response(rerender(
            "Quota exceeded — this tenant's plan does not allow more groups",
        ));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let groups = CloudflareGroupRepository::new(env);
    let group = match create_group(&groups, &NewGroupInput {
        tenant_id, parent, slug, display_name,
    }, now).await {
        Ok(g) => g,
        Err(e) => {
            let msg = match e {
                cesauth_core::ports::PortError::Conflict
                    => "Slug already taken".to_owned(),
                cesauth_core::ports::PortError::PreconditionFailed(m)
                    => m.to_owned(),
                _ => "Storage error".to_owned(),
            };
            return render::html_response(rerender(&msg));
        }
    };

    audit::write_owned(
        env, EventKind::GroupCreated,
        Some(principal.id.clone()), Some(group.id.clone()),
        Some(format!("via=saas-console,tenant={tenant_id},slug={}", group.slug)),
    ).await.ok();

    // No /admin/saas/groups/:gid page exists; bounce back to the
    // owning tenant or org page (whichever the operator is closer to).
    match group.parent {
        GroupParent::Tenant => redirect_303(&format!("/admin/saas/tenants/{tenant_id}")),
        GroupParent::Organization { organization_id } =>
            redirect_303(&format!("/admin/saas/organizations/{organization_id}")),
    }
}
