//! Group create form handlers. Two URL roots:
//! - `/admin/tenancy/tenants/:tid/groups/new`         → tenant-scoped group
//! - `/admin/tenancy/organizations/:oid/groups/new`   → org-scoped group

use cesauth_cf::tenancy::{
    CloudflareGroupRepository, CloudflareOrganizationRepository,
    CloudflareTenantRepository,
};
use cesauth_core::tenancy::ports::{NewGroupInput, OrganizationRepository, TenantRepository};
use cesauth_core::tenancy::service::create_group;
use cesauth_core::tenancy::types::GroupParent;
use cesauth_frontend::tenancy_console::forms::group_create as ui;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{
    attach_csrf_cookie, mint_csrf, parse_form, redirect_303, require_manage, verify_csrf,
};
use crate::routes::api_v1::quota;

// -----------------------------------------------------------------
// Tenant-scoped
// -----------------------------------------------------------------

/// **RFC 145 cycle 3.** Used to return the Leptos shell with no
/// matching `app.rs` route — HTTP 200 rendering `<NotFound/>`.
pub async fn form_tenant<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(&tid).await {
        Ok(Some(t)) => t, _ => return Response::error("not found", 404),
    };
    let (csrf_token, csrf_cookie) = mint_csrf()?;
    let mut resp = render::html_response(|| ui::for_tenant(&principal, &tenant.id, &tenant.slug, "", "", None, &csrf_token))?;
    attach_csrf_cookie(&mut resp, &csrf_cookie);
    Ok(resp)
}

pub async fn submit_tenant<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = parse_form(&mut req).await?;
    if !verify_csrf(&form, &cookie_header) {
        return Response::error("Bad Request", 400);
    }
    let slug         = form.get("slug").cloned().unwrap_or_default();
    let display_name = form.get("display_name").cloned().unwrap_or_default();

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(&tid).await {
        Ok(Some(t)) => t, _ => return Response::error("not found", 404),
    };

    if slug.trim().is_empty() || display_name.trim().is_empty() {
        let (csrf_token, csrf_cookie) = mint_csrf()?;
        let mut resp = render::html_response(|| ui::for_tenant(
            &principal, &tenant.id, &tenant.slug, &slug, &display_name,
            Some("Slug and display name are required"), &csrf_token,
        ))?;
        attach_csrf_cookie(&mut resp, &csrf_cookie);
        return Ok(resp);
    }

    let parent = GroupParent::Tenant;
    create_and_redirect(&ctx.env, &principal, &tid, parent, &slug, &display_name,
        |err, csrf| ui::for_tenant(&principal, &tenant.id, &tenant.slug, &slug, &display_name, Some(err), csrf),
    ).await
}

// -----------------------------------------------------------------
// Organization-scoped
// -----------------------------------------------------------------

/// **RFC 145 cycle 3.** Used to return the Leptos shell with no
/// matching `app.rs` route — HTTP 200 rendering `<NotFound/>`.
pub async fn form_org<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(&oid).await {
        Ok(Some(o)) => o, _ => return Response::error("not found", 404),
    };
    let (csrf_token, csrf_cookie) = mint_csrf()?;
    let mut resp = render::html_response(|| ui::for_organization(&principal, &org.id, &org.slug, "", "", None, &csrf_token))?;
    attach_csrf_cookie(&mut resp, &csrf_cookie);
    Ok(resp)
}

pub async fn submit_org<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(oid) = ctx.param("oid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = parse_form(&mut req).await?;
    if !verify_csrf(&form, &cookie_header) {
        return Response::error("Bad Request", 400);
    }
    let slug         = form.get("slug").cloned().unwrap_or_default();
    let display_name = form.get("display_name").cloned().unwrap_or_default();

    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match orgs.get(&oid).await {
        Ok(Some(o)) => o, _ => return Response::error("not found", 404),
    };

    if slug.trim().is_empty() || display_name.trim().is_empty() {
        let (csrf_token, csrf_cookie) = mint_csrf()?;
        let mut resp = render::html_response(|| ui::for_organization(
            &principal, &org.id, &org.slug, &slug, &display_name,
            Some("Slug and display name are required"), &csrf_token,
        ))?;
        attach_csrf_cookie(&mut resp, &csrf_cookie);
        return Ok(resp);
    }

    let parent = GroupParent::Organization { organization_id: org.id.clone() };
    create_and_redirect(&ctx.env, &principal, &org.tenant_id, parent, &slug, &display_name,
        |err, csrf| ui::for_organization(&principal, &org.id, &org.slug, &slug, &display_name, Some(err), csrf),
    ).await
}

// -----------------------------------------------------------------

/// `rerender` takes `(error, csrf)` — a fresh token is minted here,
/// right before each re-render, because the one the caller already
/// verified is spent.
async fn create_and_redirect<F: Fn(&str, &str) -> String>(
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
        let (csrf_token, csrf_cookie) = mint_csrf()?;
        let mut resp = render::html_response(|| rerender(
            "Quota exceeded — this tenant's plan does not allow more groups", &csrf_token,
        ))?;
        attach_csrf_cookie(&mut resp, &csrf_cookie);
        return Ok(resp);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let groups = CloudflareGroupRepository::new(env);
    let group = match create_group(&groups, &NewGroupInput {
        tenant_id, parent, slug, display_name,
        organization_tenant_id: None,
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
            let (csrf_token, csrf_cookie) = mint_csrf()?;
            let mut resp = render::html_response(|| rerender(&msg, &csrf_token))?;
            attach_csrf_cookie(&mut resp, &csrf_cookie);
            return Ok(resp);
        }
    };

    audit::write_owned(
        env, EventKind::GroupCreated,
        Some(principal.id.clone()), Some(group.id.clone()),
        Some(format!("via=tenancy-console,tenant={tenant_id},slug={}", group.slug)),
    ).await.ok();

    // No /admin/tenancy/groups/:gid page exists; bounce back to the
    // owning tenant or org page (whichever the operator is closer to).
    match group.parent {
        GroupParent::Tenant => redirect_303(&format!("/admin/tenancy/tenants/{tenant_id}")),
        GroupParent::Organization { organization_id } =>
            redirect_303(&format!("/admin/tenancy/organizations/{organization_id}")),
    }
}
