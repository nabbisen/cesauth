//! `GET/POST /admin/saas/tenants/:tid/organizations/new` — organization create.

use cesauth_cf::tenancy::{CloudflareOrganizationRepository, CloudflareTenantRepository};
use cesauth_core::tenancy::ports::TenantRepository;
use cesauth_core::tenancy::service::create_organization;
use cesauth_ui::saas::forms::organization_create::organization_create_form;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::saas::forms::common::{parse_form, redirect_303, require_manage};
use crate::routes::api_v1::quota;

pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid") else { return Response::error("not found", 404); };
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant = match tenants.get(tid).await {
        Ok(Some(t)) => t,
        Ok(None)    => return Response::error("not found", 404),
        Err(_)      => return Response::error("storage error", 500),
    };
    render::html_response(organization_create_form(&principal, &tenant, "", "", None))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
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
        Ok(Some(t)) => t,
        Ok(None)    => return Response::error("not found", 404),
        Err(_)      => return Response::error("storage error", 500),
    };

    if slug.trim().is_empty() || display_name.trim().is_empty() {
        return render::html_response(organization_create_form(
            &principal, &tenant, &slug, &display_name,
            Some("Slug and display name are required"),
        ));
    }

    // Plan-quota: max_organizations.
    let current = quota::count_organizations(&ctx.env, &tid).await.unwrap_or(0);
    let outcome = match quota::check_quota(&ctx.env, &tid, "max_organizations", current).await {
        Ok(o)  => o,
        Err(_) => return Response::error("storage error", 500),
    };
    if let Some(_) = quota::into_response_if_exceeded(outcome) {
        return render::html_response(organization_create_form(
            &principal, &tenant, &slug, &display_name,
            Some("Quota exceeded — this tenant's plan does not allow more organizations"),
        ));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let orgs = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match create_organization(&tenants, &orgs, &tid, &slug, &display_name, now).await {
        Ok(o) => o,
        Err(e) => {
            let msg = match e {
                cesauth_core::ports::PortError::Conflict
                    => "Slug already taken in this tenant".to_owned(),
                cesauth_core::ports::PortError::PreconditionFailed(m)
                    => m.to_owned(),
                _ => "Storage error".to_owned(),
            };
            return render::html_response(organization_create_form(
                &principal, &tenant, &slug, &display_name, Some(&msg),
            ));
        }
    };

    audit::write_owned(
        &ctx.env, EventKind::OrganizationCreated,
        Some(principal.id.clone()), Some(org.id.clone()),
        Some(format!("via=saas-console,tenant={tid},slug={}", org.slug)),
    ).await.ok();

    redirect_303(&format!("/admin/saas/organizations/{}", org.id))
}
