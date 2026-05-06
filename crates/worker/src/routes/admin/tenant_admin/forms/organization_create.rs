//! `GET/POST /admin/t/:slug/organizations/new` —
//! tenant-scoped organization create. One-click submit (additive).

use cesauth_cf::tenancy::{CloudflareOrganizationRepository, CloudflareTenantRepository};
use cesauth_core::authz::types::{PermissionCatalog, ScopeRef};
use cesauth_core::tenancy::service::create_organization;
use cesauth_ui::tenant_admin::forms::organization_create::organization_create_form;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{parse_form, redirect_303};
use crate::routes::admin::tenant_admin::gate;
use crate::routes::api_v1::quota;

pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(resp),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)     => c,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = gate::check_action(
        &ctx_ta,
        PermissionCatalog::ORGANIZATION_CREATE,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id },
        &ctx,
    ).await? { return Ok(resp); }

    render::html_response(organization_create_form(
        &ctx_ta.principal, &ctx_ta.tenant, "", "", None,
    ))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(resp),
    };
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)     => c,
        Err(resp) => return Ok(resp),
    };
    if let Err(resp) = gate::check_action(
        &ctx_ta,
        PermissionCatalog::ORGANIZATION_CREATE,
        ScopeRef::Tenant { tenant_id: &ctx_ta.tenant.id },
        &ctx,
    ).await? { return Ok(resp); }

    let form = parse_form(&mut req).await?;
    let slug         = form.get("slug").cloned().unwrap_or_default();
    let display_name = form.get("display_name").cloned().unwrap_or_default();

    if slug.trim().is_empty() || display_name.trim().is_empty() {
        return render::html_response(organization_create_form(
            &ctx_ta.principal, &ctx_ta.tenant, &slug, &display_name,
            Some("Slug and display name are required"),
        ));
    }

    // Plan-quota: max_organizations. Same enforcement as the
    // system-admin path.
    let current = quota::count_organizations(&ctx.env, &ctx_ta.tenant.id).await.unwrap_or(0);
    let outcome = match quota::check_quota(&ctx.env, &ctx_ta.tenant.id, "max_organizations", current).await {
        Ok(o)  => o,
        Err(_) => return Response::error("storage error", 500),
    };
    if quota::into_response_if_exceeded(outcome).is_some() {
        return render::html_response(organization_create_form(
            &ctx_ta.principal, &ctx_ta.tenant, &slug, &display_name,
            Some("Quota exceeded — this tenant's plan does not allow more organizations"),
        ));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let orgs    = CloudflareOrganizationRepository::new(&ctx.env);
    let org = match create_organization(&tenants, &orgs, &ctx_ta.tenant.id, &slug, &display_name, now).await {
        Ok(o)  => o,
        Err(e) => {
            let msg = match e {
                cesauth_core::ports::PortError::Conflict
                    => "Slug already taken in this tenant".to_owned(),
                cesauth_core::ports::PortError::PreconditionFailed(m)
                    => m.to_owned(),
                _ => "Storage error".to_owned(),
            };
            return render::html_response(organization_create_form(
                &ctx_ta.principal, &ctx_ta.tenant, &slug, &display_name, Some(&msg),
            ));
        }
    };

    // via=tenant-admin marks the audit entry as coming from the
    // tenant-scoped surface — distinct from via=tenancy-console
    // (system-admin) so log analyses can split by surface origin.
    audit::write_owned(
        &ctx.env, EventKind::OrganizationCreated,
        Some(ctx_ta.principal.id.clone()), Some(org.id.clone()),
        Some(format!("via=tenant-admin,tenant={},slug={}", ctx_ta.tenant.id, org.slug)),
    ).await.ok();

    redirect_303(&format!("/admin/t/{}/organizations/{}", ctx_ta.tenant.slug, org.id))
}
