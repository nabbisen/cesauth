//! `GET/POST /admin/tenancy/tenants/new` — tenant create form.

use cesauth_cf::tenancy::{CloudflareMembershipRepository, CloudflareTenantRepository};
use cesauth_core::tenancy::ports::NewTenantInput;
use cesauth_core::tenancy::service::create_tenant;
use cesauth_core::tenancy::types::TenantMembershipRole;
use cesauth_frontend::tenancy_console::forms::tenant_create::tenant_create_form;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{parse_form, redirect_303, require_manage};

/// **RFC 145 cycle 3 / §2.** Used to return the Leptos shell with no
/// `app.rs` route of its own — but this one didn't render `<NotFound/>`.
/// `path!("/admin/tenancy/tenants/:tid")` captured the literal `new`,
/// so a system admin landed on the tenant-detail page for a tenant
/// whose id is the string `"new"`: a different, plausible-looking page,
/// not an absence. Wiring this GET to the real form removes the
/// symptom (the client router never sees this path once the server
/// renders it first), but the shadow in `app.rs` stays latent — see
/// the cycle report for why that is §3's gate to catch, not this fix.
pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    render::html_response(|| tenant_create_form(&principal, "", "", "", None))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let form = parse_form(&mut req).await?;
    let slug          = form.get("slug").cloned().unwrap_or_default();
    let display_name  = form.get("display_name").cloned().unwrap_or_default();
    let owner_user_id = form.get("owner_user_id").cloned().unwrap_or_default();

    if slug.trim().is_empty() || display_name.trim().is_empty() || owner_user_id.trim().is_empty() {
        return render::html_response(|| tenant_create_form(
            &principal, &slug, &display_name, &owner_user_id,
            Some("All fields are required"),
        ));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let members = CloudflareMembershipRepository::new(&ctx.env);

    let tenant = match create_tenant(&tenants, &members, &NewTenantInput {
        slug:          &slug,
        display_name:  &display_name,
        owner_user_id: &owner_user_id,
        owner_role:    TenantMembershipRole::Owner,
    }, now).await {
        Ok(t) => t,
        Err(e) => {
            // Re-render with the operator-visible reason. Conflict
            // = slug already taken (most common); other variants
            // surface as a generic message.
            let msg = match e {
                cesauth_core::ports::PortError::Conflict
                    => "Slug already taken in this deployment".to_owned(),
                cesauth_core::ports::PortError::PreconditionFailed(m)
                    => m.to_owned(),
                cesauth_core::ports::PortError::NotFound
                    => "Owner user id not found".to_owned(),
                _ => "Storage error".to_owned(),
            };
            return render::html_response(|| tenant_create_form(
                &principal, &slug, &display_name, &owner_user_id, Some(&msg),
            ));
        }
    };

    audit::write_owned(
        &ctx.env, EventKind::TenantCreated,
        Some(principal.id.clone()), Some(tenant.id.clone()),
        Some(format!("via=tenancy-console,slug={}", tenant.slug)),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/tenants/{}", tenant.id))
}
