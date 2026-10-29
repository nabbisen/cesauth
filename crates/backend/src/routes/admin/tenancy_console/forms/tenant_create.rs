//! `GET/POST /admin/tenancy/tenants/new` — tenant create form.

use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_cf::tenancy::{CloudflareMembershipRepository, CloudflareTenantRepository};
use cesauth_core::tenancy::ports::NewTenantInput;
use cesauth_core::tenancy::service::{create_tenant, OwnerHomeOutcome};
use cesauth_core::tenancy::types::TenantMembershipRole;
use cesauth_frontend::tenancy_console::forms::tenant_create::{tenant_create_form, tenant_created_owner_home_notice};
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::log::{self, Category, Level};
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
    let users = CloudflareUserRepository::new(&ctx.env);

    let outcome = match create_tenant(&tenants, &members, &users, &NewTenantInput {
        slug:          &slug,
        display_name:  &display_name,
        owner_user_id: &owner_user_id,
        owner_role:    TenantMembershipRole::Owner,
    }, now).await {
        Ok(o) => o,
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
    let tenant = outcome.tenant;

    audit::write_owned(
        &ctx.env, EventKind::TenantCreated,
        Some(principal.id.clone()), Some(tenant.id.clone()),
        Some(audit::tenant_created_detail("via=tenancy-console,", &tenant.slug, outcome.owner_home)),
    ).await.ok();

    if outcome.owner_home == OwnerHomeOutcome::Assigned {
        audit::write_owned(
            &ctx.env, EventKind::UserTenantAssigned,
            Some(owner_user_id.clone()), Some(tenant.id.clone()),
            Some(format!("via=tenancy-console,tenant={}", tenant.id)),
        ).await.ok();
        // RFC 158 §5.6: Assigned is unchanged — straight to the tenant
        // detail page, exactly as before this RFC existed.
        return redirect_303(&format!("/admin/tenancy/tenants/{}", tenant.id));
    }

    if outcome.owner_home == OwnerHomeOutcome::Failed {
        // RFC 158: a failed owner-home assignment must be loud, not
        // just folded into the tenant_created detail above — an
        // operator scanning logs (not querying the audit table) must
        // also see that the new tenant's owner cannot reach its console.
        //
        // §5.7: do NOT propagate a config-load failure here with `?` —
        // the tenant and membership rows already exist by this point,
        // so a bad deployment variable must not turn "owner-home
        // assignment failed" into "tenant creation failed" with a 500.
        if let Ok(cfg) = Config::from_env(&ctx.env) {
            log::emit(&cfg.log, Level::Error, Category::Storage,
                &format!("tenant {}: owner-home assignment failed for user {owner_user_id}", tenant.id),
                Some(&owner_user_id));
        }
    }

    // RFC 158 §5.6: KeptExistingHome and Failed render a page instead of
    // redirecting — a 303 to an ordinary success page is how this RFC's
    // own gap stayed invisible: the operator who just named an owner has
    // no other way to learn that owner cannot open the console they were
    // just given.
    render::html_response(|| tenant_created_owner_home_notice(
        &principal, &tenant.id, &tenant.slug, &owner_user_id, outcome.owner_home,
    ))
}
