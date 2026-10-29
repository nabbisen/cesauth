//! `/api/v1/tenants/...` route handlers.

use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_cf::tenancy::{
    CloudflareMembershipRepository, CloudflareTenantRepository,
};
use cesauth_core::admin::types::AdminAction;
use cesauth_core::ports::PortError;
use cesauth_core::tenancy::ports::{NewTenantInput, TenantRepository};
use cesauth_core::tenancy::service::{create_tenant, OwnerHomeOutcome};
use cesauth_core::tenancy::types::{TenantMembershipRole, TenantStatus};
use serde::Deserialize;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::log::{self, Category, Level};
use crate::routes::api_v1::auth::{
    bad_request, json, not_found, port_error_response, require,
};

// -------------------------------------------------------------------------
// POST /api/v1/tenants
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateTenantBody {
    slug:          String,
    display_name:  String,
    /// The user who becomes the new tenant's owner. Required because
    /// the spec §8.1 forbids tenants without an owner. The user
    /// id MUST already exist in `users`; the API does not auto-
    /// create users.
    owner_user_id: String,
}

/// **RFC 158 §5.6.** Additive response shape, not a reshape: every
/// field `Tenant` already serializes stays at the top level
/// (`#[serde(flatten)]`), and `owner_home` is the one new sibling
/// field. A client reading `id` or `slug` today is unaffected. This is
/// a surface-contract change on a public route — `owner_home` is new
/// and callers that want it must start reading it; said here and in
/// the cycle report rather than left for someone to notice in a diff.
#[derive(serde::Serialize)]
struct CreateTenantResponse<'a> {
    #[serde(flatten)]
    tenant:     &'a cesauth_core::tenancy::types::Tenant,
    owner_home: &'static str,
}

pub async fn create<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let body: CreateTenantBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return bad_request("invalid_json"),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let members = CloudflareMembershipRepository::new(&ctx.env);
    let users = CloudflareUserRepository::new(&ctx.env);

    let outcome = match create_tenant(&tenants, &members, &users, &NewTenantInput {
        slug:          &body.slug,
        display_name:  &body.display_name,
        owner_user_id: &body.owner_user_id,
        owner_role:    TenantMembershipRole::Owner,
    }, now).await {
        Ok(o)  => o,
        // RFC 160 §4.7: this route has no path parameter, so a
        // `NotFound` out of `create_tenant` can only be the owner
        // reference — the tenant row is minted fresh by this same call,
        // never looked up. Naming the field beats the bare 404
        // `port_error_response` would otherwise return for a path that
        // itself exists.
        Err(PortError::NotFound) => return bad_request("owner_user_id not found"),
        Err(e) => return port_error_response(e),
    };
    let tenant = outcome.tenant;

    audit::write_owned(
        &ctx.env, EventKind::TenantCreated,
        Some(principal.id.clone()), Some(tenant.id.clone()),
        Some(audit::tenant_created_detail("", &tenant.slug, outcome.owner_home)),
    ).await.ok();

    if outcome.owner_home == OwnerHomeOutcome::Assigned {
        audit::write_owned(
            &ctx.env, EventKind::UserTenantAssigned,
            Some(body.owner_user_id.clone()), Some(tenant.id.clone()),
            Some(format!("tenant={}", tenant.id)),
        ).await.ok();
    } else if outcome.owner_home == OwnerHomeOutcome::Failed {
        // RFC 158: loud, not just in the audit detail — see the
        // console caller's identical handling.
        //
        // §5.7: do NOT propagate with `?` — the tenant and membership
        // rows already exist, so a config-load failure here must not
        // turn a successful creation into a 500.
        if let Ok(cfg) = Config::from_env(&ctx.env) {
            log::emit(&cfg.log, Level::Error, Category::Storage,
                &format!("tenant {}: owner-home assignment failed for user {}", tenant.id, body.owner_user_id),
                Some(&body.owner_user_id));
        }
    }

    json(201, &CreateTenantResponse { tenant: &tenant, owner_home: outcome.owner_home.as_str() })
}

// -------------------------------------------------------------------------
// GET /api/v1/tenants
// -------------------------------------------------------------------------

pub async fn list<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    match tenants.list_active().await {
        Ok(rows) => json(200, &rows),
        Err(e)   => port_error_response(e),
    }
}

// -------------------------------------------------------------------------
// GET /api/v1/tenants/:tid
// -------------------------------------------------------------------------

pub async fn get<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    if let Err(r) = require(AdminAction::ViewTenancy, &req, &ctx.env).await? {
        return Ok(r);
    }
    let Some(tid) = ctx.param("tid") else { return not_found(); };
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    match tenants.get(tid).await {
        Ok(Some(t)) => json(200, &t),
        Ok(None)    => not_found(),
        Err(e)      => port_error_response(e),
    }
}

// -------------------------------------------------------------------------
// PATCH /api/v1/tenants/:tid
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct UpdateTenantBody {
    display_name: Option<String>,
}

pub async fn update<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else { return not_found(); };
    let body: UpdateTenantBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    if let Some(name) = body.display_name {
        if let Err(e) = tenants.update_display_name(&tid, &name, now).await {
            return port_error_response(e);
        }
    }

    audit::write_owned(
        &ctx.env, EventKind::TenantUpdated,
        Some(principal.id.clone()), Some(tid.clone()), None,
    ).await.ok();

    match tenants.get(&tid).await {
        Ok(Some(t)) => json(200, &t),
        Ok(None)    => not_found(),
        Err(e)      => port_error_response(e),
    }
}

// -------------------------------------------------------------------------
// POST /api/v1/tenants/:tid/status
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct StatusBody { status: TenantStatus }

pub async fn set_status<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require(AdminAction::ManageTenancy, &req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(tid) = ctx.param("tid").map(|s| s.to_owned()) else { return not_found(); };
    let body: StatusBody = match req.json().await {
        Ok(b) => b, Err(_) => return bad_request("invalid_json"),
    };

    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(e) = tenants.set_status(&tid, body.status, now).await {
        return match e {
            PortError::NotFound => not_found(),
            other => port_error_response(other),
        };
    }

    audit::write_owned(
        &ctx.env, EventKind::TenantStatusChanged,
        Some(principal.id.clone()), Some(tid.clone()),
        Some(format!("{:?}", body.status).to_lowercase()),
    ).await.ok();

    match tenants.get(&tid).await {
        Ok(Some(t)) => json(200, &t),
        Ok(None)    => not_found(),
        Err(e)      => port_error_response(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::tenancy::types::{Tenant, TenantStatus};

    fn t() -> Tenant {
        Tenant {
            id:           "t-1".to_owned(),
            slug:         "acme".to_owned(),
            display_name: "Acme".to_owned(),
            status:       TenantStatus::Active,
            created_at:   0,
            updated_at:   0,
        }
    }

    // RFC 158 §5.6: additive, not a reshape — id/slug stay top-level,
    // owner_home is the one new sibling field.
    #[test]
    fn create_tenant_response_flattens_tenant_fields_with_owner_home_as_a_sibling() {
        let tenant = t();
        let resp = CreateTenantResponse { tenant: &tenant, owner_home: "assigned" };
        let v: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["id"], "t-1", "id must stay top-level, not nested under a tenant key");
        assert_eq!(v["slug"], "acme");
        assert_eq!(v["display_name"], "Acme");
        assert_eq!(v["owner_home"], "assigned");
        assert!(v.get("tenant").is_none(), "must not wrap the tenant in its own key");
    }

    #[test]
    fn create_tenant_response_carries_each_owner_home_variant() {
        let tenant = t();
        for s in ["assigned", "kept_existing_home", "failed"] {
            let resp = CreateTenantResponse { tenant: &tenant, owner_home: s };
            let v: serde_json::Value = serde_json::to_value(&resp).unwrap();
            assert_eq!(v["owner_home"], s);
        }
    }
}
