//! `GET/POST /admin/tenancy/users/:uid/role_assignments/new` — grant role.

use cesauth_cf::authz::{CloudflareRoleAssignmentRepository, CloudflareRoleRepository};
use cesauth_core::authz::ports::{RoleAssignmentRepository, RoleRepository};
use cesauth_core::authz::types::{RoleAssignment, Scope};
use cesauth_frontend::tenancy_console::forms::role_assignment_create::{
    role_assignment_create_form, RoleAssignmentCreateInput,
};
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{
    attach_csrf_cookie, mint_csrf, parse_form, redirect_303, require_manage, verify_csrf,
};

/// **RFC 145 cycle 3.** Used to return the Leptos shell with no
/// matching `app.rs` route — HTTP 200 rendering `<NotFound/>`. Reuses
/// `list_system_roles` — the exact call `submit` below makes to
/// populate the role select.
pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(uid) = ctx.param("uid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let roles_repo = CloudflareRoleRepository::new(&ctx.env);
    let available = roles_repo.list_system_roles().await.unwrap_or_default();
    let (csrf_token, csrf_cookie) = mint_csrf()?;
    let mut resp = render::html_response(|| role_assignment_create_form(&principal, &RoleAssignmentCreateInput {
        user_id: &uid,
        available_roles: &available,
        role_id: "", scope_type: "", scope_id: "", expires_at: "",
        error: None, csrf: &csrf_token,
    }))?;
    attach_csrf_cookie(&mut resp, &csrf_cookie);
    Ok(resp)
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(uid) = ctx.param("uid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };

    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = parse_form(&mut req).await?;
    if !verify_csrf(&form, &cookie_header) {
        return Response::error("Bad Request", 400);
    }
    let role_id    = form.get("role_id").cloned().unwrap_or_default();
    let scope_type = form.get("scope_type").cloned().unwrap_or_default();
    let scope_id   = form.get("scope_id").cloned().unwrap_or_default();
    let expires_at = form.get("expires_at").cloned().unwrap_or_default();

    let roles_repo = CloudflareRoleRepository::new(&ctx.env);
    let available = roles_repo.list_system_roles().await.unwrap_or_default();

    // Every re-render below needs a FRESH token: the one just
    // submitted is spent, and a corrected resubmission with a stale
    // token must not fail for a reason the page doesn't explain.
    let render_err = |err: &str| -> Result<Response> {
        let (csrf_token, csrf_cookie) = mint_csrf()?;
        let mut resp = render::html_response(|| role_assignment_create_form(&principal, &RoleAssignmentCreateInput {
            user_id: &uid,
            available_roles: &available,
            role_id: &role_id, scope_type: &scope_type, scope_id: &scope_id, expires_at: &expires_at,
            error: Some(err), csrf: &csrf_token,
        }))?;
        attach_csrf_cookie(&mut resp, &csrf_cookie);
        Ok(resp)
    };

    if role_id.trim().is_empty() {
        return render_err("Pick a role");
    }

    let scope = match (scope_type.as_str(), scope_id.trim()) {
        ("system",       _)        => Scope::System,
        ("tenant",       "")       => return render_err("Scope id required for tenant scope"),
        ("tenant",       id)       => Scope::Tenant       { tenant_id:       id.to_owned() },
        ("organization", "")       => return render_err("Scope id required for organization scope"),
        ("organization", id)       => Scope::Organization { organization_id: id.to_owned() },
        ("group",        "")       => return render_err("Scope id required for group scope"),
        ("group",        id)       => Scope::Group        { group_id:        id.to_owned() },
        ("user",         "")       => return render_err("Scope id required for user scope"),
        ("user",         id)       => Scope::User         { user_id:         id.to_owned() },
        _                          => return render_err("Choose a scope"),
    };

    // Validate the role exists; fail-fast on a typo'd id.
    if roles_repo.get(&role_id).await.ok().flatten().is_none() {
        return render_err("Unknown role id");
    }

    let expires = if expires_at.trim().is_empty() {
        None
    } else {
        match expires_at.trim().parse::<i64>() {
            Ok(t)  => Some(t),
            Err(_) => return render_err("Expires must be a unix timestamp (integer seconds) or blank"),
        }
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let assignment = RoleAssignment {
        id:         Uuid::new_v4().to_string(),
        user_id:    uid.clone(),
        role_id:    role_id.clone(),
        scope:      scope.clone(),
        granted_by: principal.id.clone(),
        granted_at: now,
        expires_at: expires,
    };

    let assignments_repo = CloudflareRoleAssignmentRepository::new(&ctx.env);
    if let Err(e) = assignments_repo.create(&assignment).await {
        worker::console_error!("role_assignment create failed: {e:?}");
        return render_err("Storage error");
    }

    audit::write_owned(
        &ctx.env, EventKind::RoleGranted,
        Some(principal.id.clone()),
        Some(assignment.id.clone()),
        Some(format!("via=tenancy-console,user={uid},role={role_id}")),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/users/{uid}/role_assignments"))
}
