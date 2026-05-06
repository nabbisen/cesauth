//! `GET/POST /admin/tenancy/role_assignments/:id/delete` — revoke a
//! role assignment with a one-step confirm.

use cesauth_cf::authz::{CloudflareRoleAssignmentRepository, CloudflareRoleRepository};
use cesauth_core::authz::ports::{RoleAssignmentRepository, RoleRepository};
use cesauth_core::authz::types::RoleAssignment;
use cesauth_ui::tenancy_console::forms::role_assignment_delete::confirm_page;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::console::render;
use crate::routes::admin::tenancy_console::forms::common::{
    confirmed, parse_form, redirect_303, require_manage,
};

/// Look up an assignment by id by walking `list_for_user(user_id)`.
/// This is the only entry point we have because the repository
/// does not expose `get_by_id` — assignment ids are not normally
/// addressable except via their owning user.
async fn fetch_assignment(
    env:     &worker::Env,
    user_id: &str,
    id:      &str,
) -> Option<RoleAssignment> {
    let repo = CloudflareRoleAssignmentRepository::new(env);
    let rows = repo.list_for_user(user_id).await.unwrap_or_default();
    rows.into_iter().find(|a| a.id == id)
}

/// Resolve a role's display name (used as page label for the
/// confirm screen). Best-effort: an unknown role id falls back to
/// the bare id.
async fn role_label(env: &worker::Env, role_id: &str) -> String {
    let roles = CloudflareRoleRepository::new(env);
    match roles.get(role_id).await.ok().flatten() {
        Some(r) => format!(
            "{name} (<code>{slug}</code>)",
            name = cesauth_ui::escape(&r.display_name),
            slug = cesauth_ui::escape(&r.slug),
        ),
        None => format!("<code>{}</code>", cesauth_ui::escape(role_id)),
    }
}

pub async fn confirm<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(id) = ctx.param("id").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };

    // The query string carries `user_id` so we know which user to
    // look up the assignment under. (The repository doesn't expose
    // a `get_by_id` — see `fetch_assignment`'s rationale above.)
    let url = req.url()?;
    let user_id = url.query_pairs()
        .find(|(k, _)| k == "user_id")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    if user_id.is_empty() {
        return Response::error("user_id query param required", 400);
    }

    let Some(assignment) = fetch_assignment(&ctx.env, &user_id, &id).await else {
        return Response::error("assignment not found for that user", 404);
    };
    let label = role_label(&ctx.env, &assignment.role_id).await;
    render::html_response(confirm_page(&principal, &user_id, &assignment, &label))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_manage(&req, &ctx.env).await? {
        Ok(p) => p, Err(r) => return Ok(r),
    };
    let Some(id) = ctx.param("id").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };

    let form = parse_form(&mut req).await?;
    let user_id = form.get("user_id").cloned().unwrap_or_default();
    if user_id.is_empty() {
        return Response::error("user_id form field required", 400);
    }

    if !confirmed(&form) {
        // Bounce back to confirm page (defensive — operators might
        // reach the POST URL directly).
        let Some(assignment) = fetch_assignment(&ctx.env, &user_id, &id).await else {
            return Response::error("assignment not found", 404);
        };
        let label = role_label(&ctx.env, &assignment.role_id).await;
        return render::html_response(confirm_page(&principal, &user_id, &assignment, &label));
    }

    let repo = CloudflareRoleAssignmentRepository::new(&ctx.env);
    if let Err(e) = repo.delete(&id).await {
        worker::console_error!("role_assignment delete failed: {e:?}");
        return Response::error("storage error", 500);
    }

    audit::write_owned(
        &ctx.env, EventKind::RoleRevoked,
        Some(principal.id.clone()),
        Some(id.clone()),
        Some(format!("via=tenancy-console,user={user_id}")),
    ).await.ok();

    redirect_303(&format!("/admin/tenancy/users/{user_id}/role_assignments"))
}
