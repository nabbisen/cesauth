//! `GET /admin/t/:slug/users/:uid/role_assignments` — every role
//! assignment held by one user, scoped to the current tenant.
//!
//! **RFC 145 cycle 2.** Previously returned the Leptos shell with no
//! matching `app.rs` route — HTTP 200 rendering `<NotFound/>`.
//! `role_assignments_page` and `render::html_response` were imported
//! and unused; this wires them. `page_json` is deleted with it: no
//! Leptos page ever called `.../role_assignments.json`
//! (`grep -rn 'role_assignments.json' crates/frontend/src/` → 0 hits),
//! the same orphan class RFC 147 D10 removed `deletion-requests.json`
//! for.

use cesauth_cf::authz::{CloudflareRoleAssignmentRepository, CloudflareRoleRepository};
use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_core::authz::ports::{RoleAssignmentRepository, RoleRepository};
use cesauth_core::ports::repo::UserRepository;
use cesauth_frontend::tenant_admin::{role_assignments_page, TenantUserRoleAssignmentsInput};
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::{gate, json_api};

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let ctx_ta = match json_api::resolve_ctx(&req, &ctx).await? {
        Ok(c)  => c,
        Err(r) => return Ok(r),
    };
    if let Err(r) = gate::check_read(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::TENANT_READ,
        &ctx,
    ).await? { return Ok(r); }

    let uid = match ctx.param("uid") {
        Some(s) => s.clone(),
        None    => return Response::error("missing user id", 400),
    };
    let users = CloudflareUserRepository::new(&ctx.env);
    let user = match users.find_by_id(&uid).await {
        Ok(Some(u)) => u,
        Ok(None)    => return Response::error("user not found", 404),
        Err(_)      => return Response::error("storage error", 500),
    };
    if user.tenant_id != ctx_ta.tenant.id {
        return Response::error("user belongs to a different tenant", 403);
    }

    let assignments_repo = CloudflareRoleAssignmentRepository::new(&ctx.env);
    let assignments = assignments_repo.list_for_user(&user.id).await.unwrap_or_default();

    // Bulk-resolve (id, slug, display_name) for every distinct role_id
    // referenced, same shape `role_assignment_revoke.rs`'s one-off
    // `role_label` helper uses, just batched for however many
    // distinct roles this user's assignments touch.
    let roles_repo = CloudflareRoleRepository::new(&ctx.env);
    let mut seen = std::collections::HashSet::new();
    let mut role_labels: Vec<(String, String, String)> = Vec::new();
    for a in &assignments {
        if !seen.insert(a.role_id.clone()) { continue; }
        if let Ok(Some(r)) = roles_repo.get(&a.role_id).await {
            role_labels.push((r.id, r.slug, r.display_name));
        }
    }

    let aff = gate::build_affordances(&ctx_ta, &ctx).await?;

    let input = TenantUserRoleAssignmentsInput {
        subject_user: &user,
        assignments:  &assignments,
        role_labels:  &role_labels,
    };
    render::html_response(|| role_assignments_page(&ctx_ta.principal, &ctx_ta.tenant, &input, &aff))
}
