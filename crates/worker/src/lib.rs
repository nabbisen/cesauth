//! # cesauth-worker
//!
//! The Cloudflare Workers entrypoint. This crate is compiled as
//! `cdylib` and is what `wrangler` actually deploys.
//!
//! ## DO re-export dance
//!
//! `#[durable_object]` generates WASM exports under whatever crate is
//! being built as the `cdylib`. Because our DO implementations live in
//! `cesauth-do` (a `rlib`), we re-export them here with `pub use` so
//! the exports land in *this* crate's WASM module. wrangler.toml's DO
//! bindings point at these re-exported names.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms)]

pub mod audit;
pub mod config;
pub mod csrf;
pub mod error;
pub mod log;
pub mod post_auth;
pub mod routes;
pub mod turnstile;

#[allow(clippy::wildcard_imports)]
use worker::*;

// Re-export the four DO classes so the macro-generated WASM exports
// land in this cdylib. Do NOT remove these without updating
// wrangler.toml and verifying DO classes still load.
pub use cesauth_cf::{ActiveSession, AuthChallenge, RateLimit, RefreshTokenFamily};

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    // Keep the top-level handler tiny: plug into Router, let each route
    // module own its logic. Errors bubble up to `error::into_response`
    // so the shape of what we emit is never ad-hoc.
    let router = Router::new();

    let response = router
        // --- Discovery / JWKS (spec §4.2) -----------------------------
        .get_async("/.well-known/openid-configuration", |req, ctx| async move {
            routes::oidc::discovery(req, ctx).await
        })
        .get_async("/jwks.json", |req, ctx| async move {
            routes::oidc::jwks(req, ctx).await
        })
        // --- OIDC endpoints ------------------------------------------
        .get_async("/authorize",  |req, ctx| async move { routes::oidc::authorize(req, ctx).await })
        .post_async("/token",     |req, ctx| async move { routes::oidc::token(req, ctx).await })
        .post_async("/revoke",    |req, ctx| async move { routes::oidc::revoke(req, ctx).await })
        // --- WebAuthn -------------------------------------------------
        .post_async("/webauthn/register/start",      |req, ctx| async move {
            routes::webauthn::register_start(req, ctx).await
        })
        .post_async("/webauthn/register/finish",     |req, ctx| async move {
            routes::webauthn::register_finish(req, ctx).await
        })
        .post_async("/webauthn/authenticate/start",  |req, ctx| async move {
            routes::webauthn::authenticate_start(req, ctx).await
        })
        .post_async("/webauthn/authenticate/finish", |req, ctx| async move {
            routes::webauthn::authenticate_finish(req, ctx).await
        })
        // --- Magic Link ----------------------------------------------
        .post_async("/magic-link/request", |req, ctx| async move {
            routes::magic_link::request(req, ctx).await
        })
        .post_async("/magic-link/verify",  |req, ctx| async move {
            routes::magic_link::verify(req, ctx).await
        })
        // --- Admin API ------------------------------------------------
        .post_async("/admin/users",          |req, ctx| async move { routes::admin::create_user(req, ctx).await })
        .delete_async("/admin/sessions/:id", |req, ctx| async move { routes::admin::revoke_session(req, ctx).await })
        // --- Admin Console (v0.3.0) ----------------------------------
        .get_async ("/admin/console",                          |req, ctx| async move { routes::admin::console::overview::page(req, ctx).await })
        .get_async ("/admin/console/cost",                     |req, ctx| async move { routes::admin::console::cost::page(req, ctx).await })
        .get_async ("/admin/console/safety",                   |req, ctx| async move { routes::admin::console::safety::page(req, ctx).await })
        .post_async("/admin/console/safety/:bucket/verify",    |req, ctx| async move { routes::admin::console::safety::verify(req, ctx).await })
        .get_async ("/admin/console/audit",                    |req, ctx| async move { routes::admin::console::audit::page(req, ctx).await })
        .get_async ("/admin/console/config",                   |req, ctx| async move { routes::admin::console::config::page(req, ctx).await })
        .post_async("/admin/console/config/:bucket/preview",   |req, ctx| async move { routes::admin::console::config::preview(req, ctx).await })
        .post_async("/admin/console/config/:bucket/apply",     |req, ctx| async move { routes::admin::console::config::apply(req, ctx).await })
        .get_async ("/admin/console/alerts",                   |req, ctx| async move { routes::admin::console::alerts::page(req, ctx).await })
        .post_async("/admin/console/thresholds/:name",         |req, ctx| async move { routes::admin::console::actions::threshold(req, ctx).await })
        // --- Admin Console (v0.4.0) ----------------------------------
        // HTML two-step confirmation for bucket-safety edits.
        .get_async ("/admin/console/config/:bucket/edit",      |req, ctx| async move { routes::admin::console::config::edit_form(req, ctx).await })
        .post_async("/admin/console/config/:bucket/edit",      |req, ctx| async move { routes::admin::console::config::edit_submit(req, ctx).await })
        // Admin-token CRUD (Super-only).
        .get_async ("/admin/console/tokens",                   |req, ctx| async move { routes::admin::console::tokens::list(req, ctx).await })
        .get_async ("/admin/console/tokens/new",               |req, ctx| async move { routes::admin::console::tokens::new_form(req, ctx).await })
        .post_async("/admin/console/tokens",                   |req, ctx| async move { routes::admin::console::tokens::create(req, ctx).await })
        .post_async("/admin/console/tokens/:id/disable",       |req, ctx| async move { routes::admin::console::tokens::disable(req, ctx).await })
        // --- tenancy console (v0.8.0 read pages) ------------------------
        // Operator-facing inspection of the v0.4.x tenancy-service
        // state. Every read route is open to ViewTenancy (every
        // valid role); see `routes/admin/tenancy_console.rs`.
        .get_async("/admin/tenancy",                                            |req, ctx| async move { routes::admin::tenancy_console::overview::page(req, ctx).await })
        .get_async("/admin/tenancy/tenants",                                    |req, ctx| async move { routes::admin::tenancy_console::tenants::page(req, ctx).await })
        .get_async("/admin/tenancy/tenants/:tid",                               |req, ctx| async move { routes::admin::tenancy_console::tenant_detail::page(req, ctx).await })
        .get_async("/admin/tenancy/tenants/:tid/subscription/history",          |req, ctx| async move { routes::admin::tenancy_console::subscription::page(req, ctx).await })
        .get_async("/admin/tenancy/organizations/:oid",                         |req, ctx| async move { routes::admin::tenancy_console::organizations::page(req, ctx).await })
        .get_async("/admin/tenancy/users/:uid/role_assignments",                |req, ctx| async move { routes::admin::tenancy_console::role_assignments::page(req, ctx).await })
        // --- tenancy console mutations (v0.9.0) -------------------------
        // HTML forms wrapping the v0.7.0 JSON API. All gated through
        // `AdminAction::ManageTenancy` (Operations+); see
        // `routes/admin/tenancy/forms.rs`. Destructive mutations
        // (status changes, group delete, plan/status changes) go
        // through the v0.4.0-style preview/confirm flow.
        .get_async ("/admin/tenancy/tenants/new",                                |req, ctx| async move { routes::admin::tenancy_console::forms::tenant_create::form(req, ctx).await })
        .post_async("/admin/tenancy/tenants/new",                                |req, ctx| async move { routes::admin::tenancy_console::forms::tenant_create::submit(req, ctx).await })
        .get_async ("/admin/tenancy/tenants/:tid/status",                        |req, ctx| async move { routes::admin::tenancy_console::forms::tenant_set_status::form(req, ctx).await })
        .post_async("/admin/tenancy/tenants/:tid/status",                        |req, ctx| async move { routes::admin::tenancy_console::forms::tenant_set_status::submit(req, ctx).await })
        .get_async ("/admin/tenancy/tenants/:tid/organizations/new",             |req, ctx| async move { routes::admin::tenancy_console::forms::organization_create::form(req, ctx).await })
        .post_async("/admin/tenancy/tenants/:tid/organizations/new",             |req, ctx| async move { routes::admin::tenancy_console::forms::organization_create::submit(req, ctx).await })
        .get_async ("/admin/tenancy/organizations/:oid/status",                  |req, ctx| async move { routes::admin::tenancy_console::forms::organization_set_status::form(req, ctx).await })
        .post_async("/admin/tenancy/organizations/:oid/status",                  |req, ctx| async move { routes::admin::tenancy_console::forms::organization_set_status::submit(req, ctx).await })
        .get_async ("/admin/tenancy/tenants/:tid/groups/new",                    |req, ctx| async move { routes::admin::tenancy_console::forms::group_create::form_tenant(req, ctx).await })
        .post_async("/admin/tenancy/tenants/:tid/groups/new",                    |req, ctx| async move { routes::admin::tenancy_console::forms::group_create::submit_tenant(req, ctx).await })
        .get_async ("/admin/tenancy/organizations/:oid/groups/new",              |req, ctx| async move { routes::admin::tenancy_console::forms::group_create::form_org(req, ctx).await })
        .post_async("/admin/tenancy/organizations/:oid/groups/new",              |req, ctx| async move { routes::admin::tenancy_console::forms::group_create::submit_org(req, ctx).await })
        .get_async ("/admin/tenancy/groups/:gid/delete",                         |req, ctx| async move { routes::admin::tenancy_console::forms::group_delete::confirm(req, ctx).await })
        .post_async("/admin/tenancy/groups/:gid/delete",                         |req, ctx| async move { routes::admin::tenancy_console::forms::group_delete::submit(req, ctx).await })
        .get_async ("/admin/tenancy/tenants/:tid/subscription/plan",             |req, ctx| async move { routes::admin::tenancy_console::forms::subscription_set_plan::form(req, ctx).await })
        .post_async("/admin/tenancy/tenants/:tid/subscription/plan",             |req, ctx| async move { routes::admin::tenancy_console::forms::subscription_set_plan::submit(req, ctx).await })
        .get_async ("/admin/tenancy/tenants/:tid/subscription/status",           |req, ctx| async move { routes::admin::tenancy_console::forms::subscription_set_status::form(req, ctx).await })
        .post_async("/admin/tenancy/tenants/:tid/subscription/status",           |req, ctx| async move { routes::admin::tenancy_console::forms::subscription_set_status::submit(req, ctx).await })
        // --- tenancy console mutations (v0.10.0: memberships + role assignments) ---
        // Three flavors of membership add/remove (one-click submit
        // for add, single-step confirm for remove) plus role
        // assignment grant/revoke. Gated through `ManageTenancy`.
        .get_async ("/admin/tenancy/tenants/:tid/memberships/new",                       |req, ctx| async move { routes::admin::tenancy_console::forms::membership_add::form_tenant(req, ctx).await })
        .post_async("/admin/tenancy/tenants/:tid/memberships/new",                       |req, ctx| async move { routes::admin::tenancy_console::forms::membership_add::submit_tenant(req, ctx).await })
        .get_async ("/admin/tenancy/tenants/:tid/memberships/:uid/delete",               |req, ctx| async move { routes::admin::tenancy_console::forms::membership_remove::confirm_tenant(req, ctx).await })
        .post_async("/admin/tenancy/tenants/:tid/memberships/:uid/delete",               |req, ctx| async move { routes::admin::tenancy_console::forms::membership_remove::submit_tenant(req, ctx).await })
        .get_async ("/admin/tenancy/organizations/:oid/memberships/new",                 |req, ctx| async move { routes::admin::tenancy_console::forms::membership_add::form_org(req, ctx).await })
        .post_async("/admin/tenancy/organizations/:oid/memberships/new",                 |req, ctx| async move { routes::admin::tenancy_console::forms::membership_add::submit_org(req, ctx).await })
        .get_async ("/admin/tenancy/organizations/:oid/memberships/:uid/delete",         |req, ctx| async move { routes::admin::tenancy_console::forms::membership_remove::confirm_org(req, ctx).await })
        .post_async("/admin/tenancy/organizations/:oid/memberships/:uid/delete",         |req, ctx| async move { routes::admin::tenancy_console::forms::membership_remove::submit_org(req, ctx).await })
        .get_async ("/admin/tenancy/groups/:gid/memberships/new",                        |req, ctx| async move { routes::admin::tenancy_console::forms::membership_add::form_group(req, ctx).await })
        .post_async("/admin/tenancy/groups/:gid/memberships/new",                        |req, ctx| async move { routes::admin::tenancy_console::forms::membership_add::submit_group(req, ctx).await })
        .get_async ("/admin/tenancy/groups/:gid/memberships/:uid/delete",                |req, ctx| async move { routes::admin::tenancy_console::forms::membership_remove::confirm_group(req, ctx).await })
        .post_async("/admin/tenancy/groups/:gid/memberships/:uid/delete",                |req, ctx| async move { routes::admin::tenancy_console::forms::membership_remove::submit_group(req, ctx).await })
        .get_async ("/admin/tenancy/users/:uid/role_assignments/new",                    |req, ctx| async move { routes::admin::tenancy_console::forms::role_assignment_create::form(req, ctx).await })
        .post_async("/admin/tenancy/users/:uid/role_assignments/new",                    |req, ctx| async move { routes::admin::tenancy_console::forms::role_assignment_create::submit(req, ctx).await })
        .get_async ("/admin/tenancy/role_assignments/:id/delete",                        |req, ctx| async move { routes::admin::tenancy_console::forms::role_assignment_delete::confirm(req, ctx).await })
        .post_async("/admin/tenancy/role_assignments/:id/delete",                        |req, ctx| async move { routes::admin::tenancy_console::forms::role_assignment_delete::submit(req, ctx).await })
        // --- tenant-scoped admin surface (v0.13.0) ---------------------
        // Reachable from a tenant-side login, gated through the
        // user-as-bearer admin token (per ADR-002). Per-route auth
        // gate enforces:
        //   1. principal.user_id.is_some() — system-admin tokens are
        //      refused at this surface (ADR-003 separation)
        //   2. URL :slug resolves to a real tenant
        //   3. principal's user belongs to that tenant — the
        //      structural defense against tenant-boundary leakage
        // See `routes/admin/tenant_admin/gate.rs`. v0.13.0 ships read
        // pages only; mutation forms land in 0.14.0.
        .get_async("/admin/t/:slug",                                                     |req, ctx| async move { routes::admin::tenant_admin::overview::page(req, ctx).await })
        .get_async("/admin/t/:slug/organizations",                                       |req, ctx| async move { routes::admin::tenant_admin::organizations::page(req, ctx).await })
        .get_async("/admin/t/:slug/organizations/:oid",                                  |req, ctx| async move { routes::admin::tenant_admin::organization_detail::page(req, ctx).await })
        .get_async("/admin/t/:slug/users",                                               |req, ctx| async move { routes::admin::tenant_admin::users::page(req, ctx).await })
        .get_async("/admin/t/:slug/users/:uid/role_assignments",                         |req, ctx| async move { routes::admin::tenant_admin::role_assignments::page(req, ctx).await })
        .get_async("/admin/t/:slug/subscription",                                        |req, ctx| async move { routes::admin::tenant_admin::subscription::page(req, ctx).await })
        // --- tenancy-service API (v0.7.0) ----------------------------
        // JSON-only surface for operator-driven tenant / org / group /
        // role-assignment / subscription provisioning. Gated through
        // the same admin-bearer auth as `/admin/console/*`. See
        // `routes/api_v1.rs` for the full route catalogue and the
        // design rationale (admin-bearer vs user-as-bearer).
        .post_async  ("/api/v1/tenants",                                     |req, ctx| async move { routes::api_v1::tenants::create(req, ctx).await })
        .get_async   ("/api/v1/tenants",                                     |req, ctx| async move { routes::api_v1::tenants::list(req, ctx).await })
        .get_async   ("/api/v1/tenants/:tid",                                |req, ctx| async move { routes::api_v1::tenants::get(req, ctx).await })
        .patch_async ("/api/v1/tenants/:tid",                                |req, ctx| async move { routes::api_v1::tenants::update(req, ctx).await })
        .post_async  ("/api/v1/tenants/:tid/status",                         |req, ctx| async move { routes::api_v1::tenants::set_status(req, ctx).await })
        .post_async  ("/api/v1/tenants/:tid/organizations",                  |req, ctx| async move { routes::api_v1::organizations::create(req, ctx).await })
        .get_async   ("/api/v1/tenants/:tid/organizations",                  |req, ctx| async move { routes::api_v1::organizations::list(req, ctx).await })
        .get_async   ("/api/v1/tenants/:tid/organizations/:oid",             |req, ctx| async move { routes::api_v1::organizations::get(req, ctx).await })
        .patch_async ("/api/v1/tenants/:tid/organizations/:oid",             |req, ctx| async move { routes::api_v1::organizations::update(req, ctx).await })
        .post_async  ("/api/v1/tenants/:tid/organizations/:oid/status",      |req, ctx| async move { routes::api_v1::organizations::set_status(req, ctx).await })
        .post_async  ("/api/v1/tenants/:tid/groups",                         |req, ctx| async move { routes::api_v1::groups::create(req, ctx).await })
        .get_async   ("/api/v1/tenants/:tid/groups",                         |req, ctx| async move { routes::api_v1::groups::list(req, ctx).await })
        .delete_async("/api/v1/groups/:gid",                                 |req, ctx| async move { routes::api_v1::groups::delete(req, ctx).await })
        .post_async  ("/api/v1/tenants/:tid/memberships",                    |req, ctx| async move { routes::api_v1::memberships::add_tenant(req, ctx).await })
        .get_async   ("/api/v1/tenants/:tid/memberships",                    |req, ctx| async move { routes::api_v1::memberships::list_tenant(req, ctx).await })
        .delete_async("/api/v1/tenants/:tid/memberships/:uid",               |req, ctx| async move { routes::api_v1::memberships::remove_tenant(req, ctx).await })
        .post_async  ("/api/v1/organizations/:oid/memberships",              |req, ctx| async move { routes::api_v1::memberships::add_org(req, ctx).await })
        .get_async   ("/api/v1/organizations/:oid/memberships",              |req, ctx| async move { routes::api_v1::memberships::list_org(req, ctx).await })
        .delete_async("/api/v1/organizations/:oid/memberships/:uid",         |req, ctx| async move { routes::api_v1::memberships::remove_org(req, ctx).await })
        .post_async  ("/api/v1/groups/:gid/memberships",                     |req, ctx| async move { routes::api_v1::memberships::add_group(req, ctx).await })
        .get_async   ("/api/v1/groups/:gid/memberships",                     |req, ctx| async move { routes::api_v1::memberships::list_group(req, ctx).await })
        .delete_async("/api/v1/groups/:gid/memberships/:uid",                |req, ctx| async move { routes::api_v1::memberships::remove_group(req, ctx).await })
        .post_async  ("/api/v1/role_assignments",                            |req, ctx| async move { routes::api_v1::role_assignments::create(req, ctx).await })
        .delete_async("/api/v1/role_assignments/:id",                        |req, ctx| async move { routes::api_v1::role_assignments::delete(req, ctx).await })
        .get_async   ("/api/v1/users/:uid/role_assignments",                 |req, ctx| async move { routes::api_v1::role_assignments::list_for_user(req, ctx).await })
        .get_async   ("/api/v1/tenants/:tid/subscription",                   |req, ctx| async move { routes::api_v1::subscriptions::get(req, ctx).await })
        .post_async  ("/api/v1/tenants/:tid/subscription/plan",              |req, ctx| async move { routes::api_v1::subscriptions::set_plan(req, ctx).await })
        .post_async  ("/api/v1/tenants/:tid/subscription/status",            |req, ctx| async move { routes::api_v1::subscriptions::set_status(req, ctx).await })
        .get_async   ("/api/v1/tenants/:tid/subscription/history",           |req, ctx| async move { routes::api_v1::subscriptions::list_history(req, ctx).await })
        // --- UI -------------------------------------------------------
        .get_async("/",         |req, ctx| async move { routes::ui::login(req, ctx).await })
        .get_async("/login",    |req, ctx| async move { routes::ui::login(req, ctx).await })
        // --- Session management --------------------------------------
        .post_async("/logout",  |req, ctx| async move { routes::session::logout(req, ctx).await })
        // --- Dev-only (guarded by WRANGLER_LOCAL=1) ------------------
        // These exist to make `docs/local-development.md` runnable
        // from curl without the full session-cookie flow. Production
        // deploys MUST NOT set WRANGLER_LOCAL; the handlers return 404
        // when the var is unset.
        .post_async("/__dev/stage-auth-code/:handle", |req, ctx| async move {
            routes::dev::stage_auth_code(req, ctx).await
        })
        .get_async("/__dev/audit", |req, ctx| async move {
            routes::dev::list_audit(req, ctx).await
        })
        // --- Default (404) --------------------------------------------
        .or_else_any_method_async("/*catchall", |_req, _ctx| async move {
            Response::error("not found", 404)
        })
        .run(req, env)
        .await;

    // Defensive: attach a handful of baseline security headers on every
    // response, including errors. Route handlers MAY override.
    let _ = ctx;
    response.map(harden_headers)
}

fn harden_headers(mut resp: Response) -> Response {
    // These are defaults. Route handlers rendering HTML may override
    // CSP for pages that legitimately need inline script (the login
    // page does, and sets its own policy).
    let h = resp.headers_mut();
    let _ = h.set("x-content-type-options", "nosniff");
    let _ = h.set("x-frame-options",        "DENY");
    let _ = h.set("referrer-policy",        "no-referrer");
    let _ = h.set("cache-control",          "no-store");
    resp
}
