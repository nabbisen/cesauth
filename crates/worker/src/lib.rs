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
