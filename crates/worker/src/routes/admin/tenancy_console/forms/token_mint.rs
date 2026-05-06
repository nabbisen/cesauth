//! `GET/POST /admin/tenancy/users/:uid/tokens/new` — mint a
//! user-bound admin token from the system-admin surface.
//!
//! Gated on `ManageAdminTokens` (per v0.4.0's existing flow).
//! Tenant admins cannot self-mint per ADR-002 / ADR-003: this
//! route lives at `/admin/tenancy/...`, not `/admin/t/<slug>/...`.
//!
//! The plaintext token is shown ONCE on the apply page. cesauth
//! stores only the SHA-256 hash; the plaintext cannot be retrieved
//! later. The preview page warns about this prominently.

use cesauth_cf::admin::CloudflareAdminTokenRepository;
use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_cf::tenancy::CloudflareTenantRepository;
use cesauth_core::admin::ports::AdminTokenRepository;
use cesauth_core::admin::types::{AdminAction, Role as AdminRole};
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::tenancy::ports::TenantRepository;
use cesauth_core::types::User;
use cesauth_ui::tenancy_console::forms::token_mint::{
    applied_page, form_page, preview_page, MintInput, MintPreviewInput,
};
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::console::tokens::{hash_hex, mint_plaintext};
use crate::routes::admin::tenancy_console::forms::common::{confirmed, parse_form};

async fn require_token_mint(
    req: &Request,
    env: &worker::Env,
) -> Result<std::result::Result<cesauth_core::admin::types::AdminPrincipal, Response>> {
    let principal = match auth::resolve_or_respond(req, env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(Err(resp)),
    };
    if let Err(resp) = auth::ensure_role_allows(&principal, AdminAction::ManageAdminTokens) {
        return Ok(Err(resp));
    }
    Ok(Ok(principal))
}

async fn load_user(env: &worker::Env, uid: &str) -> std::result::Result<User, Response> {
    let users = CloudflareUserRepository::new(env);
    match users.find_by_id(uid).await {
        Ok(Some(u)) => Ok(u),
        Ok(None)    => Err(Response::error("user not found", 404).unwrap_or_else(|_| Response::empty().unwrap())),
        Err(_)      => Err(Response::error("storage error", 500).unwrap_or_else(|_| Response::empty().unwrap())),
    }
}

fn parse_role(s: &str) -> Option<AdminRole> {
    match s {
        "read_only"  => Some(AdminRole::ReadOnly),
        "security"   => Some(AdminRole::Security),
        "operations" => Some(AdminRole::Operations),
        "super"      => Some(AdminRole::Super),
        _            => None,
    }
}

pub async fn form<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_token_mint(&req, &ctx.env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(resp),
    };
    let Some(uid) = ctx.param("uid") else { return Response::error("not found", 404); };
    let user = match load_user(&ctx.env, uid).await {
        Ok(u)     => u,
        Err(resp) => return Ok(resp),
    };
    render::html_response(form_page(
        &principal,
        &MintInput { subject_user: &user, role: "operations", name: "", error: None },
    ))
}

pub async fn submit<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match require_token_mint(&req, &ctx.env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(resp),
    };
    let Some(uid) = ctx.param("uid").map(|s| s.to_owned()) else {
        return Response::error("not found", 404);
    };
    let user = match load_user(&ctx.env, &uid).await {
        Ok(u)     => u,
        Err(resp) => return Ok(resp),
    };

    let form = parse_form(&mut req).await?;
    let role_str = form.get("role").cloned().unwrap_or_default();
    let name     = form.get("name").cloned().unwrap_or_default();

    let role = match parse_role(&role_str) {
        Some(r) => r,
        None    => {
            return render::html_response(form_page(
                &principal,
                &MintInput {
                    subject_user: &user, role: &role_str, name: &name,
                    error: Some("Pick a role"),
                },
            ));
        }
    };

    if name.trim().is_empty() {
        return render::html_response(form_page(
            &principal,
            &MintInput {
                subject_user: &user, role: &role_str, name: &name,
                error: Some("Token nickname is required (recorded in audit)"),
            },
        ));
    }

    if !confirmed(&form) {
        return render::html_response(preview_page(
            &principal,
            &MintPreviewInput { subject_user: &user, role, name: &name },
        ));
    }

    // Resolve the user's tenant slug for the post-apply page link.
    let tenants = CloudflareTenantRepository::new(&ctx.env);
    let tenant_slug = tenants.get(&user.tenant_id).await.ok().flatten()
        .map(|t| t.slug)
        .unwrap_or_else(|| user.tenant_id.clone());

    // Mint and persist.
    let plaintext = mint_plaintext();
    let hash      = hash_hex(&plaintext);
    let now       = OffsetDateTime::now_utc().unix_timestamp();
    let tokens    = CloudflareAdminTokenRepository::new(&ctx.env);
    let minted = match tokens.create_user_bound(
        &hash, role, Some(&name), &user.id, now,
    ).await {
        Ok(p)  => p,
        Err(e) => {
            worker::console_error!("admin token create_user_bound failed: {e:?}");
            return Response::error("storage error", 500);
        }
    };

    audit::write_owned(
        &ctx.env, EventKind::AdminTokenCreated,
        Some(principal.id.clone()), Some(minted.id.clone()),
        Some(format!("via=tenancy-console,user={},role={:?},name={}",
            user.id, role, name).to_lowercase()),
    ).await.ok();

    render::html_response(applied_page(&principal, &user, &tenant_slug, role, &plaintext))
}
