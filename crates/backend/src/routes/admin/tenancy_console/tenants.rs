//! `GET /admin/tenancy/tenants` — list all non-deleted tenants.

use worker::{Request, Response, Result, RouteContext};


pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let locale = crate::i18n::resolve_locale(&req);
    crate::routes::admin::operator_json_api::shell(
        &req, &ctx, cesauth_core::i18n::MessageKey::TenancyTenantsPageTitle, locale,
    ).await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    use cesauth_cf::tenancy::CloudflareTenantRepository;
    use cesauth_core::tenancy::TenantRepository;
    let repo = CloudflareTenantRepository::new(&ctx.env);
    // RFC 188 Phase 1's D5, applied here: a value that could be real
    // (an empty list) must never stand in for a value we do not have
    // (a failed read). `unwrap_or_default()` used to do exactly that —
    // a D1 outage rendered as "no tenants are registered yet", a
    // confident sentence about the deployment rather than a fact about
    // this request. Fail loud instead; the CSR component's existing
    // fetch-failure path (a non-`TenantsData`-shaped body collapses to
    // `None` via `.ok()`) renders the third state.
    let tenants = match repo.list_non_deleted().await {
        Ok(t)  => t,
        Err(e) => {
            // Round 2 §6: the write routes already log their cause
            // (`worker::console_error!`, twelve call sites); this is
            // the first *read* route whose 500 an operator sees as its
            // own distinct state (before this slice, a storage error
            // rendered a cheerful empty list) -- without this line a
            // reload that fails again has nothing anywhere about why.
            worker::console_error!("tenant list read failed: {e:?}");
            return Response::error("storage error", 500);
        }
    };
    let mut resp = Response::from_json(&serde_json::json!({ "tenants": tenants }))?;
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}
