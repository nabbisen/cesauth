//! `GET /admin/t/:slug` — tenant-scoped overview.

use cesauth_frontend::tenant_admin::overview::TenantOverviewCounts;
use serde::Deserialize;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::tenant_admin::{gate, json_api};

/// `GET /admin/t/:slug` — Leptos HTML shell (v0.79.6).
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
    json_api::shell(&req, &ctx, &format!("{} — cesauth", ctx_ta.tenant.display_name)).await
}

/// `GET /admin/t/:slug.json` — tenant overview data.
pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let ctx_ta = match json_api::resolve_ctx(&req, &ctx).await? {
        Ok(c)  => c,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    if let Err(_) = gate::check_read(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::TENANT_READ,
        &ctx,
    ).await? { return Response::error("Forbidden", 403); }

    let counts = read_counts(&ctx.env, &ctx_ta.tenant.id).await.unwrap_or_default();
    let mut resp = Response::from_json(&serde_json::json!({
        "tenant": ctx_ta.tenant,
        "counts": counts,
    }))?;
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}

// -------------------------------------------------------------------------
// Aggregates scoped to one tenant.
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct CountRow { c: i64 }

#[derive(Deserialize)]
struct PlanSlugRow { slug: String }

async fn read_counts(env: &worker::Env, tenant_id: &str)
    -> std::result::Result<TenantOverviewCounts, ()>
{
    let mut counts = TenantOverviewCounts::default();
    counts.organizations = scalar_count(env,
        "SELECT COUNT(*) AS c FROM organizations \
         WHERE tenant_id = ?1 AND status != 'deleted'",
        tenant_id).await.unwrap_or(0);
    counts.users = scalar_count(env,
        "SELECT COUNT(*) AS c FROM users \
         WHERE tenant_id = ?1 AND status != 'deleted'",
        tenant_id).await.unwrap_or(0);
    counts.groups = scalar_count(env,
        "SELECT COUNT(*) AS c FROM groups \
         WHERE tenant_id = ?1 AND status != 'deleted'",
        tenant_id).await.unwrap_or(0);

    // Current plan: most-recent active subscription's plan slug.
    counts.current_plan = read_current_plan(env, tenant_id).await.ok();

    Ok(counts)
}

async fn scalar_count(env: &worker::Env, sql: &str, tenant_id: &str)
    -> std::result::Result<i64, ()>
{
    let db = env.d1("DB").map_err(|_| ())?;
    let row: Option<CountRow> = db.prepare(sql)
        .bind(&[tenant_id.into()]).map_err(|_| ())?
        .first(None).await.map_err(|_| ())?;
    Ok(row.map(|r| r.c).unwrap_or(0))
}

async fn read_current_plan(env: &worker::Env, tenant_id: &str)
    -> std::result::Result<String, ()>
{
    let db = env.d1("DB").map_err(|_| ())?;
    let row: Option<PlanSlugRow> = db.prepare(
        "SELECT p.slug AS slug \
         FROM subscriptions s JOIN plans p ON p.id = s.plan_id \
         WHERE s.tenant_id = ?1 AND s.status = 'active' \
         ORDER BY s.started_at DESC LIMIT 1"
    )
        .bind(&[tenant_id.into()]).map_err(|_| ())?
        .first(None).await.map_err(|_| ())?;
    row.map(|r| r.slug).ok_or(())
}
