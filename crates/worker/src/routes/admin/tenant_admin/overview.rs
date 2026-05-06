//! `GET /admin/t/:slug` — tenant-scoped overview.

use cesauth_ui::tenant_admin::{TenantOverviewCounts, overview_page};
use serde::Deserialize;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;
use crate::routes::admin::tenant_admin::gate;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    // 1. Resolve bearer → principal (existing flow).
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)     => p,
        Err(resp) => return Ok(resp),
    };

    // 2. Tenant-admin gate (ADR-002 + ADR-003).
    let ctx_ta = match gate::resolve_or_respond(principal, &ctx).await? {
        Ok(c)     => c,
        Err(resp) => return Ok(resp),
    };

    // 3. Action-level authz: spec §9.2 scope-walk via check_permission.
    if let Err(resp) = gate::check_read(
        &ctx_ta,
        cesauth_core::authz::types::PermissionCatalog::TENANT_READ,
        &ctx,
    ).await? {
        return Ok(resp);
    }

    // 4. Read tenant-scoped aggregates.
    let counts = read_counts(&ctx.env, &ctx_ta.tenant.id).await
        .unwrap_or_default();

    render::html_response(overview_page(&ctx_ta.principal, &ctx_ta.tenant, &counts))
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
