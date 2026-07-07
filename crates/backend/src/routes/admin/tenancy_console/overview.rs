//! `GET /admin/tenancy` — landing page with deployment-wide counters.

use cesauth_core::admin::types::AdminAction;
use cesauth_frontend::tenancy_console::overview::{OverviewCounts, PlanBreakdownRow};
use cesauth_frontend::tenancy_console::tenancy_console_overview_page;
use serde::Deserialize;
use worker::{Request, Response, Result, RouteContext};

use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "テナント管理 — cesauth").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    // Return tenant count + basic system info for the operator overview.
    use cesauth_cf::ports::repo::CloudflareTenantRepository;
    use cesauth_core::tenancy::TenantRepository;
    let repo = CloudflareTenantRepository::new(&ctx.env);
    let tenants = repo.list(200).await.unwrap_or_default();
    let mut resp = Response::from_json(&serde_json::json!({
        "tenant_count": tenants.len(),
    }))?;
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}

// -------------------------------------------------------------------------
// Aggregate reads
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct CountRow { c: i64 }

#[derive(Deserialize)]
struct StatusCountRow { status: String, c: i64 }

#[derive(Deserialize)]
struct PlanRow {
    slug:             String,
    display_name:     String,
    subscriber_count: i64,
}

async fn read_counts(env: &worker::Env) -> std::result::Result<OverviewCounts, ()> {
    let db = env.d1("DB").map_err(|_| ())?;

    // Tenants by status — one query, one pass.
    let rows = db.prepare(
        "SELECT status, COUNT(*) AS c FROM tenants GROUP BY status"
    )
        .all().await.map_err(|_| ())?;
    let rows: Vec<StatusCountRow> = rows.results().map_err(|_| ())?;
    let mut counts = OverviewCounts::default();
    for r in rows {
        match r.status.as_str() {
            "active"    => counts.tenants_active    = r.c,
            "suspended" => counts.tenants_suspended = r.c,
            "deleted"   => counts.tenants_deleted   = r.c,
            _ => {}
        }
    }

    // Other simple counts.
    counts.organizations = scalar_count(env, "SELECT COUNT(*) AS c FROM organizations WHERE status != 'deleted'").await.unwrap_or(0);
    counts.groups        = scalar_count(env, "SELECT COUNT(*) AS c FROM groups WHERE status != 'deleted'").await.unwrap_or(0);
    counts.plans_active  = scalar_count(env, "SELECT COUNT(*) AS c FROM plans WHERE active = 1").await.unwrap_or(0);

    Ok(counts)
}

async fn scalar_count(env: &worker::Env, sql: &str) -> std::result::Result<i64, ()> {
    let db = env.d1("DB").map_err(|_| ())?;
    let rows = db.prepare(sql).all().await.map_err(|_| ())?;
    let rows: Vec<CountRow> = rows.results().map_err(|_| ())?;
    Ok(rows.into_iter().next().map(|r| r.c).unwrap_or(0))
}

async fn read_plan_breakdown(env: &worker::Env) -> std::result::Result<Vec<PlanBreakdownRow>, ()> {
    // LEFT JOIN so every active plan appears even with zero
    // subscribers — gives operators a complete catalog view.
    let db = env.d1("DB").map_err(|_| ())?;
    let rows = db.prepare(
        "SELECT p.slug         AS slug, \
                p.display_name AS display_name, \
                COUNT(s.id)    AS subscriber_count \
           FROM plans p \
           LEFT JOIN subscriptions s ON s.plan_id = p.id \
          WHERE p.active = 1 \
          GROUP BY p.id \
          ORDER BY p.slug"
    ).all().await.map_err(|_| ())?;
    let rows: Vec<PlanRow> = rows.results().map_err(|_| ())?;
    Ok(rows.into_iter().map(|r| PlanBreakdownRow {
        plan_slug:        r.slug,
        plan_label:       r.display_name,
        subscriber_count: r.subscriber_count,
    }).collect())
}
