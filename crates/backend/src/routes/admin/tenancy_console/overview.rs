//! `GET /admin/tenancy` — landing page.
//!
//! **"Deployment-wide counters" is what this file was built to serve and
//! not what it serves.** `page_json` returns a single
//! `{"tenant_count": n}`, and the CSR component renders that one number.
//!
//! `read_counts`, `read_plan_breakdown` and `scalar_count` below —
//! tenants by status, organizations, groups, active plans, and the
//! per-plan subscriber breakdown — are **dead code the compiler warns
//! about on every build**: their caller went away at `580eeba`
//! ("RFC-115 Phase C complete: old string templates removed", first
//! tagged **`0.80.0`**, 2026-07-07), and nothing has called them for 28
//! minor versions since. They are kept, not deleted, for the same reason
//! `tenancy_console/tenant_detail.rs`'s dead template is kept: this is
//! the data half of a screen whose migration stopped halfway, and
//! deleting it would destroy the only statement of what the screen was
//! for. `dead_code` is not denied in this crate — RFC 157 gated
//! `unused_imports`/`unused_variables` and deliberately left this class
//! warning-only (`docs/src/expert/contributing.md`), which is why six
//! warnings here have been visible and unaddressed rather than hidden.
//!
//! Whether to finish the port or declare the one counter sufficient is a
//! scope question; see the ROADMAP row. **Do not quietly delete these
//! functions to clear the warnings** — that turns an unfinished screen
//! into a screen nobody knows was unfinished.

use cesauth_frontend::tenancy_console::overview::{OverviewCounts, PlanBreakdownRow};
use serde::Deserialize;
use worker::{Request, Response, Result, RouteContext};


pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let locale = crate::i18n::resolve_locale(&req);
    crate::routes::admin::operator_json_api::shell(
        &req, &ctx, cesauth_core::i18n::MessageKey::TenancyOverviewPageTitle, locale,
    ).await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    // Return tenant count + basic system info for the operator overview.
    use cesauth_cf::tenancy::CloudflareTenantRepository;
    use cesauth_core::tenancy::TenantRepository;
    let repo = CloudflareTenantRepository::new(&ctx.env);
    let tenants = repo.list_active().await.unwrap_or_default();
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
