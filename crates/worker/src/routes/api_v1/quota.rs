//! Plan-quota enforcement.
//!
//! Spec §6.7: "クォータ管理". Each tenant's subscription points at a
//! plan; the plan carries `Quota { name, value }` rows. When a
//! create operation would push the tenant past its quota, we deny
//! with 409 Conflict and a `quota_exceeded:<name>` reason.
//!
//! Quota names are stable strings:
//!
//! | Name                | Counted from D1                                     |
//! |---------------------|-----------------------------------------------------|
//! | `max_users`         | `users WHERE tenant_id = ? AND status != 'deleted'` |
//! | `max_organizations` | `organizations WHERE tenant_id = ? AND status != 'deleted'` |
//! | `max_groups`        | `groups WHERE tenant_id = ? AND status != 'deleted'` |
//!
//! A value of `-1` (`Quota::UNLIMITED`) skips the check. A missing
//! row in the plan also skips — "if the plan didn't say no, allow".
//!
//! ## Why a SELECT COUNT(*) per create
//!
//! It's the correct thing for a low-volume admin API. `users`-create
//! through this surface is already a one-per-second-tops operation
//! (operator-driven, not end-user signup), and the counts are
//! already-indexed. Caching would force invalidation discipline that
//! 0.7.0 has not earned yet.
//!
//! When user self-signup lands on this surface, we will need to
//! migrate to a counter-with-occasional-reconcile pattern; until
//! then, the simple read wins.

use cesauth_core::billing::ports::{PlanRepository, SubscriptionRepository};
use cesauth_core::ports::PortResult;
use worker::Env;

use crate::routes::api_v1::auth::{conflict, port_error_response};

/// Returned by [`check_quota`].
#[derive(Debug)]
pub enum QuotaOutcome {
    /// Operation is within the limit (or unlimited / no plan / no
    /// quota row).
    Ok,
    /// Limit was hit; caller should respond with 409.
    Exceeded { name: &'static str, limit: i64, current: i64 },
}

/// Check whether a creation operation against `tenant_id` would
/// exceed `quota_name`. The current count is supplied by the caller
/// (each callsite reads from a different table — users / orgs /
/// groups — so a function pointer is overkill).
///
/// The decision logic itself lives in
/// [`cesauth_core::billing::quota_decision`] (pure over its inputs);
/// this function is the impure half that pulls the inputs from D1.
pub async fn check_quota(
    env:        &Env,
    tenant_id:  &str,
    quota_name: &'static str,
    current:    i64,
) -> PortResult<QuotaOutcome> {
    use cesauth_cf::billing::{CloudflarePlanRepository, CloudflareSubscriptionRepository};
    use cesauth_core::billing::{quota_decision, QuotaDecision};

    let subs  = CloudflareSubscriptionRepository::new(env);
    let plans = CloudflarePlanRepository::new(env);

    // No subscription -> no plan -> allow. The tenant might have
    // been operator-provisioned without one. Catalog data drives the
    // decision; we never hardcode policy here.
    let plan = match subs.current_for_tenant(tenant_id).await? {
        Some(sub) => plans.get(&sub.plan_id).await?,
        None      => None,
    };

    Ok(match quota_decision(plan.as_ref(), quota_name, current) {
        QuotaDecision::Allowed                                  => QuotaOutcome::Ok,
        QuotaDecision::Denied { limit, current, .. } => QuotaOutcome::Exceeded {
            name: quota_name, limit, current,
        },
    })
}

/// Convenience wrapper: turn a `QuotaOutcome::Exceeded` into a 409
/// response. Returns `None` on `Ok`.
pub fn into_response_if_exceeded(outcome: QuotaOutcome) -> Option<worker::Result<worker::Response>> {
    match outcome {
        QuotaOutcome::Ok => None,
        QuotaOutcome::Exceeded { name, .. } => {
            Some(conflict(&format!("quota_exceeded:{name}")))
        }
    }
}

/// Surface either the inner `Ok` value or a 500-from-PortError as a
/// `Response`. Used in handlers as
/// `match unwrap_storage(env, op).await? { Ok(v) => ..., Err(r) => r }`.
pub async fn unwrap_storage<T>(
    res: PortResult<T>,
) -> worker::Result<std::result::Result<T, worker::Response>> {
    match res {
        Ok(v)  => Ok(Ok(v)),
        Err(e) => Ok(Err(port_error_response(e)?)),
    }
}

// -------------------------------------------------------------------------
// Concrete counters
// -------------------------------------------------------------------------

pub async fn count_users(env: &Env, tenant_id: &str) -> PortResult<i64> {
    count_with_status(env, "users", tenant_id).await
}

pub async fn count_organizations(env: &Env, tenant_id: &str) -> PortResult<i64> {
    count_with_status(env, "organizations", tenant_id).await
}

pub async fn count_groups(env: &Env, tenant_id: &str) -> PortResult<i64> {
    count_with_status(env, "groups", tenant_id).await
}

async fn count_with_status(env: &Env, table: &str, tenant_id: &str) -> PortResult<i64> {
    use cesauth_core::ports::PortError;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct CountRow { c: i64 }

    let db = env.d1("DB").map_err(|_| PortError::Unavailable)?;
    let sql = format!(
        "SELECT COUNT(*) AS c FROM {table} \
         WHERE tenant_id = ?1 AND status != 'deleted'"
    );
    let rows = db.prepare(&sql)
        .bind(&[tenant_id.into()]).map_err(|_| PortError::Unavailable)?
        .all().await.map_err(|_| PortError::Unavailable)?;
    let rows: Vec<CountRow> = rows.results().map_err(|_| PortError::Serialization)?;
    Ok(rows.into_iter().next().map(|r| r.c).unwrap_or(0))
}
