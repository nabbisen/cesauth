//! Subscription and plan domain (spec §3.6).
//!
//! Plans and Subscriptions are **strictly separated** (spec §8.6):
//!
//!   * A [`Plan`] is a catalog entry. Feature flags, quotas, price.
//!     Global to cesauth; every tenant picks from the same menu.
//!   * A [`Subscription`] is a per-tenant relationship to a plan:
//!     "Tenant T is on plan P, from date X, with status Y". It is
//!     never "the tenant's plan fields merged in"; it references the
//!     plan by id.
//!
//! That separation makes plan upgrades a single row update to the
//! subscription (not a migration of tenant data) and makes plan
//! deprecations safe (old subscriptions keep pointing at the archived
//! plan row).
//!
//! A [`SubscriptionHistoryEntry`] is appended on every state change,
//! so the audit question "when did this tenant move plans?" has a
//! deterministic answer.
//!
//! # What's NOT in 0.5.0
//!
//! * Actual billing, invoicing, or payment-provider integration. The
//!   module is purely the state machine + catalog. Hooking to Stripe
//!   / Paddle / whatever is a platform-operator decision and lands
//!   in a 0.5+ extension.
//! * Quota enforcement at runtime. The plan carries the numbers;
//!   the runtime checks against them are a follow-up.
//! * Self-serve plan change. The admin surface that drives plan
//!   changes arrives with the multi-tenant admin console.

pub mod ports;
pub mod quota;
pub mod types;

pub use quota::{quota_decision, QuotaDecision};

pub use ports::{PlanRepository, SubscriptionHistoryRepository, SubscriptionRepository};
pub use types::{
    FeatureFlag, Plan, PlanId, PlanCatalog, Quota, Subscription, SubscriptionLifecycle,
    SubscriptionStatus, SubscriptionHistoryEntry,
};

#[cfg(test)]
mod tests;

// ── High-level service functions (RFC 048) ─────────────────────────────────

use crate::error::{CoreError, CoreResult};
use crate::types::UnixSeconds;
use uuid::Uuid;

/// Change a tenant's subscription plan.
///
/// Finds the tenant's current subscription, updates it to the new plan,
/// and appends a `SubscriptionHistoryEntry`.  Both operations are
/// best-effort: if the history append fails the plan change still succeeds
/// (history is an audit trail, not a lock).
///
/// Returns `Err(CoreError::InvalidRequest)` when no current subscription
/// exists for the tenant.
pub async fn change_plan<SR, PR, SHR>(
    subs_repo:    &SR,
    plan_repo:    &PR,
    history_repo: &SHR,
    tenant_id:    &str,
    to_plan_id:   &str,
    actor:        &str,
    now:          UnixSeconds,
) -> CoreResult<()>
where
    SR:  ports::SubscriptionRepository,
    PR:  ports::PlanRepository,
    SHR: ports::SubscriptionHistoryRepository,
{
    // Validate destination plan exists.
    let _new_plan = plan_repo
        .get(to_plan_id)
        .await
        .map_err(|_| CoreError::Internal)?
        .ok_or(CoreError::InvalidRequest("plan not found"))?;

    let sub = subs_repo
        .current_for_tenant(tenant_id)
        .await
        .map_err(|_| CoreError::Internal)?
        .ok_or(CoreError::InvalidRequest("no active subscription for tenant"))?;

    let from_plan_id = sub.plan_id.clone();

    // Update the subscription row.
    subs_repo
        .set_plan(&sub.id, to_plan_id, now)
        .await
        .map_err(|_| CoreError::Internal)?;

    // Append history entry (best-effort — ignore failure).
    let entry = types::SubscriptionHistoryEntry {
        id:              Uuid::new_v4().to_string(),
        subscription_id: sub.id.clone(),
        tenant_id:       tenant_id.to_owned(),
        event:           "plan_changed".to_owned(),
        from_plan_id:    Some(from_plan_id),
        to_plan_id:      Some(to_plan_id.to_owned()),
        from_status:     None,
        to_status:       None,
        actor:           actor.to_owned(),
        occurred_at:     now,
    };
    let _ = history_repo.append(&entry).await;

    Ok(())
}

/// Check whether a feature flag is enabled for a tenant's current plan.
///
/// Returns `true` if the tenant has no subscription (operator-provisioned
/// tenants are unrestricted by default) or if the plan explicitly includes
/// the feature.
pub async fn is_feature_enabled<SR, PR>(
    subs_repo: &SR,
    plan_repo: &PR,
    tenant_id: &str,
    flag:      types::FeatureFlag,
) -> bool
where
    SR: ports::SubscriptionRepository,
    PR: ports::PlanRepository,
{
    let Ok(Some(sub)) = subs_repo.current_for_tenant(tenant_id).await else {
        return true; // no subscription = unrestricted
    };
    let Ok(Some(plan)) = plan_repo.get(&sub.plan_id).await else {
        return true; // plan not found = unrestricted (fail-open for config errors)
    };
    plan.features.contains(&flag)
}

/// Check whether adding one more resource would exceed the named quota.
///
/// Returns `QuotaDecision::Allowed` when the tenant has no subscription
/// or the plan has no quota entry for `quota_name`.
pub async fn check_quota<SR, PR>(
    subs_repo:  &SR,
    plan_repo:  &PR,
    tenant_id:  &str,
    quota_name: &str,
    current:    i64,
) -> quota::QuotaDecision
where
    SR: ports::SubscriptionRepository,
    PR: ports::PlanRepository,
{
    let plan = async {
        let sub = subs_repo.current_for_tenant(tenant_id).await.ok()??;
        plan_repo.get(&sub.plan_id).await.ok()?
    }.await;

    quota::quota_decision(plan.as_ref(), quota_name, current)
}
