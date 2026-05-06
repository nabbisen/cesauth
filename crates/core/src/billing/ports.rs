//! Billing repository ports.

use crate::ports::PortResult;
use crate::types::UnixSeconds;

use super::types::{
    Plan, Subscription, SubscriptionHistoryEntry, SubscriptionStatus,
};

pub trait PlanRepository {
    async fn get(&self, id: &str) -> PortResult<Option<Plan>>;
    async fn find_by_slug(&self, slug: &str) -> PortResult<Option<Plan>>;
    /// Active plans (`active = true`). Archived plans are invisible
    /// to the new-subscription UI but remain addressable by id for
    /// existing subscriptions that reference them.
    async fn list_active(&self) -> PortResult<Vec<Plan>>;
}

pub trait SubscriptionRepository {
    async fn create(&self, s: &Subscription) -> PortResult<()>;

    /// Exactly one current subscription per tenant, or None if the
    /// tenant has never subscribed. (A freshly-created tenant is
    /// expected to get a Trial subscription immediately; 0.5.0's
    /// tenant-create helper does NOT yet do this — see the CHANGELOG
    /// for the deferred-to-0.6.0 wiring item.)
    async fn current_for_tenant(&self, tenant_id: &str) -> PortResult<Option<Subscription>>;

    async fn set_plan(
        &self,
        subscription_id: &str,
        plan_id:         &str,
        now_unix:        UnixSeconds,
    ) -> PortResult<()>;

    async fn set_status(
        &self,
        subscription_id: &str,
        status:          SubscriptionStatus,
        now_unix:        UnixSeconds,
    ) -> PortResult<()>;
}

pub trait SubscriptionHistoryRepository {
    async fn append(&self, entry: &SubscriptionHistoryEntry) -> PortResult<()>;

    /// Oldest-first; typical audit-page ordering is reverse, the
    /// caller decides. Pagination is deferred.
    async fn list_for_subscription(
        &self,
        subscription_id: &str,
    ) -> PortResult<Vec<SubscriptionHistoryEntry>>;
}
