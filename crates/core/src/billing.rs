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
//! # What's NOT in 0.4.0
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
