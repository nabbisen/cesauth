//! Billing value types.

use serde::{Deserialize, Serialize};

use crate::types::{Id, UnixSeconds};

// ---------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------

/// A catalog entry. Globally scoped; tenants subscribe to plans, not
/// the other way around.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Plan {
    /// Stable id. Usually matches [`PlanId`] for the built-ins; custom
    /// plans get UUIDs.
    pub id:          Id,
    /// Short machine key. Referenced by billing integrations and shown
    /// in URLs.
    pub slug:        String,
    pub display_name: String,
    /// Soft-archived plans stay around so old subscriptions still
    /// resolve; new subscriptions should not be created against them.
    pub active:      bool,
    /// The feature toggles this plan unlocks.
    pub features:    Vec<FeatureFlag>,
    /// Numeric quotas keyed by a stable string. Missing key ⇒
    /// unlimited for that plan.
    pub quotas:      Vec<Quota>,
    /// Human-readable price description. cesauth does NOT compute
    /// invoices — this is a display hint for the admin UI.
    pub price_description: Option<String>,
    pub created_at:  UnixSeconds,
    pub updated_at:  UnixSeconds,
}

/// Built-in plan slugs shipped with 0.4.0. Operators may add their
/// own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanId {
    Free,
    Trial,
    Pro,
    Enterprise,
}

impl PlanId {
    pub fn slug(self) -> &'static str {
        match self {
            PlanId::Free       => "free",
            PlanId::Trial      => "trial",
            PlanId::Pro        => "pro",
            PlanId::Enterprise => "enterprise",
        }
    }
}

#[derive(Debug)]
pub struct PlanCatalog;
impl PlanCatalog {
    /// The four built-in plans. Seeded by migration 0003.
    pub const ALL: &'static [PlanId] = &[
        PlanId::Free, PlanId::Trial, PlanId::Pro, PlanId::Enterprise,
    ];
}

/// A boolean capability gated by plan. Strings, not enum, so product
/// teams can add flags without a Rust release.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FeatureFlag(pub String);

impl FeatureFlag {
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn as_str(&self) -> &str { &self.0 }
}

/// A numeric limit. `value = -1` means "unlimited"; positive values
/// are hard caps. `name` is a stable key (e.g. `"max_users"`,
/// `"max_organizations"`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Quota {
    pub name:  String,
    pub value: i64,
}

impl Quota {
    pub const UNLIMITED: i64 = -1;
    pub fn is_unlimited(&self) -> bool { self.value == Self::UNLIMITED }
}

// ---------------------------------------------------------------------
// Subscription
// ---------------------------------------------------------------------

/// A tenant's ongoing relationship to a plan. One active row per
/// tenant; older rows live in `subscription_history`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subscription {
    pub id:         Id,
    pub tenant_id:  Id,
    pub plan_id:    Id,
    pub lifecycle:  SubscriptionLifecycle,
    pub status:     SubscriptionStatus,
    pub started_at: UnixSeconds,
    /// Null for evergreen subscriptions; a set value means the
    /// subscription expires at that instant unless renewed.
    pub current_period_end: Option<UnixSeconds>,
    /// Null unless `lifecycle == Trial`.
    pub trial_ends_at:      Option<UnixSeconds>,
    /// When this subscription was last moved into its current status.
    pub status_changed_at:  UnixSeconds,
    pub updated_at:         UnixSeconds,
}

/// What kind of subscription this is. Spec §8.6 is explicit that
/// trial-vs-real must be a separate axis from active-vs-cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionLifecycle {
    Trial,
    Paid,
    Grace,     // grace period after expiration before hard suspend
}

/// Current state of the subscription. Independent of lifecycle: a
/// trial can be Active or Cancelled; a paid plan can be Active,
/// PastDue, or Cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    PastDue,
    Cancelled,
    Expired,
}

// ---------------------------------------------------------------------
// History
// ---------------------------------------------------------------------

/// One event in the subscription's lifetime. Inserted on plan
/// change, status change, and trial conversion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionHistoryEntry {
    pub id:            Id,
    pub subscription_id: Id,
    pub tenant_id:     Id,
    pub event:         String,          // short slug — "plan_changed", "cancelled", "trial_expired"
    pub from_plan_id:  Option<Id>,
    pub to_plan_id:    Option<Id>,
    pub from_status:   Option<SubscriptionStatus>,
    pub to_status:     Option<SubscriptionStatus>,
    /// Actor that initiated the change. User id for human-driven
    /// events; "system" for automated transitions.
    pub actor:         String,
    pub occurred_at:   UnixSeconds,
}
