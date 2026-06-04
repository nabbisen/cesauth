//! Billing domain tests.

use super::types::*;

#[test]
fn quota_unlimited_sentinel() {
    let q = Quota { name: "max_users".into(), value: Quota::UNLIMITED };
    assert!(q.is_unlimited());
    let q = Quota { name: "max_users".into(), value: 10 };
    assert!(!q.is_unlimited());
}

#[test]
fn plan_id_slugs_match_conventional_names() {
    assert_eq!(PlanId::Free.slug(),       "free");
    assert_eq!(PlanId::Trial.slug(),      "trial");
    assert_eq!(PlanId::Pro.slug(),        "pro");
    assert_eq!(PlanId::Enterprise.slug(), "enterprise");
}

#[test]
fn subscription_lifecycle_and_status_are_orthogonal() {
    // Spec §8.6 is explicit: "試用状態と本契約状態を分ける".
    // This test is documentation more than assertion — the two enums
    // exist independently and can combine freely. If someone tries to
    // merge them later, the whole test file fails to compile.
    let s = Subscription {
        id: "s".into(), tenant_id: "t".into(), plan_id: "p".into(),
        lifecycle: SubscriptionLifecycle::Trial,
        status:    SubscriptionStatus::PastDue,
        started_at: 0, current_period_end: None, trial_ends_at: Some(1000),
        status_changed_at: 0, updated_at: 0,
    };
    // Just use the values so they're not dead-code warnings.
    assert_eq!(s.lifecycle, SubscriptionLifecycle::Trial);
    assert_eq!(s.status,    SubscriptionStatus::PastDue);
}

#[test]
fn subscription_lifecycle_serializes_snake_case() {
    let s = SubscriptionLifecycle::Paid;
    let j = serde_json::to_string(&s).unwrap();
    assert_eq!(j, r#""paid""#);
    let s: SubscriptionLifecycle = serde_json::from_str(r#""grace""#).unwrap();
    assert_eq!(s, SubscriptionLifecycle::Grace);
}

#[test]
fn plan_catalog_lists_four_builtins() {
    assert_eq!(PlanCatalog::ALL.len(), 4);
}

// ── RFC 048: change_plan + is_feature_enabled + check_quota service tests ──

use std::cell::RefCell;
use std::collections::HashMap;

#[derive(Default)]
struct StubSubs(RefCell<HashMap<String, super::types::Subscription>>);
#[derive(Default)]
struct StubPlans(HashMap<String, super::types::Plan>);
#[derive(Default)]
struct StubHistory(RefCell<Vec<super::types::SubscriptionHistoryEntry>>);

use super::ports::{PlanRepository, SubscriptionHistoryRepository, SubscriptionRepository};
use crate::ports::PortResult;

impl SubscriptionRepository for StubSubs {
    async fn create(&self, s: &super::types::Subscription) -> PortResult<()> {
        self.0.borrow_mut().insert(s.tenant_id.clone(), s.clone()); Ok(())
    }
    async fn current_for_tenant(&self, tenant_id: &str) -> PortResult<Option<super::types::Subscription>> {
        Ok(self.0.borrow().get(tenant_id).cloned())
    }
    async fn set_plan(&self, _: &str, plan_id: &str, _: i64) -> PortResult<()> {
        // Find first match and update
        for sub in self.0.borrow_mut().values_mut() {
            sub.plan_id = plan_id.to_owned();
        }
        Ok(())
    }
    async fn set_status(&self, _: &str, status: super::types::SubscriptionStatus, _: i64) -> PortResult<()> {
        for sub in self.0.borrow_mut().values_mut() { sub.status = status; }
        Ok(())
    }
}

impl PlanRepository for StubPlans {
    async fn get(&self, id: &str) -> PortResult<Option<super::types::Plan>> { Ok(self.0.get(id).cloned()) }
    async fn find_by_slug(&self, slug: &str) -> PortResult<Option<super::types::Plan>> {
        Ok(self.0.values().find(|p| p.slug == slug).cloned())
    }
    async fn list_active(&self) -> PortResult<Vec<super::types::Plan>> {
        Ok(self.0.values().filter(|p| p.active).cloned().collect())
    }
}

impl SubscriptionHistoryRepository for StubHistory {
    async fn append(&self, entry: &super::types::SubscriptionHistoryEntry) -> PortResult<()> {
        self.0.borrow_mut().push(entry.clone()); Ok(())
    }
    async fn list_for_subscription(&self, _: &str) -> PortResult<Vec<super::types::SubscriptionHistoryEntry>> {
        Ok(self.0.borrow().clone())
    }
}

fn stub_subscription(tenant_id: &str, plan_id: &str) -> super::types::Subscription {
    super::types::Subscription {
        id: "sub-1".to_owned(), tenant_id: tenant_id.to_owned(), plan_id: plan_id.to_owned(),
        lifecycle: super::types::SubscriptionLifecycle::Paid,
        status: super::types::SubscriptionStatus::Active,
        started_at: 0, current_period_end: None, trial_ends_at: None,
        status_changed_at: 0, updated_at: 0,
    }
}

fn stub_plan(id: &str, features: &[super::types::FeatureFlag], quotas: &[(&str, i64)]) -> super::types::Plan {
    super::types::Plan {
        id: id.to_owned(), slug: id.to_owned(), display_name: id.to_owned(),
        active: true,
        features: features.to_vec(),
        quotas: quotas.iter().map(|(n, v)| super::types::Quota { name: n.to_string(), value: *v }).collect(),
        price_description: None, created_at: 0, updated_at: 0,
    }
}

#[tokio::test]
async fn change_plan_updates_subscription_and_records_history() {
    let mut plans = HashMap::new();
    plans.insert("plan-a".to_owned(), stub_plan("plan-a", &[], &[]));
    plans.insert("plan-b".to_owned(), stub_plan("plan-b", &[], &[]));
    let plan_repo = StubPlans(plans);

    let subs = StubSubs::default();
    subs.create(&stub_subscription("t-1", "plan-a")).await.unwrap();

    let history = StubHistory::default();
    crate::billing::change_plan(&subs, &plan_repo, &history, "t-1", "plan-b", "admin", 1000).await.unwrap();

    // Subscription updated.
    let sub = subs.current_for_tenant("t-1").await.unwrap().unwrap();
    assert_eq!(sub.plan_id, "plan-b");

    // History recorded.
    let hist = history.list_for_subscription("sub-1").await.unwrap();
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].from_plan_id.as_deref(), Some("plan-a"));
    assert_eq!(hist[0].to_plan_id.as_deref(), Some("plan-b"));
}

#[tokio::test]
async fn change_plan_fails_when_no_subscription() {
    let plan_repo = StubPlans({ let mut m = HashMap::new(); m.insert("p".to_owned(), stub_plan("p", &[], &[])); m });
    let subs = StubSubs::default(); // no subscription
    let history = StubHistory::default();
    let result = crate::billing::change_plan(&subs, &plan_repo, &history, "t-missing", "p", "a", 0).await;
    assert!(result.is_err(), "no subscription must return error");
}

#[tokio::test]
async fn change_plan_fails_when_plan_not_found() {
    let subs = StubSubs::default();
    subs.create(&stub_subscription("t-1", "plan-a")).await.unwrap();
    let plan_repo = StubPlans(HashMap::new()); // empty
    let history = StubHistory::default();
    let result = crate::billing::change_plan(&subs, &plan_repo, &history, "t-1", "nonexistent", "a", 0).await;
    assert!(result.is_err(), "unknown plan must return error");
}

#[tokio::test]
async fn is_feature_enabled_true_for_plan_with_flag() {
    use super::types::FeatureFlag;
    let mut plans = HashMap::new();
    plans.insert("pro".to_owned(), stub_plan("pro", &[FeatureFlag::new("pro_features")], &[]));
    let plan_repo = StubPlans(plans);
    let subs = StubSubs::default();
    subs.create(&stub_subscription("t-1", "pro")).await.unwrap();

    assert!(crate::billing::is_feature_enabled(&subs, &plan_repo, "t-1", FeatureFlag::new("pro_features")).await);
}

#[tokio::test]
async fn is_feature_enabled_false_for_plan_without_flag() {
    use super::types::FeatureFlag;
    let mut plans = HashMap::new();
    plans.insert("free".to_owned(), stub_plan("free", &[FeatureFlag::new("core")], &[]));
    let plan_repo = StubPlans(plans);
    let subs = StubSubs::default();
    subs.create(&stub_subscription("t-1", "free")).await.unwrap();

    assert!(!crate::billing::is_feature_enabled(&subs, &plan_repo, "t-1", FeatureFlag::new("pro_features")).await);
}

#[tokio::test]
async fn is_feature_enabled_true_when_no_subscription() {
    use super::types::FeatureFlag;
    let plan_repo = StubPlans(HashMap::new());
    let subs = StubSubs::default(); // no subscription
    assert!(crate::billing::is_feature_enabled(&subs, &plan_repo, "t-new", FeatureFlag::new("pro_features")).await,
        "no subscription = unrestricted (all features allowed)");
}

#[tokio::test]
async fn check_quota_allowed_when_under_limit() {
    let mut plans = HashMap::new();
    plans.insert("free".to_owned(), stub_plan("free", &[], &[("max_users", 5i64)]));
    let plan_repo = StubPlans(plans);
    let subs = StubSubs::default();
    subs.create(&stub_subscription("t-1", "free")).await.unwrap();

    let decision = crate::billing::check_quota(&subs, &plan_repo, "t-1", "max_users", 4).await;
    assert!(decision.is_allowed(), "4 of 5 should be allowed");
}

#[tokio::test]
async fn check_quota_denied_when_at_limit() {
    let mut plans = HashMap::new();
    plans.insert("free".to_owned(), stub_plan("free", &[], &[("max_users", 5i64)]));
    let plan_repo = StubPlans(plans);
    let subs = StubSubs::default();
    subs.create(&stub_subscription("t-1", "free")).await.unwrap();

    let decision = crate::billing::check_quota(&subs, &plan_repo, "t-1", "max_users", 5).await;
    assert!(!decision.is_allowed(), "5 of 5 should be denied (would become 6)");
}

#[tokio::test]
async fn check_quota_allowed_when_no_subscription() {
    let plan_repo = StubPlans(HashMap::new());
    let subs = StubSubs::default();
    let decision = crate::billing::check_quota(&subs, &plan_repo, "t-new", "max_users", 9999).await;
    assert!(decision.is_allowed(), "no subscription = unrestricted");
}
