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
