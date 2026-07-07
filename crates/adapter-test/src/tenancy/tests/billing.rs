//! Originally part of `crates/adapter-test/src/tenancy/tests.rs`.
//! Split into a sibling file in v0.78.0 (test-file modularization track).

use super::super::*;     // reaches `tenancy` (the module under test)
#[allow(unused_imports)]
use super::common::*;    // shared fixtures

// Billing — round-trip + history append
// ---------------------------------------------------------------------

#[tokio::test]
async fn plan_repository_round_trips_a_seeded_plan() {
    let plans = InMemoryPlanRepository::default();
    plans.insert(Plan {
        id: "plan-pro".into(), slug: PlanId::Pro.slug().into(),
        display_name: "Pro".into(), active: true,
        features: vec![],
        quotas: vec![Quota { name: "max_users".into(), value: 100 }],
        price_description: None,
        created_at: 0, updated_at: 0,
    });
    let got = plans.find_by_slug("pro").await.unwrap().unwrap();
    assert_eq!(got.id, "plan-pro");
    assert_eq!(got.quotas.len(), 1);
    assert!(plans.list_active().await.unwrap().len() == 1);
}

#[tokio::test]
async fn one_active_subscription_per_tenant() {
    let subs = InMemorySubscriptionRepository::default();
    let s1 = Subscription {
        id: "s1".into(), tenant_id: "t-1".into(), plan_id: "plan-free".into(),
        lifecycle: SubscriptionLifecycle::Trial,
        status:    SubscriptionStatus::Active,
        started_at: 0, current_period_end: None, trial_ends_at: Some(1000),
        status_changed_at: 0, updated_at: 0,
    };
    subs.create(&s1).await.unwrap();
    // Second subscription for the same tenant must conflict.
    let s2 = Subscription { id: "s2".into(), ..s1.clone() };
    let err = subs.create(&s2).await.unwrap_err();
    assert!(matches!(err, PortError::Conflict));
}

#[tokio::test]
async fn subscription_history_records_state_changes() {
    let history = InMemorySubscriptionHistoryRepository::default();
    history.append(&SubscriptionHistoryEntry {
        id: "h1".into(), subscription_id: "s1".into(), tenant_id: "t-1".into(),
        event: "plan_changed".into(),
        from_plan_id: Some("plan-trial".into()),
        to_plan_id:   Some("plan-pro".into()),
        from_status: None, to_status: None,
        actor: "u-alice".into(), occurred_at: 1000,
    }).await.unwrap();
    history.append(&SubscriptionHistoryEntry {
        id: "h2".into(), subscription_id: "s1".into(), tenant_id: "t-1".into(),
        event: "status_changed".into(),
        from_plan_id: None, to_plan_id: None,
        from_status: Some(SubscriptionStatus::Active),
        to_status:   Some(SubscriptionStatus::PastDue),
        actor: "system".into(), occurred_at: 2000,
    }).await.unwrap();

    let entries = history.list_for_subscription("s1").await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].event, "plan_changed");
    assert_eq!(entries[1].event, "status_changed");
}

#[tokio::test]
async fn plan_catalog_lists_four_builtins() {
    assert_eq!(PlanCatalog::ALL.len(), 4);
}

// ---------------------------------------------------------------------
