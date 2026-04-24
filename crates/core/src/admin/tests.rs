//! Unit tests for the admin-console policy and service layer.

use super::policy::{
    evaluate_bucket_safety, evaluate_cost_thresholds, format_change, format_metric, role_allows,
};
use super::types::{
    AdminAction, AlertLevel, BucketSafetyState, Metric, MetricUnit, Role, ServiceId,
    Threshold, threshold_names,
};

// -------------------------------------------------------------------------
// Role matrix (§6.1, §6.2)
// -------------------------------------------------------------------------

#[test]
fn every_role_may_view_console() {
    for r in [Role::ReadOnly, Role::Security, Role::Operations, Role::Super] {
        assert!(role_allows(r, AdminAction::ViewConsole));
    }
}

#[test]
fn only_super_may_manage_admin_tokens() {
    assert!(!role_allows(Role::ReadOnly,   AdminAction::ManageAdminTokens));
    assert!(!role_allows(Role::Security,   AdminAction::ManageAdminTokens));
    assert!(!role_allows(Role::Operations, AdminAction::ManageAdminTokens));
    assert!( role_allows(Role::Super,      AdminAction::ManageAdminTokens));
}

#[test]
fn security_may_verify_but_not_edit_bucket_safety() {
    assert!( role_allows(Role::Security,   AdminAction::VerifyBucketSafety));
    assert!(!role_allows(Role::Security,   AdminAction::EditBucketSafety));
    assert!( role_allows(Role::Operations, AdminAction::EditBucketSafety));
    assert!( role_allows(Role::Super,      AdminAction::EditBucketSafety));
}

#[test]
fn read_only_cannot_change_anything() {
    for a in [
        AdminAction::VerifyBucketSafety,
        AdminAction::EditBucketSafety,
        AdminAction::EditThreshold,
        AdminAction::CreateUser,
        AdminAction::RevokeSession,
        AdminAction::ManageAdminTokens,
    ] {
        assert!(!role_allows(Role::ReadOnly, a), "ReadOnly should not be allowed {a:?}");
    }
}

#[test]
fn role_roundtrips_through_str() {
    for r in [Role::ReadOnly, Role::Security, Role::Operations, Role::Super] {
        assert_eq!(Role::from_str(r.as_str()), Some(r));
    }
    assert_eq!(Role::from_str("nope"), None);
}

// -------------------------------------------------------------------------
// Cost thresholds
// -------------------------------------------------------------------------

fn threshold(name: &str, value: i64) -> Threshold {
    Threshold {
        name: name.into(),
        value,
        unit: "count".into(),
        description: None,
        updated_at: 0,
    }
}

#[test]
fn d1_row_count_above_threshold_fires_warn() {
    let thresholds = vec![threshold(threshold_names::D1_ROW_COUNT_WARN, 1_000)];
    let metrics = vec![
        Metric { key: "row_count.users".into(), value: 500,  unit: MetricUnit::Count },
        Metric { key: "row_count.grants".into(), value: 2_000, unit: MetricUnit::Count },
    ];
    let alerts = evaluate_cost_thresholds(ServiceId::D1, &metrics, &thresholds, 100);
    assert_eq!(alerts.len(), 1, "only one metric crossed the threshold");
    assert_eq!(alerts[0].level, AlertLevel::Warn);
}

#[test]
fn r2_bytes_threshold_triggers_even_without_other_metrics() {
    let thresholds = vec![Threshold {
        name: threshold_names::R2_BYTES_WARN.into(),
        value: 10,
        unit: "bytes".into(),
        description: None,
        updated_at: 0,
    }];
    let metrics = vec![
        Metric { key: "bytes".into(), value: 20, unit: MetricUnit::Bytes },
    ];
    let alerts = evaluate_cost_thresholds(ServiceId::R2, &metrics, &thresholds, 0);
    assert_eq!(alerts.len(), 1);
}

#[test]
fn unknown_metric_key_is_informational_and_never_alerts() {
    let thresholds: Vec<Threshold> = vec![];
    let metrics = vec![
        Metric { key: "something_bespoke".into(), value: u64::MAX, unit: MetricUnit::Count },
    ];
    assert!(evaluate_cost_thresholds(ServiceId::Workers, &metrics, &thresholds, 0).is_empty());
}

// -------------------------------------------------------------------------
// Bucket safety
// -------------------------------------------------------------------------

fn bucket(name: &str, public: bool, last_verified: Option<i64>) -> BucketSafetyState {
    BucketSafetyState {
        bucket:               name.into(),
        public,
        cors_configured:      false,
        bucket_lock:          false,
        lifecycle_configured: false,
        event_notifications:  false,
        notes:                None,
        last_verified_at:     last_verified,
        last_verified_by:     None,
        updated_at:           0,
    }
}

fn staleness_thresholds(days: i64) -> Vec<Threshold> {
    vec![Threshold {
        name: threshold_names::BUCKET_VERIFICATION_STALENESS_DAYS.into(),
        value: days,
        unit: "days".into(),
        description: None,
        updated_at: 0,
    }]
}

#[test]
fn never_verified_bucket_is_stale() {
    let s = bucket("AUDIT", false, None);
    let t = staleness_thresholds(30);
    let alerts = evaluate_bucket_safety(&s, &t, 1_000_000);
    assert!(alerts.iter().any(|a| a.title.contains("stale")));
}

#[test]
fn freshly_verified_bucket_is_not_stale() {
    let s = bucket("AUDIT", false, Some(1_000_000));
    let t = staleness_thresholds(30);
    let alerts = evaluate_bucket_safety(&s, &t, 1_000_000);
    // The only possible alert here would be staleness, and it should NOT fire.
    assert!(alerts.iter().all(|a| !a.title.contains("stale")),
        "fresh verification should not raise a staleness alert; got {:?}", alerts);
}

#[test]
fn public_audit_bucket_raises_critical() {
    let s = bucket("AUDIT", true, Some(1_000_000));
    let t = staleness_thresholds(30);
    let alerts = evaluate_bucket_safety(&s, &t, 1_000_000);
    assert!(alerts.iter().any(|a| a.level == AlertLevel::Critical),
        "attested-public bucket must raise a Critical alert");
}

#[test]
fn staleness_threshold_boundary() {
    // 30 days = 2_592_000 seconds. If last_verified_at is exactly that
    // far in the past, we consider it still fresh (`>` not `>=`).
    let now = 10_000_000;
    let t = staleness_thresholds(30);
    let exactly_at_boundary = bucket("AUDIT", false, Some(now - 2_592_000));
    let alerts_boundary = evaluate_bucket_safety(&exactly_at_boundary, &t, now);
    assert!(alerts_boundary.iter().all(|a| !a.title.contains("stale")));

    let one_past = bucket("AUDIT", false, Some(now - 2_592_001));
    let alerts_past = evaluate_bucket_safety(&one_past, &t, now);
    assert!(alerts_past.iter().any(|a| a.title.contains("stale")));
}

// -------------------------------------------------------------------------
// Formatters
// -------------------------------------------------------------------------

#[test]
fn format_metric_count_adds_thousands_separator() {
    assert_eq!(format_metric(1_234_567, MetricUnit::Count), "1,234,567");
    assert_eq!(format_metric(0,         MetricUnit::Count), "0");
    assert_eq!(format_metric(999,       MetricUnit::Count), "999");
    assert_eq!(format_metric(1_000,     MetricUnit::Count), "1,000");
}

#[test]
fn format_metric_bytes_picks_unit() {
    assert_eq!(format_metric(512,            MetricUnit::Bytes), "512 B");
    // 1.5 KiB, exact
    assert_eq!(format_metric(1_536,          MetricUnit::Bytes), "1.50 KiB");
    // ~2 MiB
    assert!(format_metric(2 * 1024 * 1024,   MetricUnit::Bytes).contains("MiB"));
    assert!(format_metric(3 * 1024 * 1024 * 1024, MetricUnit::Bytes).contains("GiB"));
}

#[test]
fn format_change_handles_missing_baseline_and_zero() {
    assert_eq!(format_change(None),      "—");
    assert_eq!(format_change(Some(0)),   "unchanged");
    assert_eq!(format_change(Some(123)), "+12.3%");
    assert_eq!(format_change(Some(-45)), "-4.5%");
}

// -------------------------------------------------------------------------
// Alert counts
// -------------------------------------------------------------------------

#[test]
fn alert_counts_group_by_level() {
    use super::types::{Alert, AlertCounts, AlertKind};
    let alerts = vec![
        Alert { level: AlertLevel::Critical, kind: AlertKind::BucketIsPublic, title: "c".into(), detail: "".into(), raised_at: 0 },
        Alert { level: AlertLevel::Warn,     kind: AlertKind::BucketSafetyStale, title: "w".into(), detail: "".into(), raised_at: 0 },
        Alert { level: AlertLevel::Warn,     kind: AlertKind::BucketSafetyStale, title: "w".into(), detail: "".into(), raised_at: 0 },
        Alert { level: AlertLevel::Info,     kind: AlertKind::MissingBaseline, title: "i".into(), detail: "".into(), raised_at: 0 },
    ];
    let c = AlertCounts::from_alerts(&alerts);
    assert_eq!(c.critical, 1);
    assert_eq!(c.warn,     2);
    assert_eq!(c.info,     1);
}
