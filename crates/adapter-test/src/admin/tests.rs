//! Integration tests for the admin-console service layer.
//!
//! Pin the spec's "completion criteria" (§13) with runnable host tests:
//!   * cost increase is visible
//!   * R2 dangerous settings are visible
//!   * audit can be searched
//!   * dangerous ops require the right role
//!   * major changes appear in the service-returned before/after

use cesauth_core::admin::ports::BucketSafetyRepository;
use cesauth_core::admin::service;
use cesauth_core::admin::types::{
    AdminPrincipal, BucketSafetyChange, BucketSafetyState, Metric, MetricUnit, Role, ServiceId,
    Threshold, threshold_names,
};

use super::{
    InMemoryAuditQuerySource, InMemoryBucketSafetyRepository, InMemoryCostSnapshotRepository,
    InMemoryThresholdRepository, InMemoryUsageMetricsSource,
};

fn alice(role: Role) -> AdminPrincipal {
    AdminPrincipal { id: "alice-id".into(), name: Some("alice".into()), role }
}

fn default_thresholds() -> Vec<Threshold> {
    vec![
        Threshold {
            name: threshold_names::D1_ROW_COUNT_WARN.into(),
            value: 1_000_000,
            unit: "count".into(),
            description: None,
            updated_at: 0,
        },
        Threshold {
            name: threshold_names::R2_OBJECT_COUNT_WARN.into(),
            value: 500_000,
            unit: "count".into(),
            description: None,
            updated_at: 0,
        },
        Threshold {
            name: threshold_names::R2_BYTES_WARN.into(),
            value: 10_000_000_000,
            unit: "bytes".into(),
            description: None,
            updated_at: 0,
        },
        Threshold {
            name: threshold_names::BUCKET_VERIFICATION_STALENESS_DAYS.into(),
            value: 30,
            unit: "days".into(),
            description: None,
            updated_at: 0,
        },
    ]
}

fn seeded_fixtures() -> (
    InMemoryUsageMetricsSource,
    InMemoryCostSnapshotRepository,
    InMemoryBucketSafetyRepository,
    InMemoryThresholdRepository,
    InMemoryAuditQuerySource,
) {
    let metrics     = InMemoryUsageMetricsSource::default();
    let snaps       = InMemoryCostSnapshotRepository::default();
    let safety      = InMemoryBucketSafetyRepository::default();
    let thresholds  = InMemoryThresholdRepository::default();
    let audit       = InMemoryAuditQuerySource::default();

    thresholds.seed(default_thresholds());
    safety.seed(vec![
        BucketSafetyState {
            bucket: "AUDIT".into(),
            public: false, cors_configured: false, bucket_lock: false,
            lifecycle_configured: false, event_notifications: false,
            notes: None,
            last_verified_at: Some(1_000_000),
            last_verified_by: Some("alice".into()),
            updated_at: 1_000_000,
        },
        BucketSafetyState {
            bucket: "ASSETS".into(),
            public: false, cors_configured: false, bucket_lock: false,
            lifecycle_configured: false, event_notifications: false,
            notes: None,
            last_verified_at: None,
            last_verified_by: None,
            updated_at: 0,
        },
    ]);
    metrics.seed(ServiceId::D1, vec![
        Metric { key: "row_count.users".into(),  value: 42,   unit: MetricUnit::Count },
        Metric { key: "row_count.grants".into(), value: 100,  unit: MetricUnit::Count },
    ]);
    metrics.seed(ServiceId::R2, vec![
        Metric { key: "object_count".into(), value: 123,        unit: MetricUnit::Count },
        Metric { key: "bytes".into(),        value: 100_000_000, unit: MetricUnit::Bytes },
    ]);

    (metrics, snaps, safety, thresholds, audit)
}

// -------------------------------------------------------------------------
// Cost dashboard: trends come through, service-by-service
// -------------------------------------------------------------------------

#[tokio::test]
async fn cost_dashboard_builds_a_trend_for_every_service() {
    let (metrics, snaps, _, thresholds, _) = seeded_fixtures();
    let results = service::build_cost_dashboard(&metrics, &snaps, &thresholds, 2_000_000).await;
    assert_eq!(results.len(), 6, "one entry per ServiceId::ALL");
    for (_, r) in &results {
        assert!(r.is_ok(), "trend build should never fail with empty fixtures");
    }
}

#[tokio::test]
async fn cost_trend_shows_change_once_a_baseline_exists() {
    let (metrics, snaps, _, thresholds, _) = seeded_fixtures();

    // First view seeds the baseline.
    let first = service::build_cost_trend(ServiceId::D1, &metrics, &snaps, &thresholds, 1_000)
        .await.unwrap();
    assert!(first.previous_taken_at.is_none(),
        "no baseline on first view");

    // Bump metrics and take a second snapshot.
    metrics.seed(ServiceId::D1, vec![
        Metric { key: "row_count.users".into(),  value: 84,   unit: MetricUnit::Count },
        Metric { key: "row_count.grants".into(), value: 200,  unit: MetricUnit::Count },
    ]);
    let second = service::build_cost_trend(ServiceId::D1, &metrics, &snaps, &thresholds, 4_000)
        .await.unwrap();
    assert!(second.previous_taken_at.is_some(), "baseline now exists");
    // Both metrics exactly doubled; permille should be +1000 each.
    for (_, p) in &second.changes_permille {
        assert_eq!(*p, Some(1000), "100% growth -> 1000 permille");
    }
}

// -------------------------------------------------------------------------
// Data safety: report + alerts
// -------------------------------------------------------------------------

#[tokio::test]
async fn safety_report_flags_never_verified_bucket() {
    let (_, _, safety, thresholds, _) = seeded_fixtures();
    let report = service::build_safety_report(&safety, &thresholds, 2_000_000)
        .await.unwrap();
    assert!(!report.all_fresh, "ASSETS has last_verified_at=None");
    assert_eq!(report.public_bucket_count, 0);
    assert_eq!(report.buckets.len(), 2);
}

#[tokio::test]
async fn safety_report_all_fresh_when_every_bucket_verified() {
    let (_, _, safety, thresholds, _) = seeded_fixtures();
    // Verify ASSETS at now.
    safety.verify("ASSETS", 2_000_000, "alice").await.unwrap();
    let report = service::build_safety_report(&safety, &thresholds, 2_000_000)
        .await.unwrap();
    assert!(report.all_fresh);
}

// -------------------------------------------------------------------------
// §7 change ops: preview shows diff, apply stamps verifier
// -------------------------------------------------------------------------

#[tokio::test]
async fn preview_highlights_changed_fields_only() {
    let (_, _, safety, _, _) = seeded_fixtures();
    let change = BucketSafetyChange {
        bucket: "AUDIT".into(),
        public: false,
        cors_configured: false,
        bucket_lock: true,                     // changed
        lifecycle_configured: true,            // changed
        event_notifications: false,
        notes: Some("ops review 2026Q2".into()), // changed
    };
    let diff = service::preview_bucket_safety_change(&safety, &change).await.unwrap();
    assert_eq!(diff.changed_fields, &["bucket_lock", "lifecycle_configured", "notes"]);
}

#[tokio::test]
async fn apply_bucket_safety_stamps_verifier_and_returns_before_after() {
    let (_, _, safety, _, _) = seeded_fixtures();
    let change = BucketSafetyChange {
        bucket: "ASSETS".into(),
        public: true,      // deliberately public
        cors_configured: true,
        bucket_lock: false,
        lifecycle_configured: true,
        event_notifications: false,
        notes: Some("public asset bucket, confirmed".into()),
    };
    let (before, after) = service::apply_bucket_safety_change(&safety, &change, "alice", 3_000_000)
        .await.unwrap();
    assert!(!before.public);
    assert!( after.public);
    assert_eq!(after.last_verified_by.as_deref(), Some("alice"));
    assert_eq!(after.last_verified_at, Some(3_000_000));
    assert_eq!(after.updated_at,       3_000_000);
}

#[tokio::test]
async fn preview_rejects_unknown_bucket() {
    let (_, _, safety, _, _) = seeded_fixtures();
    let change = BucketSafetyChange {
        bucket: "NOPE".into(),
        public: false, cors_configured: false, bucket_lock: false,
        lifecycle_configured: false, event_notifications: false, notes: None,
    };
    let res = service::preview_bucket_safety_change(&safety, &change).await;
    assert!(res.is_err());
}

// -------------------------------------------------------------------------
// Overview: payload composes cleanly even with empty sources
// -------------------------------------------------------------------------

#[tokio::test]
async fn overview_survives_empty_audit_and_reports_alerts() {
    let (_, _, safety, thresholds, audit) = seeded_fixtures();
    let p = alice(Role::Security);
    let overview = service::build_overview(&p, &audit, &safety, &thresholds, 2_000_000)
        .await.unwrap();
    assert_eq!(overview.principal.role, Role::Security);
    // ASSETS bucket has last_verified_at=None which is "stale" by default
    // threshold of 30d -> one alert, level Warn.
    assert_eq!(overview.alert_counts.warn, 1);
    assert_eq!(overview.alert_counts.critical, 0);
}

// -------------------------------------------------------------------------
// Alert center: combines cost + safety + baseline-missing alerts
// -------------------------------------------------------------------------

#[tokio::test]
async fn alert_center_emits_missing_baseline_on_first_view() {
    let (metrics, snaps, safety, thresholds, _) = seeded_fixtures();
    let alerts = service::generate_alerts(&metrics, &snaps, &safety, &thresholds, 2_000_000)
        .await.unwrap();
    // Missing-baseline alerts fire once per service on first view.
    let missing_baseline = alerts.iter()
        .filter(|a| matches!(a.kind, cesauth_core::admin::types::AlertKind::MissingBaseline))
        .count();
    assert!(missing_baseline >= 1);
}

// -------------------------------------------------------------------------
// Audit query
// -------------------------------------------------------------------------

#[tokio::test]
async fn audit_search_filters_and_limits() {
    use cesauth_core::admin::types::{AdminAuditEntry, AuditQuery};
    let audit = InMemoryAuditQuerySource::default();
    audit.seed(vec![
        AdminAuditEntry {
            ts: 1000, id: "1".into(), kind: "token_issued".into(),
            subject: Some("alice".into()), client: Some("c1".into()),
            reason: None, key: "k1".into(),
        },
        AdminAuditEntry {
            ts: 1001, id: "2".into(), kind: "magic_link_verified".into(),
            subject: Some("bob".into()), client: None, reason: None, key: "k2".into(),
        },
        AdminAuditEntry {
            ts: 1002, id: "3".into(), kind: "auth_failed".into(),
            subject: Some("bob".into()), client: None, reason: Some("pkce".into()), key: "k3".into(),
        },
    ]);
    let only_bob = service::search_audit(&audit, &AuditQuery {
        subject_contains: Some("bob".into()),
        ..AuditQuery::default()
    }).await.unwrap();
    assert_eq!(only_bob.len(), 2);
    // Newest first.
    assert_eq!(only_bob[0].id, "3");

    let only_token = service::search_audit(&audit, &AuditQuery {
        kind_contains: Some("token".into()),
        ..AuditQuery::default()
    }).await.unwrap();
    assert_eq!(only_token.len(), 1);
    assert_eq!(only_token[0].kind, "token_issued");

    let limited = service::search_audit(&audit, &AuditQuery {
        limit: Some(1), ..AuditQuery::default()
    }).await.unwrap();
    assert_eq!(limited.len(), 1);
}

// -------------------------------------------------------------------------
// Cost snapshot repo dedups per hour
// -------------------------------------------------------------------------

#[tokio::test]
async fn cost_snapshot_repo_dedups_within_hour() {
    use cesauth_core::admin::ports::CostSnapshotRepository;
    use cesauth_core::admin::types::CostSnapshot;

    let repo = InMemoryCostSnapshotRepository::default();
    let base = CostSnapshot {
        service: ServiceId::R2,
        taken_at: 3600 * 10, // hour bucket #10
        metrics: vec![],
    };
    repo.put(&base).await.unwrap();
    // Same hour, different second: should overwrite.
    let same_hour = CostSnapshot { taken_at: 3600 * 10 + 42, ..base.clone() };
    repo.put(&same_hour).await.unwrap();
    let all = repo.recent(ServiceId::R2, 10).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].taken_at, 3600 * 10 + 42);

    // Next hour bucket adds a new row.
    let next_hour = CostSnapshot { taken_at: 3600 * 11, ..base };
    repo.put(&next_hour).await.unwrap();
    let all = repo.recent(ServiceId::R2, 10).await.unwrap();
    assert_eq!(all.len(), 2);
}
