//! Service layer for the admin console.
//!
//! Every function here composes ports to produce one of the page-level
//! payloads the UI renders. The functions are generic over port traits
//! - the Cloudflare adapter (`cesauth-adapter-cloudflare::admin`) and
//! the in-memory test adapter (`cesauth-adapter-test::admin`) plug in
//! the same way.
//!
//! Design choice: no function here creates an audit event. The
//! worker-side handler owns the audit sink (it's the only place that
//! has `&worker::Env`) and calls `audit::write_owned(..)` around each
//! service call. That keeps `core` free of Cloudflare deps, matching
//! spec §10.

use crate::ports::{PortError, PortResult};

use super::policy;
use super::ports::{
    AuditQuerySource, BucketSafetyRepository, CostSnapshotRepository, ThresholdRepository,
    UsageMetricsSource,
};
use super::types::{
    AdminAuditEntry, AdminPrincipal, AdminPrincipalSummary, Alert, AlertCounts, AlertKind,
    AlertLevel, AuditQuery, BucketSafetyChange, BucketSafetyState, CostTrend, DataSafetyReport,
    OverviewSummary, ServiceId, Threshold, threshold_names,
};

// -------------------------------------------------------------------------
// Overview (§4.1)
// -------------------------------------------------------------------------

/// Build the overview payload: roll up alert counts, pluck the most
/// recent audit events, surface the most recently verified buckets.
///
/// This is intentionally best-effort on the partial-failure side: if
/// any one port returns an error, the overview still renders with the
/// successful parts. The spec §11 asks for "設定取得不能時も画面全体を
/// 壊さないこと" (a partial failure must not break the whole page).
pub async fn build_overview<A, B, T>(
    principal: &AdminPrincipal,
    audit:     &A,
    safety:    &B,
    thresholds:&T,
    now_unix:  i64,
) -> PortResult<OverviewSummary>
where
    A: AuditQuerySource,
    B: BucketSafetyRepository,
    T: ThresholdRepository,
{
    let recent_audit = audit
        .search(&AuditQuery { limit: Some(10), ..AuditQuery::default() })
        .await
        .unwrap_or_default();
    let buckets  = safety.list().await.unwrap_or_default();
    let threshold_rows = thresholds.list().await.unwrap_or_default();

    // Build the alert list by walking every bucket. Cost alerts are NOT
    // computed here (that would require a metrics snapshot per service);
    // the Overview shows count + the latest few safety alerts, and the
    // Cost Dashboard is where cost alerts get their full treatment.
    let mut alerts: Vec<Alert> = Vec::new();
    for b in &buckets {
        alerts.extend(policy::evaluate_bucket_safety(b, &threshold_rows, now_unix));
    }
    alerts.sort_by(|a, b| b.raised_at.cmp(&a.raised_at));

    let alert_counts = AlertCounts::from_alerts(&alerts);
    let recent_alerts: Vec<Alert> = alerts.into_iter().take(5).collect();

    // Show the 3 most-recently-verified buckets (sorted by `updated_at`).
    let mut last_verified = buckets.clone();
    last_verified.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    last_verified.truncate(3);

    Ok(OverviewSummary {
        as_of: now_unix,
        principal: AdminPrincipalSummary {
            name: principal.name.clone(),
            role: principal.role,
        },
        alert_counts,
        recent_alerts,
        last_audit_events:     recent_audit,
        last_verified_buckets: last_verified,
    })
}

// -------------------------------------------------------------------------
// Cost Dashboard (§4.2)
// -------------------------------------------------------------------------

/// Take a fresh snapshot, persist it (best-effort), and return the
/// `CostTrend` comparing it to the previous persisted snapshot.
pub async fn build_cost_trend<M, R, T>(
    service:    ServiceId,
    metrics:    &M,
    snaps:      &R,
    thresholds: &T,
    now_unix:   i64,
) -> PortResult<CostTrend>
where
    M: UsageMetricsSource,
    R: CostSnapshotRepository,
    T: ThresholdRepository,
{
    let current = metrics.snapshot(service, now_unix).await?;
    let previous = snaps.latest(service).await.unwrap_or(None);

    // Persist the new snapshot. Best-effort: a store failure here
    // should not make the dashboard fail. The implementation dedupes
    // at the per-hour bucket level, so repeated dashboard views do not
    // create repeated rows.
    let _ = snaps.put(&current).await;

    let threshold_rows = thresholds.list().await.unwrap_or_default();
    Ok(policy::build_trend(service, current, previous.as_ref(), &threshold_rows))
}

/// Convenience: build a cost trend for every service. Uses
/// `build_cost_trend` in a loop; failure on one service does not mask
/// the others.
pub async fn build_cost_dashboard<M, R, T>(
    metrics:    &M,
    snaps:      &R,
    thresholds: &T,
    now_unix:   i64,
) -> Vec<(ServiceId, PortResult<CostTrend>)>
where
    M: UsageMetricsSource,
    R: CostSnapshotRepository,
    T: ThresholdRepository,
{
    let mut out = Vec::with_capacity(ServiceId::ALL.len());
    for svc in ServiceId::ALL {
        let res = build_cost_trend(svc, metrics, snaps, thresholds, now_unix).await;
        out.push((svc, res));
    }
    out
}

// -------------------------------------------------------------------------
// Data Safety Dashboard (§4.3)
// -------------------------------------------------------------------------

pub async fn build_safety_report<B, T>(
    safety:     &B,
    thresholds: &T,
    now_unix:   i64,
) -> PortResult<DataSafetyReport>
where
    B: BucketSafetyRepository,
    T: ThresholdRepository,
{
    let buckets  = safety.list().await?;
    let threshold_rows = thresholds.list().await.unwrap_or_default();

    let days = threshold_rows.iter()
        .find(|t| t.name == threshold_names::BUCKET_VERIFICATION_STALENESS_DAYS)
        .map(|t| t.value)
        .unwrap_or(30);
    let stale_threshold_secs = days.saturating_mul(24 * 60 * 60);

    let all_fresh = buckets.iter().all(|b| match b.last_verified_at {
        None     => false,
        Some(ts) => (now_unix - ts) <= stale_threshold_secs,
    });
    let public_bucket_count = buckets.iter().filter(|b| b.public).count() as u32;

    Ok(DataSafetyReport {
        buckets,
        all_fresh,
        public_bucket_count,
        staleness_threshold_days: days.max(0) as u32,
    })
}

// -------------------------------------------------------------------------
// Audit Log search (§4.4)
// -------------------------------------------------------------------------

pub async fn search_audit<A>(audit: &A, q: &AuditQuery) -> PortResult<Vec<AdminAuditEntry>>
where
    A: AuditQuerySource,
{
    audit.search(q).await
}

// -------------------------------------------------------------------------
// Alert Center (§4.6)
// -------------------------------------------------------------------------

/// Aggregate every source of alerts. Used by the Alert Center page and
/// by the Overview's alert-count badge.
///
/// NOTE: this walks every cost metric snapshot too, which is "heavier"
/// than the Overview's bucket-only pass. Callers that only need counts
/// should prefer `build_overview`.
pub async fn generate_alerts<M, R, B, T>(
    metrics:    &M,
    snaps:      &R,
    safety:     &B,
    thresholds: &T,
    now_unix:   i64,
) -> PortResult<Vec<Alert>>
where
    M: UsageMetricsSource,
    R: CostSnapshotRepository,
    B: BucketSafetyRepository,
    T: ThresholdRepository,
{
    let threshold_rows = thresholds.list().await.unwrap_or_default();
    let mut alerts: Vec<Alert> = Vec::new();

    // Bucket safety alerts.
    for b in safety.list().await.unwrap_or_default() {
        alerts.extend(policy::evaluate_bucket_safety(&b, &threshold_rows, now_unix));
    }

    // Cost alerts: fresh snapshot per service. If a service is
    // unreachable (e.g. a KV binding absent), skip rather than fail.
    for svc in ServiceId::ALL {
        match metrics.snapshot(svc, now_unix).await {
            Ok(snap) => {
                // Also flag "no previous snapshot" as an info alert -
                // the dashboard's trend will be missing.
                let prev = snaps.latest(svc).await.unwrap_or(None);
                if prev.is_none() {
                    alerts.push(Alert {
                        level:     AlertLevel::Info,
                        kind:      AlertKind::MissingBaseline,
                        title:     format!("{} has no baseline yet", svc.label()),
                        detail:    "First snapshot was just taken; trend will be available from the next view onward.".to_owned(),
                        raised_at: now_unix,
                    });
                }
                alerts.extend(policy::evaluate_cost_thresholds(
                    svc, &snap.metrics, &threshold_rows, now_unix,
                ));
                // Persist for future trend calculations (best-effort).
                let _ = snaps.put(&snap).await;
            }
            Err(_) => {}
        }
    }

    // Newest first.
    alerts.sort_by(|a, b| b.raised_at.cmp(&a.raised_at));
    Ok(alerts)
}

// -------------------------------------------------------------------------
// Bucket safety attestation changes (§7)
// -------------------------------------------------------------------------

/// Stamp `last_verified_at` without changing the attested flags.
/// Caller must have `VerifyBucketSafety` permission; the check happens
/// in the worker layer before this function is called.
pub async fn verify_bucket_safety<B>(
    safety:   &B,
    bucket:   &str,
    by:       &str,
    now_unix: i64,
) -> PortResult<BucketSafetyState>
where
    B: BucketSafetyRepository,
{
    safety.verify(bucket, now_unix, by).await
}

/// Commit a change to a bucket safety row. Caller must have
/// `EditBucketSafety` and have already seen a preview (the two-step
/// confirmation is implemented in the worker route layer).
pub async fn apply_bucket_safety_change<B>(
    safety:   &B,
    change:   &BucketSafetyChange,
    by:       &str,
    now_unix: i64,
) -> PortResult<(BucketSafetyState, BucketSafetyState)>
where
    B: BucketSafetyRepository,
{
    safety.apply_change(change, now_unix, by).await
}

/// Build the before/after payload without committing anything. The
/// worker route's `/admin/config/r2/:bucket/confirm` uses this to
/// render the confirmation page.
pub async fn preview_bucket_safety_change<B>(
    safety: &B,
    change: &BucketSafetyChange,
) -> PortResult<super::types::BucketSafetyDiff>
where
    B: BucketSafetyRepository,
{
    let current = safety.get(&change.bucket).await?
        .ok_or(PortError::NotFound)?;

    let mut changed = Vec::with_capacity(6);
    if current.public               != change.public               { changed.push("public"); }
    if current.cors_configured      != change.cors_configured      { changed.push("cors_configured"); }
    if current.bucket_lock          != change.bucket_lock          { changed.push("bucket_lock"); }
    if current.lifecycle_configured != change.lifecycle_configured { changed.push("lifecycle_configured"); }
    if current.event_notifications  != change.event_notifications  { changed.push("event_notifications"); }
    if current.notes.as_deref()     != change.notes.as_deref()     { changed.push("notes"); }

    Ok(super::types::BucketSafetyDiff {
        bucket:   change.bucket.clone(),
        current,
        proposed: change.clone(),
        changed_fields: changed,
    })
}

// -------------------------------------------------------------------------
// Threshold changes
// -------------------------------------------------------------------------

pub async fn update_threshold<T>(
    thresholds: &T,
    name:       &str,
    new_value:  i64,
    now_unix:   i64,
) -> PortResult<Threshold>
where
    T: ThresholdRepository,
{
    thresholds.update(name, new_value, now_unix).await
}
