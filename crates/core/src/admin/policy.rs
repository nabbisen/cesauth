//! Pure policy functions for the admin console.
//!
//! Kept synchronous and free of ports on purpose: these are the rules
//! that need unit-test coverage and that readers of the codebase want
//! to be able to audit in one place. Anything that needs storage goes
//! through [`super::service`].

use super::types::{
    AdminAction, Alert, AlertKind, AlertLevel, BucketSafetyState, CostTrend, Metric,
    MetricUnit, Role, ServiceId, Threshold, threshold_names,
};

// -------------------------------------------------------------------------
// Role -> Action permission
// -------------------------------------------------------------------------

/// Returns `true` iff `role` is allowed to perform `action`.
///
/// The matrix reflects spec §6.1 + §6.2:
///
/// | Action               | ReadOnly | Security | Operations | Super |
/// |----------------------|----------|----------|------------|-------|
/// | ViewConsole          | ✓        | ✓        | ✓          | ✓     |
/// | VerifyBucketSafety   |          | ✓        | ✓          | ✓     |
/// | EditBucketSafety     |          |          | ✓          | ✓     |
/// | EditThreshold        |          |          | ✓          | ✓     |
/// | CreateUser           |          |          | ✓          | ✓     |
/// | RevokeSession        |          | ✓        | ✓          | ✓     |
/// | ManageAdminTokens    |          |          |            | ✓     |
pub fn role_allows(role: Role, action: AdminAction) -> bool {
    match action {
        AdminAction::ViewConsole        => true, // every valid role

        AdminAction::VerifyBucketSafety |
        AdminAction::RevokeSession      => matches!(role,
            Role::Security | Role::Operations | Role::Super),

        AdminAction::EditBucketSafety   |
        AdminAction::EditThreshold      |
        AdminAction::CreateUser         => matches!(role,
            Role::Operations | Role::Super),

        AdminAction::ManageAdminTokens  => matches!(role, Role::Super),

        // v0.4.2 tenancy service API. Read is open to every role;
        // mutation is Operations+ matching the existing
        // EditBucketSafety / EditThreshold / CreateUser tier.
        AdminAction::ViewTenancy        => true,

        AdminAction::ManageTenancy      => matches!(role,
            Role::Operations | Role::Super),
    }
}

// -------------------------------------------------------------------------
// Cost thresholds
// -------------------------------------------------------------------------

/// Given a fresh snapshot and the currently-configured thresholds,
/// produce alerts for any metric that crosses its threshold.
///
/// Returns an empty vec when nothing is breaching. The caller is
/// responsible for combining with safety and audit alerts.
pub fn evaluate_cost_thresholds(
    service:    ServiceId,
    metrics:    &[Metric],
    thresholds: &[Threshold],
    now_unix:   i64,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for m in metrics {
        let threshold_name = cost_threshold_for(service, &m.key);
        let Some(tname) = threshold_name else { continue; };
        let Some(t) = thresholds.iter().find(|x| x.name == tname) else { continue; };
        if m.value as i64 > t.value {
            alerts.push(Alert {
                level:     AlertLevel::Warn,
                kind:      AlertKind::CostThresholdExceeded,
                title:     format!("{} threshold exceeded", service.label()),
                detail:    format!(
                    "{}: {} {} > threshold {} {} ({})",
                    m.key, m.value, m.unit.label(), t.value, t.unit,
                    t.description.as_deref().unwrap_or(""),
                ),
                raised_at: now_unix,
            });
        }
    }
    alerts
}

/// Maps a (service, metric-key) pair to the threshold name that applies.
/// `None` means the metric is informational and has no threshold.
fn cost_threshold_for(service: ServiceId, metric_key: &str) -> Option<&'static str> {
    match (service, metric_key) {
        (ServiceId::D1, k) if k.starts_with("row_count.") =>
            Some(threshold_names::D1_ROW_COUNT_WARN),
        (ServiceId::R2, "object_count") =>
            Some(threshold_names::R2_OBJECT_COUNT_WARN),
        (ServiceId::R2, "bytes") =>
            Some(threshold_names::R2_BYTES_WARN),
        _ => None,
    }
}

// -------------------------------------------------------------------------
// Data safety
// -------------------------------------------------------------------------

/// Produce alerts for the state of one bucket. Can return up to two
/// alerts: one if the verification is stale, one if the bucket is
/// attested public.
pub fn evaluate_bucket_safety(
    state:       &BucketSafetyState,
    thresholds:  &[Threshold],
    now_unix:    i64,
) -> Vec<Alert> {
    let mut alerts = Vec::new();

    // Staleness check.
    let days = thresholds.iter()
        .find(|t| t.name == threshold_names::BUCKET_VERIFICATION_STALENESS_DAYS)
        .map(|t| t.value)
        .unwrap_or(30);
    let stale_threshold_secs = days.saturating_mul(24 * 60 * 60);

    let stale = match state.last_verified_at {
        None          => true,
        Some(ts)      => (now_unix - ts) > stale_threshold_secs,
    };
    if stale {
        alerts.push(Alert {
            level:     AlertLevel::Warn,
            kind:      AlertKind::BucketSafetyStale,
            title:     format!("'{}' safety attestation is stale", state.bucket),
            detail:    match state.last_verified_at {
                None     => format!(
                    "Bucket '{}' has never been verified. \
                     Re-check CF dashboard settings and stamp in the Config Review page.",
                    state.bucket,
                ),
                Some(ts) => format!(
                    "Bucket '{}' last verified at unix {} (>{} days ago).",
                    state.bucket, ts, days,
                ),
            },
            raised_at: now_unix,
        });
    }

    if state.public {
        alerts.push(Alert {
            level:     AlertLevel::Critical,
            kind:      AlertKind::BucketIsPublic,
            title:     format!("'{}' is attested public", state.bucket),
            detail:    format!(
                "Bucket '{}' is marked public in the attestation. \
                 Confirm this is intentional; audit and assets buckets SHOULD NOT be public.",
                state.bucket,
            ),
            raised_at: now_unix,
        });
    }

    alerts
}

// -------------------------------------------------------------------------
// Cost-trend shaping
// -------------------------------------------------------------------------

/// Given a fresh snapshot and (optionally) a previous one, compute the
/// trend payload the dashboard renders.
pub fn build_trend(
    service:    ServiceId,
    current:    super::types::CostSnapshot,
    previous:   Option<&super::types::CostSnapshot>,
    thresholds: &[Threshold],
) -> CostTrend {
    let mut changes = Vec::with_capacity(current.metrics.len());
    for m in &current.metrics {
        let delta = previous.and_then(|p| p.metrics.iter().find(|x| x.key == m.key))
            .map(|prev| {
                if prev.value == 0 {
                    // Avoid divide-by-zero; treat as "informational only".
                    None
                } else {
                    // permille: (new - old) * 1000 / old, as i64. We cap
                    // magnitudes at i64::MAX rather than overflow.
                    let (new, old) = (m.value as i128, prev.value as i128);
                    let p = ((new - old) * 1000) / old;
                    Some(p as i64)
                }
            })
            .flatten();
        changes.push((m.key.clone(), delta));
    }

    let note = match service {
        ServiceId::Workers   => Some("Self-maintained counter; Cloudflare dashboard is authoritative."),
        ServiceId::Kv        |
        ServiceId::Turnstile => Some("Self-maintained counter; Cloudflare dashboard is authoritative."),
        ServiceId::DurableObjects => Some(
            "Workers cannot enumerate DO instances at runtime. See Cloudflare dashboard.",
        ),
        _ => None,
    };

    let breaches_threshold = !evaluate_cost_thresholds(
        service, &current.metrics, thresholds, current.taken_at,
    ).is_empty();

    CostTrend {
        service,
        previous_taken_at: previous.map(|p| p.taken_at),
        changes_permille:  changes,
        breaches_threshold,
        note,
        current,
    }
}

// -------------------------------------------------------------------------
// Small helpers used by UI formatters. Exposed here (not in `ui::admin`)
// because they're policy-shaped - decisions about which number counts
// as "notable" belong in the domain layer.
// -------------------------------------------------------------------------

/// Format a `MetricUnit` + value as a short human string (e.g. "1.2 MB",
/// "1,234", "50‰"). Unit choice is deliberately minimal - the spec §9
/// asks for numbers with units but doesn't demand locale-aware formatting.
pub fn format_metric(value: u64, unit: MetricUnit) -> String {
    match unit {
        MetricUnit::Count => {
            // Thousands separator, integer only.
            let s = value.to_string();
            let bytes = s.as_bytes();
            let mut out = String::with_capacity(bytes.len() + bytes.len() / 3);
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 && (bytes.len() - i) % 3 == 0 {
                    out.push(',');
                }
                out.push(*b as char);
            }
            out
        }
        MetricUnit::Bytes => {
            const KIB: u64 = 1 << 10;
            const MIB: u64 = 1 << 20;
            const GIB: u64 = 1 << 30;
            if value >= GIB {
                format!("{:.2} GiB", value as f64 / GIB as f64)
            } else if value >= MIB {
                format!("{:.2} MiB", value as f64 / MIB as f64)
            } else if value >= KIB {
                format!("{:.2} KiB", value as f64 / KIB as f64)
            } else {
                format!("{value} B")
            }
        }
        MetricUnit::Permille => format!("{}‰", value),
        MetricUnit::Seconds  => format!("{}s", value),
    }
}

/// Format a permille change as "+12.3%" / "-4.5%" / "unchanged".
pub fn format_change(permille: Option<i64>) -> String {
    match permille {
        None    => "—".to_owned(),
        Some(0) => "unchanged".to_owned(),
        Some(p) => {
            let sign = if p > 0 { "+" } else { "" };
            format!("{sign}{:.1}%", p as f64 / 10.0)
        }
    }
}
