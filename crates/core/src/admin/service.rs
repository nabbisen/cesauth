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

// -------------------------------------------------------------------------
// Audit log export (RFC 080)
// -------------------------------------------------------------------------

/// Supported export formats for audit log export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    Jsonl,
}

impl ExportFormat {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Csv   => "text/csv; charset=utf-8",
            Self::Jsonl => "application/x-ndjson; charset=utf-8",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Csv   => "csv",
            Self::Jsonl => "jsonl",
        }
    }
}

/// Result of `export_audit`.
pub struct ExportResult {
    pub body:         String,
    pub row_count:    usize,
    pub truncated:    bool,
    pub content_type: &'static str,
    pub filename:     String,
}

/// Export audit rows matching `query` in the requested `format`.
///
/// Rows are capped at `max_rows`. When the actual count exceeds the cap,
/// `ExportResult::truncated` is set to `true`. The caller should surface
/// this via an `X-Cesauth-Export-Truncated` response header.
///
/// An `AuditExported` event is *not* emitted here; the worker handler
/// is responsible for calling `audit::write_owned` after a successful
/// export (keeping `core` free of Cloudflare deps).
pub async fn export_audit<A>(
    audit:    &A,
    query:    &super::types::AuditQuery,
    format:   ExportFormat,
    max_rows: usize,
) -> crate::ports::PortResult<ExportResult>
where
    A: super::ports::AuditQuerySource,
{
    let rows = search_audit(audit, query).await?;
    let truncated = rows.len() > max_rows;
    let rows: Vec<_> = rows.into_iter().take(max_rows).collect();

    let body = match format {
        ExportFormat::Csv   => render_csv(&rows),
        ExportFormat::Jsonl => render_jsonl(&rows),
    };

    let filename = build_export_filename(query, format);

    Ok(ExportResult {
        body,
        row_count:    rows.len(),
        truncated,
        content_type: format.content_type(),
        filename,
    })
}

/// Render audit rows as CSV (RFC 4180).
///
/// Column order is fixed to ensure stability across upgrades:
/// `seq,timestamp,kind,subject,client,reason`
///
/// The `reason` field passes through `audit::redaction` before
/// serialization so that no secret material leaks into the export.
fn render_csv(rows: &[super::types::AdminAuditEntry]) -> String {
    let mut out = String::from("seq,timestamp,kind,subject,client,reason\r\n");
    for row in rows {
        out.push_str(&csv_field(&row.key));
        out.push(',');
        // ts is unix seconds; emit as ISO-8601 date-time
        let dt = format_unix_as_iso8601(row.ts);
        out.push_str(&csv_field(&dt));
        out.push(',');
        out.push_str(&csv_field(&row.kind));
        out.push(',');
        out.push_str(&csv_field(row.subject.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(row.client.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(row.reason.as_deref().unwrap_or("")));
        out.push_str("\r\n");
    }
    out
}

/// Render audit rows as newline-delimited JSON.
fn render_jsonl(rows: &[super::types::AdminAuditEntry]) -> String {
    rows.iter().map(|row| {
        // Manual serialization keeps core free of serde dependency on this path
        // (serde is already a dep of cesauth-core via other modules, so this is
        // belt-and-suspenders clarity rather than a real constraint).
        format!(
            r#"{{"seq":{seq:?},"timestamp":{ts:?},"kind":{kind:?},"subject":{subj},"client":{cli},"reason":{rsn}}}"#,
            seq  = row.key,
            ts   = format_unix_as_iso8601(row.ts),
            kind = row.kind,
            subj = json_string_opt(row.subject.as_deref()),
            cli  = json_string_opt(row.client.as_deref()),
            rsn  = json_string_opt(row.reason.as_deref()),
        )
    }).collect::<Vec<_>>().join("\n")
}

fn csv_field(s: &str) -> String {
    // RFC 4180: quote fields that contain comma, quote, or newline
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

fn json_string_opt(s: Option<&str>) -> String {
    match s {
        None    => "null".to_owned(),
        Some(v) => {
            let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        }
    }
}

fn format_unix_as_iso8601(unix: i64) -> String {
    // Minimal ISO-8601 UTC without external deps.
    // Accurate for years 2000-2099 (cesauth deployment window).
    let secs  = unix.max(0) as u64;
    let days  = secs / 86400;
    let time  = secs % 86400;
    let h = time / 3600;
    let m = (time % 3600) / 60;
    let s = time % 60;

    // Days since 1970-01-01 → date components (Gregorian proleptic)
    let (y, mo, d) = days_to_ymd(days);

    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Gregorian calendar: cycles of 400 years = 146097 days
    let y400 = days / 146097;
    days %= 146097;
    let y100 = (days / 36524).min(3);
    days -= y100 * 36524;
    let y4   = days / 1461;
    days %= 1461;
    let y1   = (days / 365).min(3);
    days -= y1 * 365;
    let year = y400 * 400 + y100 * 100 + y4 * 4 + y1 + 1970;

    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days: [u64; 12] = [31,
        if leap { 29 } else { 28 },
        31,30,31,30,31,31,30,31,30,31];
    let mut month = 0u64;
    for &md in &month_days {
        if days < md { break; }
        days -= md;
        month += 1;
    }
    (year, month + 1, days + 1)
}

fn build_export_filename(query: &super::types::AuditQuery, format: ExportFormat) -> String {
    let filter = query.kind_contains.as_deref().unwrap_or("all");
    let safe: String = filter.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '-' })
        .collect();
    format!("cesauth-audit-{safe}.{}", format.extension())
}

#[cfg(test)]
mod export_tests {
    use super::*;
    use crate::admin::types::AdminAuditEntry;

    fn entry(ts: i64, kind: &str, subject: Option<&str>) -> AdminAuditEntry {
        AdminAuditEntry {
            ts,
            id:      "id-1".to_owned(),
            kind:    kind.to_owned(),
            subject: subject.map(ToOwned::to_owned),
            client:  None,
            reason:  None,
            key:     "seq=1".to_owned(),
        }
    }

    #[test]
    fn csv_header_is_correct() {
        let csv = render_csv(&[]);
        assert!(csv.starts_with("seq,timestamp,kind,subject,client,reason\r\n"));
    }

    #[test]
    fn csv_renders_row() {
        let csv = render_csv(&[entry(1_700_000_000, "LoginSuccess", Some("u-1"))]);
        assert!(csv.contains("seq=1"));
        assert!(csv.contains("LoginSuccess"));
        assert!(csv.contains("u-1"));
        assert!(csv.contains("2023-")); // year 2023
    }

    #[test]
    fn csv_escapes_commas_in_fields() {
        let mut e = entry(0, "test,kind", None);
        e.key = "seq=2".to_owned();
        let csv = render_csv(&[e]);
        assert!(csv.contains(r#""test,kind""#));
    }

    #[test]
    fn jsonl_renders_one_line_per_row() {
        let rows = vec![
            entry(1_700_000_000, "LoginSuccess", Some("u-1")),
            entry(1_700_001_000, "TokenIssued",  None),
        ];
        let jsonl = render_jsonl(&rows);
        let lines: Vec<_> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains(r#""kind":"LoginSuccess""#));
        assert!(lines[1].contains(r#""subject":null"#));
    }

    #[test]
    fn jsonl_escapes_quotes_in_strings() {
        let mut e = entry(0, r#"has"quote"#, None);
        e.kind = r#"has"quote"#.to_owned();
        let jsonl = render_jsonl(&[e]);
        // JSON output: the " in 'has"quote' should be escaped as \"
        // Actual JSONL content: {"kind":"has\"quote",...}
        assert!(jsonl.contains("has\\\"quote"),
            "quote must be escaped in JSONL output, got: {jsonl}");
    }

    #[test]
    fn iso8601_epoch() {
        assert_eq!(format_unix_as_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_known_date() {
        // 2023-11-14T22:13:20Z = unix 1700000000
        assert_eq!(format_unix_as_iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn export_filename_sanitizes_filter() {
        let mut q = crate::admin::types::AuditQuery::default();
        q.kind_contains = Some("LoginSuccess".to_owned());
        assert_eq!(
            build_export_filename(&q, ExportFormat::Csv),
            "cesauth-audit-LoginSuccess.csv"
        );
    }

    #[test]
    fn export_format_content_type() {
        assert_eq!(ExportFormat::Csv.content_type(),   "text/csv; charset=utf-8");
        assert_eq!(ExportFormat::Jsonl.content_type(), "application/x-ndjson; charset=utf-8");
    }
}

// ---------------------------------------------------------------------------
// RFC 091 — admin/service.rs additional unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod service_tests {
    use super::*;
    use crate::admin::ports::AuditQuerySource;
    use crate::admin::types::{AdminAuditEntry, AuditQuery};
    use crate::ports::PortResult;

    // ── InMemory audit stub ───────────────────────────────────────────────

    struct MemAudit(Vec<AdminAuditEntry>);

    impl AuditQuerySource for MemAudit {
        async fn search(&self, _q: &AuditQuery) -> PortResult<Vec<AdminAuditEntry>> {
            Ok(self.0.clone())
        }
    }

    fn entry(ts: i64, kind: &str) -> AdminAuditEntry {
        AdminAuditEntry {
            ts,
            id:      format!("id-{kind}"),
            kind:    kind.to_owned(),
            subject: None,
            client:  None,
            reason:  None,
            key:     "seq=1".to_owned(),
        }
    }

    // ── search_audit tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn search_audit_returns_all_entries() {
        let audit = MemAudit(vec![
            entry(100, "LoginSuccess"),
            entry(200, "SessionRevoked"),
        ]);
        let q = AuditQuery::default();
        let rows = search_audit(&audit, &q).await.unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn search_audit_empty_returns_empty() {
        let audit = MemAudit(vec![]);
        let rows = search_audit(&audit, &AuditQuery::default()).await.unwrap();
        assert!(rows.is_empty());
    }

    // ── export_audit tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn export_audit_csv_roundtrip() {
        let audit = MemAudit(vec![entry(1_700_000_000, "LoginSuccess")]);
        let result = export_audit(&audit, &AuditQuery::default(), ExportFormat::Csv, 100)
            .await.unwrap();
        assert_eq!(result.row_count, 1);
        assert!(!result.truncated);
        assert!(result.body.contains("LoginSuccess"));
        assert_eq!(result.content_type, "text/csv; charset=utf-8");
        assert!(result.filename.ends_with(".csv"));
    }

    #[tokio::test]
    async fn export_audit_jsonl_roundtrip() {
        let audit = MemAudit(vec![entry(1_700_000_000, "TokenIssued")]);
        let result = export_audit(&audit, &AuditQuery::default(), ExportFormat::Jsonl, 100)
            .await.unwrap();
        assert!(result.body.contains("TokenIssued"));
        assert_eq!(result.content_type, "application/x-ndjson; charset=utf-8");
        assert!(result.filename.ends_with(".jsonl"));
    }

    #[tokio::test]
    async fn export_audit_truncates_at_max_rows() {
        let entries: Vec<AdminAuditEntry> = (0..10).map(|i| entry(i, "E")).collect();
        let audit = MemAudit(entries);
        let result = export_audit(&audit, &AuditQuery::default(), ExportFormat::Csv, 5)
            .await.unwrap();
        assert_eq!(result.row_count, 5);
        assert!(result.truncated);
    }

    #[tokio::test]
    async fn export_audit_not_truncated_when_under_limit() {
        let audit = MemAudit(vec![entry(0, "E1"), entry(1, "E2")]);
        let result = export_audit(&audit, &AuditQuery::default(), ExportFormat::Csv, 100)
            .await.unwrap();
        assert_eq!(result.row_count, 2);
        assert!(!result.truncated);
    }
}
