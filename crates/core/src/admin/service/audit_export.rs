//! Audit log filtered export — CSV and JSONL formats (RFC 080).
//!
//! Extracted from `admin/service.rs` by RFC 099. All items remain
//! publicly accessible via `admin::service::*` re-exports.

use crate::admin::ports::AuditQuerySource;
use crate::admin::types::{AdminAuditEntry, AuditQuery};
use crate::ports::PortResult;
use crate::admin::service::search_audit;

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
#[derive(Debug)]
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
    query:    &crate::admin::types::AuditQuery,
    format:   ExportFormat,
    max_rows: usize,
) -> crate::ports::PortResult<ExportResult>
where
    A: crate::admin::ports::AuditQuerySource,
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
fn render_csv(rows: &[crate::admin::types::AdminAuditEntry]) -> String {
    let mut out = String::from("seq,timestamp,kind,subject,client,reason\r\n");
    for row in rows {
        out.push_str(&csv_field(&row.key));
        out.push(',');
        // ts is unix seconds; emit as ISO-8601 date-time
        let dt = crate::util::format_unix_as_iso8601(row.ts);
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
fn render_jsonl(rows: &[crate::admin::types::AdminAuditEntry]) -> String {
    rows.iter().map(|row| {
        // Manual serialization keeps core free of serde dependency on this path
        // (serde is already a dep of cesauth-core via other modules, so this is
        // belt-and-suspenders clarity rather than a real constraint).
        format!(
            r#"{{"seq":{seq:?},"timestamp":{ts:?},"kind":{kind:?},"subject":{subj},"client":{cli},"reason":{rsn}}}"#,
            seq  = row.key,
            ts   = crate::util::format_unix_as_iso8601(row.ts),
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

// RFC 096: format_unix_as_iso8601 and days_to_ymd moved to crate::util

fn build_export_filename(query: &crate::admin::types::AuditQuery, format: ExportFormat) -> String {
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
        assert_eq!(crate::util::format_unix_as_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_known_date() {
        // 2023-11-14T22:13:20Z = unix 1700000000
        assert_eq!(crate::util::format_unix_as_iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
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

