//! Audit log filtered export — CSV and JSONL formats (RFC 080).
//!
//! Extracted from `admin/service.rs` by RFC 099. All items remain
//! publicly accessible via `admin::service::*` re-exports.
//!
//! The code below uses fully-qualified `crate::admin::*` paths in every
//! signature; the file-scope `use` statements that RFC 099 carried over
//! were left unreferenced and removed in v0.67.0 hygiene cleanup.

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
/// `seq,timestamp,kind,subject,client,reason,actor,diverges_from_payload`
///
/// **RFC 187 D4 (owner-resolved): `actor` is APPENDED, not inserted next
/// to `subject`.** This project has no published consumers of this
/// format, but it does have a downloaded-file format, and a positional
/// change breaks a spreadsheet silently — appending does not. Disclosed
/// as a surface-contract change in this cut's report even though the
/// append-only choice is correct.
///
/// **RFC 188 Phase 2, D5: `diverges_from_payload` is APPENDED last**,
/// same discipline as `actor` above — this is the slice's own
/// surface-contract change, disclosed in the report and the CHANGELOG
/// the same way `class` was in `0.108.0`. **G1 ruling, Change 1**: the
/// value is one of three words (`clean` / `diverges` /
/// `payload_unreadable`, [`crate::admin::types::PayloadDivergence::as_str`]),
/// not a bool — a plain, unquoted token here, the same word quoted as a
/// JSON string in the JSONL export below and in the viewer's own JSON.
///
/// The `reason` field passes through `audit::redaction` before
/// serialization so that no secret material leaks into the export.
fn render_csv(rows: &[crate::admin::types::AdminAuditEntry]) -> String {
    let mut out = String::from("seq,timestamp,kind,subject,client,reason,actor,diverges_from_payload\r\n");
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
        out.push(',');
        out.push_str(&csv_field(row.actor.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(row.diverges_from_payload.as_str());
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
        // RFC 187 D4: actor appended, same surface-contract discipline as
        // the CSV header above. RFC 188 Phase 2, D5: diverges_from_payload
        // appended after it, same discipline again — a quoted JSON string
        // (G1 ruling Change 1: the three-word state, not a bool).
        format!(
            r#"{{"seq":{seq:?},"timestamp":{ts:?},"kind":{kind:?},"subject":{subj},"client":{cli},"reason":{rsn},"actor":{actor},"diverges_from_payload":{diverges:?}}}"#,
            seq      = row.key,
            ts       = crate::util::format_unix_as_iso8601(row.ts),
            kind     = row.kind,
            subj     = json_string_opt(row.subject.as_deref()),
            cli      = json_string_opt(row.client.as_deref()),
            rsn      = json_string_opt(row.reason.as_deref()),
            actor    = json_string_opt(row.actor.as_deref()),
            diverges = row.diverges_from_payload.as_str(),
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
    use crate::admin::types::{AdminAuditEntry, PayloadDivergence};

    fn entry(ts: i64, kind: &str, subject: Option<&str>) -> AdminAuditEntry {
        AdminAuditEntry {
            ts,
            id:      "id-1".to_owned(),
            kind:    kind.to_owned(),
            subject: subject.map(ToOwned::to_owned),
            actor:   None,
            client:  None,
            reason:  None,
            key:     "seq=1".to_owned(),
            diverges_from_payload: PayloadDivergence::Clean,
        }
    }

    #[test]
    fn csv_header_is_correct() {
        // RFC 187 D4: actor is APPENDED, not inserted next to subject.
        // RFC 188 Phase 2, D5: diverges_from_payload is appended after it.
        let csv = render_csv(&[]);
        assert!(csv.starts_with("seq,timestamp,kind,subject,client,reason,actor,diverges_from_payload\r\n"));
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

    // ── RFC 188 Phase 2, required test (4)/(5) — byte-identity for the
    // clean case, plus the diverged row carrying the flag in both
    // export formats ──────────────────────────────────────────────────

    /// `0.108.0`'s exact CSV output for one clean row with every field
    /// populated — the pre-Phase-2 byte sequence this slice's export
    /// must reproduce unchanged, column for column, before its own
    /// appended column.
    fn pre_0_109_0_csv_row(e: &AdminAuditEntry) -> String {
        format!(
            "{},{},{},{},{},{},{}\r\n",
            csv_field(&e.key),
            csv_field(&crate::util::format_unix_as_iso8601(e.ts)),
            csv_field(&e.kind),
            csv_field(e.subject.as_deref().unwrap_or("")),
            csv_field(e.client.as_deref().unwrap_or("")),
            csv_field(e.reason.as_deref().unwrap_or("")),
            csv_field(e.actor.as_deref().unwrap_or("")),
        )
    }

    /// `0.108.0`'s exact JSONL line for the same row.
    fn pre_0_109_0_jsonl_row(e: &AdminAuditEntry) -> String {
        format!(
            r#"{{"seq":{seq:?},"timestamp":{ts:?},"kind":{kind:?},"subject":{subj},"client":{cli},"reason":{rsn},"actor":{actor}}}"#,
            seq   = e.key,
            ts    = crate::util::format_unix_as_iso8601(e.ts),
            kind  = e.kind,
            subj  = json_string_opt(e.subject.as_deref()),
            cli   = json_string_opt(e.client.as_deref()),
            rsn   = json_string_opt(e.reason.as_deref()),
            actor = json_string_opt(e.actor.as_deref()),
        )
    }

    fn clean_corpus() -> Vec<AdminAuditEntry> {
        vec![
            AdminAuditEntry {
                ts: 1_700_000_000, id: "id-1".into(), kind: "LoginSuccess".into(),
                subject: Some("u-1".into()), actor: Some("admin-1".into()),
                client: Some("client-9".into()), reason: Some("ok".into()),
                key: "seq=1".into(), diverges_from_payload: PayloadDivergence::Clean,
            },
            AdminAuditEntry {
                ts: 1_700_001_000, id: "id-2".into(), kind: "TokenIssued".into(),
                subject: None, actor: None, client: None, reason: None,
                key: "seq=2".into(), diverges_from_payload: PayloadDivergence::Clean,
            },
        ]
    }

    #[test]
    fn clean_corpus_csv_is_byte_identical_to_0_108_0_except_the_appended_column() {
        let rows = clean_corpus();
        let csv = render_csv(&rows);
        let mut expected = String::from("seq,timestamp,kind,subject,client,reason,actor\r\n");
        for e in &rows {
            expected.push_str(&pre_0_109_0_csv_row(e));
        }
        // Prove byte-identity up to the new column, not merely assert it:
        // strip "clean\r\n" from the end of every current line and the
        // appended ",diverges_from_payload" from the header, then compare.
        let header_rest = csv.strip_prefix("seq,timestamp,kind,subject,client,reason,actor,diverges_from_payload\r\n")
            .expect("header must still start with the unchanged seven columns plus the new one");
        let mut reconstructed = String::from("seq,timestamp,kind,subject,client,reason,actor\r\n");
        for line in header_rest.split_inclusive("\r\n") {
            if line.is_empty() { continue; }
            let without_flag = line.strip_suffix(",clean\r\n")
                .expect("every clean row must end with the new column's clean value, unquoted");
            reconstructed.push_str(without_flag);
            reconstructed.push_str("\r\n");
        }
        assert_eq!(reconstructed, expected,
            "every byte before the appended column must match 0.108.0's output exactly");
    }

    #[test]
    fn clean_corpus_jsonl_is_byte_identical_to_0_108_0_except_the_appended_field() {
        let rows = clean_corpus();
        let jsonl = render_jsonl(&rows);
        for (line, e) in jsonl.lines().zip(rows.iter()) {
            let without_field = line.strip_suffix(r#","diverges_from_payload":"clean"}"#)
                .expect("every clean row must end with the new field's clean value")
                .to_owned() + "}";
            assert_eq!(without_field, pre_0_109_0_jsonl_row(e),
                "every byte before the appended field must match 0.108.0's output exactly");
        }
    }

    #[test]
    fn a_diverged_row_carries_the_state_in_both_export_formats() {
        let diverged = AdminAuditEntry {
            ts: 1_700_000_000, id: "id-3".into(), kind: "LoginSuccess".into(),
            subject: Some("u-1".into()), actor: None, client: None, reason: None,
            key: "seq=3".into(), diverges_from_payload: PayloadDivergence::Diverges,
        };
        let csv = render_csv(&[diverged.clone()]);
        assert!(csv.trim_end().ends_with(",diverges"), "diverged row's CSV must carry diverges, got: {csv}");

        let jsonl = render_jsonl(&[diverged]);
        assert!(jsonl.ends_with(r#""diverges_from_payload":"diverges"}"#),
            "diverged row's JSON must carry \"diverges\", got: {jsonl}");
    }

    #[test]
    fn a_payload_unreadable_row_carries_that_state_in_both_export_formats() {
        // G1 ruling, Change 1: the third state must round-trip through
        // the export distinctly from an ordinary divergence.
        let unreadable = AdminAuditEntry {
            ts: 1_700_000_000, id: "id-4".into(), kind: "LoginSuccess".into(),
            subject: None, actor: None, client: None, reason: None,
            key: "seq=4".into(), diverges_from_payload: PayloadDivergence::PayloadUnreadable,
        };
        let csv = render_csv(&[unreadable.clone()]);
        assert!(csv.trim_end().ends_with(",payload_unreadable"),
            "unreadable row's CSV must carry payload_unreadable, got: {csv}");

        let jsonl = render_jsonl(&[unreadable]);
        assert!(jsonl.ends_with(r#""diverges_from_payload":"payload_unreadable"}"#),
            "unreadable row's JSON must carry \"payload_unreadable\", got: {jsonl}");
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
    use crate::admin::types::{AdminAuditEntry, AuditQuery, PayloadDivergence};
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
            actor:   None,
            client:  None,
            reason:  None,
            key:     "seq=1".to_owned(),
            diverges_from_payload: PayloadDivergence::Clean,
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

