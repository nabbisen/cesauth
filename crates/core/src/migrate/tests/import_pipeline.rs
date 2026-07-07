//! Originally part of `crates/core/src/migrate/tests.rs` (a single
//! 1,154-line `mod tests { ... }` block). Split into a sibling
//! file in v0.77.0 — test-file modularization (continuation of
//! v0.75.0–v0.76.0 maintenance track).

use super::*;            // reaches the parent `mod tests` (sample_manifest, etc.)
use super::super::*;     // reaches `migrate` (Manifest, FORMAT_VERSION, etc.)
use super::export_verify::make_spec;

// -----------------------------------------------------------------
// Import — full pipeline tests (v0.21.0)
// -----------------------------------------------------------------

/// A simple `ImportSink` for tests. Records every staged row
/// into a `Vec`. `commit` returns the row count; `rollback`
/// clears the staged buffer.
pub(super) struct VecSink {
    staged:    Vec<(String, serde_json::Value)>,
    committed: bool,
}
impl VecSink {
    pub(super) fn new() -> Self { Self { staged: Vec::new(), committed: false } }
}
impl ImportSink for VecSink {
    async fn stage_row(&mut self, table: &str, row: &serde_json::Value)
        -> Result<(), String>
    {
        self.staged.push((table.to_owned(), row.clone()));
        Ok(())
    }
    async fn commit(&mut self) -> Result<u64, String> {
        self.committed = true;
        Ok(self.staged.len() as u64)
    }
    async fn rollback(&mut self) -> Result<(), String> {
        self.staged.clear();
        Ok(())
    }
}

/// Build a real .cdump in-memory and return it as a Cursor
/// suitable for `import` (which needs Read + Seek).
pub(super) fn build_dump(
    tables:  &[&str],
    rows:    Vec<(&str, serde_json::Value)>,
    profile: Option<&'static RedactionProfile>,
) -> std::io::Cursor<Vec<u8>> {
    let mut buf = Vec::new();
    let mut spec = make_spec(tables);
    spec.profile = profile;
    let mut exp = Exporter::new(spec, &mut buf).unwrap();
    for (t, r) in rows {
        exp.push(t, r).unwrap();
    }
    exp.finish().unwrap();
    std::io::Cursor::new(buf)
}

/// Run `import` synchronously by spinning up a current-thread
/// runtime. Tests run as `#[test]`, not `#[tokio::test]`, to
/// avoid forcing every test in this file to depend on tokio
/// at the proc-macro level. The migrate library doesn't
/// import tokio.
pub(super) fn run_import<S: ImportSink>(
    cursor:     &mut std::io::Cursor<Vec<u8>>,
    sink:       &mut S,
    invariants: &[InvariantCheckFn],
    require_unredacted: bool,
) -> MigrateResult<ViolationReport> {
    // Build a tiny single-threaded executor. Future-block-on
    // pattern: poll the future to completion against a noop
    // waker. Works because `ImportSink` impls in tests
    // never actually `.await` on anything that yields.
    let fut = import(cursor, sink, invariants, require_unredacted);
    block_on(fut)
}

/// Minimal block_on for tests. Lives here rather than as a
/// library helper because the production caller (the CLI)
/// uses tokio properly via `#[tokio::main]`. Tests stay
/// host-only and don't need tokio in this crate's deps.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut f = std::pin::pin!(f);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending  => panic!(
                "test future returned Pending; ImportSink impls in tests \
                 must complete synchronously"),
        }
    }
}

#[test]
fn import_clean_dump_passes_with_zero_violations() {
    // Happy path: every row's references are intact.
    let tables = ["tenants", "users"];
    let rows = vec![
        ("tenants", serde_json::json!({"id":"t-1","slug":"acme"})),
        ("users",   serde_json::json!({"id":"u-1","tenant_id":"t-1","email":"a@x.com"})),
        ("users",   serde_json::json!({"id":"u-2","tenant_id":"t-1","email":"b@x.com"})),
    ];
    let mut cursor = build_dump(&tables, rows, None);
    let mut sink = VecSink::new();
    let report = run_import(&mut cursor, &mut sink,
        default_invariant_checks(), false).unwrap();
    assert!(report.is_clean());
    assert_eq!(report.rows_seen, 3);
    assert_eq!(report.rows_staged, 3);
    assert_eq!(sink.staged.len(), 3);
}

#[test]
fn import_dangling_user_tenant_ref_is_flagged() {
    // A user references a tenant that wasn't in the dump.
    // (This shouldn't happen for a well-formed export, but
    // the import is the line of defense.)
    let tables = ["tenants", "users"];
    let rows = vec![
        ("tenants", serde_json::json!({"id":"t-1","slug":"acme"})),
        ("users",   serde_json::json!({"id":"u-1","tenant_id":"t-MISSING","email":"a@x.com"})),
    ];
    let mut cursor = build_dump(&tables, rows, None);
    let mut sink = VecSink::new();
    let report = run_import(&mut cursor, &mut sink,
        default_invariant_checks(), false).unwrap();
    assert!(!report.is_clean());
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].table, "users");
    assert_eq!(report.violations[0].row_id, "u-1");
    assert!(report.violations[0].reason.contains("missing tenant"));
    // Row was still staged (violations don't block staging,
    // only commit).
    assert_eq!(sink.staged.len(), 2);
}

#[test]
fn import_dangling_membership_ref_is_flagged() {
    let tables = ["tenants", "users", "user_tenant_memberships"];
    let rows = vec![
        ("tenants", serde_json::json!({"id":"t-1","slug":"acme"})),
        ("users",   serde_json::json!({"id":"u-1","tenant_id":"t-1"})),
        ("user_tenant_memberships",
            serde_json::json!({"user_id":"u-MISSING","tenant_id":"t-1"})),
    ];
    let mut cursor = build_dump(&tables, rows, None);
    let mut sink = VecSink::new();
    let report = run_import(&mut cursor, &mut sink,
        default_invariant_checks(), false).unwrap();
    assert!(!report.is_clean());
    let v = &report.violations[0];
    assert_eq!(v.table, "user_tenant_memberships");
    assert!(v.reason.contains("missing user"));
}

#[test]
fn import_multiple_violations_accumulate_per_row() {
    // role_assignments has both role_id and user_id checks;
    // both can fire on one row.
    let tables = ["tenants", "users", "roles", "role_assignments"];
    let rows = vec![
        ("tenants", serde_json::json!({"id":"t-1"})),
        ("users",   serde_json::json!({"id":"u-1","tenant_id":"t-1"})),
        ("roles",   serde_json::json!({"id":"r-1"})),
        ("role_assignments",
            serde_json::json!({"role_id":"r-MISSING","user_id":"u-MISSING"})),
    ];
    let mut cursor = build_dump(&tables, rows, None);
    let mut sink = VecSink::new();
    let report = run_import(&mut cursor, &mut sink,
        default_invariant_checks(), false).unwrap();
    // The role_assignment_refs check is one function and
    // returns a single Violation describing the FIRST broken
    // field (role_id), not both. That's an intentional
    // simplification for v0.21.0 — operators get a
    // diagnosable signal without log spam.
    assert_eq!(report.violations.len(), 1);
    assert!(report.violations[0].reason.contains("missing role"));
}

#[test]
fn import_violation_report_groups_by_table() {
    // by_table() is what the CLI uses for the operator
    // summary. Pin its grouping behavior.
    let report = ViolationReport {
        rows_seen: 4, rows_staged: 4,
        violations: vec![
            Violation { table: "users".into(), row_id: "u-1".into(), reason: "x".into() },
            Violation { table: "users".into(), row_id: "u-2".into(), reason: "x".into() },
            Violation { table: "groups".into(), row_id: "g-1".into(), reason: "x".into() },
        ],
    };
    let groups = report.by_table();
    assert_eq!(groups, vec![("users".into(), 2), ("groups".into(), 1)]);
}

#[test]
fn import_refuses_redacted_dump_when_required_unredacted() {
    // An operator running production-restore (not staging-
    // refresh) wants to refuse redacted dumps.
    let tables = ["users"];
    let rows = vec![
        ("users", serde_json::json!({"id":"u-1","email":"a@x.com","display_name":"A"})),
    ];
    let prof = lookup_profile("prod-to-staging");
    let mut cursor = build_dump(&tables, rows, prof);
    let mut sink = VecSink::new();
    let err = run_import(&mut cursor, &mut sink,
        default_invariant_checks(), true).unwrap_err();
    match err {
        MigrateError::Parse(s) => {
            assert!(s.contains("redaction profile"));
            assert!(s.contains("require-unredacted"));
        }
        other => panic!("expected Parse error, got: {other}"),
    }
    // Sink was not asked to stage anything before the bail.
    assert_eq!(sink.staged.len(), 0);
}

#[test]
fn import_runs_verify_first_and_rejects_tampered_dump() {
    // A tampered dump must fail verify (pass 1), so import
    // never starts staging rows — the destination stays
    // unmodified.
    let tables = ["users"];
    let rows = vec![
        ("users", serde_json::json!({"id":"u-1"})),
    ];
    let mut cursor = build_dump(&tables, rows, None);

    // Mutate the payload after the manifest line.
    let buf = cursor.get_mut();
    let nl = buf.iter().position(|&b| b == b'\n').unwrap();
    buf[nl + 20] ^= 0x01;

    let mut sink = VecSink::new();
    let err = run_import(&mut cursor, &mut sink,
        default_invariant_checks(), false).unwrap_err();
    assert!(matches!(err,
        MigrateError::TableHashMismatch { .. } |
        MigrateError::PayloadHashMismatch |
        MigrateError::SignatureMismatch |
        MigrateError::Parse(_)),
        "got: {err}");
    // Critically: nothing was staged.
    assert_eq!(sink.staged.len(), 0);
}

#[test]
fn import_with_disabled_invariants_passes_dangling_refs() {
    // The CLI's `--no-invariant-checks` flag makes the
    // operator-supplied invariants empty. Verify the report
    // is then always clean (the rows still get staged but
    // no violations are emitted).
    let tables = ["tenants", "users"];
    let rows = vec![
        ("tenants", serde_json::json!({"id":"t-1"})),
        ("users",   serde_json::json!({"id":"u-1","tenant_id":"t-MISSING"})),
    ];
    let mut cursor = build_dump(&tables, rows, None);
    let mut sink = VecSink::new();
    // Empty invariants slice = no checks.
    let report = run_import(&mut cursor, &mut sink,
        &[], false).unwrap();
    assert!(report.is_clean());
    assert_eq!(sink.staged.len(), 2);
}

#[test]
fn default_invariant_checks_returns_at_least_four() {
    // Tripwire: a refactor that accidentally drops a check
    // function from the slice fails this test. The exact
    // number is allowed to grow as new checks land.
    let n = default_invariant_checks().len();
    assert!(n >= 4, "expected ≥4 default checks, got {n}");
}

