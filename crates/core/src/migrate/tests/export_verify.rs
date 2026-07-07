//! Originally part of `crates/core/src/migrate/tests.rs` (a single
//! 1,154-line `mod tests { ... }` block). Split into a sibling
//! file in v0.77.0 — test-file modularization (continuation of
//! v0.75.0–v0.76.0 maintenance track).

use super::*;            // reaches the parent `mod tests` (sample_manifest, etc.)
use super::super::*;     // reaches `migrate` (Manifest, FORMAT_VERSION, etc.)

// -----------------------------------------------------------------
// Export + verify round-trip (v0.20.0)
// -----------------------------------------------------------------

pub(super) fn make_spec<'a>(tables: &'a [&'a str]) -> ExportSpec<'a> {
    ExportSpec {
        cesauth_version:       "0.20.0",
        schema_version:        SCHEMA_VERSION,
        exported_at:           1_714_287_000,
        source_account_id:     "test-account",
        source_d1_database_id: Some("test-d1"),
        tables,
        profile:               None,
        tenants:               None,
    }
}

#[test]
fn export_then_verify_round_trip() {
    // The end-to-end happy path: export rows → verify the
    // resulting bytes. This is the most load-bearing test in
    // the file — every other test is targeted at one
    // sub-property, this one ensures the parts compose.
    let mut buf = Vec::new();
    let tables = ["tenants", "users"];
    let mut exp = Exporter::new(make_spec(&tables), &mut buf).unwrap();
    exp.push("tenants", serde_json::json!({
        "id": "t-1", "slug": "acme", "display_name": "Acme",
    })).unwrap();
    exp.push("users", serde_json::json!({
        "id": "u-1", "tenant_id": "t-1", "email": "alice@acme.example",
    })).unwrap();
    exp.push("users", serde_json::json!({
        "id": "u-2", "tenant_id": "t-1", "email": "bob@acme.example",
    })).unwrap();
    exp.finish().unwrap();

    // Round-trip through verify.
    let report = verify(std::io::Cursor::new(&buf)).unwrap();
    assert_eq!(report.manifest.format_version, FORMAT_VERSION);
    assert_eq!(report.manifest.schema_version, SCHEMA_VERSION);
    assert_eq!(report.manifest.tables.len(), 2);
    assert_eq!(report.manifest.tables[0].name, "tenants");
    assert_eq!(report.manifest.tables[0].row_count, 1);
    assert_eq!(report.manifest.tables[1].name, "users");
    assert_eq!(report.manifest.tables[1].row_count, 2);
    // table_counts surfaces re-computed counts.
    assert_eq!(
        report.table_counts,
        vec![("tenants".into(), 1), ("users".into(), 2)],
    );
    // Redaction was None → manifest records None.
    assert!(report.manifest.redaction_profile.is_none());
}

#[test]
fn export_with_no_rows_produces_valid_dump() {
    // An empty deployment can still be migrated (a fresh-start
    // dump with no users). The manifest must be valid; verify
    // must accept it; row counts should all be zero.
    let mut buf = Vec::new();
    let tables = ["tenants", "users"];
    let exp = Exporter::new(make_spec(&tables), &mut buf).unwrap();
    // Don't push anything.
    exp.finish().unwrap();

    let report = verify(std::io::Cursor::new(&buf)).unwrap();
    assert_eq!(report.manifest.tables[0].row_count, 0);
    assert_eq!(report.manifest.tables[1].row_count, 0);
}

#[test]
fn export_records_redaction_profile_in_manifest() {
    // When a profile is supplied, the manifest must record
    // the profile name. The importer uses this to decide
    // whether a `--require-unredacted` flag should refuse.
    let mut buf = Vec::new();
    let tables = ["users"];
    let mut spec = make_spec(&tables);
    let prof = lookup_profile("prod-to-staging").unwrap();
    spec.profile = Some(prof);
    let mut exp = Exporter::new(spec, &mut buf).unwrap();
    exp.push("users", serde_json::json!({
        "id": "u-1", "email": "alice@example.com", "display_name": "Alice",
    })).unwrap();
    exp.finish().unwrap();

    let report = verify(std::io::Cursor::new(&buf)).unwrap();
    assert_eq!(report.manifest.redaction_profile.as_deref(),
        Some("prod-to-staging"));
}

#[test]
fn export_applies_redaction_to_payload_rows() {
    // The redaction must actually transform the row bytes
    // that are signed and shipped — not just the manifest
    // marker. Re-parse the payload and check.
    let mut buf = Vec::new();
    let tables = ["users"];
    let mut spec = make_spec(&tables);
    let prof = lookup_profile("prod-to-staging").unwrap();
    spec.profile = Some(prof);
    let mut exp = Exporter::new(spec, &mut buf).unwrap();
    exp.push("users", serde_json::json!({
        "id": "u-1", "email": "alice@example.com", "display_name": "Alice",
    })).unwrap();
    exp.finish().unwrap();

    // Skip the manifest line, parse the first payload line.
    let s = std::str::from_utf8(&buf).unwrap();
    let mut lines = s.lines();
    let _ = lines.next();
    let payload_line: PayloadLine = serde_json::from_str(lines.next().unwrap()).unwrap();
    // Email was redacted.
    let email = payload_line.row["email"].as_str().unwrap();
    assert!(email.contains("@example.invalid"));
    assert!(!email.contains("alice@example.com"));
    // Display name redacted to literal.
    assert_eq!(payload_line.row["display_name"], "[redacted]");
}

#[test]
fn verify_rejects_tampered_payload() {
    // Tampering a single byte of the payload after signing
    // must break the signature. This is the core defense the
    // signed-manifest design provides.
    let mut buf = Vec::new();
    let tables = ["users"];
    let mut exp = Exporter::new(make_spec(&tables), &mut buf).unwrap();
    exp.push("users", serde_json::json!({
        "id": "u-1", "email": "alice@example.com",
    })).unwrap();
    exp.finish().unwrap();

    // Find a position in the payload (after the manifest line)
    // and flip a byte.
    let nl = buf.iter().position(|&b| b == b'\n').unwrap();
    // Flip a byte in the payload (well after the newline).
    buf[nl + 20] ^= 0x01;

    let err = verify(std::io::Cursor::new(&buf)).unwrap_err();
    // The first check that fails depends on what was hit:
    // table-hash, payload-hash, or signature. Any of them is
    // an acceptable rejection for tampering.
    assert!(matches!(err,
        MigrateError::TableHashMismatch { .. } |
        MigrateError::PayloadHashMismatch |
        MigrateError::SignatureMismatch |
        MigrateError::Parse(_)),
        "tampered byte must be rejected, got: {err}");
}

#[test]
fn verify_rejects_tampered_signature() {
    // Edit the signature in the manifest. The signed payload
    // is unchanged (so payload+table hashes match), but the
    // signature won't verify against the recomputed digest.
    let mut buf = Vec::new();
    let tables = ["users"];
    let mut exp = Exporter::new(make_spec(&tables), &mut buf).unwrap();
    exp.push("users", serde_json::json!({"id": "u-1"})).unwrap();
    exp.finish().unwrap();

    // Parse manifest, mutate signature, re-emit.
    let nl = buf.iter().position(|&b| b == b'\n').unwrap();
    let manifest_line = std::str::from_utf8(&buf[..nl]).unwrap();
    let mut m: Manifest = serde_json::from_str(manifest_line).unwrap();
    // Swap the signature for a different valid base64url
    // string. (Same length, different bytes.)
    let mut sig_bytes = base64_url_decode(&m.signature).unwrap();
    sig_bytes[0] ^= 0xff;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    m.signature = URL_SAFE_NO_PAD.encode(&sig_bytes);
    let mut new_buf = serde_json::to_vec(&m).unwrap();
    new_buf.push(b'\n');
    new_buf.extend_from_slice(&buf[nl+1..]);

    let err = verify(std::io::Cursor::new(&new_buf)).unwrap_err();
    assert!(matches!(err, MigrateError::SignatureMismatch),
        "tampered signature must be rejected as SignatureMismatch, got: {err}");
}

#[test]
fn verify_rejects_unknown_format_version() {
    // A dump from a future cesauth (FORMAT_VERSION = 2 or
    // higher) must be refused, not silently downgraded.
    let mut m = sample_manifest();
    m.format_version = 999;
    let line = serde_json::to_string(&m).unwrap();
    let buf = format!("{line}\n");

    let err = verify(std::io::Cursor::new(buf.as_bytes())).unwrap_err();
    assert!(matches!(err, MigrateError::UnsupportedFormatVersion {
        found: 999, supported: 1
    }), "got: {err}");
}

#[test]
fn verify_rejects_empty_input() {
    // Empty file → Parse error, not panic.
    let buf: &[u8] = &[];
    let err = verify(std::io::Cursor::new(buf)).unwrap_err();
    assert!(matches!(err, MigrateError::Parse(_)));
}

#[test]
fn verify_rejects_malformed_manifest() {
    // Garbage in the manifest line → Parse, not panic.
    let buf = b"this is not JSON\n{}\n";
    let err = verify(std::io::Cursor::new(&buf[..])).unwrap_err();
    assert!(matches!(err, MigrateError::Parse(_)));
}

#[test]
fn export_refuses_out_of_topological_order() {
    // After pushing a `users` row, pushing a `tenants` row
    // (earlier table in spec.tables) must fail. Streaming
    // importers rely on topological order; a CLI bug that
    // shuffles tables would silently produce an
    // unimportable dump without this check.
    let mut buf = Vec::new();
    let tables = ["tenants", "users"];
    let mut exp = Exporter::new(make_spec(&tables), &mut buf).unwrap();
    exp.push("users",   serde_json::json!({"id": "u-1"})).unwrap();
    let err = exp.push("tenants", serde_json::json!({"id": "t-1"}))
        .expect_err("out-of-order push must error");
    assert!(matches!(err, MigrateError::Parse(_)));
}

#[test]
fn export_refuses_unknown_table() {
    // A row for a table not in spec.tables must error rather
    // than silently producing a dump that no importer can
    // handle (the manifest's tables list won't reference it).
    let mut buf = Vec::new();
    let tables = ["users"];
    let mut exp = Exporter::new(make_spec(&tables), &mut buf).unwrap();
    let err = exp.push("does_not_exist", serde_json::json!({}))
        .expect_err("unknown table must error");
    assert!(matches!(err, MigrateError::Parse(_)));
}

#[test]
fn exporter_fingerprint_matches_post_finish_manifest() {
    // The CLI prints fingerprint() at export start so the
    // operator can read it out-of-band BEFORE the import
    // finishes. The fingerprint must be deterministic with
    // the eventual manifest's value.
    let mut buf = Vec::new();
    let tables = ["users"];
    let exp = Exporter::new(make_spec(&tables), &mut buf).unwrap();
    let prefix_fp = exp.fingerprint();
    exp.finish().unwrap();

    let report = verify(std::io::Cursor::new(&buf)).unwrap();
    let post_fp = report.manifest.fingerprint();
    assert_eq!(prefix_fp, post_fp,
        "operator-printed fingerprint must equal eventual manifest fingerprint");
}

