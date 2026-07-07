//! Originally part of `crates/core/src/migrate/tests.rs` (a single
//! 1,154-line `mod tests { ... }` block). Split into a sibling
//! file in v0.77.0 — test-file modularization (continuation of
//! v0.75.0–v0.76.0 maintenance track).

use super::*;            // reaches the parent `mod tests` (sample_manifest, etc.)
use super::super::*;     // reaches `migrate` (Manifest, FORMAT_VERSION, etc.)
use super::export_verify::make_spec;

// -----------------------------------------------------------------
// v0.22.0 — manifest carries tenant scope
// -----------------------------------------------------------------

#[test]
fn manifest_records_tenant_scope_when_filtered() {
    let mut buf = Vec::new();
    let tables = ["tenants", "users"];
    let mut spec = make_spec(&tables);
    let scoped = vec!["t-acme".to_string(), "t-corp".to_string()];
    spec.tenants = Some(&scoped);
    let mut exp = Exporter::new(spec, &mut buf).unwrap();
    exp.push("tenants", serde_json::json!({"id":"t-acme"})).unwrap();
    exp.push("tenants", serde_json::json!({"id":"t-corp"})).unwrap();
    exp.push("users",   serde_json::json!({"id":"u-1","tenant_id":"t-acme"})).unwrap();
    exp.finish().unwrap();

    let report = verify(std::io::Cursor::new(&buf)).unwrap();
    let recorded = report.manifest.tenants.expect("tenants must be in manifest");
    assert_eq!(recorded, vec!["t-acme".to_string(), "t-corp".to_string()]);
}

#[test]
fn manifest_omits_tenant_scope_for_full_export() {
    // Round-trip: a full-database export emits no tenants
    // field, and the deserializer doesn't synthesize one.
    let mut buf = Vec::new();
    let tables = ["users"];
    let exp = Exporter::new(make_spec(&tables), &mut buf).unwrap();
    exp.finish().unwrap();

    let report = verify(std::io::Cursor::new(&buf)).unwrap();
    assert!(report.manifest.tenants.is_none(),
        "whole-database export must not set the tenants field");
}

#[test]
fn manifest_round_trips_tenants_through_serde() {
    // Pin the wire format: tenants serializes as a JSON
    // array of strings, deserializes back equivalently.
    let mut m = sample_manifest();
    m.tenants = Some(vec!["t-alpha".into(), "t-beta".into()]);
    let s  = serde_json::to_string(&m).unwrap();
    // Field name on the wire.
    assert!(s.contains("\"tenants\""));
    let m2 = serde_json::from_str::<Manifest>(&s).unwrap();
    assert_eq!(m, m2);
}

#[test]
fn manifest_deserializes_dumps_without_tenants_field() {
    // Forward compatibility: a 0.21.0-shaped manifest (no
    // tenants field) must still parse against the 0.22.0
    // type. `#[serde(default)]` on the field makes this
    // work.
    let mut m = sample_manifest();
    let s = serde_json::to_string(&m).unwrap();
    // Manually strip the field if present (sample_manifest
    // emits None which already skips serialization, but be
    // paranoid).
    m.tenants = None;
    let s2 = serde_json::to_string(&m).unwrap();
    // Search for the exact field name as it would appear on the
    // wire. `"tenants":` is unambiguous (won't match `"tables":`
    // or any other substring).
    assert!(!s2.contains("\"tenants\":"),
        "tenants field must be skipped when None: {s2}");
    // Round-trip without the field.
    let m3 = serde_json::from_str::<Manifest>(&s).unwrap();
    assert_eq!(m3.tenants, None);
}
