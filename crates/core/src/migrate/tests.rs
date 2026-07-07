//! Unit tests for `cesauth_core::migrate`.
//!
//! v0.77.0 removed a redundant inline `mod tests { ... }` wrapper that
//! double-nested the module path as `migrate::tests::tests`. This file
//! is already the `tests` module (declared in migrate.rs via
//! `#[cfg(test)] mod tests;`); the wrapper served no purpose and
//! prevented nested submodule resolution for the v0.77.0 file split.

use super::*;


fn sample_manifest() -> Manifest {
    Manifest {
        format_version:        FORMAT_VERSION,
        cesauth_version:       "0.19.0".into(),
        schema_version:        SCHEMA_VERSION,
        exported_at:           1_714_287_000,
        source_account_id:     "acct-test".into(),
        source_d1_database_id: Some("d1-uuid".into()),
        signature_alg:         "ed25519".into(),
        // 32 bytes of zeros, base64url-no-pad
        signature_pubkey:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        signature:             "QkFTRTY0_SIGNATURE_PLACEHOLDER".into(),
        payload_sha256:        "0".repeat(64),
        tables: vec![
            TableSummary { name: "tenants".into(), row_count: 3,  sha256: "a".repeat(64) },
            TableSummary { name: "users".into(),   row_count: 42, sha256: "b".repeat(64) },
        ],
        redaction_profile: None,
        tenants:           None,
    }
}

#[test]
fn manifest_round_trips_through_serde_json() {
    // The on-disk format is JSON-on-a-line. Round-tripping
    // is the load-bearing property: any drift between
    // serialize and deserialize blocks every importer.
    let m  = sample_manifest();
    let s  = serde_json::to_string(&m).unwrap();
    let m2 = serde_json::from_str::<Manifest>(&s).unwrap();
    assert_eq!(m, m2);
}

#[test]
fn manifest_fingerprint_is_stable_for_same_pubkey() {
    // The handshake relies on this being deterministic:
    // exporter prints fingerprint X, importer prints
    // fingerprint X for the same pubkey, the operator
    // confirms they match.
    let m  = sample_manifest();
    let f1 = m.fingerprint();
    let f2 = m.fingerprint();
    assert_eq!(f1, f2);
    // 16 hex chars = 64 bits. ADR-005 §Q3 boundary.
    assert_eq!(f1.len(), 16);
    // Hex.
    assert!(f1.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn manifest_fingerprint_changes_with_pubkey() {
    // Two distinct keys must produce distinct fingerprints
    // (modulo the 64-bit collision space, irrelevant for
    // this case). A regression that returned the same
    // string for any input would break the handshake's
    // mismatch detection.
    let mut a = sample_manifest();
    a.signature_pubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
    let mut b = sample_manifest();
    b.signature_pubkey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBE".into();
    assert_ne!(a.fingerprint(), b.fingerprint());
}

#[test]
fn manifest_fingerprint_handles_invalid_pubkey() {
    // Garbage in `signature_pubkey` (not valid base64url)
    // must surface a sentinel, not panic. The importer
    // checks for the sentinel and refuses to proceed.
    let mut m = sample_manifest();
    m.signature_pubkey = "!!!not-base64!!!".into();
    assert_eq!(m.fingerprint(), "<invalid>");
}

#[test]
fn payload_line_round_trips() {
    // Same property as the manifest test, applied to the
    // payload's row format. JSON values cover the polymorphism.
    let line = PayloadLine {
        table: "users".to_owned(),
        row:   serde_json::json!({
            "id": "u-1",
            "email": "alice@example.com",
            "tenant_id": "tenant-default",
        }),
    };
    let s    = serde_json::to_string(&line).unwrap();
    let back = serde_json::from_str::<PayloadLine<serde_json::Value>>(&s).unwrap();
    assert_eq!(back.table, "users");
    assert_eq!(back.row["id"], "u-1");
}

#[test]
fn lookup_profile_finds_built_ins() {
    assert_eq!(
        lookup_profile("prod-to-staging").map(|p| p.name),
        Some("prod-to-staging"),
    );
    assert_eq!(
        lookup_profile("prod-to-dev").map(|p| p.name),
        Some("prod-to-dev"),
    );
}

#[test]
fn lookup_profile_returns_none_for_unknown() {
    assert!(lookup_profile("does-not-exist").is_none());
    assert!(lookup_profile("").is_none());
}

#[test]
fn prod_to_staging_drops_totp_tables() {
    // ADR-009 §Q5/§Q11. TOTP secrets must NOT survive
    // redaction even encrypted; the staging deployment
    // would otherwise let any operator authenticate as
    // those users. Pin so a future profile-edit can't
    // silently regress this property.
    let p = lookup_profile("prod-to-staging").unwrap();
    assert!(p.drop_tables.contains(&"totp_authenticators"),
        "prod-to-staging must drop totp_authenticators: {:?}", p.drop_tables);
    assert!(p.drop_tables.contains(&"totp_recovery_codes"),
        "prod-to-staging must drop totp_recovery_codes: {:?}", p.drop_tables);
}

#[test]
fn prod_to_dev_drops_totp_tables() {
    // Stricter than prod-to-staging — same TOTP-drop
    // requirement applies all the more.
    let p = lookup_profile("prod-to-dev").unwrap();
    assert!(p.drop_tables.contains(&"totp_authenticators"));
    assert!(p.drop_tables.contains(&"totp_recovery_codes"));
}

#[test]
fn built_in_profile_drop_tables_reference_known_tables() {
    // Defense in depth: the dropped table names should be
    // tables that actually exist in our schema. A typo
    // in `drop_tables` (e.g., "totp_authenticator" without
    // the s) would silently NOT drop the table, leaving
    // a privacy hole.
    //
    // We can't easily import MIGRATION_TABLE_ORDER from
    // cesauth-migrate (cyclic — migrate depends on core),
    // but we can pin the names against a hard-coded list
    // of known TOTP tables that MUST stay in sync. Any
    // future addition of a "drop entire table" rule
    // referencing a non-TOTP table will fail this test
    // and force the developer to update both lists.
    const KNOWN_DROPPABLE: &[&str] = &[
        "totp_authenticators",
        "totp_recovery_codes",
    ];
    for p in built_in_profiles() {
        for t in p.drop_tables {
            assert!(KNOWN_DROPPABLE.contains(t),
                "profile {} references unknown table to drop: {t}",
                p.name);
        }
    }
}

#[test]
fn built_in_profiles_have_unique_names() {
    // Two profiles with the same `name` would make the
    // CLI's `--profile <name>` ambiguous. Catch at compile-
    // time-equivalent (test runs in CI) rather than at
    // runtime.
    let ps = built_in_profiles();
    for (i, a) in ps.iter().enumerate() {
        for b in &ps[i+1..] {
            assert_ne!(a.name, b.name,
                "duplicate profile name: {}", a.name);
        }
    }
}

#[test]
fn prod_to_staging_redacts_email_with_hashed_kind() {
    // The HashedEmail kind preserves the UNIQUE invariant
    // on users.email after redaction. Pin the kind here so
    // a future refactor that flips it to StaticString
    // (which would collapse all emails to one literal and
    // explode UNIQUE on import) gets caught.
    let p = lookup_profile("prod-to-staging").unwrap();
    let r = p.rules.iter()
        .find(|r| r.table == "users" && r.column == "email")
        .expect("prod-to-staging must redact users.email");
    assert_eq!(r.kind, RedactionKind::HashedEmail,
        "users.email redaction must preserve UNIQUE invariant");
}

#[test]
fn format_version_constant_is_one() {
    // Defensive: bumping this constant has cross-importer
    // implications (old importers will refuse new dumps).
    // A test that fails on bump is a forcing function for
    // the bump-author to consider whether the change is
    // intended.
    assert_eq!(FORMAT_VERSION, 1);
}

#[test]
fn schema_version_matches_migration_count() {
    // SCHEMA_VERSION should equal the number of migration
    // files at build time. If a migration ships without
    // bumping this constant, dumps from this build will
    // misadvertise their schema version, and the importer
    // on the destination side will not know what skipped
    // migrations to apply.
    //
    // This test reads the migrations directory at test
    // time. If the relative path differs from the repo
    // layout (cargo runs tests from the package root),
    // adjust here.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()  // out of crates/core
        .parent().unwrap()  // out of crates
        .join("migrations");
    let count = std::fs::read_dir(&dir)
        .map(|it| it
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path().extension()
                    .map(|x| x == "sql")
                    .unwrap_or(false)
            })
            .count() as u32)
        .expect("migrations dir must exist");
    assert_eq!(SCHEMA_VERSION, count,
        "SCHEMA_VERSION ({}) must match migration count ({}). \
         Bump the constant when adding a new migration.",
        SCHEMA_VERSION, count);
}

// ─── Themed test groups split into sibling files (v0.77.0) ────────
mod redaction;
mod export_verify;
mod import_invariants;
mod import_pipeline;
mod email_uniqueness;
mod manifest_tenant;
