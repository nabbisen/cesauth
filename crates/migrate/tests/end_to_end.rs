//! End-to-end integration tests for cesauth-migrate.
//!
//! Tests the round trip: library exports a dump → CLI's `verify`
//! subcommand reads it back. The CLI binary is invoked as a
//! subprocess. This test only runs after the binary is built;
//! `cargo test -p cesauth-migrate` triggers that automatically.

use std::process::Command;

/// Write a real `.cdump` file to `path`. Caller decides what's
/// in it.
fn write_dump(path: &std::path::Path, profile: Option<&str>) {
    use cesauth_core::migrate::{
        lookup_profile, ExportSpec, Exporter, SCHEMA_VERSION,
    };
    let mut buf = std::fs::File::create(path).unwrap();
    let tables = ["tenants", "users"];
    let prof = profile.and_then(lookup_profile);
    let spec = ExportSpec {
        cesauth_version:   "0.20.0-test",
        schema_version:    SCHEMA_VERSION,
        exported_at:       1_714_000_000,
        source_account_id: "e2e-account",
        source_d1_database_id: Some("e2e-d1"),
        tables: &tables,
        profile: prof,
    };
    let mut exp = Exporter::new(spec, &mut buf).unwrap();
    exp.push("tenants", serde_json::json!({
        "id": "t-1", "slug": "acme",
    })).unwrap();
    exp.push("users", serde_json::json!({
        "id": "u-1", "email": "alice@example.com", "display_name": "Alice",
    })).unwrap();
    exp.push("users", serde_json::json!({
        "id": "u-2", "email": "bob@example.com", "display_name": "Bob",
    })).unwrap();
    exp.finish().unwrap();
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cesauth-migrate"))
}

#[test]
fn verify_accepts_clean_dump() {
    let dir = tempdir();
    let path = dir.join("e2e-clean.cdump");
    write_dump(&path, None);

    let out = cli().args(["verify", "-i"]).arg(&path).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(),
        "verify must succeed on clean dump.\nstdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("Signature verified"));
    assert!(stdout.contains("tenants"));
    assert!(stdout.contains("users"));
    assert!(stdout.contains("3 rows across 2 tables"));
}

#[test]
fn verify_surfaces_redaction_profile_in_summary() {
    let dir = tempdir();
    let path = dir.join("e2e-redacted.cdump");
    write_dump(&path, Some("prod-to-staging"));

    let out = cli().args(["verify", "-i"]).arg(&path).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(stdout.contains("prod-to-staging"));
}

#[test]
fn verify_rejects_truncated_dump() {
    // Truncate the dump's payload mid-row. Verify must reject
    // (truncation invalidates the payload SHA-256 if not the
    // signature first).
    let dir = tempdir();
    let path = dir.join("e2e-truncated.cdump");
    write_dump(&path, None);

    // Lop off the last 50 bytes.
    let mut bytes = std::fs::read(&path).unwrap();
    let n = bytes.len().saturating_sub(50);
    bytes.truncate(n);
    std::fs::write(&path, &bytes).unwrap();

    let out = cli().args(["verify", "-i"]).arg(&path).output().unwrap();
    assert!(!out.status.success(),
        "verify must reject truncated dump");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("verification failed") ||
            combined.contains("Parse") ||
            combined.contains("hash") ||
            combined.contains("signature"),
        "rejection must be diagnosable. combined: {combined}");
}

#[test]
fn verify_rejects_nonexistent_file() {
    let out = cli().args(["verify", "-i", "/tmp/this-file-does-not-exist-12345.cdump"])
        .output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn list_profiles_prints_the_two_built_ins() {
    let out = cli().args(["list-profiles"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("prod-to-staging"));
    assert!(stdout.contains("prod-to-dev"));
    assert!(stdout.contains("HashedEmail"));
}

#[test]
fn export_refuses_to_clobber_existing_file() {
    let dir = tempdir();
    let path = dir.join("e2e-existing.cdump");
    std::fs::write(&path, b"existing content").unwrap();

    // We can't actually export (no wrangler in test env) but
    // the clobber check runs before the wrangler call.
    let out = cli().args([
        "export", "-o",
    ])
        .arg(&path)
        .args(["--account-id", "test", "--database", "test"])
        .output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("already exists"),
        "stderr should mention pre-existing file: {stderr}");
}

#[test]
fn import_with_closed_stdin_declines_at_handshake() {
    // The import path prompts for fingerprint confirmation. With
    // stdin closed (the default for `Command::output()`), the
    // prompt's read_line returns 0 bytes immediately, which the
    // CLI treats as decline. Result: import aborts with a
    // diagnostic, destination D1 untouched.
    let dir = tempdir();
    let path = dir.join("e2e-import-decline.cdump");
    write_dump(&path, None);

    let out = cli().args(["import", "-i"])
        .arg(&path)
        .args(["--account-id", "test-acct", "--database", "never-touched"])
        .output().unwrap();
    assert!(!out.status.success(), "must abort when handshake is declined");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stdout}{stderr}");
    // Diagnostic must mention the handshake or operator decision
    // — not crash or report stuck state.
    assert!(
        combined.contains("declined")
            || combined.contains("aborted")
            || combined.contains("fingerprint"),
        "abort must be diagnosable. combined: {combined}",
    );
    // Verify must have run (pre-handshake) and printed something
    // about the dump.
    assert!(combined.contains("Dump verified") || combined.contains("Reading"),
        "verify pass should run before handshake. combined: {combined}");
}

#[test]
fn import_rejects_invalid_dump_before_handshake() {
    // A dump that fails verify must abort before the handshake
    // prompt — operators shouldn't be asked to confirm
    // a fingerprint for a tampered file.
    let dir = tempdir();
    let path = dir.join("e2e-import-bad.cdump");
    write_dump(&path, None);

    // Tamper.
    let mut bytes = std::fs::read(&path).unwrap();
    let nl = bytes.iter().position(|&b| b == b'\n').unwrap();
    bytes[nl + 20] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();

    let out = cli().args(["import", "-i"])
        .arg(&path)
        .args(["--account-id", "test", "--database", "never-touched"])
        .output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr);
    assert!(combined.contains("verification failed")
        || combined.contains("hash")
        || combined.contains("signature")
        || combined.contains("Parse")
        || combined.contains("UTF-8")
        || combined.contains("I/O error"),
        "tampered dump must surface a verify failure. combined: {combined}");
    // Must NOT have asked for handshake — checking absence of
    // the prompt phrase.
    assert!(!combined.contains("[Y/n]") && !combined.contains("[y/N]"),
        "handshake must not run on a failed-verify dump");
}

#[test]
fn export_rejects_unknown_profile() {
    let dir = tempdir();
    let path = dir.join("e2e-unknown-profile.cdump");
    let out = cli().args([
        "export", "-o",
    ])
        .arg(&path)
        .args([
            "--account-id", "test",
            "--database",   "test",
            "--profile",    "this-profile-does-not-exist",
        ])
        .output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown redaction profile"),
        "should fail-fast on bad profile name: {stderr}");
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Return a fresh per-test temp directory under /tmp. We don't
/// use the `tempfile` crate because we don't need cleanup
/// guarantees in CI; the test-process exit removes /tmp.
fn tempdir() -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos()).unwrap_or(0);
    let p = std::path::PathBuf::from(format!("/tmp/cesauth-migrate-test-{nanos}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}
