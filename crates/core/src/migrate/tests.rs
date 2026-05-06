use super::*;

#[cfg(test)]
mod tests {
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

    // -----------------------------------------------------------------
    // Redaction (v0.20.0)
    // -----------------------------------------------------------------

    #[test]
    fn apply_redaction_hashed_email_is_deterministic() {
        // Hashing the same source email twice must produce the
        // same redacted value. Without this, re-exporting the same
        // database would produce diff-noise in the dump and break
        // any "did the dump change" check operators rely on.
        let p = lookup_profile("prod-to-staging").unwrap();
        let mut row1 = serde_json::json!({"email": "alice@example.com"});
        let mut row2 = serde_json::json!({"email": "alice@example.com"});
        apply_redaction(p, "users", &mut row1);
        apply_redaction(p, "users", &mut row2);
        assert_eq!(row1, row2);
        // Format check: anon-XXXXXXXX@example.invalid
        let s = row1["email"].as_str().unwrap();
        assert!(s.starts_with("anon-"));
        assert!(s.ends_with("@example.invalid"));
    }

    #[test]
    fn apply_redaction_hashed_email_distinguishes_distinct_emails() {
        // The whole point of HashedEmail is to preserve UNIQUE
        // across redaction. Two distinct source emails must
        // produce distinct redacted values.
        let p = lookup_profile("prod-to-staging").unwrap();
        let mut a = serde_json::json!({"email": "alice@example.com"});
        let mut b = serde_json::json!({"email": "bob@example.com"});
        apply_redaction(p, "users", &mut a);
        apply_redaction(p, "users", &mut b);
        assert_ne!(a["email"], b["email"]);
    }

    #[test]
    fn apply_redaction_static_string_is_uniform() {
        // For display_name, all rows collapse to "[redacted]".
        // That's intentional — display_name has no UNIQUE
        // constraint, and uniformity makes the dump diff-clean
        // in unrelated columns.
        let p = lookup_profile("prod-to-staging").unwrap();
        let mut a = serde_json::json!({"display_name": "Alice"});
        let mut b = serde_json::json!({"display_name": "Bob"});
        apply_redaction(p, "users", &mut a);
        apply_redaction(p, "users", &mut b);
        assert_eq!(a["display_name"], "[redacted]");
        assert_eq!(b["display_name"], "[redacted]");
    }

    #[test]
    fn apply_redaction_skips_unmatched_table() {
        // A profile that targets `users` must not transform
        // rows from `tenants`, even if the column name happens
        // to match. The rule is `(table, column)` keyed.
        let p = lookup_profile("prod-to-staging").unwrap();
        // tenants doesn't have email but try with display_name
        // which exists on users in prod-to-staging.
        let mut row = serde_json::json!({"display_name": "Acme Corp"});
        apply_redaction(p, "tenants", &mut row);
        assert_eq!(row["display_name"], "Acme Corp",
            "tenants.display_name must NOT be redacted by users-targeted rules");
    }

    #[test]
    fn apply_redaction_preserves_unrelated_columns() {
        // Columns not mentioned by the profile pass through.
        let p = lookup_profile("prod-to-staging").unwrap();
        let mut row = serde_json::json!({
            "id": "u-1",
            "email": "alice@example.com",
            "tenant_id": "tenant-default",
        });
        apply_redaction(p, "users", &mut row);
        assert_eq!(row["id"], "u-1");
        assert_eq!(row["tenant_id"], "tenant-default");
        // Email transformed.
        assert!(row["email"].as_str().unwrap().contains("@example.invalid"));
    }

    #[test]
    fn apply_redaction_null_kind_drops_value() {
        // The Null kind sets the value to JSON null. Used for
        // optional columns that don't carry invariants.
        let p = lookup_profile("prod-to-dev").unwrap();
        let mut row = serde_json::json!({"name": "ops-2026-01"});
        apply_redaction(p, "admin_tokens", &mut row);
        assert_eq!(row["name"], serde_json::Value::Null);
    }

    // -----------------------------------------------------------------
    // Export + verify round-trip (v0.20.0)
    // -----------------------------------------------------------------

    fn make_spec<'a>(tables: &'a [&'a str]) -> ExportSpec<'a> {
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

    // -----------------------------------------------------------------
    // Import — invariant checks (v0.21.0)
    // -----------------------------------------------------------------

    /// A `SeenSnapshot` populated with a small known-good fixture.
    /// Each test starts from this and assert what flips when a
    /// reference is missing.
    fn fixture_seen() -> SeenSnapshot {
        let mut s = SeenSnapshot::default();
        s.insert("tenants", "t-1".into());
        s.insert("tenants", "t-2".into());
        s.insert("users",   "u-1".into());
        s.insert("users",   "u-2".into());
        s.insert("organizations", "o-1".into());
        s.insert("groups",  "g-1".into());
        s.insert("roles",   "r-1".into());
        s
    }

    #[test]
    fn check_user_tenant_ref_passes_for_known_tenant() {
        let mut seen = fixture_seen();
        let row = serde_json::json!({"id":"u-3","tenant_id":"t-1"});
        assert!(check_user_tenant_ref("users", &row, &mut seen).is_none());
    }

    #[test]
    fn check_user_tenant_ref_fails_for_unknown_tenant() {
        let mut seen = fixture_seen();
        let row = serde_json::json!({"id":"u-3","tenant_id":"t-missing"});
        let r = check_user_tenant_ref("users", &row, &mut seen);
        assert!(r.is_some());
        assert!(r.unwrap().contains("missing tenant"));
    }

    #[test]
    fn check_user_tenant_ref_skips_other_tables() {
        // Defensive: a check function must only fire for its
        // owned table. Returning a violation for an unrelated
        // row is a worse failure than missing a violation.
        let mut seen = fixture_seen();
        let row = serde_json::json!({"id":"t-1","tenant_id":"missing-but-irrelevant"});
        assert!(check_user_tenant_ref("tenants", &row, &mut seen).is_none());
    }

    #[test]
    fn check_membership_user_ref_fires_only_for_membership_tables() {
        let mut seen = fixture_seen();
        let row = serde_json::json!({"user_id":"u-missing"});
        // Membership tables fire.
        for t in &["user_tenant_memberships", "user_organization_memberships", "user_group_memberships"] {
            let r = check_membership_user_ref(t, &row, &mut seen);
            assert!(r.is_some(), "should fire on {t}");
        }
        // Non-membership tables don't fire.
        for t in &["users", "tenants", "organizations"] {
            let r = check_membership_user_ref(t, &row, &mut seen);
            assert!(r.is_none(), "should not fire on {t}");
        }
    }

    #[test]
    fn check_membership_container_dispatches_per_table() {
        let mut seen = fixture_seen();

        // tenant_id checked against tenants
        let r = check_membership_container_ref("user_tenant_memberships",
            &serde_json::json!({"tenant_id":"t-missing"}), &mut seen);
        assert!(r.unwrap().contains("missing tenants"));

        // organization_id checked against organizations
        let r = check_membership_container_ref("user_organization_memberships",
            &serde_json::json!({"organization_id":"o-missing"}), &mut seen);
        assert!(r.unwrap().contains("missing organizations"));

        // group_id checked against groups
        let r = check_membership_container_ref("user_group_memberships",
            &serde_json::json!({"group_id":"g-missing"}), &mut seen);
        assert!(r.unwrap().contains("missing groups"));
    }

    #[test]
    fn check_role_assignment_refs_catches_both_sides() {
        let mut seen = fixture_seen();

        // Missing role
        let r = check_role_assignment_refs("role_assignments",
            &serde_json::json!({"role_id":"r-missing","user_id":"u-1"}), &mut seen);
        assert!(r.unwrap().contains("missing role"));

        // Missing user
        let r = check_role_assignment_refs("role_assignments",
            &serde_json::json!({"role_id":"r-1","user_id":"u-missing"}), &mut seen);
        assert!(r.unwrap().contains("missing user"));

        // Both present
        let r = check_role_assignment_refs("role_assignments",
            &serde_json::json!({"role_id":"r-1","user_id":"u-1"}), &mut seen);
        assert!(r.is_none());
    }

    // -----------------------------------------------------------------
    // Import — full pipeline tests (v0.21.0)
    // -----------------------------------------------------------------

    /// A simple `ImportSink` for tests. Records every staged row
    /// into a `Vec`. `commit` returns the row count; `rollback`
    /// clears the staged buffer.
    struct VecSink {
        staged:    Vec<(String, serde_json::Value)>,
        committed: bool,
    }
    impl VecSink {
        fn new() -> Self { Self { staged: Vec::new(), committed: false } }
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
    fn build_dump(
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
    fn run_import<S: ImportSink>(
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

    // -----------------------------------------------------------------
    // v0.22.0 — email uniqueness + scoped secondary index
    // -----------------------------------------------------------------

    #[test]
    fn scoped_secondary_index_tracks_per_tuple() {
        // The `record_scoped_secondary` returns true on duplicate
        // (i.e., the value was already present). Pin the
        // semantic — checks rely on this exact return value.
        let mut s = SeenSnapshot::default();
        // First insert: not a duplicate.
        let dup = s.record_scoped_secondary(
            "users", "tenant_id", "t-1", "alice@x".into());
        assert!(!dup, "first insert must report not-already-present");
        // Second insert of same value: duplicate.
        let dup = s.record_scoped_secondary(
            "users", "tenant_id", "t-1", "alice@x".into());
        assert!(dup, "second insert must report already-present");
        // Different scope, same value: not a duplicate.
        let dup = s.record_scoped_secondary(
            "users", "tenant_id", "t-2", "alice@x".into());
        assert!(!dup, "scope change must reset uniqueness");
    }

    #[test]
    fn check_user_email_unique_skips_when_table_not_users() {
        let mut s = SeenSnapshot::default();
        let row = serde_json::json!({"email":"a@x","tenant_id":"t-1"});
        assert!(check_user_email_unique_per_tenant("tenants", &row, &mut s).is_none());
        assert!(check_user_email_unique_per_tenant("groups",  &row, &mut s).is_none());
    }

    #[test]
    fn check_user_email_unique_passes_for_distinct_emails() {
        let mut s = SeenSnapshot::default();
        let r1 = check_user_email_unique_per_tenant("users",
            &serde_json::json!({"email":"alice@x","tenant_id":"t-1"}), &mut s);
        let r2 = check_user_email_unique_per_tenant("users",
            &serde_json::json!({"email":"bob@x","tenant_id":"t-1"}), &mut s);
        assert!(r1.is_none());
        assert!(r2.is_none());
    }

    #[test]
    fn check_user_email_unique_flags_duplicate_within_tenant() {
        let mut s = SeenSnapshot::default();
        let r1 = check_user_email_unique_per_tenant("users",
            &serde_json::json!({"email":"alice@x","tenant_id":"t-1"}), &mut s);
        assert!(r1.is_none());
        let r2 = check_user_email_unique_per_tenant("users",
            &serde_json::json!({"email":"alice@x","tenant_id":"t-1"}), &mut s);
        let reason = r2.expect("duplicate must be flagged");
        assert!(reason.contains("duplicates an earlier user"));
        assert!(reason.contains("alice@x"));
        assert!(reason.contains("t-1"));
    }

    #[test]
    fn check_user_email_unique_allows_same_email_in_different_tenants() {
        // Per-tenant uniqueness, not global uniqueness. The
        // schema permits the same email in two distinct tenants.
        let mut s = SeenSnapshot::default();
        let r1 = check_user_email_unique_per_tenant("users",
            &serde_json::json!({"email":"alice@x","tenant_id":"t-1"}), &mut s);
        let r2 = check_user_email_unique_per_tenant("users",
            &serde_json::json!({"email":"alice@x","tenant_id":"t-2"}), &mut s);
        assert!(r1.is_none());
        assert!(r2.is_none(), "same email in distinct tenants must pass");
    }

    #[test]
    fn check_user_email_unique_is_case_insensitive() {
        // cesauth's schema declares email UNIQUE COLLATE NOCASE.
        // The check must mirror that semantic.
        let mut s = SeenSnapshot::default();
        let r1 = check_user_email_unique_per_tenant("users",
            &serde_json::json!({"email":"Alice@example.COM","tenant_id":"t-1"}), &mut s);
        assert!(r1.is_none());
        let r2 = check_user_email_unique_per_tenant("users",
            &serde_json::json!({"email":"alice@example.com","tenant_id":"t-1"}), &mut s);
        assert!(r2.is_some(), "case difference must NOT escape the check");
    }

    #[test]
    fn check_user_email_unique_skips_users_without_email() {
        // Anonymous users have no email; the check must not
        // panic or flag them. The first row sets up the tenant;
        // the second is anonymous (no email field).
        let mut s = SeenSnapshot::default();
        let r = check_user_email_unique_per_tenant("users",
            &serde_json::json!({"id":"u-anon","tenant_id":"t-1"}), &mut s);
        assert!(r.is_none(), "missing email field must not trigger the check");
    }

    #[test]
    fn import_flags_duplicate_email_within_tenant() {
        // End-to-end through the import driver. Two users in the
        // same tenant with the same email — the second is
        // flagged.
        let tables = ["tenants", "users"];
        let rows = vec![
            ("tenants", serde_json::json!({"id":"t-1"})),
            ("users",   serde_json::json!({"id":"u-1","tenant_id":"t-1","email":"alice@x"})),
            ("users",   serde_json::json!({"id":"u-2","tenant_id":"t-1","email":"alice@x"})),
        ];
        let mut cursor = build_dump(&tables, rows, None);
        let mut sink = VecSink::new();
        let report = run_import(&mut cursor, &mut sink,
            default_invariant_checks(), false).unwrap();
        assert!(!report.is_clean());
        // Find the email violation specifically — other checks
        // shouldn't fire on this fixture.
        let email_v = report.violations.iter()
            .find(|v| v.reason.contains("duplicates"))
            .expect("email-uniqueness violation should be present");
        assert_eq!(email_v.row_id, "u-2");
        assert_eq!(email_v.table, "users");
    }

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
}

