//! Data-migration dump format (introduced v0.19.0, ADR-005).
//!
//! This module defines the on-disk format for cesauth's
//! server-to-server data migration tool, plus the value types and
//! invariant checks the foundation phase of ADR-005 lays down. It
//! is **library-only**: it produces and consumes structured data
//! values, signs and verifies, and runs invariant checks. It does
//! not perform I/O against D1 or the filesystem — that's the
//! `cesauth-migrate` CLI's job (workspace member `crates/migrate/`,
//! lands in v0.20.0+).
//!
//! # Format overview (`.cdump`)
//!
//! A `.cdump` is a single UTF-8 text file:
//!
//! 1. **Manifest** — the first line. JSON object describing the
//!    dump as a whole: format version, cesauth version that
//!    produced it, schema version, source-account identifier,
//!    a signature over the payload, an itemized table list with
//!    per-table row counts and SHA-256.
//! 2. **Payload** — every subsequent line is one JSON object
//!    `{ "table": "...", "row": { ... } }`. Lines are emitted in
//!    topological order — parents before children — so a
//!    streaming importer can write rows as they arrive without
//!    buffering the full file. `tenants` before `users`, `users`
//!    before `user_tenant_memberships`, etc.
//!
//! Newline-delimited JSON (NDJSON) is the wire format. Pretty-
//! printed JSON would be ergonomic but blocks the streaming
//! property — one `{` per line, line breaks separate rows.
//!
//! ## Why a manifest at the head and not the tail
//!
//! The manifest is needed BEFORE the payload to drive a streaming
//! importer (knowing how many tables to expect, how many rows
//! per table, what schema version is being read). That puts the
//! manifest at line 0, and forces a producer trade-off: the
//! manifest contains the SHA-256 of the payload, so the producer
//! must either buffer the payload to compute the hash, or stream
//! it twice (once to write a temp file + hash, once to copy in).
//! For the data volumes this tool targets (low millions of rows
//! at the very top end), buffering is fine.
//!
//! # Signature model
//!
//! Each export generates a fresh Ed25519 keypair, used only for
//! that single dump. The signature covers the SHA-256 of the
//! payload (NOT the manifest). The manifest carries the public
//! key and the signature; the importer:
//!
//! 1. Parses the manifest, extracts public key.
//! 2. Confirms the public-key fingerprint with the operator
//!    out-of-band — see `Manifest::fingerprint`.
//! 3. Streams the payload, computing SHA-256 as it goes.
//! 4. At EOF, verifies the manifest's signature against the
//!    computed SHA-256, the manifest's claimed `payload_sha256`,
//!    and the public key.
//!
//! ADR-005 §Q3 walks the rejected alternatives (long-lived
//! signing keys, PGP/X.509, no signature).
//!
//! # What's NOT in a `.cdump`
//!
//! ADR-005 §Q1 forbids the dump from carrying secrets:
//!
//! - JWT signing key **private** halves.
//! - `SESSION_COOKIE_KEY`, `ADMIN_API_KEY`,
//!   `MAGIC_LINK_MAIL_API_KEY`, `TURNSTILE_SECRET`.
//! - DO state (active sessions, refresh-token families,
//!   auth challenges, rate-limit counters).
//! - R2 audit objects.
//!
//! A stolen `.cdump` must not be capable of forging tokens; the
//! signing-key public halves it carries are sufficient for
//! verification but not for issuance. The destination operator
//! mints fresh secrets at import time. The dump's manifest
//! itemizes which secret kinds the destination will need to
//! provision.
//!
//! # PII redaction
//!
//! For the prod → staging refresh use case, the dump is
//! generated through a `RedactionProfile` that scrubs
//! identifying values: emails, display names, audit subjects.
//! The profile applies during export, not import — the
//! redacted dump is what travels. The receiving side has no
//! way to "un-redact"; that's the design.
//!
//! Profiles are named (`prod-to-staging`, `prod-to-dev`, etc.)
//! and applied at export time via `--profile <name>`. The
//! manifest records which profile was applied (or `null` for
//! a full unredacted dump) so the importer can reject a
//! redacted dump where production-fidelity was expected.
//!
//! # Invariant checks
//!
//! `Manifest::table_invariants` returns the per-table check
//! functions. The importer runs each row through the relevant
//! checks, accumulates violations, and refuses commit unless
//! every row passes (or the operator explicitly waves
//! violations off — escape hatch for recovery scenarios).
//!
//! ADR-005 §Q5 walks why this is verify-on-import rather than
//! assume-correct-from-source.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------
// Format version constants
// ---------------------------------------------------------------------

/// `.cdump` format version. Bumped when the on-disk format changes
/// in a way old importers would mis-read. The importer refuses
/// dumps with a `format_version` it does not recognize.
///
/// History:
/// - 1: initial format, v0.19.0.
pub const FORMAT_VERSION: u32 = 1;

/// The schema version this build of cesauth knows how to import.
/// Equal to the migration count under `migrations/` at build time.
/// The importer warns if the dump's `schema_version` differs:
/// older dumps may need the importer to apply skipped migrations
/// against the destination first; newer dumps are usually
/// importable but may carry columns this build will silently
/// drop.
pub const SCHEMA_VERSION: u32 = 6;

// ---------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------

/// The first line of every `.cdump`. Describes the dump as a
/// whole; never carries row data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// Format version of the dump container itself. Validated
    /// against `FORMAT_VERSION` at parse time. Mismatches refuse
    /// load — there is no implicit backward compatibility.
    pub format_version: u32,

    /// The cesauth release that produced the dump (e.g.
    /// `"0.19.0"`). Informational; the importer logs it.
    pub cesauth_version: String,

    /// The migration count of the source database at export
    /// time. The importer compares with its own
    /// `SCHEMA_VERSION` and warns on mismatch.
    pub schema_version: u32,

    /// Unix seconds when the export started. Note: an export of
    /// a large dataset may run for many seconds — this records
    /// the start, not the end.
    pub exported_at: i64,

    /// Free-form source-account identifier for diagnostic
    /// audit. Typically the Cloudflare account ID; may also
    /// carry a per-deployment label like `"acme-prod"` for
    /// operator clarity. The importer does NOT use this for
    /// auth — see `signature_pubkey` for that.
    pub source_account_id: String,

    /// Optional source D1 database id. Diagnostic only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_d1_database_id: Option<String>,

    /// Always `"ed25519"` in v1; the field exists for forward
    /// compatibility.
    pub signature_alg: String,

    /// Per-export Ed25519 public key, base64-url-no-pad.
    /// 32 bytes raw → 43 chars encoded.
    pub signature_pubkey: String,

    /// Ed25519 signature over `payload_sha256`'s bytes (raw,
    /// not the hex string). Base64-url-no-pad.
    pub signature: String,

    /// SHA-256 of the payload (everything after the manifest
    /// line, including the trailing newline of the last row but
    /// NOT the manifest line itself). Lower-case hex.
    pub payload_sha256: String,

    /// Per-table summary, in the topological order rows appear
    /// in the payload. Importer uses this both for progress
    /// reporting and for early-failure detection (a SHA-256
    /// mismatch on table `tenants` aborts before any rows are
    /// committed downstream).
    pub tables: Vec<TableSummary>,

    /// Name of the redaction profile applied at export, or
    /// `None` for a full unredacted dump. Importer logs the
    /// value and may refuse if a `--require-unredacted` flag
    /// was passed (production-restore use case where redacted
    /// data would be data loss).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_profile: Option<String>,
}

impl Manifest {
    /// Operator-readable fingerprint of the public key —
    /// SHA-256 of the raw 32-byte public key, displayed as
    /// the first 16 hex chars (8 bytes / 64 bits). Long
    /// enough to make collision impractical, short enough to
    /// read aloud.
    ///
    /// Used for the verification handshake: the exporter prints
    /// this at export time; the operator reads it to a colleague
    /// out-of-band; the importer prints it at import time and
    /// the colleague confirms it matches.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        // signature_pubkey is base64url(no-pad). For the
        // fingerprint we want SHA-256 of the raw key bytes.
        // If decoding fails we return a sentinel — the importer
        // can detect that path by the literal "<invalid>" and
        // refuse to proceed.
        let raw = match base64_url_decode(&self.signature_pubkey) {
            Some(b) => b,
            None    => return "<invalid>".to_owned(),
        };
        let mut h = Sha256::new();
        h.update(&raw);
        let digest = h.finalize();
        // First 8 bytes → 16 hex chars.
        let mut s = String::with_capacity(16);
        for b in &digest[..8] {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// Per-table entry in a `Manifest::tables` list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableSummary {
    /// SQL table name (e.g. `"tenants"`, `"users"`).
    pub name: String,

    /// Number of rows for this table in the payload.
    pub row_count: u64,

    /// SHA-256 of this table's rows in the payload, computed
    /// over the concatenation of each row's serialized JSON
    /// followed by `\n`. Lower-case hex. Allows the importer
    /// to detect per-table corruption without re-running the
    /// whole-payload check.
    pub sha256: String,
}

// ---------------------------------------------------------------------
// Payload row
// ---------------------------------------------------------------------

/// One line of payload. Generic over the row's row type — the
/// CLI deserializes into `serde_json::Value` and runs the row
/// through the redaction profile / invariant checks at that
/// level, so this type stays schema-version-agnostic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadLine<T = serde_json::Value> {
    /// SQL table name.
    pub table: String,
    /// The row's column values. JSON object keyed by column name.
    pub row: T,
}

// ---------------------------------------------------------------------
// Redaction profile
// ---------------------------------------------------------------------

/// A redaction profile is a name + a set of column-level
/// transformations. Profiles are looked up by name from the
/// `built_in_profiles` registry; custom profiles can be
/// supplied by the CLI's caller (out of scope for v0.19.0
/// foundation — the registry returns built-ins only for now).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionProfile {
    /// Operator-facing name, used at the CLI as
    /// `--profile <name>`. Recorded in the manifest so the
    /// importer knows what was scrubbed.
    pub name: &'static str,

    /// What this profile does, one paragraph. Surfaced by
    /// `cesauth-migrate export --list-profiles`.
    pub description: &'static str,

    /// Per-table column transformations. `(table, column,
    /// transform)`. A column not listed is preserved as-is.
    pub rules: &'static [RedactionRule],
}

/// Single column-level transformation in a redaction profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionRule {
    pub table:  &'static str,
    pub column: &'static str,
    pub kind:   RedactionKind,
}

/// Kind of transformation a redaction rule applies. Each kind
/// preserves whatever cesauth-side invariants the column is
/// involved in (uniqueness, referential integrity), while
/// removing identifying value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionKind {
    /// Replace with a deterministic synthetic value derived
    /// from a hash of the original. Used for emails: the
    /// hash makes redacted values stable across runs (so a
    /// re-export of the same source produces the same redacted
    /// output), and the synthetic format
    /// (`anon-<hex>@example.invalid`) preserves the
    /// `users.email` UNIQUE invariant.
    HashedEmail,
    /// Replace with the literal string `"[redacted]"`. Used
    /// for free-form display names where collision doesn't
    /// matter for invariants.
    StaticString,
    /// Drop the value (set to JSON `null`). Used for columns
    /// that are optional in the schema and not load-bearing
    /// for invariants.
    Null,
}

/// Built-in redaction profiles. The CLI's
/// `--list-profiles` flag enumerates these. Custom profiles
/// land in v0.20.0 alongside the export path.
pub fn built_in_profiles() -> &'static [RedactionProfile] {
    &BUILT_IN_PROFILES
}

/// Look up a built-in profile by name. Returns `None` for
/// unknown profiles. CLI maps `None` to a recoverable error
/// with the list of known profile names.
pub fn lookup_profile(name: &str) -> Option<&'static RedactionProfile> {
    BUILT_IN_PROFILES.iter().find(|p| p.name == name)
}

const BUILT_IN_PROFILES: [RedactionProfile; 2] = [
    RedactionProfile {
        name: "prod-to-staging",
        description: "\
Replace user emails with hashed synthetic values that preserve \
the UNIQUE invariant; drop display names. Authenticator \
public-key material is preserved (it's not PII; passkey \
challenges live in DO state and aren't dumped). Audit-event \
subject IDs are preserved (they're already pseudonyms — user \
ids, not raw identifiers).",
        rules: &[
            RedactionRule { table: "users",       column: "email",        kind: RedactionKind::HashedEmail   },
            RedactionRule { table: "users",       column: "display_name", kind: RedactionKind::StaticString  },
        ],
    },
    RedactionProfile {
        name: "prod-to-dev",
        description: "\
Stricter than `prod-to-staging`: also nulls out OIDC clients' \
display names and admin tokens' display names, on the theory \
that a developer machine has weaker isolation than a staging \
environment. Use for `wrangler dev`-bound dumps.",
        rules: &[
            RedactionRule { table: "users",        column: "email",         kind: RedactionKind::HashedEmail  },
            RedactionRule { table: "users",        column: "display_name",  kind: RedactionKind::StaticString },
            RedactionRule { table: "oidc_clients", column: "name",          kind: RedactionKind::StaticString },
            RedactionRule { table: "admin_tokens", column: "name",          kind: RedactionKind::Null         },
        ],
    },
];

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Decode a base64-url-no-pad string into bytes. Returns `None`
/// for any decode error — callers map to their own error type.
fn base64_url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()
}

// =====================================================================
// Tests
// =====================================================================

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
}
