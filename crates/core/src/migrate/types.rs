use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use super::error::{MigrateError, MigrateResult};
use super::redaction::base64_url_decode;

pub const FORMAT_VERSION: u32 = 1;

/// The schema version this build of cesauth knows how to import.
/// Equal to the migration count under `migrations/` at build time.
/// The importer warns if the dump's `schema_version` differs:
/// older dumps may need the importer to apply skipped migrations
/// against the destination first; newer dumps are usually
/// importable but may carry columns this build will silently
/// drop.
pub const SCHEMA_VERSION: u32 = 10;

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

    /// Tenant scope of this dump. `None` for a whole-database
    /// dump (every tenant); `Some(ids)` for a `--tenant`-filtered
    /// export. Recorded in the manifest so the importer knows
    /// what scope it's getting; a future operator who runs
    /// `cesauth-migrate verify` on the file sees the scope in
    /// the summary. Empty `Some(vec![])` is technically valid
    /// (nothing exported) but the CLI rejects it operator-side.
    ///
    /// Added in v0.22.0; older dumps that didn't carry the field
    /// deserialize as `None` (i.e., whole-database).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenants: Option<Vec<String>>,
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
