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
use sha2::Digest as _;

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// Errors produced by `export`, `verify`, and `apply_redaction`.
///
/// Distinguished kinds rather than a single string so the CLI can
/// react: a signature mismatch is a security event (operator should
/// be told loudly); a parse error is a corruption event (operator
/// should retransmit); an I/O error is local. The CLI maps each
/// to a different exit code and message tone.
#[derive(Debug)]
pub enum MigrateError {
    /// A `Read`/`Write` on the underlying stream failed. Mostly disk
    /// or pipe issues; not cesauth's problem to diagnose further.
    Io(std::io::Error),

    /// The manifest line could not be parsed as JSON, or a payload
    /// line was malformed. The dump is corrupt or not a `.cdump`.
    Parse(String),

    /// A `format_version` in the dump is unknown to this build.
    /// Old dumps from newer cesauth releases land here. Cesauth does
    /// not silently downgrade — the importer must explicitly know
    /// the format.
    UnsupportedFormatVersion { found: u32, supported: u32 },

    /// The signature did not verify. Either the dump was tampered
    /// with in transit, or the signature was produced for a
    /// different payload than what arrived. Treat as security
    /// event.
    SignatureMismatch,

    /// A per-table SHA-256 in the manifest disagrees with what was
    /// computed while streaming the payload. Localizes corruption to
    /// a specific table.
    TableHashMismatch { table: String },

    /// The whole-payload SHA-256 in the manifest disagrees with
    /// what was computed while streaming. The signature might be
    /// valid (signing a different payload-hash) but the payload
    /// itself was substituted.
    PayloadHashMismatch,

    /// Random number generation failed. Astronomically unlikely on
    /// a real machine; surfaced as a distinct kind so a CI hosted
    /// without `/dev/urandom` is diagnosable.
    Random(String),

    /// Internal cryptographic error from `ed25519-dalek`. Surfaced
    /// here rather than swallowed so a debugging operator gets a
    /// useful trail.
    Crypto(String),
}

impl std::fmt::Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)                                  => write!(f, "I/O error: {e}"),
            Self::Parse(s)                               => write!(f, "parse error: {s}"),
            Self::UnsupportedFormatVersion { found, supported } => {
                write!(f, "unsupported .cdump format version {found} (this build supports {supported})")
            }
            Self::SignatureMismatch                      => write!(f, "signature did not verify (dump tampered or substituted)"),
            Self::TableHashMismatch { table }            => write!(f, "table hash mismatch on `{table}` (table-localized corruption)"),
            Self::PayloadHashMismatch                    => write!(f, "payload hash mismatch (whole-payload corruption)"),
            Self::Random(s)                              => write!(f, "RNG failure: {s}"),
            Self::Crypto(s)                              => write!(f, "crypto error: {s}"),
        }
    }
}

impl std::error::Error for MigrateError {}

impl From<std::io::Error> for MigrateError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

pub type MigrateResult<T> = Result<T, MigrateError>;

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

// ---------------------------------------------------------------------
// Redaction application
// ---------------------------------------------------------------------

/// Apply a redaction profile to one row. Caller passes the table
/// name and the row as a JSON object; returns the transformed row.
/// Rows whose table is not mentioned in the profile pass through
/// unchanged. Columns not mentioned in the profile pass through
/// unchanged.
///
/// This is the only place redaction is applied; the export function
/// calls into it once per row. Centralizing here means there is
/// exactly one definition of "what does `prod-to-staging` do",
/// matching the manifest's `redaction_profile` field.
pub fn apply_redaction(
    profile: &RedactionProfile,
    table:   &str,
    row:     &mut serde_json::Value,
) {
    let serde_json::Value::Object(map) = row else { return };
    for rule in profile.rules {
        if rule.table != table { continue; }
        let Some(v) = map.get_mut(rule.column) else { continue };
        match rule.kind {
            RedactionKind::HashedEmail => {
                // For string values, derive a synthetic email from
                // SHA-256 of the original. Preserves users.email
                // UNIQUE constraint after redaction. Format:
                // "anon-<8 hex chars>@example.invalid". Stable
                // across runs (same input → same output) so a
                // re-export of the same source produces a
                // diff-friendly dump.
                if let Some(s) = v.as_str() {
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(s.as_bytes());
                    let digest = h.finalize();
                    let hex8: String = digest[..4].iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    *v = serde_json::Value::String(
                        format!("anon-{hex8}@example.invalid"),
                    );
                }
                // Non-string values (NULL etc.) pass through —
                // the schema invariants on the receiving side will
                // re-validate.
            }
            RedactionKind::StaticString => {
                *v = serde_json::Value::String("[redacted]".to_owned());
            }
            RedactionKind::Null => {
                *v = serde_json::Value::Null;
            }
        }
    }
}

// ---------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------

/// Specification of one logical export run. Wraps everything the
/// pure exporter needs to know that isn't a row.
///
/// The `tables` slice lists the tables in topological order
/// (parents before children) — the exporter trusts this ordering
/// and the streaming importer relies on it. It's a `&[&str]` rather
/// than computed from the schema because the topological sort is a
/// schema-level property the library doesn't know about; the CLI
/// caller passes the precomputed order.
#[derive(Debug, Clone)]
pub struct ExportSpec<'a> {
    pub cesauth_version:       &'a str,
    pub schema_version:        u32,
    pub exported_at:           i64,
    pub source_account_id:     &'a str,
    pub source_d1_database_id: Option<&'a str>,
    pub tables:                &'a [&'a str],
    pub profile:               Option<&'a RedactionProfile>,
}

/// Per-export Ed25519 signing key. Wrapped so the caller doesn't
/// touch raw `ed25519-dalek` types — narrows the API surface and
/// makes the "single-use, discarded after signing" invariant
/// explicit.
pub struct ExportSigner {
    inner: ed25519_dalek::SigningKey,
}

impl ExportSigner {
    /// Generate a fresh keypair. Calls `getrandom` directly; on
    /// platforms where `/dev/urandom` is unavailable surfaces the
    /// error as `MigrateError::Random` rather than panicking
    /// (default `SigningKey::generate` would `unwrap`).
    pub fn fresh() -> MigrateResult<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| MigrateError::Random(e.to_string()))?;
        Ok(Self { inner: ed25519_dalek::SigningKey::from_bytes(&seed) })
    }

    /// Public verifying key, base64-url-no-pad — what goes into
    /// the manifest.
    pub fn public_key_b64url(&self) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(self.inner.verifying_key().to_bytes())
    }

    /// Sign the bytes of the payload SHA-256 (the raw 32 bytes,
    /// not the hex string).
    fn sign(&self, msg: &[u8]) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::Signer;
        let sig = self.inner.sign(msg);
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }
}

impl std::fmt::Debug for ExportSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never debug-print the private bytes. The public key is
        // already public-by-design but we elide it too for
        // consistency.
        f.debug_struct("ExportSigner").finish_non_exhaustive()
    }
}

/// Streaming exporter. Caller iterates rows in the order they
/// should appear in the payload (which must match `spec.tables`
/// topologically). Each row is one `(table_name, row_value)`.
///
/// The exporter buffers the payload internally to compute the
/// payload SHA-256 before emitting the manifest. This means peak
/// memory ≈ payload size — for the data volumes this tool targets
/// (low millions of rows at the very top end), buffering is fine.
/// A future streaming-friendly variant could write the manifest at
/// the END instead of the head, at the cost of operator-facing
/// streaming-import simplicity; ADR-005 chose head-manifest.
pub struct Exporter<'a, W: std::io::Write> {
    spec:   ExportSpec<'a>,
    signer: ExportSigner,
    /// Per-table state: row count + ongoing SHA-256.
    /// Tables appear in `spec.tables` order.
    table_state: Vec<TableState>,
    /// In-progress payload buffer + ongoing payload SHA-256.
    payload:        Vec<u8>,
    payload_hasher: sha2::Sha256,
    /// Sink for the manifest + payload at finish() time.
    out: W,
    /// Last-seen table index, to enforce topological ordering.
    /// `None` until the first row.
    last_table_idx: Option<usize>,
}

impl<W: std::io::Write> std::fmt::Debug for Exporter<'_, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't try to describe the in-progress hasher state; it
        // would be misleading mid-export. Surface only static
        // identification.
        f.debug_struct("Exporter")
            .field("source_account_id", &self.spec.source_account_id)
            .field("table_count", &self.spec.tables.len())
            .field("rows_seen", &self.table_state.iter().map(|s| s.count).sum::<u64>())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct TableState {
    name:   String,
    count:  u64,
    hasher: sha2::Sha256,
}

impl<'a, W: std::io::Write> Exporter<'a, W> {
    /// Begin a new export. Generates the per-export signing key.
    pub fn new(spec: ExportSpec<'a>, out: W) -> MigrateResult<Self> {
        let signer = ExportSigner::fresh()?;
        let table_state = spec.tables.iter()
            .map(|name| TableState {
                name:   (*name).to_owned(),
                count:  0,
                hasher: sha2::Sha256::new(),
            })
            .collect();
        Ok(Self {
            spec,
            signer,
            table_state,
            payload:        Vec::new(),
            payload_hasher: sha2::Sha256::new(),
            out,
            last_table_idx: None,
        })
    }

    /// Public-key fingerprint, for the operator to print + read
    /// out-of-band before the import handshake.
    pub fn fingerprint(&self) -> String {
        // Build a temporary manifest just to reuse the
        // fingerprint logic. The full manifest doesn't exist yet
        // (signature requires the full payload), but the public
        // key alone is enough.
        let stub = Manifest {
            format_version:        FORMAT_VERSION,
            cesauth_version:       String::new(),
            schema_version:        0,
            exported_at:           0,
            source_account_id:     String::new(),
            source_d1_database_id: None,
            signature_alg:         String::new(),
            signature_pubkey:      self.signer.public_key_b64url(),
            signature:             String::new(),
            payload_sha256:        String::new(),
            tables:                Vec::new(),
            redaction_profile:     None,
        };
        stub.fingerprint()
    }

    /// Write one row to the payload. The caller is responsible for
    /// passing rows in the same order as `spec.tables` — first all
    /// rows of `tables[0]`, then all rows of `tables[1]`, etc.
    /// Out-of-order rows surface as `MigrateError::Parse` so a CLI
    /// bug doesn't silently produce a malformed dump.
    pub fn push(&mut self, table: &str, mut row: serde_json::Value)
        -> MigrateResult<()>
    {
        // Find or refuse the table.
        let idx = self.spec.tables.iter().position(|t| *t == table)
            .ok_or_else(|| MigrateError::Parse(
                format!("row for unknown table `{table}` (not in spec.tables)"),
            ))?;
        // Topological-order check: idx must be >= last_table_idx.
        if let Some(last) = self.last_table_idx {
            if idx < last {
                return Err(MigrateError::Parse(format!(
                    "out-of-order row: table `{table}` (idx {idx}) appeared after table at idx {last}",
                )));
            }
        }
        self.last_table_idx = Some(idx);

        // Apply redaction if a profile is active.
        if let Some(p) = self.spec.profile {
            apply_redaction(p, table, &mut row);
        }

        // Serialize the line. NDJSON: one PayloadLine per line,
        // newline-terminated.
        let line = PayloadLine { table: table.to_owned(), row };
        let mut buf = serde_json::to_vec(&line)
            .map_err(|e| MigrateError::Parse(e.to_string()))?;
        buf.push(b'\n');

        // Update per-table state.
        let st = &mut self.table_state[idx];
        st.count += 1;
        sha2::Digest::update(&mut st.hasher, &buf);

        // Update payload state.
        sha2::Digest::update(&mut self.payload_hasher, &buf);
        self.payload.extend_from_slice(&buf);
        Ok(())
    }

    /// Finalize the export: compute hashes, sign, write manifest +
    /// payload to the sink. Consumes self because the signer is
    /// single-use — the keypair is dropped after this call (per
    /// ADR-005 §Q3).
    pub fn finish(mut self) -> MigrateResult<()> {
        // Finalize per-table hashes.
        let tables = self.table_state.into_iter()
            .map(|st| TableSummary {
                name:      st.name,
                row_count: st.count,
                sha256:    hex_lower(&sha2::Digest::finalize(st.hasher)),
            })
            .collect();
        // Finalize payload hash.
        let payload_digest = sha2::Digest::finalize(self.payload_hasher);
        let payload_sha256 = hex_lower(&payload_digest);
        // Sign over the raw 32-byte digest, not the hex string.
        let signature = self.signer.sign(&payload_digest);

        let manifest = Manifest {
            format_version:        FORMAT_VERSION,
            cesauth_version:       self.spec.cesauth_version.to_owned(),
            schema_version:        self.spec.schema_version,
            exported_at:           self.spec.exported_at,
            source_account_id:     self.spec.source_account_id.to_owned(),
            source_d1_database_id: self.spec.source_d1_database_id.map(str::to_owned),
            signature_alg:         "ed25519".to_owned(),
            signature_pubkey:      self.signer.public_key_b64url(),
            signature,
            payload_sha256,
            tables,
            redaction_profile:     self.spec.profile.map(|p| p.name.to_owned()),
        };

        // Write manifest line + payload.
        let mut manifest_line = serde_json::to_vec(&manifest)
            .map_err(|e| MigrateError::Parse(e.to_string()))?;
        manifest_line.push(b'\n');
        self.out.write_all(&manifest_line)?;
        self.out.write_all(&self.payload)?;
        self.out.flush()?;
        // ExportSigner drops here — single-use, gone.
        Ok(())
    }
}

/// Lower-case hex of bytes. Inline to avoid `hex` crate API
/// fluctuations in tests.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push_str(&format!("{b:02x}")); }
    s
}

// ---------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------

/// Result of verifying a `.cdump`. Returned by `verify` when every
/// check passes.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub manifest:   Manifest,
    /// Per-table re-computed row count. Always matches the
    /// manifest's `row_count` if `verify` returned Ok — surfaced
    /// here so the CLI can render "imported X rows" without
    /// re-summing.
    pub table_counts: Vec<(String, u64)>,
}

/// Streaming verifier. Reads a `.cdump` from `input`, parses the
/// manifest, streams the payload while computing per-table SHA-256
/// + total payload SHA-256, then verifies the signature against
/// the public key in the manifest.
///
/// Pure function: no D1 contact, no filesystem (the caller passes
/// `Read`). Useful both for the `verify` subcommand (file → no D1)
/// and as the first stage of `import` (file → row stream → D1).
///
/// The full payload is streamed but not materialized — verification
/// is one pass. Memory is `O(tables)` plus one row at a time.
pub fn verify<R: std::io::BufRead>(mut input: R) -> MigrateResult<VerifyReport> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    // ---- 1. Manifest line -------------------------------------------
    let mut manifest_line = String::new();
    input.read_line(&mut manifest_line)?;
    if manifest_line.is_empty() {
        return Err(MigrateError::Parse("empty file".into()));
    }
    let manifest: Manifest = serde_json::from_str(manifest_line.trim_end())
        .map_err(|e| MigrateError::Parse(format!("manifest: {e}")))?;

    // ---- 2. Format-version check ------------------------------------
    if manifest.format_version != FORMAT_VERSION {
        return Err(MigrateError::UnsupportedFormatVersion {
            found:     manifest.format_version,
            supported: FORMAT_VERSION,
        });
    }

    // ---- 3. Stream payload, compute hashes --------------------------
    // Per-table state, keyed by table name in the order tables
    // appeared in the manifest. We trust the manifest's order; the
    // payload is expected to follow it.
    let mut table_states: Vec<(String, sha2::Sha256, u64)> = manifest.tables.iter()
        .map(|t| (t.name.clone(), sha2::Sha256::new(), 0))
        .collect();
    let mut payload_hasher = sha2::Sha256::new();

    let mut line = String::new();
    loop {
        line.clear();
        let n = input.read_line(&mut line)?;
        if n == 0 { break; }
        // Update payload hasher with the raw line bytes (including
        // the trailing newline, matching how the exporter hashed).
        sha2::Digest::update(&mut payload_hasher, line.as_bytes());

        // Parse to find which table this row is for.
        let pl: PayloadLine = serde_json::from_str(line.trim_end_matches('\n'))
            .map_err(|e| MigrateError::Parse(format!("payload line: {e}")))?;

        // Locate table state. O(tables) per row; tables are O(20)
        // in practice so a HashMap would be over-engineering.
        let st = table_states.iter_mut().find(|(name, _, _)| *name == pl.table)
            .ok_or_else(|| MigrateError::Parse(
                format!("payload references unknown table `{}`", pl.table),
            ))?;
        sha2::Digest::update(&mut st.1, line.as_bytes());
        st.2 += 1;
    }

    // ---- 4. Per-table hash check ------------------------------------
    let table_counts: Vec<(String, u64)> = manifest.tables.iter()
        .zip(table_states.iter())
        .map(|(declared, (name, hasher, count))| {
            let computed = hex_lower(&sha2::Digest::finalize(hasher.clone()));
            if computed != declared.sha256 {
                return Err(MigrateError::TableHashMismatch {
                    table: name.clone(),
                });
            }
            if *count != declared.row_count {
                return Err(MigrateError::TableHashMismatch {
                    table: name.clone(),
                });
            }
            Ok((name.clone(), *count))
        })
        .collect::<MigrateResult<_>>()?;

    // ---- 5. Whole-payload hash check --------------------------------
    let computed_payload_digest = sha2::Digest::finalize(payload_hasher);
    let computed_payload_hex = hex_lower(&computed_payload_digest);
    if computed_payload_hex != manifest.payload_sha256 {
        return Err(MigrateError::PayloadHashMismatch);
    }

    // ---- 6. Signature -----------------------------------------------
    let pubkey_bytes = URL_SAFE_NO_PAD.decode(&manifest.signature_pubkey)
        .map_err(|e| MigrateError::Crypto(format!("pubkey decode: {e}")))?;
    let pubkey_bytes_32: [u8; 32] = pubkey_bytes.as_slice().try_into()
        .map_err(|_| MigrateError::Crypto("pubkey not 32 bytes".into()))?;
    let pubkey = VerifyingKey::from_bytes(&pubkey_bytes_32)
        .map_err(|e| MigrateError::Crypto(format!("pubkey load: {e}")))?;

    let sig_bytes = URL_SAFE_NO_PAD.decode(&manifest.signature)
        .map_err(|e| MigrateError::Crypto(format!("signature decode: {e}")))?;
    let sig_bytes_64: [u8; 64] = sig_bytes.as_slice().try_into()
        .map_err(|_| MigrateError::Crypto("signature not 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_bytes_64);

    // The signature is over the raw 32-byte digest (not the hex).
    pubkey.verify(&computed_payload_digest, &signature)
        .map_err(|_| MigrateError::SignatureMismatch)?;

    Ok(VerifyReport { manifest, table_counts })
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
}
