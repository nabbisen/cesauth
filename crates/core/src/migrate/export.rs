use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use super::error::{MigrateError, MigrateResult};
use super::types::{FORMAT_VERSION, Manifest, PayloadLine, TableSummary};
use super::redaction::{RedactionProfile, apply_redaction};

pub struct ExportSpec<'a> {
    pub cesauth_version:       &'a str,
    pub schema_version:        u32,
    pub exported_at:           i64,
    pub source_account_id:     &'a str,
    pub source_d1_database_id: Option<&'a str>,
    pub tables:                &'a [&'a str],
    pub profile:               Option<&'a RedactionProfile>,
    /// `Some(ids)` if the export is tenant-scoped (--tenant
    /// flag); `None` for a whole-database export. Added in
    /// v0.22.0. The exporter records this in the manifest's
    /// `tenants` field; the source side is responsible for
    /// actually filtering rows on this list (the library
    /// doesn't issue queries).
    pub tenants:               Option<&'a [String]>,
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
            tenants:               None,
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
            tenants:               self.spec.tenants.map(|t| t.to_vec()),
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

