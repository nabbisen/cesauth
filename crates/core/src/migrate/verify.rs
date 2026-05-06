use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use super::error::{MigrateError, MigrateResult};
use super::types::{FORMAT_VERSION, Manifest, PayloadLine};
use super::redaction::RedactionProfile;

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


// ---------------------------------------------------------------------
// Import (v0.21.0)
// ---------------------------------------------------------------------

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push_str(&format!("{b:02x}")); }
    s
}
