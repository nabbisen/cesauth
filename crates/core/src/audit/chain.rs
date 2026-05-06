//! Hash chain calculation for the audit log (ADR-010).
//!
//! Pure functions, no storage, no clock. Adapters call into this
//! module to compute the `payload_hash` and `chain_hash` for a new
//! row, given the previous row's `chain_hash` and the new event's
//! payload + metadata.
//!
//! ## Byte layout
//!
//! The `chain_input` is the SHA-256 input that produces `chain_hash`.
//! Its layout is:
//!
//! ```text
//! chain_input = previous_hash || ":" || payload_hash || ":" ||
//!               seq          || ":" || ts            || ":" ||
//!               kind         || ":" || id
//! ```
//!
//! All values are encoded as UTF-8 strings in their canonical
//! representations:
//!
//! - `previous_hash`, `payload_hash` — 64-character lowercase hex.
//! - `seq` — base-10 ASCII (no leading zeros, no sign).
//! - `ts` — base-10 ASCII signed (matches Unix timestamp sign).
//! - `kind` — the snake_case `EventKind` discriminant string.
//! - `id` — UUID v4 in 8-4-4-4-12 lowercase hex form.
//!
//! The `:` separators are unambiguous because no other field's
//! canonical form contains `:`. (UUIDs use `-`, hashes are hex,
//! sequence/timestamp are decimal.)
//!
//! Changing any of this is a CHAIN BREAK. The Phase 2 verifier
//! consults this module's [`compute_chain_hash`] to validate
//! existing rows; a layout change without a chain version bump
//! would mark every previously-valid row as tampered.
//!
//! ## Genesis sentinel
//!
//! [`GENESIS_HASH`] is the all-zeros 64-character hex string that
//! seeds the chain. The migration's genesis row uses it for both
//! `previous_hash` and `chain_hash`. The first real event's
//! `previous_hash` is the genesis row's `chain_hash`, which by
//! convention is also `GENESIS_HASH` — making the practical
//! starting point of the active chain "the genesis row's
//! chain_hash" without special-case code in the writer.

use sha2::{Digest, Sha256};

/// All-zeros 64-character hex string used as the genesis seed for
/// `previous_hash` and the genesis row's `chain_hash`. The chain
/// verifier treats `seq=1` (the genesis row) as the start condition
/// and stops walking back when it sees this value as a row's
/// `previous_hash`.
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// SHA-256 of `{}` (a JSON empty object), in lowercase hex. This
/// is the genesis row's `payload_hash`. Pinned as a constant so a
/// future migration that re-emits the genesis row produces the
/// same payload_hash without having to recompute SHA-256 of `{}`.
pub const GENESIS_PAYLOAD_HASH: &str =
    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// Hash a payload byte slice into the lowercase hex SHA-256 the
/// chain expects. Use this for the `payload_hash` column.
///
/// The input is the **exact** bytes serialized for the `payload`
/// column. The chain doesn't tolerate "pretty-print this JSON" or
/// whitespace normalization between hash time and storage time —
/// any difference invalidates the chain.
pub fn compute_payload_hash(payload_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(payload_bytes);
    let digest = h.finalize();
    encode_hex(&digest)
}

/// Compute a row's `chain_hash` from its predecessors and metadata.
///
/// `previous_hash` is the predecessor row's `chain_hash` (or
/// [`GENESIS_HASH`] for the first real event). `payload_hash` is
/// the result of [`compute_payload_hash`] on the same row's
/// payload bytes. The remaining fields come straight from the
/// row's columns.
///
/// Returns the lowercase hex SHA-256.
pub fn compute_chain_hash(
    previous_hash: &str,
    payload_hash:  &str,
    seq:           i64,
    ts:            i64,
    kind:          &str,
    id:            &str,
) -> String {
    let mut h = Sha256::new();
    h.update(previous_hash.as_bytes());
    h.update(b":");
    h.update(payload_hash.as_bytes());
    h.update(b":");
    h.update(seq.to_string().as_bytes());
    h.update(b":");
    h.update(ts.to_string().as_bytes());
    h.update(b":");
    h.update(kind.as_bytes());
    h.update(b":");
    h.update(id.as_bytes());
    encode_hex(&h.finalize())
}

/// Verify that a row's `chain_hash` was produced by the canonical
/// inputs. Returns `true` when the recomputed hash matches the
/// stored one — i.e., the row hasn't been tampered with at the
/// `chain_hash` level.
///
/// This is the building block for the Phase 2 sweep: walk the
/// table by seq ascending, calling `verify_chain_link` on each
/// row, expecting `true`. A `false` is a chain break — the row
/// reports its `chain_hash` doesn't match what the inputs imply.
///
/// Note: this verifies a single link, not the chain end-to-end.
/// The caller is responsible for threading `previous_hash` from
/// row to row.
pub fn verify_chain_link(
    expected_chain_hash: &str,
    previous_hash:       &str,
    payload_hash:        &str,
    seq:                 i64,
    ts:                  i64,
    kind:                &str,
    id:                  &str,
) -> bool {
    let recomputed = compute_chain_hash(previous_hash, payload_hash, seq, ts, kind, id);
    constant_time_eq(recomputed.as_bytes(), expected_chain_hash.as_bytes())
}

/// Verify that a payload's stored hash matches the recomputed one.
/// Used by the Phase 2 sweep alongside [`verify_chain_link`].
pub fn verify_payload_hash(expected_payload_hash: &str, payload_bytes: &[u8]) -> bool {
    let recomputed = compute_payload_hash(payload_bytes);
    constant_time_eq(recomputed.as_bytes(), expected_payload_hash.as_bytes())
}

// ---------------------------------------------------------------------
// Helpers (internal — kept here to avoid a dependency on `hex` for one
// hex-encode call site)
// ---------------------------------------------------------------------

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble((*b >> 4) & 0xF));
        out.push(nibble(*b & 0xF));
    }
    out
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _     => (b'a' + n - 10) as char,
    }
}

/// Constant-time byte comparison. Returns true iff the two slices
/// are identical. Used for hash equality so a row's stored hash
/// can't be brute-force-distinguished from a recomputation by
/// timing. (Practically this is overkill — chain verification is
/// not on a remote-attacker timing path — but the cost is one
/// loop, and consistency with the rest of the codebase's
/// constant-time-eq habit is worth keeping.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests;
