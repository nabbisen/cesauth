//! Unit tests for the audit chain hash calculation.
//!
//! Coverage targets:
//!
//! - **Determinism**: same inputs → same output, every time.
//! - **Sensitivity**: every input field changes the output (a
//!   tamper on any field is detected).
//! - **Reference vectors**: pinned hashes for known inputs so a
//!   future refactor that breaks the byte layout fails loudly.
//! - **Genesis sentinel correctness**: the published constants
//!   match what they claim to be.
//! - **Constant-time-eq behavior**: catches the obvious wrong
//!   slice-length case.

use super::*;

// ---------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------

#[test]
fn compute_payload_hash_is_deterministic() {
    // Same input bytes → same hex output across calls.
    let payload = br#"{"kind":"login","user":"alice"}"#;
    let h1 = compute_payload_hash(payload);
    let h2 = compute_payload_hash(payload);
    assert_eq!(h1, h2);
}

#[test]
fn compute_chain_hash_is_deterministic() {
    let h1 = compute_chain_hash(
        GENESIS_HASH,
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        2,
        1_700_000_000,
        "login_succeeded",
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    );
    let h2 = compute_chain_hash(
        GENESIS_HASH,
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        2,
        1_700_000_000,
        "login_succeeded",
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    );
    assert_eq!(h1, h2);
}

// ---------------------------------------------------------------------
// Output shape
// ---------------------------------------------------------------------

#[test]
fn payload_hash_is_64_lowercase_hex_chars() {
    let h = compute_payload_hash(b"anything");
    assert_eq!(h.len(), 64,
        "payload hash must be 64 hex chars (256 bits): {h}");
    assert!(h.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "payload hash must be lowercase hex: {h}");
}

#[test]
fn chain_hash_is_64_lowercase_hex_chars() {
    let h = compute_chain_hash(GENESIS_HASH, GENESIS_PAYLOAD_HASH, 1, 0, "k", "id");
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
}

// ---------------------------------------------------------------------
// Sensitivity — every field affects the output
// ---------------------------------------------------------------------
//
// A tamper is detected only if every input bit influences the
// chain hash. Each test below alters one field and asserts the
// hash changes; collectively they pin the chain's tamper-evidence.

const FIXED_PREV: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const FIXED_PAYLOAD_HASH: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const FIXED_KIND: &str = "test_event";
const FIXED_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

fn baseline_hash() -> String {
    compute_chain_hash(FIXED_PREV, FIXED_PAYLOAD_HASH, 5, 1_700_000_000, FIXED_KIND, FIXED_ID)
}

#[test]
fn changing_previous_hash_changes_chain_hash() {
    let altered = compute_chain_hash(
        "9999999999999999999999999999999999999999999999999999999999999999",
        FIXED_PAYLOAD_HASH, 5, 1_700_000_000, FIXED_KIND, FIXED_ID,
    );
    assert_ne!(baseline_hash(), altered);
}

#[test]
fn changing_payload_hash_changes_chain_hash() {
    let altered = compute_chain_hash(
        FIXED_PREV,
        "8888888888888888888888888888888888888888888888888888888888888888",
        5, 1_700_000_000, FIXED_KIND, FIXED_ID,
    );
    assert_ne!(baseline_hash(), altered);
}

#[test]
fn changing_seq_changes_chain_hash() {
    let altered = compute_chain_hash(FIXED_PREV, FIXED_PAYLOAD_HASH, 6, 1_700_000_000, FIXED_KIND, FIXED_ID);
    assert_ne!(baseline_hash(), altered);
}

#[test]
fn changing_ts_changes_chain_hash() {
    let altered = compute_chain_hash(FIXED_PREV, FIXED_PAYLOAD_HASH, 5, 1_700_000_001, FIXED_KIND, FIXED_ID);
    assert_ne!(baseline_hash(), altered);
}

#[test]
fn changing_kind_changes_chain_hash() {
    let altered = compute_chain_hash(FIXED_PREV, FIXED_PAYLOAD_HASH, 5, 1_700_000_000, "different_event", FIXED_ID);
    assert_ne!(baseline_hash(), altered);
}

#[test]
fn changing_id_changes_chain_hash() {
    let altered = compute_chain_hash(FIXED_PREV, FIXED_PAYLOAD_HASH, 5, 1_700_000_000, FIXED_KIND,
        "00000000-0000-4000-8000-000000000000");
    assert_ne!(baseline_hash(), altered);
}

#[test]
fn changing_one_byte_in_payload_changes_payload_hash() {
    // Avalanche property of SHA-256 — flipping any single bit of
    // the input changes ~half the bits of the output. Pin a
    // representative case.
    let h_a = compute_payload_hash(b"hello");
    let h_b = compute_payload_hash(b"hellp"); // last byte differs by 1 bit
    assert_ne!(h_a, h_b);
}

// ---------------------------------------------------------------------
// Field separator integrity
// ---------------------------------------------------------------------
//
// The chain input uses `:` as a field separator. If a future
// refactor accidentally drops a separator or swaps two fields,
// hash collisions become possible between distinct input tuples.
// This test exercises a case where dropped separators would
// silently collide.

#[test]
fn separator_prevents_field_boundary_ambiguity() {
    // Without the `:` between seq and ts, an attacker who could
    // pick (seq, ts) might find pairs that produce the same
    // concatenation. With `:`, any seq/ts pair is unambiguous.
    //
    // Two pairs that would collide under naive concatenation:
    //   seq=12, ts=345  ->  "12345"
    //   seq=1,  ts=2345 ->  "12345"
    //
    // Pin that the separator-aware hash distinguishes them.
    let h1 = compute_chain_hash(GENESIS_HASH, GENESIS_PAYLOAD_HASH, 12, 345,  "k", "id");
    let h2 = compute_chain_hash(GENESIS_HASH, GENESIS_PAYLOAD_HASH, 1,  2345, "k", "id");
    assert_ne!(h1, h2,
        "separator must disambiguate seq vs ts boundary; got collision");
}

#[test]
fn separator_prevents_kind_id_boundary_ambiguity() {
    // Same idea for the kind/id boundary. UUID format starts
    // with hex digits, so a pathological (kind, id) pair could
    // shift bytes between fields without separators.
    let h1 = compute_chain_hash(GENESIS_HASH, GENESIS_PAYLOAD_HASH, 1, 0, "ka", "bcde-id");
    let h2 = compute_chain_hash(GENESIS_HASH, GENESIS_PAYLOAD_HASH, 1, 0, "kab", "cde-id");
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------
// Reference vectors — pinned hashes
// ---------------------------------------------------------------------
//
// These pin the exact byte layout. If the layout changes (e.g.
// someone "improves" the separator or reorders fields) these
// vectors fail and force the change to be intentional.

#[test]
fn reference_vector_genesis_payload_hash() {
    // SHA-256("{}") = the known constant. Pin so a refactor that
    // accidentally double-encodes (e.g. JSON-quotes the payload)
    // is caught.
    let h = compute_payload_hash(b"{}");
    assert_eq!(h, GENESIS_PAYLOAD_HASH);
}

#[test]
fn reference_vector_first_event_chain_hash() {
    // The first real event after genesis has:
    //   previous_hash = GENESIS_HASH (all zeros)
    //   payload_hash  = some known value
    //   seq = 2 (genesis is seq=1)
    //   ts, kind, id  = chosen values
    //
    // Compute the expected chain_hash by hand once and pin it.
    // If this test fails, either the byte layout changed or
    // SHA-256 itself has been swapped — both are clear signals
    // worth investigating.
    let payload_hash = compute_payload_hash(br#"{"kind":"first"}"#);
    let computed = compute_chain_hash(
        GENESIS_HASH,
        &payload_hash,
        2,
        1_700_000_000,
        "first",
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    );
    // Reference output captured once, lowercase hex, 64 chars.
    // If the layout changes deliberately, regenerate this.
    assert_eq!(
        computed,
        // Computed at v0.32.0 development time and pinned here.
        // If this test fails, the chain byte layout has changed —
        // either deliberately (regenerate this constant and bump
        // the chain version) or accidentally (find the regression).
        "851334e169b92e421066ac1bbc2252f25fe823ea27807d635481bca730299a91",
    );
}

// ---------------------------------------------------------------------
// Verify functions
// ---------------------------------------------------------------------

#[test]
fn verify_chain_link_accepts_correct_inputs() {
    let prev = GENESIS_HASH;
    let payload_hash = compute_payload_hash(br#"{"x":1}"#);
    let h = compute_chain_hash(prev, &payload_hash, 2, 100, "kind", "id");
    assert!(verify_chain_link(&h, prev, &payload_hash, 2, 100, "kind", "id"));
}

#[test]
fn verify_chain_link_rejects_wrong_chain_hash() {
    let prev = GENESIS_HASH;
    let payload_hash = compute_payload_hash(br#"{"x":1}"#);
    let bad = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    assert!(!verify_chain_link(bad, prev, &payload_hash, 2, 100, "kind", "id"));
}

#[test]
fn verify_chain_link_rejects_tampered_seq() {
    let prev = GENESIS_HASH;
    let payload_hash = compute_payload_hash(br#"{"x":1}"#);
    let stored = compute_chain_hash(prev, &payload_hash, 2, 100, "kind", "id");
    // Same stored hash, but verifier asked with a different seq.
    assert!(!verify_chain_link(&stored, prev, &payload_hash, 3, 100, "kind", "id"));
}

#[test]
fn verify_payload_hash_accepts_correct_payload() {
    let payload = br#"{"a":1}"#;
    let h = compute_payload_hash(payload);
    assert!(verify_payload_hash(&h, payload));
}

#[test]
fn verify_payload_hash_rejects_modified_payload() {
    let payload = br#"{"a":1}"#;
    let h = compute_payload_hash(payload);
    let modified = br#"{"a":2}"#;
    assert!(!verify_payload_hash(&h, modified));
}

// ---------------------------------------------------------------------
// Genesis constants
// ---------------------------------------------------------------------

#[test]
fn genesis_hash_is_64_zeros() {
    assert_eq!(GENESIS_HASH.len(), 64);
    assert!(GENESIS_HASH.chars().all(|c| c == '0'),
        "GENESIS_HASH must be all zeros: {GENESIS_HASH}");
}

#[test]
fn genesis_payload_hash_matches_sha256_of_empty_object() {
    // SHA-256 of the bytes `{}` is the published constant.
    let h = compute_payload_hash(b"{}");
    assert_eq!(h, GENESIS_PAYLOAD_HASH);
}

// ---------------------------------------------------------------------
// constant_time_eq corner cases
// ---------------------------------------------------------------------

#[test]
fn constant_time_eq_handles_unequal_lengths() {
    assert!(!constant_time_eq(b"abc", b"abcd"));
    assert!(!constant_time_eq(b"", b"a"));
}

#[test]
fn constant_time_eq_handles_empty_slices() {
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn constant_time_eq_distinguishes_one_byte() {
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(constant_time_eq(b"abc", b"abc"));
}
