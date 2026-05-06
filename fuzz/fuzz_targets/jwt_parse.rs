//! Fuzz target for cesauth's JWT parser surface.
//!
//! ## What this tests
//!
//! cesauth's JWS Compact deserializer in `cesauth_core::jwt::signer::verify`
//! receives potentially adversarial `Authorization: Bearer …` tokens from the
//! network on every protected request. The verifier must **never panic** on
//! any byte sequence — it should return `Ok` or `Err`, nothing else.
//!
//! Fuzz goal: confirm the parser is panic-free, DoS-resistant, and does not
//! allocate unbounded memory on malformed input.
//!
//! ## What this does NOT test
//!
//! Whether any random input verifies. It almost never will. The point is
//! correctness-of-failure, not correctness-of-success.
//!
//! ## Hardcoded public key
//!
//! `PUB_KEY` is a static 32-byte test value — the public half of a
//! deterministic Ed25519 keypair (seed = `[1u8; 32]`). No production key is
//! embedded here; this is intentionally a non-secret test value. If a fuzz
//! run ever produces a result that passes signature verification against this
//! fixed key, that is a critical finding worth reporting as a security issue
//! per `.github/SECURITY.md`.
//!
//! ## Running locally
//!
//! ```sh
//! # One-shot (60 seconds, matching CI):
//! cargo +nightly fuzz run jwt_parse -- -max_total_time=60
//!
//! # Extended run (hours, for deeper coverage):
//! cargo +nightly fuzz run jwt_parse
//!
//! # If libfuzzer reports benign leak-on-exit:
//! cargo +nightly fuzz run jwt_parse -- -detect_leaks=0
//! ```
//!
//! Findings are stored in `fuzz/artifacts/jwt_parse/`. File as a security
//! issue; do NOT push the artifact in a public PR.

#![no_main]

use cesauth_core::jwt::{AccessTokenClaims, signer::verify};
use libfuzzer_sys::fuzz_target;

/// Public key for the test keypair (seed = `[1u8; 32]`).
/// Not a production key; hardcoded for stability across fuzz runs.
const PUB_KEY: &[u8; 32] = &[
    0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95,
    0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
    0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b,
    0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
];

fuzz_target!(|data: &[u8]| {
    // Non-UTF-8 byte sequences are not valid JWT inputs; skip them.
    // The verifier's contract is `&str`, so we respect that boundary.
    let s = match std::str::from_utf8(data) {
        Ok(s)  => s,
        Err(_) => return,
    };

    // Call verify with fixed issuer/audience/leeway. The return value is
    // intentionally ignored — we only care that no panic occurs.
    // `verify` internally: splits on '.', base64-decodes header + payload +
    // signature, checks alg header, verifies Ed25519 signature, validates
    // iss/aud/exp/nbf, then deserialises claims. Any error returns Err.
    let _ = verify::<AccessTokenClaims>(
        s,
        PUB_KEY,
        "https://cesauth.fuzz.test",   // expected_iss
        "fuzz-client",                  // expected_aud
        9_999_999_999,                  // leeway_secs — huge; never expires
    );

    // Also exercise verify_for_introspect (aud-relaxed path, RFC 009).
    // Same panic-freedom contract applies.
    let _ = cesauth_core::jwt::signer::verify_for_introspect::<AccessTokenClaims>(
        s,
        PUB_KEY,
        "https://cesauth.fuzz.test",
        9_999_999_999,
    );
});
