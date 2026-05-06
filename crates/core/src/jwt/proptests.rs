//! Property-based tests for JWT signing and verification (RFC 003, v0.51.1).
//!
//! These properties catch adversarial inputs that example-based tests can't
//! realistically cover: unusual claim strings, random key seeds, and
//! single-byte tamper positions across the token's full length.

use proptest::prelude::*;

use crate::jwt::claims::AccessTokenClaims;
use crate::jwt::signer::{verify, JwtSigner};
use ed25519_dalek::{SigningKey, VerifyingKey};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Build a test `JwtSigner` from a fixed 32-byte seed.
fn signer_from_seed(seed: [u8; 32]) -> (JwtSigner, VerifyingKey) {
    let sk = SigningKey::from_bytes(&seed);
    let vk = VerifyingKey::from(&sk);
    // Build a minimal PEM for the signer. We use ed25519-dalek's
    // PKCS#8 serialisation to get the canonical PEM format JwtSigner
    // expects (`from_pkcs8_pem`).
    use pkcs8::EncodePrivateKey;
    let pem = sk
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .expect("test key to PEM");
    let signer = JwtSigner::from_pem(
        "test-kid".to_owned(),
        pem.as_bytes(),
        "https://cesauth.test".to_owned(),
    )
    .expect("build test signer");
    (signer, vk)
}

fn claims_from_parts(sub: &str, aud: &str, cid: &str) -> AccessTokenClaims {
    AccessTokenClaims {
        iss:   "https://cesauth.test".to_owned(),
        sub:   sub.to_owned(),
        aud:   aud.to_owned(),
        exp:   9_999_999_999, // year ~2286, never expires in tests
        iat:   0,
        jti:   "test-jti".to_owned(),
        scope: "email".to_owned(),
        cid:   cid.to_owned(),
    }
}

// ─── Properties ──────────────────────────────────────────────────────────────

proptest! {
    /// **Property 1** — JWT sign/verify round-trip with arbitrary claim strings.
    ///
    /// Any well-formed claim set (non-empty strings, valid UTF-8) that is
    /// signed with a known Ed25519 key must verify correctly, and the decoded
    /// claims must equal the original.
    #[test]
    fn jwt_sign_verify_round_trip(
        seed in any::<[u8; 32]>(),
        sub  in "[a-zA-Z0-9_-]{1,64}",
        aud  in "[a-zA-Z0-9_.-]{1,64}",
        cid  in "[a-zA-Z0-9_-]{1,64}",
    ) {
        let (signer, vk) = signer_from_seed(seed);
        let original = claims_from_parts(&sub, &aud, &cid);
        let token = signer.sign(&original).expect("sign");
        let decoded: AccessTokenClaims = verify(
            &token,
            vk.as_bytes(),
            "https://cesauth.test",
            &aud,
            // Leeway: large so exp=9_999_999_999 always passes
            // regardless of wall-clock time in CI.
            999_999_999,
        ).expect("verify");

        prop_assert_eq!(&decoded.sub,   &original.sub);
        prop_assert_eq!(&decoded.aud,   &original.aud);
        prop_assert_eq!(&decoded.cid,   &original.cid);
        prop_assert_eq!(&decoded.scope, &original.scope);
    }

    /// **Property 2** — Single-byte tamper always causes verify to fail.
    ///
    /// No matter where a single byte is flipped in a validly-signed token,
    /// `verify` must return `Err`. Tests that signature verification is
    /// genuine, not vacuous.
    #[test]
    fn jwt_single_byte_tamper_causes_verify_failure(
        seed       in any::<[u8; 32]>(),
        tamper_pos in any::<usize>(),
    ) {
        let (signer, vk) = signer_from_seed(seed);
        let claims = claims_from_parts("user1", "client1", "cid1");
        let token = signer.sign(&claims).expect("sign");

        let mut bytes = token.into_bytes();
        // Flip one byte at `tamper_pos mod len`. Always modifies something.
        let idx = tamper_pos % bytes.len();
        bytes[idx] = bytes[idx].wrapping_add(1);

        let tampered = String::from_utf8_lossy(&bytes).into_owned();
        let result = verify::<AccessTokenClaims>(
            &tampered, vk.as_bytes(), "https://cesauth.test", "client1", 999_999_999,
        );
        prop_assert!(
            result.is_err(),
            "tampered token at position {idx} must not verify"
        );
    }

    /// **Property 3** — Wrong public key always causes verify to fail.
    ///
    /// A token signed by `seed_a` must not verify under `seed_b` (different
    /// key pair). Guards against a weaker-than-expected signature check.
    #[test]
    fn jwt_wrong_key_causes_verify_failure(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
    ) {
        // If seeds happen to be equal the test is vacuous — skip it.
        prop_assume!(seed_a != seed_b);

        let (signer_a, _vk_a) = signer_from_seed(seed_a);
        let (_signer_b, vk_b) = signer_from_seed(seed_b);
        let claims = claims_from_parts("user1", "aud1", "cid1");
        let token = signer_a.sign(&claims).expect("sign with key A");

        let result = verify::<AccessTokenClaims>(
            &token, vk_b.as_bytes(), "https://cesauth.test", "aud1", 999_999_999,
        );
        prop_assert!(
            result.is_err(),
            "token signed with key A must not verify under key B"
        );
    }
}

// ─── Magic Link round-trip ────────────────────────────────────────────────────

proptest! {
    /// **Property 4** — Magic Link issue/verify round-trip.
    ///
    /// Any OTP generated by `magic_link::issue` must verify correctly before
    /// its expiry.
    #[test]
    fn magic_link_issue_verify_round_trip(now in 0i64..1_000_000_000i64) {
        let ttl = 600i64;
        let issued = crate::magic_link::issue(now, ttl).expect("issue");
        let result = crate::magic_link::verify(
            &issued.delivery_payload,
            &issued.code_hash,
            now,
            issued.expires_at,
        );
        prop_assert!(result.is_ok(), "issued OTP must verify before expiry");
    }

    /// **Property 5** — Magic Link OTP with a single character changed fails.
    #[test]
    fn magic_link_tampered_otp_fails_verify(now in 0i64..1_000_000_000i64) {
        let issued = crate::magic_link::issue(now, 600).expect("issue");
        // Flip the first character of the code.
        let mut tampered = issued.delivery_payload.clone();
        if let Some(c) = tampered.chars().next() {
            let replacement = if c == 'A' { 'B' } else { 'A' };
            tampered = replacement.to_string() + &tampered[1..];
        }
        // Only run the assertion if the tamper actually changed the code.
        if tampered != issued.delivery_payload {
            let result = crate::magic_link::verify(
                &tampered, &issued.code_hash, now, issued.expires_at,
            );
            prop_assert!(result.is_err(), "tampered OTP must not verify");
        }
    }
}
