//! Tests for `cesauth_core::totp`. Extracted to keep the parent
//! file focused on production code.
//!
//! The RFC 6238 test vectors at the top of the file pin the
//! HMAC-SHA1 implementation against the canonical reference.
//! Everything else exercises cesauth-specific behavior:
//! replay protection, encryption with AAD, recovery code
//! semantics, otpauth URI shape.

use super::*;

// =====================================================================
// RFC 6238 Appendix B test vectors
// =====================================================================
//
// The published test vectors use a 20-byte ASCII secret
// "12345678901234567890" and the SHA-1 variant. cesauth locks to
// SHA-1 so all RFC vectors apply directly.
//
// Sample table (selected):
//   Time (sec)     Step (hex)       SHA-1 TOTP
//   59             0000000000000001 94287082
//   1111111109     00000000023523EC 07081804
//   1111111111     00000000023523ED 14050471
//   1234567890     000000000273EF07 89005924
//   2000000000     0000000003F940AA 69279037
//
// The RFC's reference codes are 8-digit; cesauth uses 6 digits. To
// derive the 6-digit values we apply `% 10^6` to the RFC's
// 8-digit values:
//   94287082 % 1000000 = 287082
//   07081804 % 1000000 =  81804  -> formatted "081804"
//   14050471 % 1000000 =  50471  -> formatted "050471"
//   89005924 % 1000000 =   5924  -> formatted "005924"
//   69279037 % 1000000 = 279037

const RFC6238_SECRET_ASCII: &[u8] = b"12345678901234567890";

fn rfc_secret() -> Secret {
    Secret::from_bytes(RFC6238_SECRET_ASCII.to_vec()).unwrap()
}

#[test]
fn rfc6238_vector_t_59() {
    let s = rfc_secret();
    let step = step_for_unix(59);
    assert_eq!(step, 1);
    assert_eq!(compute_code(&s, step), 287082);
}

#[test]
fn rfc6238_vector_t_1111111109() {
    let s = rfc_secret();
    let step = step_for_unix(1111111109);
    assert_eq!(compute_code(&s, step), 81804);
}

#[test]
fn rfc6238_vector_t_1111111111() {
    let s = rfc_secret();
    let step = step_for_unix(1111111111);
    assert_eq!(compute_code(&s, step), 50471);
}

#[test]
fn rfc6238_vector_t_1234567890() {
    let s = rfc_secret();
    let step = step_for_unix(1234567890);
    assert_eq!(compute_code(&s, step), 5924);
}

#[test]
fn rfc6238_vector_t_2000000000() {
    let s = rfc_secret();
    let step = step_for_unix(2000000000);
    assert_eq!(compute_code(&s, step), 279037);
}

// =====================================================================
// step_for_unix
// =====================================================================

#[test]
fn step_zero_at_epoch() {
    assert_eq!(step_for_unix(0), 0);
}

#[test]
fn step_clamps_negative_to_zero() {
    // Negative timestamps can't happen in practice (no real
    // verify happens before 1970) but pin the saturating
    // behavior so a clock-skewed Worker doesn't panic.
    assert_eq!(step_for_unix(-1), 0);
    assert_eq!(step_for_unix(i64::MIN), 0);
}

#[test]
fn step_advances_every_30_seconds() {
    assert_eq!(step_for_unix(29), 0);
    assert_eq!(step_for_unix(30), 1);
    assert_eq!(step_for_unix(59), 1);
    assert_eq!(step_for_unix(60), 2);
}

// =====================================================================
// Secret round-trip and validation
// =====================================================================

#[test]
fn secret_generate_returns_correct_length() {
    let s = Secret::generate().unwrap();
    assert_eq!(s.as_bytes().len(), SECRET_BYTES);
}

#[test]
fn secret_generate_is_random() {
    // Two consecutive generates must differ. Probability of
    // collision is ~ 2^-160 per call; if this test ever fails,
    // the CSPRNG is broken.
    let a = Secret::generate().unwrap();
    let b = Secret::generate().unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
}

#[test]
fn secret_base32_round_trip() {
    let original = Secret::generate().unwrap();
    let b32 = original.to_base32();
    let decoded = Secret::from_base32(&b32).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn secret_from_base32_tolerates_whitespace_and_lowercase() {
    let original = Secret::generate().unwrap();
    let b32 = original.to_base32();

    // Insert spaces every 4 chars (a common formatting users
    // produce when typing from paper) and lowercase everything.
    let formatted: String = b32
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            let lc = c.to_ascii_lowercase();
            if i > 0 && i % 4 == 0 {
                vec![' ', lc]
            } else {
                vec![lc]
            }
        })
        .collect();

    let decoded = Secret::from_base32(&formatted).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn secret_from_base32_tolerates_padding() {
    // Some QR-code apps emit padded base32. We strip padding
    // before decoding. Use a real 20-byte secret to round-trip.
    let original = Secret::generate().unwrap();
    let b32 = original.to_base32();
    // Append spurious padding (BASE32_NOPAD wouldn't emit any,
    // but a malformed input with `=` chars should still decode).
    let with_padding = format!("{b32}====");
    let decoded = Secret::from_base32(&with_padding).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn secret_from_base32_rejects_garbage() {
    assert!(Secret::from_base32("not_valid_base32!").is_err());
    assert!(Secret::from_base32("").is_err());          // empty
    assert!(Secret::from_base32("AB").is_err());        // 1 byte
}

#[test]
fn secret_from_bytes_validates_length() {
    assert!(Secret::from_bytes(vec![0; SECRET_BYTES]).is_ok());
    assert!(Secret::from_bytes(vec![0; SECRET_BYTES - 1]).is_err());
    assert!(Secret::from_bytes(vec![0; SECRET_BYTES + 1]).is_err());
    assert!(Secret::from_bytes(vec![]).is_err());
}

#[test]
fn secret_debug_does_not_leak_value() {
    let s = Secret::generate().unwrap();
    let dbg = format!("{:?}", s);
    assert!(!dbg.contains(&s.to_base32()),
        "Secret Debug must not include the base32-encoded value");
    assert!(dbg.contains("20"), "should mention byte length");
}

// =====================================================================
// format_code / parse_code
// =====================================================================

#[test]
fn format_code_pads_with_leading_zeros() {
    assert_eq!(format_code(0),      "000000");
    assert_eq!(format_code(1),      "000001");
    assert_eq!(format_code(81804),  "081804");
    assert_eq!(format_code(999999), "999999");
}

#[test]
fn parse_code_accepts_zero_padded() {
    assert_eq!(parse_code("000000").unwrap(),    0);
    assert_eq!(parse_code("000001").unwrap(),    1);
    assert_eq!(parse_code("081804").unwrap(), 81804);
}

#[test]
fn parse_code_accepts_non_padded() {
    // User typed without leading zeros — common in apps that
    // strip them for display. Accept; the integer comparison
    // matches.
    assert_eq!(parse_code("1").unwrap(), 1);
    assert_eq!(parse_code("81804").unwrap(), 81804);
}

#[test]
fn parse_code_rejects_non_digits() {
    assert!(parse_code("12345A").is_err());
    assert!(parse_code("").is_err());          // empty
    assert!(parse_code(" 12345").is_err());    // leading space
    assert!(parse_code("12 345").is_err());    // embedded space
}

#[test]
fn parse_code_rejects_too_long() {
    assert!(parse_code("1234567").is_err());
}

// =====================================================================
// verify_with_replay_protection
// =====================================================================

#[test]
fn verify_accepts_current_step() {
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let code = compute_code(&s, step);

    let result = verify_with_replay_protection(&s, code, 0, now).unwrap();
    assert_eq!(result, step);
}

#[test]
fn verify_accepts_previous_step_within_skew() {
    // User typed the code right at a step boundary; by the time
    // the request reaches the Worker the step has advanced.
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let prev_code = compute_code(&s, step - 1);

    let result = verify_with_replay_protection(&s, prev_code, 0, now).unwrap();
    assert_eq!(result, step - 1);
}

#[test]
fn verify_accepts_next_step_within_skew() {
    // User's clock runs ahead of the Worker's clock by ~30s.
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let next_code = compute_code(&s, step + 1);

    let result = verify_with_replay_protection(&s, next_code, 0, now).unwrap();
    assert_eq!(result, step + 1);
}

#[test]
fn verify_rejects_step_outside_skew() {
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    // Two steps back — outside ±SKEW_STEPS.
    let stale_code = compute_code(&s, step - 2);

    let result = verify_with_replay_protection(&s, stale_code, 0, now);
    assert_eq!(result, Err(TotpError::InvalidCode));
}

#[test]
fn verify_rejects_replay_within_window() {
    // First verify succeeds → returns last_used_step.
    // Second verify with the same code and the persisted
    // last_used_step should fail (replay protection).
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let code = compute_code(&s, step);

    let last_used = verify_with_replay_protection(&s, code, 0, now).unwrap();
    assert_eq!(last_used, step);

    // Same code, same now, but last_used_step is now `step`.
    let replay = verify_with_replay_protection(&s, code, last_used, now);
    assert_eq!(replay, Err(TotpError::InvalidCode));
}

#[test]
fn verify_advances_to_latest_matching_step() {
    // Edge case: the verify flow walks -1..=+1 windows. If only
    // one matches, we land on that. Pin that the returned step
    // is the matched step, not e.g. the current step.
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let prev_code = compute_code(&s, step - 1);

    let result = verify_with_replay_protection(&s, prev_code, 0, now).unwrap();
    assert_eq!(result, step - 1, "should record the matched step, not the current one");
}

#[test]
fn verify_rejects_random_code() {
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;

    // 000000 is a valid code, but very unlikely to be the
    // current/adjacent code for a random secret. ~1/3*10^6
    // chance of false-success which we accept as an
    // astronomically rare flake.
    let result = verify_with_replay_protection(&s, 999_999, 0, now);
    let result2 = verify_with_replay_protection(&s, 0, 0, now);
    // At least one of these MUST be rejected (probability of
    // both matching: 1/10^12, negligible).
    assert!(result.is_err() || result2.is_err());
}

#[test]
fn verify_rejects_already_used_step_even_if_within_window() {
    // last_used_step is the current step. None of the three
    // skew-window candidates (step-1, step, step+1) should be
    // accepted: step-1 and step are ≤ last_used (rejected by
    // replay gate), and step+1 yields a different code than
    // the current step's code.
    let s = Secret::generate().unwrap();
    let now = 1_700_000_000;
    let step = step_for_unix(now);
    let code_at_step = compute_code(&s, step);

    let result = verify_with_replay_protection(&s, code_at_step, step, now);
    assert_eq!(result, Err(TotpError::InvalidCode));
}

// =====================================================================
// otpauth_uri
// =====================================================================

#[test]
fn otpauth_uri_includes_required_params() {
    let s = rfc_secret();
    let uri = otpauth_uri("cesauth", "alice@example.com", &s);

    assert!(uri.starts_with("otpauth://totp/cesauth:alice%40example.com?"));
    assert!(uri.contains("secret="));
    assert!(uri.contains("issuer=cesauth"));
    assert!(uri.contains("algorithm=SHA1"));
    assert!(uri.contains("digits=6"));
    assert!(uri.contains("period=30"));
}

#[test]
fn otpauth_uri_url_encodes_account() {
    // `@` and ` ` must be percent-encoded.
    let s = rfc_secret();
    let uri = otpauth_uri("cesauth", "alice smith@example.com", &s);
    assert!(uri.contains("alice%20smith%40example.com"),
        "spaces and @ must be percent-encoded: {uri}");
}

#[test]
fn otpauth_uri_url_encodes_issuer() {
    let s = rfc_secret();
    let uri = otpauth_uri("Acme Inc", "alice@example.com", &s);
    assert!(uri.contains("Acme%20Inc:"), "issuer label encoded: {uri}");
    assert!(uri.contains("issuer=Acme%20Inc"), "issuer param encoded: {uri}");
}

#[test]
fn otpauth_uri_secret_is_base32_no_padding() {
    let s = rfc_secret();
    let uri = otpauth_uri("c", "u", &s);
    assert!(uri.contains(&format!("secret={}", s.to_base32())));
    // The secret value (after `secret=`, before `&`) must not
    // contain base32 `=` padding. We use `BASE32_NOPAD` which
    // never emits padding for output, but pin the property so
    // a future migration to a different base32 encoder doesn't
    // silently start emitting padding.
    let secret_value = uri
        .split('?').nth(1).unwrap()
        .split('&')
        .find_map(|kv| kv.strip_prefix("secret="))
        .unwrap();
    assert!(!secret_value.contains('='),
        "secret value must be NOPAD base32: {secret_value}");
}

// =====================================================================
// Recovery codes
// =====================================================================

#[test]
fn generate_recovery_codes_returns_correct_count() {
    let codes = generate_recovery_codes().unwrap();
    assert_eq!(codes.len(), RECOVERY_CODES_PER_USER);
}

#[test]
fn recovery_codes_are_unique_within_batch() {
    // Probability of collision among 10 randomly-drawn 50-bit
    // strings is (10 choose 2) * 2^-50 ≈ 4 * 10^-14. Effectively
    // zero. If this test ever fails, the CSPRNG is broken.
    let codes = generate_recovery_codes().unwrap();
    let mut seen = std::collections::HashSet::new();
    for c in &codes {
        assert!(seen.insert(c.as_str().to_owned()),
            "duplicate recovery code in fresh batch");
    }
}

#[test]
fn recovery_code_format_is_xxxxx_xxxxx() {
    let codes = generate_recovery_codes().unwrap();
    for c in &codes {
        let s = c.as_str();
        assert_eq!(s.len(), 11);          // 5 + 1 + 5
        assert_eq!(&s[5..6], "-");
        // Both halves are base32 alphabet uppercase.
        for byte in s[0..5].bytes().chain(s[6..11].bytes()) {
            let ok = matches!(byte, b'A'..=b'Z' | b'2'..=b'7');
            assert!(ok, "non-base32 char in recovery code: {s}");
        }
    }
}

#[test]
fn recovery_code_debug_redacts_value() {
    let codes = generate_recovery_codes().unwrap();
    let c = &codes[0];
    let dbg = format!("{:?}", c);
    assert!(!dbg.contains(c.as_str()),
        "Debug must not leak the recovery code value");
}

#[test]
fn recovery_code_display_renders_value() {
    // Display IS allowed to render — that's the "show once at
    // enrollment" path's mechanism.
    let codes = generate_recovery_codes().unwrap();
    let c = &codes[0];
    let s = format!("{}", c);
    assert_eq!(s, c.as_str());
}

#[test]
fn hash_recovery_code_is_deterministic() {
    let h1 = hash_recovery_code("ABCDE-FGHIJ");
    let h2 = hash_recovery_code("ABCDE-FGHIJ");
    assert_eq!(h1, h2);
}

#[test]
fn hash_recovery_code_canonicalizes_input() {
    // Same canonical form → same hash. Lowercase, dashes,
    // whitespace are all stripped/normalized.
    let canonical = hash_recovery_code("ABCDEFGHIJ");
    assert_eq!(hash_recovery_code("abcde-fghij"),  canonical);
    assert_eq!(hash_recovery_code("ABCDE-FGHIJ"),  canonical);
    assert_eq!(hash_recovery_code(" abcde fghij "),canonical);
    assert_eq!(hash_recovery_code("ABCDE FGHIJ"),  canonical);
    assert_eq!(hash_recovery_code("ABCDE--FGHIJ"), canonical);
}

#[test]
fn hash_recovery_code_distinguishes_different_codes() {
    let a = hash_recovery_code("AAAAA-AAAAA");
    let b = hash_recovery_code("AAAAA-AAAAB");
    assert_ne!(a, b);
}

#[test]
fn hash_recovery_code_output_is_hex() {
    let h = hash_recovery_code("ABCDE-FGHIJ");
    assert_eq!(h.len(), 64); // SHA-256 → 32 bytes → 64 hex chars
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(h.chars().all(|c| !c.is_ascii_uppercase()),
        "hex output should be lowercase");
}

// =====================================================================
// Encryption / decryption
// =====================================================================

fn test_key() -> Vec<u8> {
    // Fixed key for deterministic tests. NEVER use this in
    // production — operators must mint fresh keys from CSPRNG.
    (0..32).collect()
}

#[test]
fn encrypt_decrypt_round_trip() {
    let secret = Secret::generate().unwrap();
    let key    = test_key();
    let aad    = aad_for_id("row-abc");

    let (ct, nonce) = encrypt_secret(&secret, &key, &aad).unwrap();
    let decrypted   = decrypt_secret(&ct, &nonce, &key, &aad).unwrap();
    assert_eq!(secret, decrypted);
}

#[test]
fn encrypt_produces_different_ciphertexts_each_call() {
    // Random nonces → different ciphertexts even for the same
    // secret + key. AES-GCM nonce-misuse-resistance hinges on
    // this property; pin it.
    let secret = Secret::generate().unwrap();
    let key    = test_key();
    let aad    = aad_for_id("row-abc");

    let (ct_a, _) = encrypt_secret(&secret, &key, &aad).unwrap();
    let (ct_b, _) = encrypt_secret(&secret, &key, &aad).unwrap();
    assert_ne!(ct_a, ct_b);
}

#[test]
fn decrypt_rejects_wrong_aad() {
    // The whole point of AAD is to bind ciphertext to its row.
    // Mismatched AAD → DecryptionError, NOT a successful decrypt
    // with a tampered value.
    let secret = Secret::generate().unwrap();
    let key    = test_key();
    let aad_a  = aad_for_id("row-a");
    let aad_b  = aad_for_id("row-b");

    let (ct, nonce) = encrypt_secret(&secret, &key, &aad_a).unwrap();
    let result = decrypt_secret(&ct, &nonce, &key, &aad_b);
    assert_eq!(result, Err(TotpError::DecryptionError));
}

#[test]
fn decrypt_rejects_wrong_key() {
    let secret = Secret::generate().unwrap();
    let key_a  = test_key();
    let mut key_b = test_key();
    key_b[0] ^= 0xff;
    let aad = aad_for_id("row-abc");

    let (ct, nonce) = encrypt_secret(&secret, &key_a, &aad).unwrap();
    let result = decrypt_secret(&ct, &nonce, &key_b, &aad);
    assert_eq!(result, Err(TotpError::DecryptionError));
}

#[test]
fn decrypt_rejects_tampered_ciphertext() {
    let secret = Secret::generate().unwrap();
    let key    = test_key();
    let aad    = aad_for_id("row-abc");

    let (mut ct, nonce) = encrypt_secret(&secret, &key, &aad).unwrap();
    ct[0] ^= 0xff;  // flip a bit
    let result = decrypt_secret(&ct, &nonce, &key, &aad);
    assert_eq!(result, Err(TotpError::DecryptionError));
}

#[test]
fn encrypt_rejects_short_key() {
    let secret = Secret::generate().unwrap();
    let short  = vec![0u8; 16]; // AES-128 size, not what we want
    let aad    = aad_for_id("row");

    let result = encrypt_secret(&secret, &short, &aad);
    assert_eq!(result.err(), Some(TotpError::InvalidKeyLength));
}

#[test]
fn decrypt_rejects_short_nonce() {
    let secret = Secret::generate().unwrap();
    let key    = test_key();
    let aad    = aad_for_id("row");

    let (ct, _) = encrypt_secret(&secret, &key, &aad).unwrap();
    let bad_nonce = vec![0u8; 8]; // too short
    let result = decrypt_secret(&ct, &bad_nonce, &key, &aad);
    assert_eq!(result.err(), Some(TotpError::InvalidNonceLength));
}

#[test]
fn aad_for_id_is_deterministic() {
    assert_eq!(aad_for_id("abc"), aad_for_id("abc"));
    assert_eq!(aad_for_id("abc"), b"totp:abc");
}

#[test]
fn aad_for_id_distinguishes_different_ids() {
    assert_ne!(aad_for_id("a"), aad_for_id("b"));
}
