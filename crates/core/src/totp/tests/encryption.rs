//! Originally part of `crates/core/src/totp/tests.rs`.
//! Split into a sibling file in v0.78.0.

use super::super::*;

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
