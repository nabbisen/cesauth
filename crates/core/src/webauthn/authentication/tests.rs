//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;
use crate::webauthn::cose::{CosePublicKey, FLAG_UP};
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::{OsRng, RngCore};

fn rp() -> RelyingParty {
    RelyingParty {
        id:     "auth.example.com".into(),
        name:   "cesauth".into(),
        origin: "https://auth.example.com".into(),
    }
}

fn make_client_data_json(challenge_b64: &str, ty: &str, origin: &str) -> Vec<u8> {
    serde_json::json!({
        "type":       ty,
        "challenge":  challenge_b64,
        "origin":     origin,
        "crossOrigin": false,
    }).to_string().into_bytes()
}

/// Build an assertion authData (no AT flag, no attested cred data).
fn build_assertion_auth_data(rp_id: &str, sign_count: u32, flags: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(37);
    v.extend_from_slice(&sha256(rp_id.as_bytes()));
    v.push(flags);
    v.extend_from_slice(&sign_count.to_be_bytes());
    v
}

#[test]
fn start_empty_allow_list_means_usernameless() {
    let (chal, state) = start(&rp(), &[], None).unwrap();
    let arr = chal.public_key["allowCredentials"].as_array().unwrap();
    assert!(arr.is_empty());
    assert!(!state.challenge.is_empty());
}

#[test]
fn finish_accepts_valid_ed25519_assertion() {
    let rp = rp();
    // Deterministic Ed25519 key for the test.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);
    let vk_bytes = signing.verifying_key().to_bytes();
    let pk = CosePublicKey::Ed25519 { raw: vk_bytes };

    let stored = StoredAuthenticator {
        id:              "authn-1".into(),
        user_id:         "user-1".into(),
        credential_id:   URL_SAFE_NO_PAD.encode(b"cred-xyz"),
        public_key:      pk.to_cose_bytes(),
        sign_count:      0,
        transports:      None,
        aaguid:          None,
        backup_eligible: false,
        backup_state:    false,
        name:            None,
        created_at:      0,
        last_used_at:    None,
    };

    let challenge_raw = [42u8; 32];
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge_raw);
    let state = AuthenticationState { challenge: challenge_b64.clone(), pinned_user_id: None };

    let auth_data = build_assertion_auth_data(&rp.id, 1, FLAG_UP);
    let client_data = make_client_data_json(&challenge_b64, "webauthn.get", &rp.origin);
    let client_hash = sha256(&client_data);

    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(&auth_data);
    to_sign.extend_from_slice(&client_hash);
    let sig = signing.sign(&to_sign);

    let response = AuthenticationResponse {
        id:        URL_SAFE_NO_PAD.encode(b"cred-xyz"),
        raw_id:    URL_SAFE_NO_PAD.encode(b"cred-xyz"),
        cred_type: "public-key".into(),
        response:  serde_json::json!({
            "clientDataJSON":    URL_SAFE_NO_PAD.encode(&client_data),
            "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
            "signature":         URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        }),
    };

    let out = finish(&rp, &state, &response, &stored).unwrap();
    assert_eq!(out.user_id, "user-1");
    assert_eq!(out.new_sign_count, 1);
}

#[test]
fn finish_rejects_bad_signature() {
    let rp = rp();
    let signing = SigningKey::from_bytes(&[11u8; 32]);
    let pk = CosePublicKey::Ed25519 { raw: signing.verifying_key().to_bytes() };
    let stored = StoredAuthenticator {
        id: "a".into(), user_id: "u".into(),
        credential_id: URL_SAFE_NO_PAD.encode(b"c"),
        public_key: pk.to_cose_bytes(),
        sign_count: 0, transports: None, aaguid: None,
        backup_eligible: false, backup_state: false, name: None,
        created_at: 0, last_used_at: None,
    };
    let challenge_b64 = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let state = AuthenticationState { challenge: challenge_b64.clone(), pinned_user_id: None };
    let auth_data = build_assertion_auth_data(&rp.id, 1, FLAG_UP);
    let client_data = make_client_data_json(&challenge_b64, "webauthn.get", &rp.origin);
    // Signature over GARBAGE, not the actual message.
    let bogus = signing.sign(b"wrong input");
    let response = AuthenticationResponse {
        id: "c".into(), raw_id: URL_SAFE_NO_PAD.encode(b"c"),
        cred_type: "public-key".into(),
        response: serde_json::json!({
            "clientDataJSON":    URL_SAFE_NO_PAD.encode(&client_data),
            "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
            "signature":         URL_SAFE_NO_PAD.encode(bogus.to_bytes()),
        }),
    };
    assert!(finish(&rp, &state, &response, &stored).is_err());
}

#[test]
fn finish_rejects_non_monotonic_sign_count() {
    let rp = rp();
    let signing = SigningKey::from_bytes(&[12u8; 32]);
    let pk = CosePublicKey::Ed25519 { raw: signing.verifying_key().to_bytes() };
    let stored = StoredAuthenticator {
        id: "a".into(), user_id: "u".into(),
        credential_id: URL_SAFE_NO_PAD.encode(b"c"),
        public_key: pk.to_cose_bytes(),
        sign_count: 5,                      // prior value
        transports: None, aaguid: None,
        backup_eligible: false, backup_state: false, name: None,
        created_at: 0, last_used_at: None,
    };
    let challenge_b64 = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let state = AuthenticationState { challenge: challenge_b64.clone(), pinned_user_id: None };

    // Present sign_count=3 - lower than stored. Must be rejected
    // even if the signature is otherwise valid. Sign the whole
    // thing for real so the failure is the monotonicity check.
    let auth_data = build_assertion_auth_data(&rp.id, 3, FLAG_UP);
    let client_data = make_client_data_json(&challenge_b64, "webauthn.get", &rp.origin);
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(&auth_data);
    to_sign.extend_from_slice(&sha256(&client_data));
    let sig = signing.sign(&to_sign);

    let response = AuthenticationResponse {
        id: "c".into(), raw_id: URL_SAFE_NO_PAD.encode(b"c"),
        cred_type: "public-key".into(),
        response: serde_json::json!({
            "clientDataJSON":    URL_SAFE_NO_PAD.encode(&client_data),
            "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
            "signature":         URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        }),
    };
    assert!(finish(&rp, &state, &response, &stored).is_err());
}

#[test]
fn finish_rejects_type_confusion() {
    // Even with a valid signature, if the clientDataJSON type is
    // "webauthn.create" we must refuse (the signed bytes would be
    // reusable as a registration).
    let rp = rp();
    let signing = SigningKey::from_bytes(&[13u8; 32]);
    let pk = CosePublicKey::Ed25519 { raw: signing.verifying_key().to_bytes() };
    let stored = StoredAuthenticator {
        id: "a".into(), user_id: "u".into(),
        credential_id: URL_SAFE_NO_PAD.encode(b"c"),
        public_key: pk.to_cose_bytes(),
        sign_count: 0, transports: None, aaguid: None,
        backup_eligible: false, backup_state: false, name: None,
        created_at: 0, last_used_at: None,
    };
    let challenge_b64 = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let state = AuthenticationState { challenge: challenge_b64.clone(), pinned_user_id: None };

    let auth_data = build_assertion_auth_data(&rp.id, 1, FLAG_UP);
    // The attacker sends a clientData with type=webauthn.create
    // but a valid signature over it.
    let client_data = make_client_data_json(&challenge_b64, "webauthn.create", &rp.origin);
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(&auth_data);
    to_sign.extend_from_slice(&sha256(&client_data));
    let sig = signing.sign(&to_sign);

    let response = AuthenticationResponse {
        id: "c".into(), raw_id: URL_SAFE_NO_PAD.encode(b"c"),
        cred_type: "public-key".into(),
        response: serde_json::json!({
            "clientDataJSON":    URL_SAFE_NO_PAD.encode(&client_data),
            "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
            "signature":         URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        }),
    };
    assert!(finish(&rp, &state, &response, &stored).is_err());
}
