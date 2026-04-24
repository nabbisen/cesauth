//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;
use crate::webauthn::cose::{CosePublicKey, FLAG_UP};

fn rp() -> RelyingParty {
    RelyingParty {
        id:     "auth.example.com".into(),
        name:   "cesauth".into(),
        origin: "https://auth.example.com".into(),
    }
}

#[test]
fn start_emits_required_fields() {
    let (chal, state) = start(&rp(), None, Some("alice")).unwrap();
    let aso = &chal.public_key["authenticatorSelection"];
    assert_eq!(aso["residentKey"], "required");
    assert!(!state.user_id.is_empty());
}

#[test]
fn start_only_advertises_supported_algs() {
    // After the RSA cut we advertise only EdDSA and ES256. Tests
    // read the array to fail loudly if someone re-adds RS256
    // without also implementing RSA verification.
    let (chal, _) = start(&rp(), None, None).unwrap();
    let params = chal.public_key["pubKeyCredParams"].as_array().unwrap();
    let algs: Vec<i64> = params.iter()
        .filter_map(|p| p["alg"].as_i64())
        .collect();
    assert_eq!(algs, vec![-8, -7]);
}

/// Build a synthetic `attestationObject` with fmt=none and a
/// specified Ed25519 credential. We use this for finish-path tests
/// because running a real authenticator ceremony is out of scope
/// for unit tests; what we need is coverage of the *parser* and
/// the *validation* logic, both of which are reachable with a
/// canned attestation object.
fn build_test_att_obj(
    rp_id:         &str,
    cred_id:       &[u8],
    pk:            &CosePublicKey,
    sign_count:    u32,
) -> Vec<u8> {
    use ciborium::value::Value as V;

    // authData layout.
    let rp_hash = sha256(rp_id.as_bytes());
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_hash);
    auth_data.push(FLAG_UP | FLAG_AT);               // flags
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    // attestedCredentialData
    auth_data.extend_from_slice(&[0u8; 16]);          // aaguid
    auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(cred_id);
    auth_data.extend_from_slice(&pk.to_cose_bytes());

    let obj = V::Map(vec![
        (V::Text("fmt".into()),          V::Text("none".into())),
        (V::Text("attStmt".into()),      V::Map(vec![])),
        (V::Text("authData".into()),     V::Bytes(auth_data)),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&obj, &mut out).unwrap();
    out
}

fn make_client_data_json(challenge_b64: &str, ty: &str, origin: &str) -> Vec<u8> {
    serde_json::json!({
        "type":       ty,
        "challenge":  challenge_b64,
        "origin":     origin,
        "crossOrigin": false,
    }).to_string().into_bytes()
}

#[test]
fn finish_accepts_valid_ed25519_none_attestation() {
    let rp = rp();
    let challenge_raw = [9u8; 32];
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge_raw);
    let state = RegistrationState {
        inner:   serde_json::json!({ "challenge": challenge_b64 }),
        user_id: "u1".into(),
    };
    let pk = CosePublicKey::Ed25519 { raw: [5u8; 32] };
    let cred_id = b"cred-xyz".to_vec();
    let att_obj = build_test_att_obj(&rp.id, &cred_id, &pk, 7);
    let client_data = make_client_data_json(&challenge_b64, "webauthn.create", &rp.origin);

    let response = RegistrationResponse {
        id:        URL_SAFE_NO_PAD.encode(&cred_id),
        raw_id:    URL_SAFE_NO_PAD.encode(&cred_id),
        cred_type: "public-key".into(),
        response:  serde_json::json!({
            "clientDataJSON":    URL_SAFE_NO_PAD.encode(&client_data),
            "attestationObject": URL_SAFE_NO_PAD.encode(&att_obj),
        }),
    };

    let authn = finish(&rp, &state, &response, 1_700_000_000).unwrap();
    assert_eq!(authn.user_id, "u1");
    assert_eq!(authn.sign_count, 7);
    assert_eq!(authn.credential_id, URL_SAFE_NO_PAD.encode(&cred_id));
}

#[test]
fn finish_rejects_wrong_origin() {
    let rp = rp();
    let challenge_b64 = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let state = RegistrationState {
        inner:   serde_json::json!({ "challenge": challenge_b64 }),
        user_id: "u1".into(),
    };
    let pk = CosePublicKey::Ed25519 { raw: [5u8; 32] };
    let att_obj = build_test_att_obj(&rp.id, b"c", &pk, 0);
    // Mismatched origin.
    let client_data = make_client_data_json(&challenge_b64, "webauthn.create", "https://evil.example");

    let response = RegistrationResponse {
        id:        "c".into(),
        raw_id:    URL_SAFE_NO_PAD.encode(b"c"),
        cred_type: "public-key".into(),
        response:  serde_json::json!({
            "clientDataJSON":    URL_SAFE_NO_PAD.encode(&client_data),
            "attestationObject": URL_SAFE_NO_PAD.encode(&att_obj),
        }),
    };
    assert!(finish(&rp, &state, &response, 0).is_err());
}

#[test]
fn finish_rejects_wrong_challenge() {
    let rp = rp();
    let good_challenge = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let bad_challenge  = URL_SAFE_NO_PAD.encode([0u8; 32]);
    let state = RegistrationState {
        inner:   serde_json::json!({ "challenge": good_challenge }),
        user_id: "u1".into(),
    };
    let pk = CosePublicKey::Ed25519 { raw: [5u8; 32] };
    let att_obj = build_test_att_obj(&rp.id, b"c", &pk, 0);
    let client_data = make_client_data_json(&bad_challenge, "webauthn.create", &rp.origin);

    let response = RegistrationResponse {
        id:        "c".into(),
        raw_id:    URL_SAFE_NO_PAD.encode(b"c"),
        cred_type: "public-key".into(),
        response:  serde_json::json!({
            "clientDataJSON":    URL_SAFE_NO_PAD.encode(&client_data),
            "attestationObject": URL_SAFE_NO_PAD.encode(&att_obj),
        }),
    };
    assert!(finish(&rp, &state, &response, 0).is_err());
}

#[test]
fn finish_rejects_type_create_confusion() {
    // An attacker tries to pass a `webauthn.get` clientData into
    // registration. We must refuse.
    let rp = rp();
    let challenge_b64 = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let state = RegistrationState {
        inner:   serde_json::json!({ "challenge": challenge_b64 }),
        user_id: "u1".into(),
    };
    let pk = CosePublicKey::Ed25519 { raw: [5u8; 32] };
    let att_obj = build_test_att_obj(&rp.id, b"c", &pk, 0);
    let client_data = make_client_data_json(&challenge_b64, "webauthn.get", &rp.origin);

    let response = RegistrationResponse {
        id:        "c".into(),
        raw_id:    URL_SAFE_NO_PAD.encode(b"c"),
        cred_type: "public-key".into(),
        response:  serde_json::json!({
            "clientDataJSON":    URL_SAFE_NO_PAD.encode(&client_data),
            "attestationObject": URL_SAFE_NO_PAD.encode(&att_obj),
        }),
    };
    assert!(finish(&rp, &state, &response, 0).is_err());
}

#[test]
fn finish_rejects_rp_id_hash_mismatch() {
    let rp = rp();
    let challenge_b64 = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let state = RegistrationState {
        inner:   serde_json::json!({ "challenge": challenge_b64 }),
        user_id: "u1".into(),
    };
    let pk = CosePublicKey::Ed25519 { raw: [5u8; 32] };
    // Attestation object built for a *different* RP ID.
    let att_obj = build_test_att_obj("other.example.com", b"c", &pk, 0);
    let client_data = make_client_data_json(&challenge_b64, "webauthn.create", &rp.origin);

    let response = RegistrationResponse {
        id:        "c".into(),
        raw_id:    URL_SAFE_NO_PAD.encode(b"c"),
        cred_type: "public-key".into(),
        response:  serde_json::json!({
            "clientDataJSON":    URL_SAFE_NO_PAD.encode(&client_data),
            "attestationObject": URL_SAFE_NO_PAD.encode(&att_obj),
        }),
    };
    assert!(finish(&rp, &state, &response, 0).is_err());
}
