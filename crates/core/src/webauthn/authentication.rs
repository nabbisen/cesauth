//! Authentication ceremony (logging in with a passkey).
//!
//! Split into the same start/finish pair as registration. Username-less
//! flow (spec §4.1) means the `allowCredentials` list is empty - the
//! platform then offers whichever discoverable credential it has.
//!
//! `finish()` performs the actual cryptographic verification, using the
//! pure-Rust primitives in [`crate::webauthn::cose`]. See that module's
//! doc comment for the algorithm-support policy.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::webauthn::cose::{AuthData, parse_cose_public_key, sha256};
use crate::webauthn::{RelyingParty, StoredAuthenticator};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    pub challenge: String,
    /// If the caller already knows who they're authenticating (e.g.
    /// after a Magic Link step-up), they pin a user. Otherwise we're in
    /// true username-less mode.
    pub pinned_user_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthenticationChallenge {
    pub public_key: serde_json::Value,
}

/// Begin an assertion ceremony.
///
/// `allow_credentials` is expected to be empty for the default
/// username-less flow; pass non-empty only when the caller explicitly
/// wants to restrict which credentials can satisfy the challenge.
pub fn start(
    rp:                &RelyingParty,
    allow_credentials: &[String],
    pinned_user_id:    Option<String>,
) -> CoreResult<(AuthenticationChallenge, AuthenticationState)> {
    let mut challenge_bytes = [0u8; 32];
    getrandom::getrandom(&mut challenge_bytes)
        .map_err(|_| CoreError::Internal)?;
    let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

    let allow_json: Vec<_> = allow_credentials
        .iter()
        .map(|id| serde_json::json!({ "type": "public-key", "id": id }))
        .collect();

    let public_key = serde_json::json!({
        "challenge":        challenge,
        "rpId":             rp.id,
        "timeout":          60000,
        "userVerification": "preferred",
        // Empty list => browser surfaces discoverable creds (passkeys).
        "allowCredentials": allow_json,
    });

    Ok((
        AuthenticationChallenge { public_key },
        AuthenticationState { challenge, pinned_user_id },
    ))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationResponse {
    pub id:        String,
    pub raw_id:    String,
    #[serde(rename = "type")]
    pub cred_type: String,
    /// The JS client sends `response` as an object with base64url
    /// fields: `clientDataJSON`, `authenticatorData`, `signature`,
    /// optionally `userHandle`.
    pub response:  serde_json::Value,
}

/// Outcome of a successful assertion.
#[derive(Debug, Clone)]
pub struct AuthenticationOutcome {
    pub user_id:           String,
    pub authenticator_id:  String,
    /// The updated sign counter the caller must persist back to D1. If
    /// this is <= the stored value, the counter check in `finish` has
    /// already rejected the assertion.
    pub new_sign_count:    u32,
}

/// Verify the browser's assertion.
///
/// The caller must have already looked up the `known_authenticator` row
/// by matching `response.id` / `response.raw_id` against
/// `StoredAuthenticator::credential_id`. This function verifies the
/// signature, the rpIdHash, the flags, the clientData, and the
/// sign-count monotonicity.
///
/// On success, the caller MUST persist `new_sign_count` back to D1
/// *before* returning any bearer to the browser.
pub fn finish(
    rp:                  &RelyingParty,
    state:               &AuthenticationState,
    response:            &AuthenticationResponse,
    known_authenticator: &StoredAuthenticator,
) -> CoreResult<AuthenticationOutcome> {
    // 1. Response-shape checks.
    if response.cred_type != "public-key" {
        return Err(CoreError::WebAuthn("response.type not public-key"));
    }

    // 2. rawId MUST match the credential row we looked up. Defense in
    //    depth: the caller already matched on this, but re-check so a
    //    buggy lookup path can't turn into a silent cross-credential.
    let raw_id_bytes = URL_SAFE_NO_PAD
        .decode(response.raw_id.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&response.raw_id))
        .map_err(|_| CoreError::WebAuthn("rawId b64"))?;
    let stored_id_bytes = URL_SAFE_NO_PAD
        .decode(known_authenticator.credential_id.trim_end_matches('='))
        .map_err(|_| CoreError::WebAuthn("stored credential_id b64"))?;
    if raw_id_bytes != stored_id_bytes {
        return Err(CoreError::WebAuthn("rawId mismatch"));
    }

    // 3. Extract the four response pieces. Browsers send base64url.
    let client_data_bytes = decode_b64(
        response.response.get("clientDataJSON").and_then(|v| v.as_str())
            .ok_or(CoreError::WebAuthn("response.clientDataJSON missing"))?,
    )?;
    let auth_data_bytes = decode_b64(
        response.response.get("authenticatorData").and_then(|v| v.as_str())
            .ok_or(CoreError::WebAuthn("response.authenticatorData missing"))?,
    )?;
    let signature_bytes = decode_b64(
        response.response.get("signature").and_then(|v| v.as_str())
            .ok_or(CoreError::WebAuthn("response.signature missing"))?,
    )?;

    // 4. clientData checks.
    check_client_data(&client_data_bytes, "webauthn.get", &state.challenge, &rp.origin)?;

    // 5. authData flags + rpIdHash. Unlike registration, AT is NOT
    //    expected on an assertion (the credential data was delivered
    //    during registration and is already on file).
    let auth_data = AuthData::parse(&auth_data_bytes)?;
    if auth_data.rp_id_hash != sha256(rp.id.as_bytes()) {
        return Err(CoreError::WebAuthn("rpIdHash mismatch"));
    }
    if !auth_data.user_present() {
        return Err(CoreError::WebAuthn("authData: UP flag not set"));
    }

    // 6. Sign-count monotonicity. The spec allows sign_count=0 to be
    //    repeated (authenticators that don't implement a counter).
    //    Otherwise it must strictly increase.
    let new_sign_count = auth_data.sign_count;
    let old = known_authenticator.sign_count;
    if !(new_sign_count == 0 && old == 0) && new_sign_count <= old {
        return Err(CoreError::WebAuthn("sign count did not advance (clone?)"));
    }

    // 7. Signature. The message the authenticator signed is
    //    authData || sha256(clientDataJSON). See spec §7.2 step 19.
    let client_data_hash = sha256(&client_data_bytes);
    let mut to_verify = Vec::with_capacity(auth_data_bytes.len() + client_data_hash.len());
    to_verify.extend_from_slice(&auth_data_bytes);
    to_verify.extend_from_slice(&client_data_hash);

    let pk = parse_cose_public_key(&known_authenticator.public_key)?;
    pk.verify(&to_verify, &signature_bytes)?;

    // 8. Optional: check the `pinned_user_id` matches `userHandle`
    //    when both are present. WebAuthn's `userHandle` is the
    //    base64url of the user.id from registration time.
    if let Some(pinned) = state.pinned_user_id.as_deref() {
        if let Some(uh_b64) = response.response.get("userHandle").and_then(|v| v.as_str()) {
            let uh_bytes = decode_b64(uh_b64)?;
            let pinned_bytes = pinned.as_bytes();
            if uh_bytes != pinned_bytes {
                return Err(CoreError::WebAuthn("userHandle != pinned user"));
            }
        }
    }

    Ok(AuthenticationOutcome {
        user_id:          known_authenticator.user_id.clone(),
        authenticator_id: known_authenticator.id.clone(),
        new_sign_count,
    })
}

fn decode_b64(s: &str) -> CoreResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .map_err(|_| CoreError::WebAuthn("b64 decode"))
}

fn check_client_data(
    raw:                 &[u8],
    expected_type:       &str,
    expected_challenge:  &str,
    expected_origin:     &str,
) -> CoreResult<()> {
    #[derive(Deserialize)]
    struct ClientData<'a> {
        #[serde(rename = "type")]
        cd_type:  &'a str,
        challenge: &'a str,
        origin:   &'a str,
    }
    let s = std::str::from_utf8(raw)
        .map_err(|_| CoreError::WebAuthn("clientDataJSON not utf-8"))?;
    let cd: ClientData<'_> = serde_json::from_str(s)
        .map_err(|_| CoreError::WebAuthn("clientDataJSON not json"))?;
    if cd.cd_type != expected_type {
        return Err(CoreError::WebAuthn("clientDataJSON type mismatch"));
    }
    if cd.challenge.trim_end_matches('=') != expected_challenge.trim_end_matches('=') {
        return Err(CoreError::WebAuthn("clientDataJSON challenge mismatch"));
    }
    if cd.origin != expected_origin {
        return Err(CoreError::WebAuthn("clientDataJSON origin mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
