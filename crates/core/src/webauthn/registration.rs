//! Registration ceremony (creating a new passkey).
//!
//! Flow, with responsibilities:
//!
//! 1. `start()` - build the `PublicKeyCredentialCreationOptions` that the
//!    browser's `navigator.credentials.create()` call needs. The caller
//!    stores the opaque `RegistrationState` we return into the
//!    `AuthChallenge` Durable Object, keyed by a short-lived handle.
//! 2. `finish()` - consume the attestation response from the browser,
//!    verify it against the stored state, and emit a
//!    [`crate::webauthn::StoredAuthenticator`] ready to persist.
//!
//! We do NOT call into storage from this module. The worker layer
//! orchestrates.
//!
//! ## What this module verifies
//!
//! For `attestation = "none"` (which is what we request):
//!
//! * clientDataJSON: type is `webauthn.create`, challenge matches, origin
//!   matches RP.origin.
//! * attestationObject: fmt is `none`, attStmt is an empty map.
//! * authData: rpIdHash matches sha256(rp.id), UP flag set, attested
//!   credential data present (AT flag), COSE public key in a supported
//!   algorithm.
//!
//! What this module does NOT do (intentional scope cuts):
//!
//! * Verify `packed` / `tpm` / `android-key` / other attestation
//!   statements. We advertise only `attestation: "none"` in `start()`.
//! * Validate attestation CA chains. Without a root store this is
//!   performative; browsers don't hand the user a way to choose
//!   attestation trust anyway.
//! * RSA signature verification (alg -257). `start()` does not offer
//!   RS256 in `pubKeyCredParams`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, CoreResult};
use crate::webauthn::cose::{
    AuthData, FLAG_AT, auth_data_from_att_obj, parse_att_obj,
    require_none_attestation, sha256,
};
use crate::webauthn::{RelyingParty, StoredAuthenticator};

/// Opaque challenge-side state for the registration ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    /// The raw JSON blob emitted by `start()`. Today it just carries
    /// the challenge; keeping the shape extensible lets us add bits
    /// (user-verification policy, extensions) without a migration.
    pub inner:   serde_json::Value,
    pub user_id: String,
}

/// What the worker hands to the browser (as JSON) to initiate
/// `navigator.credentials.create()`. The browser library will parse this
/// directly; the caller should pass it through unchanged.
#[derive(Debug, Clone, Serialize)]
pub struct RegistrationChallenge {
    pub public_key: serde_json::Value,
}

/// Start a new registration ceremony.
///
/// Per the spec: "The most prioritized flow is Username-less Passkey".
/// We therefore create a fresh `user_id` here if the caller has no
/// stable one yet - they can later link it to an email when/if the user
/// provides one.
///
/// `preferred_name` is used only as the WebAuthn `userName`; it is the
/// on-device label the authenticator shows. It is not an email address.
pub fn start(
    rp:             &RelyingParty,
    user_id:        Option<String>,
    preferred_name: Option<&str>,
) -> CoreResult<(RegistrationChallenge, RegistrationState)> {
    let user_handle = user_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let display     = preferred_name.unwrap_or("cesauth user");

    let mut challenge_bytes = [0u8; 32];
    getrandom::getrandom(&mut challenge_bytes)
        .map_err(|_| CoreError::Internal)?;
    let challenge_b64 = base64_url(&challenge_bytes);

    let public_key = serde_json::json!({
        "rp": {
            "id":   rp.id,
            "name": rp.name,
        },
        "user": {
            "id":          base64_url(user_handle.as_bytes()),
            "name":        display,
            "displayName": display,
        },
        "challenge":        challenge_b64,
        "pubKeyCredParams": [
            // Only algorithms we can actually verify in `finish()`.
            // RS256 was dropped intentionally - see cose.rs module doc.
            { "type": "public-key", "alg": -8 },   // EdDSA (Ed25519)
            { "type": "public-key", "alg": -7 },   // ES256
        ],
        "timeout":          60000,
        "attestation":      "none",
        "authenticatorSelection": {
            "residentKey":       "required",
            "userVerification":  "preferred",
        },
    });

    let state = RegistrationState {
        inner:   serde_json::json!({ "challenge": challenge_b64 }),
        user_id: user_handle,
    };

    Ok((RegistrationChallenge { public_key }, state))
}

/// The attestation response from the browser.
///
/// Fields are the URL-safe base64-encoded bytes the WebAuthn JS client
/// delivers. We accept the whole `response` as a JSON object because
/// we want to extract `clientDataJSON` and `attestationObject` from it
/// by name rather than hardcoding field order.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponse {
    pub id:        String,
    pub raw_id:    String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response:  serde_json::Value,
}

/// Consume a registration response and produce the row to persist.
///
/// `now_unix` is used only to stamp `created_at` on the new
/// authenticator; it does not gate any cryptographic step (challenges
/// carry their own expiry via the DO).
pub fn finish(
    rp:       &RelyingParty,
    state:    &RegistrationState,
    response: &RegistrationResponse,
    now_unix: i64,
) -> CoreResult<StoredAuthenticator> {
    // 1. Response-shape checks. `type` per WebAuthn is always
    //    "public-key"; anything else indicates the client library is
    //    sending us something we did not ask for.
    if response.cred_type != "public-key" {
        return Err(CoreError::WebAuthn("response.type not public-key"));
    }

    let client_data_b64 = response.response.get("clientDataJSON")
        .and_then(|v| v.as_str())
        .ok_or(CoreError::WebAuthn("response.clientDataJSON missing"))?;
    let att_obj_b64 = response.response.get("attestationObject")
        .and_then(|v| v.as_str())
        .ok_or(CoreError::WebAuthn("response.attestationObject missing"))?;

    let client_data_bytes = URL_SAFE_NO_PAD
        .decode(client_data_b64.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(client_data_b64))
        .map_err(|_| CoreError::WebAuthn("clientDataJSON b64"))?;
    let att_obj_bytes = URL_SAFE_NO_PAD
        .decode(att_obj_b64.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(att_obj_b64))
        .map_err(|_| CoreError::WebAuthn("attestationObject b64"))?;

    // 2. clientData checks. The challenge in the JSON is base64url of
    //    the raw 32-byte server challenge; we compare strings.
    let expected_challenge = state.inner.get("challenge")
        .and_then(|v| v.as_str())
        .ok_or(CoreError::WebAuthn("state.challenge missing"))?;
    check_client_data(&client_data_bytes, "webauthn.create", expected_challenge, &rp.origin)?;

    // 3. attestationObject: fmt=none, empty attStmt, extract authData.
    let att_obj = parse_att_obj(&att_obj_bytes)?;
    require_none_attestation(&att_obj)?;
    let auth_data_bytes = auth_data_from_att_obj(&att_obj)?;
    let auth_data = AuthData::parse(&auth_data_bytes)?;

    // 4. rpIdHash + flags.
    let expected_rp_id_hash = sha256(rp.id.as_bytes());
    if auth_data.rp_id_hash != expected_rp_id_hash {
        return Err(CoreError::WebAuthn("rpIdHash mismatch"));
    }
    if !auth_data.user_present() {
        return Err(CoreError::WebAuthn("authData: UP flag not set"));
    }
    if auth_data.flags & FLAG_AT == 0 {
        return Err(CoreError::WebAuthn("authData: AT flag not set"));
    }

    // 5. Attested credential data: grab the credential id and COSE key.
    let attested = auth_data.attested.as_ref()
        .ok_or(CoreError::WebAuthn("authData: attested cred data absent"))?;

    // `response.rawId` and the id inside authData SHOULD match. We
    // enforce both for defense in depth; a mismatch is strong evidence
    // the response was stitched together from two ceremonies.
    let raw_id_bytes = URL_SAFE_NO_PAD
        .decode(response.raw_id.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&response.raw_id))
        .map_err(|_| CoreError::WebAuthn("rawId b64"))?;
    if raw_id_bytes != attested.credential_id {
        return Err(CoreError::WebAuthn("rawId != authData credentialId"));
    }

    // 6. Build the StoredAuthenticator row to persist.
    let credential_id_b64 = URL_SAFE_NO_PAD.encode(&attested.credential_id);
    Ok(StoredAuthenticator {
        id:              Uuid::new_v4().to_string(),
        user_id:         state.user_id.clone(),
        credential_id:   credential_id_b64,
        // Store the CBOR COSE key bytes verbatim. assertion::finish
        // re-parses this with the same CoseKey parser so round-tripping
        // is guaranteed.
        public_key:      attested.public_key_cose_bytes.clone(),
        sign_count:      auth_data.sign_count,
        transports:      None,
        aaguid:          Some(hex::encode(attested.aaguid)),
        backup_eligible: false,
        backup_state:    false,
        name:            None,
        created_at:      now_unix,
        last_used_at:    None,
    })
}

/// Validate the clientDataJSON against the expected type, challenge
/// and origin. The input is the **raw** UTF-8 bytes of the JSON object
/// the browser produced; we parse it as JSON.
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
    // The JS side sends base64url-no-pad; our expected is the same.
    if cd.challenge.trim_end_matches('=') != expected_challenge.trim_end_matches('=') {
        return Err(CoreError::WebAuthn("clientDataJSON challenge mismatch"));
    }
    if cd.origin != expected_origin {
        return Err(CoreError::WebAuthn("clientDataJSON origin mismatch"));
    }
    Ok(())
}

fn base64_url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests;
