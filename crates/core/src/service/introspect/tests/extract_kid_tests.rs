//! Originally a nested `mod extract_kid_tests` inside
//! `crates/core/src/service/introspect/tests.rs`. Split into its
//! own file in v0.76.0 (test-file modularization continued from
//! v0.75.0; see CHANGELOG).

use crate::jwt::signer::extract_kid;
use ed25519_dalek::{Signer, SigningKey};

/// Same compact-JWS construction as the multi_key
/// tests above: build base64url(header) +
/// base64url(payload) + base64url(ed25519 signature)
/// directly so we stay independent of
/// jsonwebtoken's EncodingKey plumbing (which
/// requires PKCS#8 DER wrapping rather than raw
/// 32-byte seed).
fn sign_with_kid(kid: Option<&str>) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let header_json = match kid {
        Some(k) => format!(r#"{{"alg":"EdDSA","typ":"JWT","kid":"{k}"}}"#),
        None    => r#"{"alg":"EdDSA","typ":"JWT"}"#.to_owned(),
    };
    let payload_json = "{}";
    let header_b64  = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = sk.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

#[test]
fn extracts_kid_when_present() {
    let token = sign_with_kid(Some("test-kid-123"));
    assert_eq!(extract_kid(&token).as_deref(), Some("test-kid-123"));
}

#[test]
fn returns_none_when_kid_absent() {
    let token = sign_with_kid(None);
    assert!(extract_kid(&token).is_none(),
        "kid-less JWT must yield None: token={token}");
}

#[test]
fn returns_none_on_garbage_input() {
    assert!(extract_kid("not-a-jwt").is_none());
    assert!(extract_kid("").is_none());
    assert!(extract_kid("a.b.c").is_none(),
        "three-part garbage must yield None");
    assert!(extract_kid("eyJxxx.eyJxxx").is_none(),
        "two-part garbage must yield None");
}

#[test]
fn does_not_verify_signature() {
    // Tamper with signature segment. extract_kid MUST
    // still return the kid because it doesn't touch
    // the signature.
    let mut token = sign_with_kid(Some("untouched"));
    let last_dot = token.rfind('.').unwrap();
    token.truncate(last_dot + 1);
    token.push_str("AAAAAAA");
    assert_eq!(extract_kid(&token).as_deref(), Some("untouched"),
        "extract_kid must not gate on signature validity");
}
