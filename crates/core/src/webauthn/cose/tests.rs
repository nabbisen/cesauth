//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;
use ciborium::value::Value as V;

#[test]
fn ed25519_roundtrip_via_cose_bytes() {
    let raw = [7u8; 32];
    let key = CosePublicKey::Ed25519 { raw };
    let bytes = key.to_cose_bytes();
    let back  = parse_cose_public_key(&bytes).unwrap();
    match back {
        CosePublicKey::Ed25519 { raw: r2 } => assert_eq!(r2, raw),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn es256_roundtrip_via_cose_bytes() {
    let x = [1u8; 32];
    let y = [2u8; 32];
    let key = CosePublicKey::Es256 { x, y };
    let bytes = key.to_cose_bytes();
    let back  = parse_cose_public_key(&bytes).unwrap();
    match back {
        CosePublicKey::Es256 { x: x2, y: y2 } => {
            assert_eq!(x2, x);
            assert_eq!(y2, y);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn rejects_rsa_kty() {
    // kty=3 (RSA) is a supported kty per RFC 8152, but we refuse.
    let v = V::Map(vec![
        (V::Integer(1.into()), V::Integer(3.into())),
        (V::Integer(3.into()), V::Integer((-257_i64).into())),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&v, &mut bytes).unwrap();
    assert!(parse_cose_public_key(&bytes).is_err());
}

#[test]
fn none_attestation_requires_empty_stmt() {
    let ok = V::Map(vec![
        (V::Text("fmt".into()),     V::Text("none".into())),
        (V::Text("attStmt".into()), V::Map(vec![])),
        (V::Text("authData".into()), V::Bytes(vec![0u8; 37])),
    ]);
    assert!(require_none_attestation(&ok).is_ok());

    let bad = V::Map(vec![
        (V::Text("fmt".into()), V::Text("packed".into())),
        (V::Text("attStmt".into()), V::Map(vec![])),
    ]);
    assert!(require_none_attestation(&bad).is_err());

    let bad_stmt = V::Map(vec![
        (V::Text("fmt".into()), V::Text("none".into())),
        (V::Text("attStmt".into()), V::Map(vec![
            (V::Text("alg".into()), V::Integer((-7_i64).into())),
        ])),
    ]);
    assert!(require_none_attestation(&bad_stmt).is_err());
}
