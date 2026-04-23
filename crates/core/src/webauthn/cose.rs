//! COSE key parsing and signature verification for WebAuthn.
//!
//! This is the minimum we need to verify passkey assertions without
//! pulling in the OpenSSL-linked `webauthn-rs-core`. The target set is:
//!
//! * **EdDSA / Ed25519** (COSE alg -8) - the preferred passkey algorithm.
//! * **ES256 / ECDSA-P256-SHA256** (COSE alg -7) - what most platform
//!   authenticators still emit today.
//!
//! RSA (alg -257) is NOT supported; the worker crate's `start()` fn
//! therefore does not advertise it. If a browser nevertheless sends an
//! RSA credential, `parse_cose_public_key` returns `Err` and the
//! ceremony fails loudly.
//!
//! ## Why pure-Rust crypto and not openssl/ring
//!
//! `webauthn-rs-core` 0.5 has a hard dep on `openssl` / `openssl-sys`
//! which do NOT build for `wasm32-unknown-unknown`. The pure-Rust
//! `ed25519-dalek` and `p256` crates both compile for wasm32 and are
//! well-audited for our purposes: we verify exactly one signature per
//! assertion, no private-key operations, no side-channel risk.

use ciborium::Value as CborValue;
use ed25519_dalek::{Signature as EdSignature, Verifier as _, VerifyingKey as EdVerifyingKey};
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};

use crate::error::{CoreError, CoreResult};

/// COSE algorithm identifiers we recognize. The numbers are RFC 8152.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseAlg {
    EdDsa = -8,
    Es256 = -7,
}

/// A parsed COSE_Key in the forms we accept.
#[derive(Debug, Clone)]
pub enum CosePublicKey {
    /// Ed25519 (kty=OKP, alg=-8). 32 raw public-key bytes.
    Ed25519 { raw: [u8; 32] },
    /// ECDSA-P256 (kty=EC2, alg=-7). 32-byte x and y coordinates.
    Es256   { x: [u8; 32], y: [u8; 32] },
}

impl CosePublicKey {
    pub fn alg(&self) -> CoseAlg {
        match self {
            Self::Ed25519 { .. } => CoseAlg::EdDsa,
            Self::Es256   { .. } => CoseAlg::Es256,
        }
    }

    /// Verify `signature` over `message`. The signature encoding is the
    /// one the WebAuthn spec says the authenticator emits for each alg:
    ///
    /// * Ed25519: raw 64-byte Ed25519 signature.
    /// * ES256: DER-encoded ECDSA-Sig-Value.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CoreResult<()> {
        match self {
            Self::Ed25519 { raw } => {
                let vk = EdVerifyingKey::from_bytes(raw)
                    .map_err(|_| CoreError::WebAuthn("ed25519 pubkey invalid"))?;
                let sig = EdSignature::from_slice(signature)
                    .map_err(|_| CoreError::WebAuthn("ed25519 signature shape"))?;
                vk.verify(message, &sig)
                    .map_err(|_| CoreError::WebAuthn("ed25519 signature invalid"))
            }
            Self::Es256 { x, y } => {
                // SEC1 uncompressed point prefix 0x04 || X || Y.
                let mut sec1 = [0u8; 65];
                sec1[0] = 0x04;
                sec1[1..33].copy_from_slice(x);
                sec1[33..].copy_from_slice(y);
                let vk = EcdsaVerifyingKey::from_sec1_bytes(&sec1)
                    .map_err(|_| CoreError::WebAuthn("p256 pubkey invalid"))?;
                let sig = EcdsaSignature::from_der(signature)
                    .map_err(|_| CoreError::WebAuthn("p256 signature DER"))?;
                vk.verify(message, &sig)
                    .map_err(|_| CoreError::WebAuthn("p256 signature invalid"))
            }
        }
    }

    /// Re-encode this public key as a CBOR map keyed by the COSE label
    /// integers (RFC 8152 §7). This is what we store in D1 so later
    /// assertions can reconstruct the key without re-parsing whatever
    /// shape the attestation originally used.
    pub fn to_cose_bytes(&self) -> Vec<u8> {
        use ciborium::value::Value::{Bytes, Integer};
        let v = match self {
            Self::Ed25519 { raw } => {
                // kty=1 (OKP), alg=-8, crv=6 (Ed25519), x=raw
                CborValue::Map(vec![
                    (Integer(1.into()),  Integer(1.into())),
                    (Integer(3.into()),  Integer((-8_i64).into())),
                    (Integer((-1_i64).into()), Integer(6.into())),
                    (Integer((-2_i64).into()), Bytes(raw.to_vec())),
                ])
            }
            Self::Es256 { x, y } => {
                // kty=2 (EC2), alg=-7, crv=1 (P-256), x, y
                CborValue::Map(vec![
                    (Integer(1.into()),  Integer(2.into())),
                    (Integer(3.into()),  Integer((-7_i64).into())),
                    (Integer((-1_i64).into()), Integer(1.into())),
                    (Integer((-2_i64).into()), Bytes(x.to_vec())),
                    (Integer((-3_i64).into()), Bytes(y.to_vec())),
                ])
            }
        };
        let mut out = Vec::new();
        ciborium::into_writer(&v, &mut out).expect("cbor re-encode cannot fail");
        out
    }
}

/// Parse a CBOR-encoded COSE_Key into our supported set.
///
/// Returns `Err(CoreError::WebAuthn(...))` for unsupported algorithms
/// (RSA, ECDSA-P384, etc.) rather than silently falling back to
/// "unverified" mode.
pub fn parse_cose_public_key(bytes: &[u8]) -> CoreResult<CosePublicKey> {
    let v: CborValue = ciborium::from_reader(bytes)
        .map_err(|_| CoreError::WebAuthn("cose key not cbor"))?;
    let map = match v {
        CborValue::Map(m) => m,
        _ => return Err(CoreError::WebAuthn("cose key not a map")),
    };

    // Helper: lookup a label in the CBOR map. COSE labels are integers.
    let lookup = |k: i64| -> Option<&CborValue> {
        map.iter().find_map(|(lbl, val)| match lbl {
            CborValue::Integer(i) => {
                let as_i: i128 = (*i).into();
                if as_i == i128::from(k) { Some(val) } else { None }
            }
            _ => None,
        })
    };

    let kty = lookup(1)
        .and_then(|v| {
            if let CborValue::Integer(i) = v {
                let as_i: i128 = (*i).into();
                i64::try_from(as_i).ok()
            } else { None }
        })
        .ok_or(CoreError::WebAuthn("cose: kty missing"))?;

    let alg = lookup(3)
        .and_then(|v| {
            if let CborValue::Integer(i) = v {
                let as_i: i128 = (*i).into();
                i64::try_from(as_i).ok()
            } else { None }
        })
        .ok_or(CoreError::WebAuthn("cose: alg missing"))?;

    match (kty, alg) {
        // OKP + EdDSA
        (1, -8) => {
            let crv = lookup(-1)
                .and_then(|v| {
                    if let CborValue::Integer(i) = v {
                        let as_i: i128 = (*i).into();
                        i64::try_from(as_i).ok()
                    } else { None }
                })
                .ok_or(CoreError::WebAuthn("cose: crv missing"))?;
            if crv != 6 {
                return Err(CoreError::WebAuthn("cose: EdDSA requires crv=Ed25519"));
            }
            let x = lookup(-2)
                .and_then(|v| match v {
                    CborValue::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or(CoreError::WebAuthn("cose: x missing"))?;
            let raw: [u8; 32] = x.as_slice().try_into()
                .map_err(|_| CoreError::WebAuthn("cose: Ed25519 x not 32 bytes"))?;
            Ok(CosePublicKey::Ed25519 { raw })
        }

        // EC2 + ES256
        (2, -7) => {
            let crv = lookup(-1)
                .and_then(|v| {
                    if let CborValue::Integer(i) = v {
                        let as_i: i128 = (*i).into();
                        i64::try_from(as_i).ok()
                    } else { None }
                })
                .ok_or(CoreError::WebAuthn("cose: crv missing"))?;
            if crv != 1 {
                return Err(CoreError::WebAuthn("cose: ES256 requires crv=P-256"));
            }
            let x_bytes = lookup(-2)
                .and_then(|v| match v {
                    CborValue::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or(CoreError::WebAuthn("cose: x missing"))?;
            let y_bytes = lookup(-3)
                .and_then(|v| match v {
                    CborValue::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or(CoreError::WebAuthn("cose: y missing"))?;
            let x: [u8; 32] = x_bytes.as_slice().try_into()
                .map_err(|_| CoreError::WebAuthn("cose: P-256 x not 32 bytes"))?;
            let y: [u8; 32] = y_bytes.as_slice().try_into()
                .map_err(|_| CoreError::WebAuthn("cose: P-256 y not 32 bytes"))?;
            Ok(CosePublicKey::Es256 { x, y })
        }

        // RSA (kty=3) or any other combination.
        _ => Err(CoreError::WebAuthn("cose: unsupported (kty, alg) pair")),
    }
}

/// Verify that the attestationObject's `fmt` field is "none" and its
/// `attStmt` is an empty map. Anything else is a real attestation
/// format that we do not yet support.
pub fn require_none_attestation(att_obj: &CborValue) -> CoreResult<()> {
    let map = match att_obj {
        CborValue::Map(m) => m,
        _ => return Err(CoreError::WebAuthn("attObj not a map")),
    };

    let mut fmt   = None;
    let mut stmt  = None;
    for (k, v) in map {
        if let CborValue::Text(s) = k {
            match s.as_str() {
                "fmt"     => fmt  = Some(v),
                "attStmt" => stmt = Some(v),
                _ => {}
            }
        }
    }

    let fmt = fmt.ok_or(CoreError::WebAuthn("attObj: fmt missing"))?;
    let fmt_s = match fmt {
        CborValue::Text(s) => s,
        _ => return Err(CoreError::WebAuthn("attObj: fmt not text")),
    };
    if fmt_s != "none" {
        return Err(CoreError::WebAuthn("attestation format not supported"));
    }

    let stmt = stmt.ok_or(CoreError::WebAuthn("attObj: attStmt missing"))?;
    match stmt {
        CborValue::Map(m) if m.is_empty() => Ok(()),
        _ => Err(CoreError::WebAuthn("attObj: attStmt must be empty for 'none'")),
    }
}

/// Extract the `authData` byte string from a parsed attestationObject.
pub fn auth_data_from_att_obj(att_obj: &CborValue) -> CoreResult<Vec<u8>> {
    let map = match att_obj {
        CborValue::Map(m) => m,
        _ => return Err(CoreError::WebAuthn("attObj not a map")),
    };
    for (k, v) in map {
        if let CborValue::Text(s) = k {
            if s == "authData" {
                return match v {
                    CborValue::Bytes(b) => Ok(b.clone()),
                    _ => Err(CoreError::WebAuthn("attObj: authData not bytes")),
                };
            }
        }
    }
    Err(CoreError::WebAuthn("attObj: authData missing"))
}

/// Parse the attestationObject CBOR into a `Value`.
pub fn parse_att_obj(bytes: &[u8]) -> CoreResult<CborValue> {
    ciborium::from_reader(bytes)
        .map_err(|_| CoreError::WebAuthn("attObj not cbor"))
}

// -------------------------------------------------------------------------
// authData parser.
//
// Layout (spec §6.1):
//   rpIdHash          32 bytes (sha256 of RP ID as UTF-8)
//   flags              1 byte  (bit 0x01 UP, 0x04 UV, 0x40 AT, 0x80 ED)
//   signCount          4 bytes (big-endian)
//   [ attestedCredentialData if AT ]
//       aaguid            16 bytes
//       credIdLen          2 bytes (big-endian)
//       credId             credIdLen bytes
//       credentialPubKey  CBOR (remainder of attestedCredData)
//   [ extensions          CBOR if ED ]
// -------------------------------------------------------------------------

/// Mask for the UP (user-present) flag.
pub const FLAG_UP: u8 = 0x01;
/// Mask for the UV (user-verified) flag.
pub const FLAG_UV: u8 = 0x04;
/// Mask for the AT (attested credential data present) flag.
pub const FLAG_AT: u8 = 0x40;

#[derive(Debug, Clone)]
pub struct AuthData<'a> {
    pub rp_id_hash:  &'a [u8],     // 32 bytes
    pub flags:       u8,
    pub sign_count:  u32,
    /// Present iff `flags & FLAG_AT != 0`.
    pub attested:    Option<AttestedCredentialData>,
}

#[derive(Debug, Clone)]
pub struct AttestedCredentialData {
    pub aaguid:        [u8; 16],
    pub credential_id: Vec<u8>,
    /// The CBOR-encoded COSE public key as it appears in authData.
    /// We keep the raw bytes because the verifier must hash them
    /// back along with the rest of authData on each assertion.
    pub public_key_cose_bytes: Vec<u8>,
    /// Parsed form for signature verification.
    pub public_key: CosePublicKey,
}

impl<'a> AuthData<'a> {
    pub fn parse(bytes: &'a [u8]) -> CoreResult<Self> {
        if bytes.len() < 37 {
            return Err(CoreError::WebAuthn("authData too short"));
        }
        let rp_id_hash = &bytes[0..32];
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes([
            bytes[33], bytes[34], bytes[35], bytes[36],
        ]);

        let mut attested = None;
        let mut cursor = 37usize;

        if flags & FLAG_AT != 0 {
            if bytes.len() < cursor + 18 {
                return Err(CoreError::WebAuthn("authData: attestedCredData truncated"));
            }
            let mut aaguid = [0u8; 16];
            aaguid.copy_from_slice(&bytes[cursor..cursor + 16]);
            cursor += 16;

            let id_len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;

            if bytes.len() < cursor + id_len {
                return Err(CoreError::WebAuthn("authData: credId truncated"));
            }
            let credential_id = bytes[cursor..cursor + id_len].to_vec();
            cursor += id_len;

            // The COSE key is CBOR. Parse streamingly from the cursor;
            // note where ciborium ends so we can extract the exact byte
            // range and hand it back verbatim.
            let remaining = &bytes[cursor..];
            // ciborium lacks a "parse and tell me how many bytes were
            // consumed" call. We parse a `Value` and then re-encode it
            // back to bytes - this is safe because the COSE encoding
            // rules are canonical.
            let pk_value: CborValue = ciborium::from_reader(remaining)
                .map_err(|_| CoreError::WebAuthn("authData: COSE key not cbor"))?;
            let mut pk_bytes = Vec::new();
            ciborium::into_writer(&pk_value, &mut pk_bytes)
                .map_err(|_| CoreError::WebAuthn("authData: COSE re-encode"))?;

            let public_key = parse_cose_public_key(&pk_bytes)?;

            attested = Some(AttestedCredentialData {
                aaguid,
                credential_id,
                public_key_cose_bytes: pk_bytes,
                public_key,
            });
        }

        Ok(AuthData { rp_id_hash, flags, sign_count, attested })
    }

    pub fn user_present(&self)  -> bool { self.flags & FLAG_UP != 0 }
    pub fn user_verified(&self) -> bool { self.flags & FLAG_UV != 0 }
}

/// SHA-256 helper used in several places (clientDataHash, rpIdHash).
pub fn sha256(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
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
}
