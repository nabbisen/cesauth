//! RFC 116 — secret newtype tests.
//!
//! Pins: Debug redaction (acceptance criterion 2), hash compatibility
//! with the pre-RFC 116 `sha256_hex` encoding, constant-time-only
//! equality, and serde transparency of `HashedSecret`.

use super::*;

#[test]
fn raw_secret_debug_is_redacted() {
    let s = RawSecret::new("hunter2".to_owned());
    let dbg = format!("{s:?}");
    assert!(dbg.contains(REDACTION_MARKER));
    assert!(!dbg.contains("hunter2"));
}

#[test]
fn hashed_secret_debug_is_redacted() {
    let h = RawSecret::new("hunter2".to_owned()).sha256();
    let dbg = format!("{h:?}");
    assert!(dbg.contains(REDACTION_MARKER));
    assert!(!dbg.contains(h.as_storage_str()));
}

#[test]
fn redacted_secret_displays_marker() {
    assert_eq!(RedactedSecret.to_string(), REDACTION_MARKER);
    assert_eq!(format!("{RedactedSecret:?}"), REDACTION_MARKER);
}

#[test]
fn sha256_matches_legacy_client_auth_encoding() {
    // `clients.client_secret_hash` rows were written by
    // `service::client_auth::sha256_hex` (lowercase hex). RFC 116
    // must compare-compatible with every existing row.
    let secret = "correct horse battery staple";
    let legacy = crate::service::client_auth::sha256_hex(secret.as_bytes());
    let typed = RawSecret::new(secret.to_owned()).sha256();
    assert!(typed.ct_eq(&HashedSecret::from_storage(legacy)));
}

#[test]
fn ct_eq_agrees_with_equality_semantics() {
    let a = RawSecret::new("alpha".to_owned()).sha256();
    let a2 = RawSecret::new("alpha".to_owned()).sha256();
    let b = RawSecret::new("beta".to_owned()).sha256();
    assert!(a.ct_eq(&a2));
    assert!(!a.ct_eq(&b));
}

#[test]
fn hashed_secret_serde_is_transparent() {
    let h = HashedSecret::from_storage("deadbeef");
    assert_eq!(serde_json::to_string(&h).unwrap(), "\"deadbeef\"");
    let back: HashedSecret = serde_json::from_str("\"deadbeef\"").unwrap();
    assert!(back.ct_eq(&h));
}

#[test]
fn expose_returns_the_material() {
    // `expose()` is the audited read point; it must of course work.
    let s = RawSecret::new("otp-12345".to_owned());
    assert_eq!(s.expose(), "otp-12345");
}

mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Typed hashing agrees with the legacy helper on all inputs.
        #[test]
        fn sha256_differential_vs_legacy(s in ".{0,256}") {
            let legacy = crate::service::client_auth::sha256_hex(s.as_bytes());
            let typed  = RawSecret::new(s).sha256();
            prop_assert!(typed.ct_eq(&HashedSecret::from_storage(legacy)));
        }

        /// `ct_eq` is exactly string equality of digests (functional
        /// correctness; timing is covered by `util` tests).
        #[test]
        fn ct_eq_matches_eq_oracle(a in ".{0,64}", b in ".{0,64}") {
            let ha = HashedSecret::from_storage(a.clone());
            let hb = HashedSecret::from_storage(b.clone());
            prop_assert_eq!(ha.ct_eq(&hb), a == b);
        }
    }
}
