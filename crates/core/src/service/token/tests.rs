//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn refresh_round_trip() {
    let encoded = encode_refresh("fam", "jti-1", 3600, 1_000_000);
    let (fam, jti) = decode_refresh(&encoded).unwrap();
    assert_eq!(fam, "fam");
    assert_eq!(jti, "jti-1");
}

#[test]
fn decode_rejects_garbage() {
    assert!(decode_refresh("!!!").is_err());
}
