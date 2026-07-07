//! RFC 116 — identifier newtype tests.
//!
//! Pins: parse shape rules, mint shape, Debug tagging, serde
//! transparency, and (by doc-test in `ids.rs`'s parent docs) the
//! compile-time non-interchangeability of distinct id types.

use super::*;

#[test]
fn parse_accepts_uuid_shape() {
    let u = uuid::Uuid::new_v4().to_string();
    assert_eq!(UserId::parse(u.clone()).unwrap().as_str(), u);
}

#[test]
fn parse_accepts_legacy_default_tenant_slug() {
    // `tenant-default` predates RFC 116 and must keep working.
    let t = TenantId::parse("tenant-default").unwrap();
    assert_eq!(t, TenantId::default_tenant());
}

#[test]
fn parse_accepts_base64url_handle_shape() {
    // 32 random bytes, base64url → 43 chars incl. `-` and `_`.
    let h = "Ab-_cD0123456789Ab-_cD0123456789Ab-_cD01234";
    assert!(ChallengeHandle::parse(h).is_ok());
}

#[test]
fn parse_rejects_empty() {
    assert_eq!(TenantId::parse("").unwrap_err(), IdParseError::Empty);
}

#[test]
fn parse_rejects_overlong() {
    let s = "a".repeat(MAX_ID_LEN + 1);
    assert_eq!(UserId::parse(s).unwrap_err(), IdParseError::TooLong);
}

#[test]
fn parse_accepts_exact_max_len() {
    let s = "a".repeat(MAX_ID_LEN);
    assert!(UserId::parse(s).is_ok());
}

#[test]
fn parse_rejects_whitespace_controls_and_non_ascii() {
    for bad in ["a b", "a\tb", "a\nb", "a\0b", "日本語", "a\u{7f}b", " "] {
        assert_eq!(
            ClientId::parse(bad).unwrap_err(),
            IdParseError::InvalidCharacter,
            "should reject {bad:?}"
        );
    }
}

#[test]
fn mint_produces_parseable_uuid() {
    let id = SessionId::mint();
    // Round-trips through the boundary constructor…
    assert!(SessionId::parse(id.as_str()).is_ok());
    // …and is a real UUID.
    assert!(uuid::Uuid::parse_str(id.as_str()).is_ok());
}

#[test]
fn debug_is_type_tagged_full_echo() {
    let t = TenantId::parse("tenant-default").unwrap();
    assert_eq!(format!("{t:?}"), "TenantId(tenant-default)");
    // Display is the bare value (for SQL params / log interpolation).
    assert_eq!(format!("{t}"), "tenant-default");
}

#[test]
fn serde_is_transparent() {
    let f = FamilyId::parse("fam-123").unwrap();
    let json = serde_json::to_string(&f).unwrap();
    assert_eq!(json, "\"fam-123\"");
    let back: FamilyId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, f);
}

#[test]
fn from_storage_bypasses_validation() {
    // Storage is trusted; a hypothetical legacy row with a space must
    // re-hydrate rather than brick reads. (`parse` would reject it.)
    let raw = "legacy id with space";
    assert_eq!(UserId::from_storage(raw).as_str(), raw);
    assert!(UserId::parse(raw).is_err());
}

mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// `parse` accepts exactly the documented shape — agreement
        /// with an independent oracle over arbitrary inputs.
        #[test]
        fn parse_matches_shape_oracle(s in ".*") {
            let oracle_ok = !s.is_empty()
                && s.len() <= MAX_ID_LEN
                && s.bytes().all(|b| (0x21..=0x7E).contains(&b));
            prop_assert_eq!(UserId::parse(s.clone()).is_ok(), oracle_ok);
        }

        /// Accepted values round-trip losslessly through serde.
        #[test]
        fn accepted_ids_roundtrip_serde(s in "[\\x21-\\x7E]{1,128}") {
            let id = TenantId::parse(s.clone()).unwrap();
            let json = serde_json::to_string(&id).unwrap();
            let back: TenantId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(back.as_str(), s);
        }
    }
}
