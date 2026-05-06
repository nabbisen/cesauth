//! Unit tests for the flash module. These cover the pure codec
//! (encode / decode / extract_cookie / set_cookie_header /
//! clear_cookie_header). The env-aware functions
//! [`set_on_response`] and [`take_from_request`] are exercised
//! by handler integration tests in PR-9, since they need a
//! [`worker::Env`] mock.
//!
//! Test categories:
//!
//! - **Round-trip**: encode then decode preserves value.
//! - **Tamper**: any single-byte mutation of the cookie value
//!   makes decode return `None`.
//! - **Format hardening**: malformed shapes return `None`
//!   without panicking.
//! - **Cookie attribute shape**: `Set-Cookie` value matches the
//!   cesauth invariants (`__Host-` prefix, `SameSite=Lax`,
//!   `HttpOnly`, `Secure`, correct `Max-Age`).
//! - **Token-table closure**: every `FlashKey` has a non-empty
//!   display string, every `FlashLevel` has a CSS modifier and
//!   icon, the `aria-live` mapping matches plan.

use super::*;

const TEST_KEY: &[u8] = b"this-is-a-32-byte-test-key-12345";

// ---------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------

#[test]
fn round_trip_every_level_and_key() {
    // Pin that every level × key combination encodes to a value
    // that decodes back to the same Flash. Catches accidental
    // shadowing or table drift in `as_str`/`from_str`.
    let levels = [FlashLevel::Info, FlashLevel::Success, FlashLevel::Warning, FlashLevel::Danger];
    let keys = [
        FlashKey::TotpEnabled,
        FlashKey::TotpDisabled,
        FlashKey::TotpRecovered,
        FlashKey::LoggedOut,
    ];
    for &level in &levels {
        for &key in &keys {
            let flash = Flash::new(level, key);
            let value = encode(&flash, TEST_KEY);
            let decoded = decode(&value, TEST_KEY)
                .unwrap_or_else(|| panic!("round-trip failed for {flash:?} → {value}"));
            assert_eq!(decoded, flash);
        }
    }
}

#[test]
fn encoded_value_starts_with_format_prefix() {
    // `v1:` prefix lets us bump the format in a future release
    // without breaking in-flight cookies. Pin so a refactor
    // can't silently drop the prefix.
    let f = Flash::new(FlashLevel::Success, FlashKey::TotpDisabled);
    let v = encode(&f, TEST_KEY);
    assert!(v.starts_with("v1:"), "encoded value must start with v1: — got {v}");
}

#[test]
fn encoded_value_has_two_dot_separated_parts_after_prefix() {
    // Format is `v1:{payload_b64}.{tag_b64}`. Exactly one `.`
    // after the prefix.
    let f = Flash::new(FlashLevel::Info, FlashKey::LoggedOut);
    let v = encode(&f, TEST_KEY);
    let after_prefix = v.strip_prefix("v1:").expect("prefix");
    assert_eq!(after_prefix.matches('.').count(), 1,
        "expected exactly one `.` after the prefix, got {after_prefix}");
}

#[test]
fn encoded_value_size_under_cookie_budget() {
    // Cookie is one of several `__Host-*` cookies on requests.
    // Keep the encoded form well under 256 bytes so we don't
    // bump into per-cookie or total-Cookie-header limits in
    // browsers + intermediate proxies.
    for &level in &[FlashLevel::Info, FlashLevel::Success, FlashLevel::Warning, FlashLevel::Danger] {
        for &key in &[FlashKey::TotpEnabled, FlashKey::TotpDisabled, FlashKey::TotpRecovered, FlashKey::LoggedOut] {
            let v = encode(&Flash::new(level, key), TEST_KEY);
            assert!(v.len() <= 256, "encoded length {} exceeds budget 256: {v}", v.len());
        }
    }
}

// ---------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------

#[test]
fn decode_rejects_modified_payload() {
    let f = Flash::new(FlashLevel::Success, FlashKey::TotpDisabled);
    let v = encode(&f, TEST_KEY);

    // Find the payload portion (after `v1:`, before `.`) and
    // flip a byte. With unpadded base64url, mutations may yield
    // an invalid base64 (decode-side `None`) or a different
    // payload bytes (HMAC mismatch). Either path returns None.
    let after_prefix = v.strip_prefix("v1:").unwrap();
    let dot = after_prefix.find('.').unwrap();
    let mut bytes = v.as_bytes().to_vec();
    let pos = "v1:".len() + dot - 1; // last char of payload_b64
    // Replace with something definitely not the original char.
    bytes[pos] = if bytes[pos] == b'A' { b'B' } else { b'A' };
    let mutated = String::from_utf8(bytes).unwrap();

    assert!(decode(&mutated, TEST_KEY).is_none(),
        "decode must reject payload mutation; got Some for {mutated}");
}

#[test]
fn decode_rejects_modified_tag() {
    let f = Flash::new(FlashLevel::Warning, FlashKey::TotpRecovered);
    let v = encode(&f, TEST_KEY);

    let after_prefix = v.strip_prefix("v1:").unwrap();
    let dot = after_prefix.find('.').unwrap();
    let tag_start_in_v = "v1:".len() + dot + 1;
    let mut bytes = v.as_bytes().to_vec();
    // Flip the first byte of the tag.
    bytes[tag_start_in_v] =
        if bytes[tag_start_in_v] == b'A' { b'B' } else { b'A' };
    let mutated = String::from_utf8(bytes).unwrap();

    assert!(decode(&mutated, TEST_KEY).is_none(),
        "decode must reject tag mutation; got Some for {mutated}");
}

#[test]
fn decode_rejects_wrong_key() {
    // Cookie signed with TEST_KEY must fail HMAC under a
    // different key. This is the "different deployment can't
    // verify our flash" property — protects rolling-key
    // rotations.
    let f = Flash::new(FlashLevel::Info, FlashKey::LoggedOut);
    let v = encode(&f, TEST_KEY);
    let other_key: &[u8] = b"completely-different-key-256bit!";
    assert!(decode(&v, other_key).is_none());
}

// ---------------------------------------------------------------------
// Malformed input shapes
// ---------------------------------------------------------------------

#[test]
fn decode_rejects_missing_prefix() {
    // No "v1:" prefix.
    let f = Flash::new(FlashLevel::Success, FlashKey::TotpEnabled);
    let v = encode(&f, TEST_KEY);
    let stripped = v.strip_prefix("v1:").unwrap();
    assert!(decode(stripped, TEST_KEY).is_none(),
        "decode must reject value without v1: prefix");
}

#[test]
fn decode_rejects_wrong_prefix_version() {
    // `v9:` prefix → unknown format → drop. This is the path
    // that protects against rolling format upgrades.
    assert!(decode("v9:anything.here", TEST_KEY).is_none());
    assert!(decode("v0:something", TEST_KEY).is_none());
}

#[test]
fn decode_rejects_empty_string() {
    assert!(decode("", TEST_KEY).is_none());
}

#[test]
fn decode_rejects_only_prefix() {
    assert!(decode("v1:", TEST_KEY).is_none());
}

#[test]
fn decode_rejects_no_separator() {
    // Has prefix but no `.` separator inside.
    assert!(decode("v1:abcdef", TEST_KEY).is_none());
}

#[test]
fn decode_rejects_multiple_separators() {
    // More than one `.` ambiguates payload vs tag.
    assert!(decode("v1:a.b.c", TEST_KEY).is_none());
}

#[test]
fn decode_rejects_empty_payload() {
    assert!(decode("v1:.abc", TEST_KEY).is_none());
}

#[test]
fn decode_rejects_empty_tag() {
    assert!(decode("v1:abc.", TEST_KEY).is_none());
}

#[test]
fn decode_rejects_non_base64_payload() {
    // `!@#` is not valid base64url.
    assert!(decode("v1:!@#.abcd", TEST_KEY).is_none());
}

#[test]
fn decode_rejects_unknown_level_code() {
    // Forge a payload with a level code that's not i/s/w/d.
    // The MAC won't match because the attacker doesn't have
    // TEST_KEY, so this path is double-defended:
    // - HMAC fails (primary defense, tested above)
    // - But even if MAC passed, the `from_code` lookup would
    //   reject "x". Construct a properly-MAC'd cookie with a
    //   bogus level to test the second layer.
    let payload = "x.totp_enabled".as_bytes();
    let mut mac = HmacSha256::new_from_slice(TEST_KEY).unwrap();
    mac.update(payload);
    let tag = mac.finalize().into_bytes();
    let value = format!(
        "v1:{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(tag),
    );
    assert!(decode(&value, TEST_KEY).is_none(),
        "decode must reject unknown level code even with valid MAC");
}

#[test]
fn decode_rejects_unknown_key() {
    // Same shape as the level-code test but the key portion is
    // bogus. Defends against future flash keys that aren't yet
    // in the table.
    let payload = "s.totp_unknown_future_key".as_bytes();
    let mut mac = HmacSha256::new_from_slice(TEST_KEY).unwrap();
    mac.update(payload);
    let tag = mac.finalize().into_bytes();
    let value = format!(
        "v1:{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(tag),
    );
    assert!(decode(&value, TEST_KEY).is_none());
}

// ---------------------------------------------------------------------
// Cookie attribute shape
// ---------------------------------------------------------------------

#[test]
fn set_cookie_header_carries_required_attributes() {
    let v = encode(&Flash::new(FlashLevel::Info, FlashKey::LoggedOut), TEST_KEY);
    let h = set_cookie_header(&v);
    assert!(h.starts_with(&format!("{COOKIE_NAME}={v}")));
    assert!(h.contains(&format!("Max-Age={TTL_SECONDS}")));
    assert!(h.contains("Path=/"));
    assert!(h.contains("HttpOnly"));
    assert!(h.contains("Secure"));
    assert!(h.contains("SameSite=Lax"),
        "flash cookie must be SameSite=Lax to survive OAuth redirects: {h}");
}

#[test]
fn cookie_name_uses_host_prefix() {
    // `__Host-` prefix is load-bearing: it forces Secure +
    // Path=/ + no Domain attribute at the user-agent level.
    // Pin so a future name refactor can't downgrade us.
    assert!(COOKIE_NAME.starts_with("__Host-"));
}

#[test]
fn clear_cookie_header_zeros_max_age() {
    let h = clear_cookie_header();
    assert!(h.contains("Max-Age=0"),
        "clear path must zero Max-Age: {h}");
    assert!(h.contains("SameSite=Lax"),
        "clear path must keep the same SameSite as set path: {h}");
    assert!(h.contains("Path=/"));
}

#[test]
fn ttl_is_short_but_nonzero() {
    // Plan §3.1 P0-B specifies a short TTL (60s) so an
    // abandoned flash doesn't display a stale message later.
    // Pin range so a future tweak stays sane.
    assert!(TTL_SECONDS >= 30 && TTL_SECONDS <= 600,
        "TTL_SECONDS = {TTL_SECONDS} should be 30-600s");
}

// ---------------------------------------------------------------------
// extract_cookie — raw header parsing
// ---------------------------------------------------------------------

#[test]
fn extract_cookie_finds_value_in_typical_header() {
    let header = format!("foo=1; {COOKIE_NAME}=v1:abc.def; bar=2");
    assert_eq!(extract_cookie(&header), Some("v1:abc.def"));
}

#[test]
fn extract_cookie_returns_none_when_absent() {
    assert_eq!(extract_cookie("foo=1; bar=2"), None);
    assert_eq!(extract_cookie(""), None);
}

#[test]
fn extract_cookie_does_not_match_prefix_substring() {
    // `__Host-cesauth_flashing` is NOT our cookie. Pin that
    // we don't confuse it. (`strip_prefix` + `=` check
    // handles this, but pin so a future regex-based rewrite
    // can't introduce the bug.)
    let header = format!("__Host-cesauth_flashing=evil; ok=ok");
    assert_eq!(extract_cookie(&header), None);
}

// ---------------------------------------------------------------------
// Token table — display text closure
// ---------------------------------------------------------------------

#[test]
fn every_flash_key_has_nonempty_display_text() {
    // No empty strings in the dictionary. An empty `display_text`
    // would render as an icon-only banner with no message — a
    // bug we want to catch at compile-test rather than at QA.
    for key in [FlashKey::TotpEnabled, FlashKey::TotpDisabled, FlashKey::TotpRecovered, FlashKey::LoggedOut] {
        let t = key.display_text();
        assert!(!t.is_empty(), "{key:?} display_text must not be empty");
    }
}

#[test]
fn aria_live_mapping_matches_plan() {
    // Plan §3.1 P0-B: info/success → polite, warning/danger →
    // assertive. Pin so a UX iteration doesn't accidentally
    // make every flash assertive (which is fatiguing for SR
    // users).
    assert_eq!(FlashLevel::Info.aria_live(),    "polite");
    assert_eq!(FlashLevel::Success.aria_live(), "polite");
    assert_eq!(FlashLevel::Warning.aria_live(), "assertive");
    assert_eq!(FlashLevel::Danger.aria_live(),  "assertive");
}

#[test]
fn css_modifier_mapping_matches_css_classes() {
    // The CSS classes were defined in PR-1 (BASE_CSS). Pin
    // that the worker emits exactly those modifier names.
    assert_eq!(FlashLevel::Info.css_modifier(),    "flash--info");
    assert_eq!(FlashLevel::Success.css_modifier(), "flash--success");
    assert_eq!(FlashLevel::Warning.css_modifier(), "flash--warning");
    assert_eq!(FlashLevel::Danger.css_modifier(),  "flash--danger");
}

#[test]
fn icon_mapping_is_distinct_per_level() {
    // Color blind users rely on the icon to disambiguate level.
    // Pin that all four icons are distinct strings (would catch
    // a copy-paste bug where two levels share the same glyph).
    let mut icons = [
        FlashLevel::Info.icon(),
        FlashLevel::Success.icon(),
        FlashLevel::Warning.icon(),
        FlashLevel::Danger.icon(),
    ];
    icons.sort();
    let mut deduped = icons.to_vec();
    deduped.dedup();
    assert_eq!(deduped.len(), icons.len(),
        "all four FlashLevel icons must be distinct: got {icons:?}");
}

#[test]
fn level_codes_round_trip() {
    for &level in &[FlashLevel::Info, FlashLevel::Success, FlashLevel::Warning, FlashLevel::Danger] {
        let code = level.as_code();
        assert_eq!(FlashLevel::from_code(code), Some(level));
    }
}

#[test]
fn level_from_code_rejects_unknown() {
    assert_eq!(FlashLevel::from_code(""), None);
    assert_eq!(FlashLevel::from_code("x"), None);
    assert_eq!(FlashLevel::from_code("S"), None); // case-sensitive
    assert_eq!(FlashLevel::from_code("info"), None); // not the encoded form
}

#[test]
fn key_from_str_rejects_unknown() {
    assert_eq!(FlashKey::from_str(""), None);
    assert_eq!(FlashKey::from_str("totp_enabled_v2"), None);
    assert_eq!(FlashKey::from_str("TOTP_ENABLED"), None); // case-sensitive
}
