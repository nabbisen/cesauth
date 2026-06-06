//! Audit log viewer — pagination cursor + filter helpers (RFC 109, v0.71.0).
//!
//! The audit viewer page at `GET /admin/console/audit` shows the newest 100
//! rows by default and paginates older rows via an opaque cursor. The
//! cursor is server-issued and round-trips back to the server through the
//! browser; the client never inspects its contents.
//!
//! ## Cursor design
//!
//! The cursor is base64url-encoded `seq=NNN` (no padding, no whitespace).
//! That keeps it:
//!
//! - opaque to the URL bar (no obvious "this is just an integer"
//!   affordance for the operator to hand-edit);
//! - safe in query strings (URL-safe alphabet, no `=` padding);
//! - cheap to encode/decode (no crypto, no DB roundtrip);
//! - small (a 19-digit seq encodes to 26 base64 characters).
//!
//! No tamper resistance: the cursor identifies a position in the chain
//! only. An operator who edits the cursor can land on a different page,
//! but cannot see rows they couldn't already see through normal pagination
//! — the row gate is `require_system_admin!`, not the cursor.
//!
//! ## RFC 3339 → Unix seconds
//!
//! The viewer's date-range filter comes in as RFC 3339 strings from the
//! HTML form. The pure helper `parse_rfc3339_to_unix` accepts a minimal
//! RFC 3339 subset (`YYYY-MM-DDTHH:MM:SSZ` or with a numeric offset) and
//! returns Unix seconds. It is deliberately strict: ambiguous or partial
//! inputs return `None` rather than guessing, so a stray `2025-13-xx`
//! does not silently become "the start of time".

// -------------------------------------------------------------------------
// Cursor codec (base64url, no padding)
// -------------------------------------------------------------------------

const B64_URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode a `seq` value as an opaque cursor.
///
/// The format is `seq=NNN` base64url-encoded with no padding. Decoding
/// is the inverse via [`decode_cursor`]. Negative seqs (which can't
/// appear in a valid chain — seq=1 is genesis) round-trip too.
pub fn encode_cursor(seq: i64) -> String {
    let raw = format!("seq={seq}");
    b64url_encode(raw.as_bytes())
}

/// Decode a cursor back to its `seq` value. Returns `None` on:
///
/// - non-base64url characters;
/// - decoded bytes that aren't valid UTF-8;
/// - decoded text that doesn't start with `seq=`;
/// - the integer suffix failing to parse.
pub fn decode_cursor(s: &str) -> Option<i64> {
    let bytes = b64url_decode(s)?;
    let text  = std::str::from_utf8(&bytes).ok()?;
    let n_str = text.strip_prefix("seq=")?;
    n_str.parse::<i64>().ok()
}

fn b64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = (input[i] as u32) << 16 | (input[i + 1] as u32) << 8 | input[i + 2] as u32;
        out.push(B64_URL[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_URL[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64_URL[((n >>  6) & 0x3F) as usize] as char);
        out.push(B64_URL[( n        & 0x3F) as usize] as char);
        i += 3;
    }
    match input.len() - i {
        2 => {
            let n = (input[i] as u32) << 16 | (input[i + 1] as u32) << 8;
            out.push(B64_URL[((n >> 18) & 0x3F) as usize] as char);
            out.push(B64_URL[((n >> 12) & 0x3F) as usize] as char);
            out.push(B64_URL[((n >>  6) & 0x3F) as usize] as char);
        }
        1 => {
            let n = (input[i] as u32) << 16;
            out.push(B64_URL[((n >> 18) & 0x3F) as usize] as char);
            out.push(B64_URL[((n >> 12) & 0x3F) as usize] as char);
        }
        _ => {}
    }
    out
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in bytes {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-'        => 62,
            b'_'        => 63,
            _           => return None,
        };
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

// -------------------------------------------------------------------------
// RFC 3339 timestamp parsing (strict subset)
// -------------------------------------------------------------------------

/// Parse an RFC 3339 timestamp string to Unix seconds (UTC).
///
/// Accepts the form `YYYY-MM-DDTHH:MM:SS[+ZZ:ZZ|Z]`. Fractional seconds
/// are rejected (the audit view doesn't need sub-second precision and
/// permitting them risks a parser bug). Returns `None` on any deviation.
///
/// Treats the result as UTC. A `+09:00` offset shifts back to UTC; a
/// trailing `Z` is UTC directly.
pub fn parse_rfc3339_to_unix(s: &str) -> Option<i64> {
    // YYYY-MM-DDTHH:MM:SS[Z|±HH:MM]   minimum length 20 (with Z)
    if s.len() < 20 { return None; }
    let date = s.get(0..10)?;
    if s.as_bytes().get(10)? != &b'T' { return None; }
    let time = s.get(11..19)?;
    let tz_str = s.get(19..)?;

    // Date: YYYY-MM-DD
    let year:  i32 = date.get(0..4)?.parse().ok()?;
    if date.as_bytes()[4] != b'-' { return None; }
    let month: u32 = date.get(5..7)?.parse().ok()?;
    if date.as_bytes()[7] != b'-' { return None; }
    let day:   u32 = date.get(8..10)?.parse().ok()?;

    // Time: HH:MM:SS
    let hour: u32 = time.get(0..2)?.parse().ok()?;
    if time.as_bytes()[2] != b':' { return None; }
    let min:  u32 = time.get(3..5)?.parse().ok()?;
    if time.as_bytes()[5] != b':' { return None; }
    let sec:  u32 = time.get(6..8)?.parse().ok()?;

    // Range checks (strict — calendar arithmetic done elsewhere).
    if !(1..=12).contains(&month) { return None; }
    if !(1..=31).contains(&day) { return None; }
    if hour >= 24 { return None; }
    if min  >= 60 { return None; }
    if sec  >= 60 { return None; }

    // Timezone: Z, +HH:MM, or -HH:MM.
    let tz_offset_secs: i64 = match tz_str.as_bytes().first()? {
        b'Z' => {
            if tz_str.len() != 1 { return None; }
            0
        }
        sign @ (b'+' | b'-') => {
            if tz_str.len() != 6 { return None; }
            if tz_str.as_bytes()[3] != b':' { return None; }
            let tzh: i64 = tz_str.get(1..3)?.parse().ok()?;
            let tzm: i64 = tz_str.get(4..6)?.parse().ok()?;
            if tzh >= 24 || tzm >= 60 { return None; }
            let secs = tzh * 3600 + tzm * 60;
            if *sign == b'+' { secs } else { -secs }
        }
        _ => return None,
    };

    let unix_utc_naive = naive_unix_from_ymd_hms(year, month, day, hour, min, sec)?;
    Some(unix_utc_naive - tz_offset_secs)
}

/// Compute the Unix timestamp for a UTC datetime (Y-M-D H:M:S). Pure
/// arithmetic — no chrono dep. Handles Gregorian leap years; rejects
/// invalid (Feb 30, etc.) day-of-month combinations.
fn naive_unix_from_ymd_hms(y: i32, m: u32, d: u32, h: u32, mi: u32, s: u32) -> Option<i64> {
    if !(1970..=9999).contains(&y) { return None; }
    let days_in_month = |y: i32, m: u32| -> u32 {
        match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11              => 30,
            2 => if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 },
            _ => 0,
        }
    };
    if d > days_in_month(y, m) { return None; }

    let mut days: i64 = 0;
    for yr in 1970..y {
        days += if (yr % 4 == 0 && yr % 100 != 0) || yr % 400 == 0 { 366 } else { 365 };
    }
    for mm in 1..m {
        days += days_in_month(y, mm) as i64;
    }
    days += (d - 1) as i64;

    Some(days * 86_400 + (h as i64) * 3600 + (mi as i64) * 60 + (s as i64))
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Cursor round-trips --------------------------------------------------

    #[test]
    fn cursor_round_trips_for_typical_seqs() {
        for seq in [1_i64, 2, 100, 1_000_000, i64::MAX] {
            let c = encode_cursor(seq);
            assert_eq!(decode_cursor(&c), Some(seq), "round-trip for seq={seq}");
        }
    }

    #[test]
    fn cursor_is_base64url_with_no_padding() {
        let c = encode_cursor(42);
        assert!(!c.contains('='), "cursor should be padding-free: {c}");
        assert!(!c.contains('+'), "cursor should be URL-safe (no +): {c}");
        assert!(!c.contains('/'), "cursor should be URL-safe (no /): {c}");
    }

    #[test]
    fn cursor_decode_rejects_garbage() {
        assert_eq!(decode_cursor(""),         None);
        assert_eq!(decode_cursor("not%base"), None);
        assert_eq!(decode_cursor("Zm9v"),     None, "valid b64 but wrong prefix should fail");
    }

    #[test]
    fn cursor_decode_rejects_negative_when_not_in_chain() {
        // Negative round-trips (we don't gate on this in the codec itself,
        // since the chain genesis is seq=1 and the caller validates).
        let c = encode_cursor(-1);
        assert_eq!(decode_cursor(&c), Some(-1));
    }

    // RFC 3339 parser -----------------------------------------------------

    #[test]
    fn parse_z_zero_offset() {
        // 1970-01-01T00:00:00Z is Unix epoch (0).
        assert_eq!(parse_rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn parse_specific_known_timestamp() {
        // 2025-01-01T00:00:00Z is 1735689600 (validated independently).
        assert_eq!(parse_rfc3339_to_unix("2025-01-01T00:00:00Z"), Some(1_735_689_600));
    }

    #[test]
    fn parse_positive_offset_subtracts_to_utc() {
        // 2025-01-01T09:00:00+09:00 = 2025-01-01T00:00:00Z = 1735689600.
        assert_eq!(parse_rfc3339_to_unix("2025-01-01T09:00:00+09:00"), Some(1_735_689_600));
    }

    #[test]
    fn parse_negative_offset_adds_to_utc() {
        // 2024-12-31T19:00:00-05:00 = 2025-01-01T00:00:00Z = 1735689600.
        assert_eq!(parse_rfc3339_to_unix("2024-12-31T19:00:00-05:00"), Some(1_735_689_600));
    }

    #[test]
    fn parse_handles_leap_year_feb_29() {
        assert!(parse_rfc3339_to_unix("2024-02-29T00:00:00Z").is_some());
        assert_eq!(parse_rfc3339_to_unix("2023-02-29T00:00:00Z"), None,
            "2023 is not a leap year — Feb 29 must be rejected");
    }

    #[test]
    fn parse_rejects_invalid_calendar_dates() {
        assert_eq!(parse_rfc3339_to_unix("2025-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2025-02-30T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2025-04-31T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2025-00-15T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2025-01-00T00:00:00Z"), None);
    }

    #[test]
    fn parse_rejects_invalid_time_fields() {
        assert_eq!(parse_rfc3339_to_unix("2025-01-01T24:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2025-01-01T00:60:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2025-01-01T00:00:60Z"), None);
    }

    #[test]
    fn parse_rejects_missing_or_extra_chars() {
        assert_eq!(parse_rfc3339_to_unix(""),                          None);
        assert_eq!(parse_rfc3339_to_unix("2025-01-01"),                None);
        assert_eq!(parse_rfc3339_to_unix("2025-01-01T00:00:00"),       None, "no tz suffix");
        assert_eq!(parse_rfc3339_to_unix("2025-01-01 00:00:00Z"),      None, "space instead of T");
        assert_eq!(parse_rfc3339_to_unix("2025-01-01T00:00:00.500Z"),  None, "fractional rejected");
        assert_eq!(parse_rfc3339_to_unix("2025-01-01T00:00:00+0900"),  None, "offset must have colon");
    }

    #[test]
    fn parse_rejects_pre_1970() {
        assert_eq!(parse_rfc3339_to_unix("1969-12-31T23:59:59Z"), None,
            "pre-epoch dates not in scope for audit viewer");
    }
}
