//! Shared pure utilities for `cesauth-core`.
//!
//! All items here are `pub(crate)` unless they serve a downstream
//! consumer (adapter crates, UI crate). The rule is: if the same
//! algorithm appears in more than one module, extract it here.

// ─── Constant-time comparison ─────────────────────────────────────────────

/// Constant-time byte-slice equality.
///
/// Both slices must have the same length; unequal lengths return `false`
/// in constant time (no branching on which byte differs, only on whether
/// lengths match).
///
/// Replaces five independent copies in pkce, preview, principal_resolver,
/// csrf, and totp (RFC 096).
#[inline]
pub fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Constant-time string equality (operates on UTF-8 bytes).
#[inline]
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    constant_time_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// Constant-time `u32` equality.
///
/// Used for TOTP code comparison where timing attacks could theoretically
/// reveal how many digits were guessed correctly.
#[inline]
pub fn constant_time_eq_u32(a: u32, b: u32) -> bool {
    // XOR all 4 bytes; if they are equal the result is 0.
    let diff = a ^ b;
    // Widen to u64 so the subtraction doesn't overflow on the
    // identity subtraction trick; the important property is that
    // every arithmetic operation touches all bits.
    let diff64 = diff as u64;
    let zero   = diff64.wrapping_sub(1) >> 63;
    zero == 1
}

// ─── ISO-8601 UTC formatter ────────────────────────────────────────────────

/// Format a Unix timestamp (seconds since 1970-01-01T00:00:00Z) as an
/// ISO-8601 UTC date-time string (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Accurate for years 2000-2099 — the cesauth deployment window. No
/// external dependencies; no leap-second handling (UTC convention).
///
/// Replaces two identical copies in `admin/service.rs` and
/// `worker/src/cron_status.rs` (RFC 096).
pub fn format_unix_as_iso8601(unix: i64) -> String {
    let secs = unix.max(0) as u64;
    let days = secs / 86400;
    let time = secs % 86400;
    let h = time / 3600;
    let m = (time % 3600) / 60;
    let s = time % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Convert days-since-Unix-epoch to `(year, month, day)`.
/// Gregorian calendar using 400/100/4-year cycle arithmetic.
pub fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let y400 = days / 146097; days %= 146097;
    let y100 = (days / 36524).min(3); days -= y100 * 36524;
    let y4   = days / 1461;           days %= 1461;
    let y1   = (days / 365).min(3);   days -= y1 * 365;
    let year = y400 * 400 + y100 * 100 + y4 * 4 + y1 + 1970;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let md: [u64; 12] = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 0u64;
    for &mdays in &md {
        if days < mdays { break; }
        days -= mdays;
        mo += 1;
    }
    (year, mo + 1, days + 1)
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── constant_time_eq_bytes ──────────────────────────────────────────

    #[test]
    fn eq_bytes_equal() {
        assert!(constant_time_eq_bytes(b"hello", b"hello"));
        assert!(constant_time_eq_bytes(b"", b""));
    }

    #[test]
    fn eq_bytes_different() {
        assert!(!constant_time_eq_bytes(b"hello", b"world"));
        assert!(!constant_time_eq_bytes(b"a",     b"b"));
    }

    #[test]
    fn eq_bytes_different_length() {
        assert!(!constant_time_eq_bytes(b"abc", b"ab"));
        assert!(!constant_time_eq_bytes(b"",    b"a"));
    }

    // ── constant_time_eq_str ────────────────────────────────────────────

    #[test]
    fn eq_str_equal()    { assert!( constant_time_eq_str("tok-abc", "tok-abc")); }
    #[test]
    fn eq_str_different(){ assert!(!constant_time_eq_str("tok-abc", "tok-xyz")); }

    // ── constant_time_eq_u32 ────────────────────────────────────────────

    #[test]
    fn eq_u32_equal()    { assert!( constant_time_eq_u32(123456, 123456)); }
    #[test]
    fn eq_u32_different(){ assert!(!constant_time_eq_u32(123456, 123457)); }
    #[test]
    fn eq_u32_zero()     { assert!( constant_time_eq_u32(0, 0)); }

    // ── ISO-8601 formatter ──────────────────────────────────────────────

    #[test]
    fn iso8601_epoch() {
        assert_eq!(format_unix_as_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_known_date() {
        // 2023-11-14T22:13:20Z
        assert_eq!(format_unix_as_iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn iso8601_year_boundary() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(format_unix_as_iso8601(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_negative_saturates_to_epoch() {
        assert_eq!(format_unix_as_iso8601(-1), "1970-01-01T00:00:00Z");
    }
}
