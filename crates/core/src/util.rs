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
/// Negative input clamps to the epoch rather than rendering a pre-1970
/// date — a recorded decision (RFC 111 D1, [`crate::types::UnixSeconds`]),
/// not an omission: no importer of pre-1970 data exists today, but if one
/// ever lands, this function must handle negatives before it ships, or
/// the display will silently rewrite history to 1970. Accurate for every
/// non-negative input the proleptic Gregorian calendar defines —
/// `days_to_ymd`'s cycle arithmetic has no upper bound of its own; the
/// year field simply grows past four digits (`{y:04}` is a minimum width,
/// not a maximum). No external dependencies; no leap-second handling
/// (UTC convention).
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
///
/// Howard Hinnant's `civil_from_days`: the 400/100/4-year cycle
/// decomposition is only valid once the year is shifted to start on
/// 1 March, so every sub-cycle's leap day falls at the *end* of the
/// cycle rather than inside it. The prior version of this function
/// omitted that shift (RFC 111 slice C, `0.108.0`) and was wrong for
/// 45.5% of all days.
pub fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = yoe + era * 400;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
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

    /// Independent inverse of `days_to_ymd` — Howard Hinnant's
    /// `days_from_civil`, written separately from `days_to_ymd`'s own
    /// (now-fixed) forward arithmetic so the round-trip test below isn't
    /// just the same algorithm read backwards. Domain: `year >= 1970`,
    /// which is all `days_to_ymd` ever produces for a `u64` input.
    fn ymd_to_days(year: u64, month: u64, day: u64) -> u64 {
        let y = if month <= 2 { year - 1 } else { year };
        let m_adj = if month > 2 { month - 3 } else { month + 9 };
        let doy = (153 * m_adj + 2) / 5 + day - 1;
        let era = y / 400;
        let yoe = y - era * 400;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// RFC 111 slice B found this function's real range wasn't a
    /// documentation gap but a genuine arithmetic bug (see the git
    /// history and `.git-exclude/reviewed/111b-days-to-ymd-STOP-ruling.md`
    /// for the full characterization): the 400/100/4/1-year cycle
    /// decomposition requires the year to start on 1 March so the leap day
    /// falls at the *end* of every sub-cycle, and the prior version never
    /// made that shift. Fixed in RFC 111 slice C (`0.108.0`) by switching
    /// to Howard Hinnant's `civil_from_days`. This test is the mechanical
    /// proof the fix is right: every day from 1970-01-01 to 2200-12-31
    /// round-trips through `days_to_ymd` and the independent inverse
    /// above, and produces a syntactically valid date (month in 1..=12,
    /// day in 1..=31) — the month-13 overflow the bug produced on 31
    /// December of 1973, 1977, 1981, … is exactly the shape this second
    /// assertion would have caught.
    #[test]
    fn days_to_ymd_round_trips_and_stays_valid_1970_through_2200() {
        // 1970-01-01 to 2200-12-31 inclusive.
        let last_day = ymd_to_days(2200, 12, 31);
        for days in 0..=last_day {
            let (y, m, d) = days_to_ymd(days);
            assert!(
                (1..=12).contains(&m) && (1..=31).contains(&d),
                "day {days} produced an invalid date {y:04}-{m:02}-{d:02}",
            );
            assert_eq!(
                ymd_to_days(y, m, d), days,
                "day {days} -> {y:04}-{m:02}-{d:02} did not round-trip",
            );
        }
    }

    /// Boundary table over the function's real behaviour. Every expected
    /// string here was computed independently of this function — `date -u
    /// -d @<n> +"%Y-%m-%dT%H:%M:%SZ"` and Python's
    /// `datetime.utcfromtimestamp`, both agreeing — never by reading
    /// `format_unix_as_iso8601`'s own output back. Passes now that RFC 111
    /// slice C's arithmetic fix has landed; see
    /// `days_to_ymd_round_trips_and_stays_valid_1970_through_2200` above
    /// for the exhaustive proof this table is only a sample of.
    #[test]
    fn iso8601_boundary_table() {
        let cases: &[(i64, &str)] = &[
            // Negative: clamps to epoch rather than rendering a pre-1970
            // date. `-1` is "just before epoch"; `-86_400` is a full day
            // before it, so the clamp is the same regardless of magnitude.
            (-1,            "1970-01-01T00:00:00Z"),
            (-86_400,       "1970-01-01T00:00:00Z"),
            // Epoch itself.
            (0,             "1970-01-01T00:00:00Z"),
            // A 1970s value.
            (100_000_000,   "1973-03-03T09:46:40Z"),
            // A 1985 value.
            (473_385_600,   "1985-01-01T00:00:00Z"),
            // The 1999 -> 2000 boundary, both sides.
            (946_684_799,   "1999-12-31T23:59:59Z"),
            (946_684_800,   "2000-01-01T00:00:00Z"),
            // A current-era value.
            (1_700_000_000, "2023-11-14T22:13:20Z"),
            // The 2099 -> 2100 boundary, both sides. The bug this slice
            // fixed made 2099-12-31 (the first case) render one day late;
            // both now pass.
            (4_102_444_799, "2099-12-31T23:59:59Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                format_unix_as_iso8601(*input), *expected,
                "input {input} should format as {expected}",
            );
        }
    }

    /// Named regression cases for the specific inputs
    /// `.git-exclude/reviewed/111b-days-to-ymd-STOP-ruling.md` measured as
    /// wrong before this slice's fix, kept as individually-named cases (not
    /// folded into the sweep alone) so a future regression names exactly
    /// which historical failure shape came back.
    #[test]
    fn days_to_ymd_known_bad_inputs_from_the_stop_ruling() {
        // Off-by-one: the day after a leap-year's last day.
        assert_eq!(format_unix_as_iso8601(100_000_000),   "1973-03-03T09:46:40Z");
        assert_eq!(format_unix_as_iso8601(94_694_400),    "1973-01-01T00:00:00Z");
        // Off-by-two: a date past the point the error has compounded twice.
        assert_eq!(format_unix_as_iso8601(4_102_444_799), "2099-12-31T23:59:59Z");
        // A date in a wholly-wrong year (every one of 2025's 365 days was
        // off by one before this fix).
        assert_eq!(format_unix_as_iso8601(1_763_000_000), "2025-11-13T02:13:20Z");
        // 1972-12-31: the off-by-one shape's first occurrence.
        assert_eq!(format_unix_as_iso8601(94_608_000),    "1972-12-31T00:00:00Z");
        // 1973-12-31: the month-13 overflow shape's first occurrence.
        assert_eq!(format_unix_as_iso8601(126_144_000),   "1973-12-31T00:00:00Z");
    }

    #[test]
    fn iso8601_far_future_still_correct() {
        // 9999-12-31T23:59:59Z = 253_402_300_799, the latest instant a
        // 4-digit year can express. Computed independently via Python's
        // datetime.utcfromtimestamp; `date -u -d @<n>` on this host
        // refuses inputs this large, which is itself a data point about
        // the *host tool's* range, not this function's.
        assert_eq!(
            format_unix_as_iso8601(253_402_300_799),
            "9999-12-31T23:59:59Z",
        );
        // One second later: year field is five digits -- `{y:04}` is a
        // *minimum* width, not a maximum -- "10000-01-01T00:00:00Z", not
        // a panic. Still just this one instant, not a general claim.
        assert_eq!(
            format_unix_as_iso8601(253_402_300_800),
            "10000-01-01T00:00:00Z",
        );
    }
}
