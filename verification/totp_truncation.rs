// RFC 183 — Verus narrow pilot.
//
// A COPY, not the production code. The real function is
// crates/core/src/totp.rs:242-260 (`compute_code`), which Verus cannot
// verify directly: it goes through `hmac::Hmac`/`sha1::Sha1`, external
// crates Verus does not understand, and returns a `GenericArray<u8, U20>`,
// not a primitive array. The HMAC computation itself is irrelevant to
// the two obligations below -- they are about the TRUNCATION step only --
// so this copy takes the 20-byte HMAC-SHA1 output as an opaque `[u8; 20]`
// input. Verus's own function-argument semantics (an ordinary `fn`
// parameter, no further constraint) quantify over every possible value
// of it, which is exactly "for all 2^160 HMAC outputs" (RFC 4226 §5.3 /
// RFC 183 §1).
//
// scripts/drift-scan.sh's "RFC 183 pilot" check byte-compares the marked
// region below against the equivalent five lines in totp.rs. Keep them
// IDENTICAL to production, character for character -- that is what makes
// the drift check meaningful at all. Every Verus annotation (assert,
// ensures) lives outside the marked region on purpose.

use vstd::prelude::*;

verus! {

/// Proves the two RFC 183 §1 obligations over the truncation step of
/// RFC 4226 §5.3's dynamic truncation, for an arbitrary 20-byte HMAC
/// output.
fn compute_code_truncation(result: &[u8; 20]) -> (bin_code: u32)
    ensures
        bin_code < 0x8000_0000, // obligation 2: high bit clear (< 2^31)
{
    assert(forall|b: u8| (#[trigger] (b & 0x0fu8)) <= 15u8) by (bit_vector);
    assert(forall|a: u8, b: u8, c: u8, d: u8|
        #[trigger] (((a & 0x7fu8) as u32) << 24 | ((b & 0xffu8) as u32) << 16
                  | ((c & 0xffu8) as u32) << 8  |  (d & 0xffu8) as u32) < 0x8000_0000u32
    ) by (bit_vector);

    // RFC 183 drift-check region: BEGIN
    let offset = (result[19] & 0x0f) as usize;
    let bin_code = ((result[offset]     & 0x7f) as u32) << 24
                 | ((result[offset + 1] & 0xff) as u32) << 16
                 | ((result[offset + 2] & 0xff) as u32) << 8
                 |  (result[offset + 3] & 0xff) as u32;
    // RFC 183 drift-check region: END
    bin_code
}

} // verus!

fn main() {}

