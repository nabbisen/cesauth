//! QR code SVG generation for the TOTP enrollment page.
//!
//! Wraps the `qrcode` crate's SVG renderer with sensible defaults
//! for our use case: medium error-correction level (so a phone
//! camera with mild glare or a light bend on a printed page still
//! reads cleanly), a fixed size that fits comfortably in the
//! enrollment-page layout, and no JS dependency.
//!
//! Caller is the worker layer's `/me/security/totp/enroll`
//! handler. Input is the `otpauth://` URI from
//! `cesauth_core::totp::otpauth_uri`. Output is the inline SVG
//! markup the enrollment template embeds directly into the page.
//!
//! v0.28.0 surface. Earlier releases (v0.26.0, v0.27.0) had the
//! TOTP library and storage; v0.28.0 adds the
//! presentation-layer pieces (this module + UI templates) plus
//! the enrollment-flow helper.

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

/// QR code dimensions in pixels. Large enough that a phone
/// camera held at typical reading distance focuses cleanly;
/// small enough to fit beside the manual-entry secret in the
/// enrollment-page layout. Both numbers are min-dimensions
/// the renderer honors by scaling pixel size up if needed.
const DIMENSION_PX: u32 = 240;

/// Error correction level. `M` (medium, ~15% recovery) is the
/// pragmatic choice: a printed page with a coffee stain or a
/// phone screen with a fingerprint smudge still reads. `L` (low,
/// ~7%) is too fragile; `Q` and `H` (~25% / ~30%) make the QR
/// noticeably bigger or denser without UX gain — authenticator
/// apps don't need extreme robustness.
///
/// Locked here as a constant rather than a parameter — there's
/// no operator-visible reason to vary this and it's easier to
/// audit if the choice is checked in.
const ERROR_CORRECTION: EcLevel = EcLevel::M;

/// Render an `otpauth://` URI as inline SVG markup.
///
/// Returns the raw `<svg>...</svg>` string that the enrollment
/// template inlines into the page. The SVG is server-generated
/// from a server-issued URI; the template intentionally does NOT
/// HTML-escape it (escaping would break rendering).
///
/// On encoding failure (impossible in practice for an
/// `otpauth://` URI of bounded length) returns an `Err` with a
/// human-readable string the caller can log.
///
/// The output is deterministic for a given input: the same URI
/// produces byte-identical SVG. This makes the output reproducible
/// for tests.
pub fn otpauth_to_svg(otpauth_uri: &str) -> Result<String, String> {
    let code = QrCode::with_error_correction_level(otpauth_uri.as_bytes(), ERROR_CORRECTION)
        .map_err(|e| format!("qrcode encode failed: {e}"))?;

    // SVG colors as raw strings. Black-on-transparent is the
    // standard rendering — black on transparent so the page's
    // background shows through (works on dark-mode and light-
    // mode browser themes alike).
    //
    // The renderer's `light_color` is the background; passing
    // `none` would be ideal but the SVG generator rejects
    // empty/none. Pass white but rely on the page CSS to put
    // a transparent-friendly background, OR use white knowing
    // most pages are white. We choose white: most enrollment
    // pages are themed white-on-white anyway, and a future
    // dark-mode iteration can swap the colors via a parameter
    // if needed.
    let svg = code
        .render::<svg::Color<'_>>()
        .min_dimensions(DIMENSION_PX, DIMENSION_PX)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();

    Ok(svg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svg_starts_with_svg_tag() {
        let svg = otpauth_to_svg("otpauth://totp/cesauth:alice?secret=JBSWY3DPEHPK3PXP")
            .expect("encode succeeds");
        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"),
            "output must be valid SVG markup: starts with {:?}", &svg[..svg.len().min(40)]);
    }

    #[test]
    fn svg_ends_with_svg_close_tag() {
        let svg = otpauth_to_svg("otpauth://totp/cesauth:alice?secret=JBSWY3DPEHPK3PXP")
            .expect("encode succeeds");
        assert!(svg.trim_end().ends_with("</svg>"),
            "SVG must close cleanly: tail = {:?}",
            &svg[svg.len().saturating_sub(40)..]);
    }

    #[test]
    fn svg_includes_dark_color_at_least_once() {
        // Pin that we asked for black; a future encoder swap
        // shouldn't silently drop the dark-color choice.
        let svg = otpauth_to_svg("otpauth://totp/cesauth:alice?secret=JBSWY3DPEHPK3PXP")
            .expect("encode succeeds");
        assert!(svg.contains("#000000"),
            "SVG must reference black for dark cells");
    }

    #[test]
    fn svg_is_deterministic() {
        // Same URI → same SVG. Pin so a renderer change that
        // introduces non-determinism (random ordering, etc.) is
        // caught.
        let uri = "otpauth://totp/cesauth:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=cesauth&algorithm=SHA1&digits=6&period=30";
        let a = otpauth_to_svg(uri).unwrap();
        let b = otpauth_to_svg(uri).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn svg_changes_when_uri_changes() {
        // Different URIs must produce different QR codes.
        // Astronomically true, but pin so a regression where the
        // caller's `secret=` isn't reaching the encoder fails
        // closed.
        let a = otpauth_to_svg("otpauth://totp/cesauth:a?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let b = otpauth_to_svg("otpauth://totp/cesauth:a?secret=BBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn svg_handles_long_uri() {
        // The full otpauth URI with a long issuer + account is
        // bigger than the demo "alice" cases. Pin no panics on a
        // realistic-length input.
        let uri = "otpauth://totp/cesauth-production:alice.smith+test@subdomain.example.com?\
                   secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&\
                   issuer=cesauth-production&algorithm=SHA1&digits=6&period=30";
        let svg = otpauth_to_svg(uri).expect("realistic-length URI encodes");
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn dimension_constant_is_reasonable() {
        // The renderer treats DIMENSION_PX as a *minimum*; the
        // actual output may scale up. Pin that the constant is
        // non-zero and reasonable for embedding in a page (not
        // 4 px, not 4000 px).
        assert!(DIMENSION_PX >= 100 && DIMENSION_PX <= 600,
            "DIMENSION_PX should be page-embeddable: {DIMENSION_PX}");
    }
}
