//! Shared test helpers for the `crates/ui/src/templates/tests/` submodules.
//!
//! `templates/tests.rs` exceeded 2,000 lines, well over the 500-ELOC
//! "strongly recommended split" threshold from the development
//! guidelines. v0.75.0 splits it into per-feature submodules; this file
//! holds the helper(s) every submodule needs.

#[allow(dead_code)]
pub(super) fn strip_inline_style(html: &str) -> String {
    // v0.52.0: style tags may have `nonce="..."` attribute (RFC 006).
    // Find the opening <style...> tag and closing </style>.
    let style_start = html.find("<style").or_else(|| html.find("<style>"));
    let style_end   = html.find("</style>").map(|i| i + "</style>".len());
    if let (Some(start), Some(end)) = (style_start, style_end) {
        if end > start {
            let mut out = String::with_capacity(html.len());
            out.push_str(&html[..start]);
            out.push_str(&html[end..]);
            return out;
        }
    }
    html.to_owned()
}

// ─── Cross-module test fixtures ───────────────────────────────────────────

/// Build a `SecurityCenterState` fixture. Used by `v0_31_design` (which
/// originally defined this) and by `rfc_006_and_later`.
#[allow(dead_code)]
pub(super) fn make_state(
    method:  super::super::security_center::PrimaryAuthMethod,
    enabled: bool,
    n:       u32,
) -> super::super::security_center::SecurityCenterState {
    super::super::security_center::SecurityCenterState {
        primary_method:           method,
        totp_enabled:             enabled,
        recovery_codes_remaining: n,
        active_sessions_count:    None,
    }
}

/// Build a sessions-page `SessionListItem` fixture. Used by
/// `v0_35_sessions` (which originally defined this) and by
/// `v0_45_bulk_revoke`.
#[allow(dead_code)]
pub(super) fn sample_item(
    id: &str, current: bool, method: &str, created: i64,
) -> super::super::security_center::SessionListItem {
    super::super::security_center::SessionListItem {
        session_id:   id.to_owned(),
        auth_method:  method.to_owned(),
        client_id:    "demo_client".to_owned(),
        created_at:   created,
        last_seen_at: created,
        is_current:   current,
    }
}
