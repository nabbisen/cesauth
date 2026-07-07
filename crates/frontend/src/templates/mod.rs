//! HTML page templates for cesauth (RFC 098 split).
//!
//! This module re-exports all public symbols from the sub-modules so
//! that call sites continue to use `cesauth_frontend::templates::*` unchanged.
//! The split exists purely for editor navigation and incremental build;
//! it introduces no new API surface.

// Sub-modules (RFC 098)
pub mod chrome;
pub mod login;
pub mod totp;
pub mod security_center;

// Re-exports — public API surface identical to the old single-file layout
// escape is defined in crate root (crates/ui/src/lib.rs)
pub use chrome::{flash_block, FlashView, frame_for, frame_with_flash, BASE_CSS};
pub use login::{
    error_page, error_page_for,
        magic_link_sent_page, magic_link_sent_page_for,
};
pub use totp::{
        totp_enroll_page, totp_enroll_page_for,
    totp_recovery_codes_page, totp_recovery_codes_page_for,
    totp_verify_page, totp_verify_page_for,
};
pub use security_center::{
    PrimaryAuthMethod,
    SecurityCenterState,
    SessionListItem,
        };

#[cfg(test)]
mod tests;
