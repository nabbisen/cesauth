//! v0.45.0 — sessions bulk-revoke (ADR-012 §Q4).
//!
//! Split out from `templates/tests.rs` in v0.75.0 (test-file
//! modularization per the dev guidelines' 500-ELOC strongly-recommended
//! split threshold).

use super::super::*;
use super::super::chrome::frame;
#[allow(unused_imports)]
use cesauth_core::i18n::Locale;
#[allow(unused_imports)]
use super::common::{strip_inline_style, sample_item};

// v0.45.0 — bulk "revoke all other sessions" button (ADR-012 §Q4)
// =====================================================================
