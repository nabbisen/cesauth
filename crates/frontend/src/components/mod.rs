//! UI component library, imported from the cesauth-mockup foundation
//! (RFC 131 R2a, R2b).
//!
//! The mockup organises this into four groups — `primitives`, `nav`,
//! `shells`, `domain`. `primitives` crossed in R2a; `nav`, `shells`,
//! and `domain` cross in R2b (RFC 180), with the mockup's own
//! Leptos-reactive locale mechanism (`Msg`, `LocaleContext`,
//! `use_locale()`, `LocaleToggle`) deleted rather than imported —
//! every file here resolves strings through
//! `cesauth_core::i18n::lookup` via a plain `locale: Locale` prop
//! (or, for `OperatorShell`, a hardcoded JA-only lookup; ADR-013).
//!
//! All ten R2b files land dormant: nothing routes to them yet. Pairing
//! them with real routes and data is R3's job, not this one's.

pub mod domain;
pub mod nav;
pub mod primitives;
pub mod shells;
