//! UI component library, imported from the cesauth-mockup foundation
//! (RFC 131 R2a).
//!
//! The mockup organises this into four groups — `primitives`, `nav`,
//! `shells`, `domain`. Only `primitives` crosses in R2a: the other three
//! depend on a Leptos-reactive locale mechanism that collides with
//! cesauth's per-request i18n (RFC 131 §5 R2, deferred as R2b pending
//! RFC 132 §13 q1).

pub mod primitives;
