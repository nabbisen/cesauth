//! # cesauth-ui
//!
//! Server-rendered HTML. Per spec §7 the UI is semantic HTML first and
//! accessibility is a hard requirement: every form control has a label,
//! error / status regions use `aria-live`, and the pages work with
//! JavaScript disabled except for the WebAuthn client-side call itself.
//!
//! The module purposely ships **zero** template engine dependencies.
//! The pages are small; `format!` is obvious; there is no upside to
//! pulling in askama or handlebars for something this size.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms)]

pub mod admin;
pub mod templates;

/// Minimal HTML attribute-value escaper. Covers the five characters
/// that must be escaped inside an attribute or text node.
///
/// We deliberately do not expose "safe" unescaped HTML insertion
/// anywhere. Anything the caller wants rendered passes through here.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&'  => out.push_str("&amp;"),
            '<'  => out.push_str("&lt;"),
            '>'  => out.push_str("&gt;"),
            '"'  => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _    => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests;
