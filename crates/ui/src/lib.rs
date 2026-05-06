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
pub mod tenancy_console;
pub mod tenant_admin;
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

/// Encode `s` as a double-quoted JavaScript string literal,
/// suitable for inlining into `<script>` blocks. Adopted in
/// v0.39.0 alongside the i18n-aware login page where the
/// passkey-failed error message comes from a catalog and can
/// contain characters that would break a naive interpolation
/// (quotes, backslashes, newlines, or — for JA translations —
/// multi-byte UTF-8 that must NOT be split mid-codepoint).
///
/// Specifically escapes: `\\`, `"`, the control characters
/// `\n` / `\r` / `\t`, the byte ranges `0x00..=0x1f` that
/// aren't named above (encoded as `\uXXXX`), and the two
/// character sequences that would let the string break out
/// of a `<script>` block: `</` (becomes `<\/`) and `<!--`
/// (becomes `<\!--`).
///
/// Multi-byte UTF-8 (non-ASCII letters, JA translations, etc.)
/// passes through unchanged — JS source files are UTF-8 and
/// the browser parses them correctly.
///
/// The returned string includes the surrounding double quotes,
/// so callers interpolate it directly: `err.textContent =
/// {js_string};`.
pub fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"'  => out.push_str(r#"\""#),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            // </script> escape: a bare `</` inside a JS
            // string would still close the surrounding
            // <script> tag during HTML parsing. Insert a
            // backslash so the HTML parser sees `<\/` and
            // doesn't terminate the script element.
            '<' if chars.peek() == Some(&'/') => {
                out.push_str(r"<\/");
                chars.next();
            }
            // Same defensive treatment for `<!--`.
            '<' if {
                // peek 3 chars without consuming
                let mut iter = chars.clone();
                iter.next() == Some('!') && iter.next() == Some('-') && iter.next() == Some('-')
            } => {
                out.push_str(r"<\!--");
                chars.next(); chars.next(); chars.next();
            }
            // Other control characters: \uXXXX. The ASCII
            // controls are the only ones that need this
            // (codepoints above 0x7f pass through fine).
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(&mut out, "\\u{:04x}", c as u32);
            }
            // Everything else (including multi-byte UTF-8)
            // passes through verbatim.
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests;
