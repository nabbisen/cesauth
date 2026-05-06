//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn escape_covers_common_payloads() {
    let bad = r#"<script>"&'"#;
    let out = escape(bad);
    assert_eq!(out, "&lt;script&gt;&quot;&amp;&#x27;");
}

// =====================================================================
// v0.39.0 — js_string_literal (i18n inline-script interpolation)
// =====================================================================

#[test]
fn js_string_literal_wraps_in_double_quotes() {
    assert_eq!(js_string_literal("hello"), r#""hello""#);
}

#[test]
fn js_string_literal_escapes_double_quotes_and_backslashes() {
    // Both characters have meaning inside a "..." JS string
    // and must be escaped so the literal stays balanced.
    assert_eq!(js_string_literal(r#"a"b"#), r#""a\"b""#);
    assert_eq!(js_string_literal(r"a\b"),   r#""a\\b""#);
}

#[test]
fn js_string_literal_escapes_newlines_tabs_and_cr() {
    // Untreated \n in a JS string literal is a syntax error
    // (literal newline mid-string); we emit the escape form.
    assert_eq!(js_string_literal("a\nb"), r#""a\nb""#);
    assert_eq!(js_string_literal("a\tb"), r#""a\tb""#);
    assert_eq!(js_string_literal("a\rb"), r#""a\rb""#);
}

#[test]
fn js_string_literal_escapes_other_controls_as_uxxxx() {
    // 0x07 (BEL) is a control character below 0x20 that
    // doesn't have a named escape; goes through \uXXXX.
    let s = String::from("a\x07b");
    assert_eq!(js_string_literal(&s), r#""a\u0007b""#);
}

#[test]
fn js_string_literal_passes_multibyte_utf8_through_verbatim() {
    // The JA login error message contains non-ASCII; we must
    // NOT split codepoints or emit \uXXXX for them. The browser
    // parses the source as UTF-8 and the JS engine constructs
    // the string from those code points correctly.
    let ja = "パスキーでサインインできませんでした。";
    let out = js_string_literal(ja);
    assert_eq!(out, format!("\"{ja}\""));
    // Sanity: make sure it round-trips through bytes — no
    // codepoint corruption.
    assert!(out.contains("パスキー"));
    assert!(out.contains("できませんでした"));
}

#[test]
fn js_string_literal_neutralizes_script_close_tag() {
    // A bare `</` inside a JS string would still close the
    // surrounding <script> element during HTML parsing,
    // which is a known XSS-ish problem with naive
    // interpolation. We escape it as `<\/`.
    let out = js_string_literal("done</script>");
    assert!(!out.contains("</"),
        "raw `</` must not appear in the output: {out}");
    assert!(out.contains(r"<\/"),
        "expected `<\\/` escape: {out}");
}

#[test]
fn js_string_literal_neutralizes_html_comment_opener() {
    let out = js_string_literal("<!-- comment");
    assert!(!out.contains("<!--"),
        "raw `<!--` must not appear in the output: {out}");
    assert!(out.contains(r"<\!--"));
}

#[test]
fn js_string_literal_lone_lt_passes_through() {
    // `<` alone (not followed by `/` or `!--`) is fine in a
    // JS string and shouldn't be escaped — only the
    // dangerous bigram patterns get treated.
    assert_eq!(js_string_literal("a < b"), r#""a < b""#);
}
