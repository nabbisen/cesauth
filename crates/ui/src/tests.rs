//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn escape_covers_common_payloads() {
    let bad = r#"<script>"&'"#;
    let out = escape(bad);
    assert_eq!(out, "&lt;script&gt;&quot;&amp;&#x27;");
}
