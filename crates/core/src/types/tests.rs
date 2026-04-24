//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn scopes_parse_handles_multiple_spaces() {
    let s = Scopes::parse("openid   profile\temail");
    assert_eq!(s.0, vec!["openid", "profile", "email"]);
}

#[test]
fn scopes_restrict_drops_unknown() {
    let requested = Scopes::parse("openid profile evil");
    let allowed   = vec!["openid".to_string(), "profile".to_string()];
    let out       = requested.restrict_to(&allowed);
    assert_eq!(out.0, vec!["openid", "profile"]);
}
