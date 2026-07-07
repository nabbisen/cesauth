//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn level_ordering() {
    assert!(Level::Trace < Level::Debug);
    assert!(Level::Debug < Level::Info);
    assert!(Level::Info  < Level::Warn);
    assert!(Level::Warn  < Level::Error);
}

#[test]
fn level_parse_case_insensitive() {
    assert_eq!(Level::parse("INFO"),    Some(Level::Info));
    assert_eq!(Level::parse("warning"), Some(Level::Warn));
    assert_eq!(Level::parse("err"),     Some(Level::Error));
    assert_eq!(Level::parse("bogus"),   None);
}

#[test]
fn sensitive_categories_are_flagged() {
    assert!(Category::Auth.is_sensitive());
    assert!(Category::Session.is_sensitive());
    assert!(Category::Crypto.is_sensitive());
    assert!(!Category::Http.is_sensitive());
    assert!(!Category::Storage.is_sensitive());
    assert!(!Category::RateLimit.is_sensitive());
    assert!(!Category::Config.is_sensitive());
    assert!(!Category::Dev.is_sensitive());
}

#[test]
fn record_serializes_without_subject() {
    let rec = Record {
        ts: 1000, level: Level::Info, category: "http",
        msg: "hello", subject: None,
    };
    let out = serde_json::to_string(&rec).unwrap();
    assert!(out.contains(r#""ts":1000"#));
    assert!(out.contains(r#""level":"info""#));
    assert!(out.contains(r#""category":"http""#));
    assert!(out.contains(r#""msg":"hello""#));
    assert!(!out.contains("subject"));
}

#[test]
fn record_serializes_with_subject() {
    let rec = Record {
        ts: 1, level: Level::Warn, category: "auth",
        msg: "x", subject: Some("u-1"),
    };
    let out = serde_json::to_string(&rec).unwrap();
    assert!(out.contains(r#""subject":"u-1""#));
}
