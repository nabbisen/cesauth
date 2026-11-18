//! The payload-side mirror of `audit_events`'s seven cross-checked
//! columns (RFC 188 D4, Phase 1).
//!
//! `crates/backend/src::audit::Event` is the writer's borrowed view and
//! is what actually gets serialized into the `payload` column. This
//! module cannot depend on `cesauth-backend` (it would be a dependency
//! cycle — `cesauth-backend` depends on `cesauth-core`), so this is a
//! second, narrower `Deserialize`-only struct in `cesauth-core` that
//! reads back exactly the same JSON shape. `cesauth-backend`'s own
//! cross-crate pin test (RFC 188 D4) asserts the two agree — this crate
//! cannot assert that itself, since it never sees `Event`.
//!
//! Every field is `#[serde(default)]`: a payload written before
//! migration `0015` (no `request_id`) or `0021` (no `actor`) omits the
//! key entirely, and an absent key must deserialize as `None`, the same
//! as the column's own `NULL` for those rows (RFC 188 D5). This is not
//! a general defensive habit — it is the specific thing that keeps
//! Phase 1 from alarming on legitimate pre-migration history, which is
//! this slice's single most important false-positive case.

use serde::{Deserialize, Serialize};

/// The seven `audit_events` columns this cut cross-checks against the
/// payload's own copy of each field, in the same order
/// `CROSS_CHECKED_COLUMNS` (`crate::audit::verifier`) lists them.
///
/// Deliberately **not** all of `Event`'s fields — `ts`, `id`, `kind`,
/// `payload`/`payload_hash`/`previous_hash`/`chain_hash` are chain
/// inputs, already covered by `verify_chain`'s existing three checks,
/// and `created_at` has no payload twin by design (migration `0008`'s
/// own comment). Adding a field here without adding it to
/// `CROSS_CHECKED_COLUMNS` (or vice versa) is caught by this crate's
/// own mirror/const agreement test (`payload::tests`) and, cross-crate,
/// by the schema↔verifier gate (T8).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPayloadMirror {
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
}

impl AuditPayloadMirror {
    /// Parse a stored row's `payload` column. `Err` means the payload
    /// is not valid JSON or not an object with the expected shape —
    /// RFC 188 S6: this is its own finding (`payload_unparseable`), not
    /// a column mismatch, and the caller must not treat it as one.
    pub fn parse(payload: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_object_reads_as_all_none() {
        // The genesis row's own payload, and every `build_chain` test
        // fixture's payload, is exactly `"{}"`.
        let m = AuditPayloadMirror::parse("{}").unwrap();
        assert_eq!(m, AuditPayloadMirror::default());
    }

    #[test]
    fn pre_0015_pre_0021_payload_omitting_request_id_and_actor_reads_as_none() {
        // D5's false-positive case: a payload written before either
        // migration omits both keys entirely, not `null`.
        let m = AuditPayloadMirror::parse(r#"{"subject":"user-1"}"#).unwrap();
        assert_eq!(m.subject, Some("user-1".to_owned()));
        assert_eq!(m.actor, None);
        assert_eq!(m.request_id, None);
    }

    #[test]
    fn explicit_null_and_absent_key_are_indistinguishable_here() {
        let absent = AuditPayloadMirror::parse(r#"{}"#).unwrap();
        let explicit_null = AuditPayloadMirror::parse(r#"{"actor":null}"#).unwrap();
        assert_eq!(absent.actor, explicit_null.actor);
    }

    #[test]
    fn all_seven_fields_populated() {
        let json = r#"{
            "subject":"user-2","actor":"admin-1","client_id":"client-9",
            "ip":"203.0.113.5","user_agent":"curl/8","reason":"pkce_mismatch",
            "request_id":"cf-ray-abc"
        }"#;
        let m = AuditPayloadMirror::parse(json).unwrap();
        assert_eq!(m.subject, Some("user-2".to_owned()));
        assert_eq!(m.actor, Some("admin-1".to_owned()));
        assert_eq!(m.client_id, Some("client-9".to_owned()));
        assert_eq!(m.ip, Some("203.0.113.5".to_owned()));
        assert_eq!(m.user_agent, Some("curl/8".to_owned()));
        assert_eq!(m.reason, Some("pkce_mismatch".to_owned()));
        assert_eq!(m.request_id, Some("cf-ray-abc".to_owned()));
    }

    #[test]
    fn malformed_payload_is_an_error_not_a_panic() {
        // RFC 188 S6: the caller distinguishes this from a column
        // mismatch and reports `payload_unparseable`.
        //
        // Not tested here: a top-level JSON array (e.g. `["an","array"]`)
        // — derived `Deserialize` happily maps it positionally onto the
        // struct's fields (`subject="an", actor="array", ...`), which is
        // ordinary serde behaviour for any plain struct, not a defect.
        // Genuinely malformed: invalid JSON syntax, and a field whose
        // value cannot coerce to the declared type.
        assert!(AuditPayloadMirror::parse("not json").is_err());
        assert!(AuditPayloadMirror::parse(r#"{"subject": 123}"#).is_err());
    }

    /// Mirror/const agreement (§9's in-crate half): the struct's own
    /// JSON key set must equal `CROSS_CHECKED_COLUMNS`, so the two
    /// cannot drift independently of each other.
    #[test]
    fn json_keys_equal_cross_checked_columns() {
        let m = AuditPayloadMirror {
            subject:    Some("s".into()),
            actor:      Some("a".into()),
            client_id:  Some("c".into()),
            ip:         Some("i".into()),
            user_agent: Some("u".into()),
            reason:     Some("r".into()),
            request_id: Some("q".into()),
        };
        let v = serde_json::to_value(&m).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected: Vec<&str> = crate::audit::verifier::CROSS_CHECKED_COLUMNS.to_vec();
        expected.sort_unstable();
        assert_eq!(keys, expected);
    }
}
