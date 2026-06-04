//! Audience scoping management helpers — RFC 017.
//!
//! Pure functions for the OIDC client audience-scoping admin editor.
//! No I/O; the handler injects the repository reads.

use crate::error::{CoreError, CoreResult};

/// The three semantically distinct states of `oidc_clients.audience`.
///
/// Operators and the admin editor think in these states; the database
/// stores `NULL` vs `""` vs `"<value>"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudienceTarget {
    /// `NULL` in the database — pre-v0.50.0 legacy behavior.
    /// This client may introspect any token cesauth issues.
    Unscoped,
    /// `Some("")` — explicit empty string.
    /// Matches only tokens whose `aud` claim is the empty string.
    /// Distinct from `Unscoped`; operators who set this must understand
    /// they're scoping to a zero-length audience, not disabling scoping.
    ExplicitEmpty,
    /// `Some(value)` — scoped to the given non-empty audience.
    Scoped(String),
}

impl AudienceTarget {
    /// Convert to the `Option<String>` form stored in `oidc_clients.audience`.
    pub fn to_db_value(self) -> Option<String> {
        match self {
            Self::Unscoped       => None,
            Self::ExplicitEmpty  => Some(String::new()),
            Self::Scoped(v)      => Some(v),
        }
    }

    /// Construct from the `Option<String>` form stored in the database.
    pub fn from_db_value(v: Option<String>) -> Self {
        match v {
            None    => Self::Unscoped,
            Some(s) if s.is_empty() => Self::ExplicitEmpty,
            Some(s) => Self::Scoped(s),
        }
    }

    /// Human-readable label for display.
    pub fn display_label(&self) -> &str {
        match self {
            Self::Unscoped      => "Unscoped (legacy — any audience)",
            Self::ExplicitEmpty => "Scoped to: \"\" (empty string)",
            Self::Scoped(_)     => "Scoped to audience value",
        }
    }

    /// Return `true` when this is effectively the same as `other`
    /// (same state and same value for `Scoped`).
    pub fn is_same_as(&self, other: &Self) -> bool {
        self == other
    }
}

/// Resolve the `AudienceTarget` from the admin form submission.
///
/// `mode` is the value of the `mode` radio button:
/// - `"unscoped"` → `AudienceTarget::Unscoped`
/// - `"scoped"`   → resolved from `audience_value`:
///     - empty string → `AudienceTarget::ExplicitEmpty`
///     - non-empty    → `AudienceTarget::Scoped(value)`
///
/// Returns `Err(CoreError::InvalidRequest)` for:
/// - Unknown `mode` value.
/// - `audience_value` containing newline or NUL byte (malformed copy-paste guard).
pub fn resolve_audience_target(
    mode:            &str,
    audience_value:  &str,
) -> CoreResult<AudienceTarget> {
    match mode {
        "unscoped" => Ok(AudienceTarget::Unscoped),
        "scoped"   => {
            // Guard against accidental copy-paste of multi-line text or
            // binary garbage.  RFC 7519 §4.1.3 audience must be a string;
            // newline / NUL are never valid in a URI-shaped audience identifier.
            if audience_value.contains('\n') || audience_value.contains('\r')
               || audience_value.contains('\0') {
                return Err(CoreError::InvalidRequest(
                    "audience value must not contain newline or NUL characters",
                ));
            }
            if audience_value.is_empty() {
                Ok(AudienceTarget::ExplicitEmpty)
            } else {
                Ok(AudienceTarget::Scoped(audience_value.trim().to_owned()))
            }
        }
        _ => Err(CoreError::InvalidRequest("unknown audience mode; expected 'unscoped' or 'scoped'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- resolve_audience_target -----

    #[test]
    fn mode_unscoped_produces_unscoped() {
        let target = resolve_audience_target("unscoped", "anything").unwrap();
        assert_eq!(target, AudienceTarget::Unscoped);
    }

    #[test]
    fn mode_scoped_empty_produces_explicit_empty() {
        let target = resolve_audience_target("scoped", "").unwrap();
        assert_eq!(target, AudienceTarget::ExplicitEmpty);
    }

    #[test]
    fn mode_scoped_value_produces_scoped() {
        let target = resolve_audience_target("scoped", "https://api.example.com").unwrap();
        assert_eq!(target, AudienceTarget::Scoped("https://api.example.com".to_owned()));
    }

    #[test]
    fn mode_scoped_trims_whitespace() {
        let target = resolve_audience_target("scoped", "  https://api.example.com  ").unwrap();
        assert_eq!(target, AudienceTarget::Scoped("https://api.example.com".to_owned()));
    }

    #[test]
    fn unknown_mode_is_error() {
        let result = resolve_audience_target("invalid", "");
        assert!(result.is_err());
    }

    #[test]
    fn audience_with_newline_is_rejected() {
        let result = resolve_audience_target("scoped", "https://api.example.com\nevil");
        assert!(result.is_err(), "newline in audience must be rejected");
    }

    #[test]
    fn audience_with_nul_byte_is_rejected() {
        let result = resolve_audience_target("scoped", "value\0nul");
        assert!(result.is_err(), "NUL byte in audience must be rejected");
    }

    // ----- AudienceTarget round-trip -----

    #[test]
    fn unscoped_roundtrip_through_db() {
        let target = AudienceTarget::Unscoped;
        let db = target.clone().to_db_value();
        assert_eq!(db, None);
        assert_eq!(AudienceTarget::from_db_value(db), target);
    }

    #[test]
    fn explicit_empty_roundtrip_through_db() {
        let target = AudienceTarget::ExplicitEmpty;
        let db = target.clone().to_db_value();
        assert_eq!(db, Some(String::new()));
        assert_eq!(AudienceTarget::from_db_value(db), target);
    }

    #[test]
    fn scoped_roundtrip_through_db() {
        let target = AudienceTarget::Scoped("https://api.example.com".to_owned());
        let db = target.clone().to_db_value();
        assert_eq!(db.as_deref(), Some("https://api.example.com"));
        assert_eq!(AudienceTarget::from_db_value(db), target);
    }

    #[test]
    fn unscoped_and_explicit_empty_are_distinct() {
        let unscoped = AudienceTarget::Unscoped;
        let empty    = AudienceTarget::ExplicitEmpty;
        assert_ne!(unscoped, empty,
            "Unscoped (NULL) and ExplicitEmpty ('') must be distinct states");
    }
}
