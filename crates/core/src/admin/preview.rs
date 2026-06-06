//! Preview-and-apply infrastructure — RFC 018.
//!
//! Every destructive admin operation follows the pattern:
//!
//! ```text
//! GET  /admin/.../config          ← view current state
//! POST /admin/.../config/preview  ← compute diff, render preview page
//! POST /admin/.../config/apply    ← verify preview token, commit change
//! ```
//!
//! ## Key types
//!
//! * [`ImpactStatement`] — operator-readable explanation of what will change.
//! * [`ImpactSeverity`] — Low / Medium / High; controls the preview banner colour.
//! * [`PreviewToken`] — HMAC-signed payload binding the apply request to the
//!   specific preview the operator saw.  Signed with the session HMAC key.
//!   Expires after 5 minutes.
//!
//! ## Security notes
//!
//! * The preview token carries `(operation_id, before, after, preview_ts, csrf)`.
//!   An attacker who modifies any field invalidates the HMAC.
//! * `csrf` in the token binds the apply to the session that generated the
//!   preview — cross-session replay is rejected.
//! * `preview_ts` enforces the 5-minute TTL; a stale token is rejected at apply.
//! * The apply handler must re-check permissions and re-fetch current state; the
//!   token does not encode authorization.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{CoreError, CoreResult};

// ---------------------------------------------------------------------------
// ImpactSeverity / ImpactStatement
// ---------------------------------------------------------------------------

/// How severe is the change being previewed?
///
/// Controls the banner colour in the preview template:
/// - `Low`    → info (blue)
/// - `Medium` → warning (amber)
/// - `High`   → danger (red), plus "DESTRUCTIVE — cannot be undone" banner text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImpactSeverity {
    Low,
    Medium,
    High,
}

impl ImpactSeverity {
    /// CSS class name applied to the preview banner.
    pub fn banner_css_class(self) -> &'static str {
        match self {
            Self::Low    => "preview-banner preview-banner--info",
            Self::Medium => "preview-banner preview-banner--warning",
            Self::High   => "preview-banner preview-banner--danger",
        }
    }
}

/// Operator-readable explanation of what will change and how to reverse it.
///
/// Operation-specific pure functions produce this value; the template renders
/// it as a preview page without any domain knowledge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactStatement {
    /// Short title, e.g. "Logging verbosity change".
    pub title:    String,
    /// Bullet points describing the concrete effects.  At least one.
    pub bullets:  Vec<String>,
    /// How to reverse the change, written as operator-actionable prose.
    pub rollback: String,
    /// Severity; drives the banner colour.
    pub severity: ImpactSeverity,
}

impl ImpactStatement {
    /// Convenience builder.
    pub fn new(
        title:    impl Into<String>,
        bullets:  Vec<String>,
        rollback: impl Into<String>,
        severity: ImpactSeverity,
    ) -> Self {
        Self {
            title:    title.into(),
            bullets,
            rollback: rollback.into(),
            severity,
        }
    }
}

// ---------------------------------------------------------------------------
// Diff entry
// ---------------------------------------------------------------------------

/// One row in the before/after diff table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub field:  String,
    pub before: String,
    pub after:  String,
}

impl DiffEntry {
    pub fn new(field: impl Into<String>, before: impl Into<String>, after: impl Into<String>) -> Self {
        Self { field: field.into(), before: before.into(), after: after.into() }
    }

    /// Returns `true` when `before == after` (no-op entry).
    pub fn is_unchanged(&self) -> bool {
        self.before == self.after
    }
}

// ---------------------------------------------------------------------------
// PreviewToken
// ---------------------------------------------------------------------------

/// The signed payload embedded as a hidden field on the preview/apply form.
///
/// Wire form: `b64url(canonical_json) + '.' + b64url(hmac_sha256)`
///
/// The apply handler:
/// 1. Splits on `'.'`.
/// 2. Re-computes HMAC over the JSON payload using the session HMAC key.
/// 3. Rejects if HMAC mismatch.
/// 4. Deserializes, checks `preview_ts + 300 > now`.
/// 5. Verifies `csrf` matches the session CSRF cookie.
/// 6. Proceeds to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewTokenPayload {
    /// Identifies the operation, e.g. `"config.log_level"`.
    pub operation_id: String,
    /// JSON representation of the before-value.
    pub before:       serde_json::Value,
    /// JSON representation of the after-value.
    pub after:        serde_json::Value,
    /// Unix timestamp when the preview was generated.
    pub preview_ts:   i64,
    /// CSRF token bound to the originating session.
    pub csrf:         String,
}

/// Maximum age of a preview token in seconds.
pub const PREVIEW_TOKEN_TTL_SECS: i64 = 300; // 5 minutes

/// Mint a new preview token, returning the wire form.
///
/// `hmac_key` is the session HMAC key (same key used for session cookies
/// and flash cookies in v0.31.0+).
pub fn mint_preview_token(
    payload:  &PreviewTokenPayload,
    hmac_key: &[u8],
) -> CoreResult<String> {
    let json = serde_json::to_string(payload)
        .map_err(|_| CoreError::Serialization)?;
    let json_b64 = URL_SAFE_NO_PAD.encode(json.as_bytes());

    let sig = hmac_sign(json_b64.as_bytes(), hmac_key);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

    Ok(format!("{json_b64}.{sig_b64}"))
}

/// Verify and decode a preview token.
///
/// Returns `Err` if:
/// - The token is malformed (missing `.` separator).
/// - The HMAC does not match.
/// - `preview_ts + PREVIEW_TOKEN_TTL_SECS < now_unix` (expired).
/// - `csrf` does not match `expected_csrf`.
pub fn verify_preview_token(
    token:         &str,
    hmac_key:      &[u8],
    now_unix:      i64,
    expected_csrf: &str,
) -> CoreResult<PreviewTokenPayload> {
    let (json_b64, sig_b64) = token.split_once('.')
        .ok_or_else(|| CoreError::InvalidRequest("malformed preview token"))?;

    // Verify HMAC.
    let expected_sig = hmac_sign(json_b64.as_bytes(), hmac_key);
    let presented_sig = URL_SAFE_NO_PAD.decode(sig_b64)
        .map_err(|_| CoreError::InvalidRequest("preview token sig decode failed"))?;
    if !crate::util::constant_time_eq_bytes(&expected_sig, &presented_sig) {
        return Err(CoreError::InvalidRequest("preview token HMAC mismatch"));
    }

    // Decode payload.
    let json_bytes = URL_SAFE_NO_PAD.decode(json_b64)
        .map_err(|_| CoreError::InvalidRequest("preview token payload decode failed"))?;
    let payload: PreviewTokenPayload = serde_json::from_slice(&json_bytes)
        .map_err(|_| CoreError::InvalidRequest("preview token payload deserialization failed"))?;

    // Check TTL.
    if payload.preview_ts + PREVIEW_TOKEN_TTL_SECS < now_unix {
        return Err(CoreError::InvalidRequest("preview token expired"));
    }

    // Check CSRF binding.
    if payload.csrf != expected_csrf {
        return Err(CoreError::InvalidRequest("preview token CSRF mismatch"));
    }

    Ok(payload)
}

// ---------------------------------------------------------------------------
// Per-operation impact functions
// ---------------------------------------------------------------------------

/// Impact statement for a `LOG_LEVEL` change.
///
/// `before` / `after` are the old and new log-level strings
/// (e.g. `"info"`, `"debug"`, `"warn"`).
pub fn log_level_impact(before: &str, after: &str) -> ImpactStatement {
    let severity = if after == "debug" || after == "trace" {
        ImpactSeverity::Medium  // debug/trace can be verbose / leak internals
    } else {
        ImpactSeverity::Low
    };

    ImpactStatement::new(
        "Logging verbosity change",
        vec![
            format!("Records at level '{after}' and above will be emitted."),
            format!("Records below '{after}' will be dropped silently."),
            if after == "debug" || after == "trace" {
                "⚠ Debug/trace logging may emit sensitive internal state. \
                 Enable only temporarily and in controlled environments.".to_owned()
            } else {
                "No unusual data exposure expected at this level.".to_owned()
            },
        ],
        format!("Set LOG_LEVEL back to '{before}' in wrangler.toml and re-deploy."),
        severity,
    )
}

/// Impact statement for an admin token rotation (high severity).
pub fn admin_token_rotation_impact(token_label: &str) -> ImpactStatement {
    ImpactStatement::new(
        "Admin token rotation — destructive",
        vec![
            format!("Token '{token_label}' will be permanently invalidated."),
            "Any operator or script using this token will receive 401 Unauthorized immediately.".to_owned(),
            "The replacement token is shown ONCE on the next page; cesauth cannot recover it.".to_owned(),
        ],
        "This change cannot be undone. If access is lost, generate a new token via the same flow.",
        ImpactSeverity::High,
    )
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn hmac_sign(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// RFC 096: constant_time_eq_bytes moved to crate::util

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-hmac-key-32-bytes-xxxxxxxxxxx";

    fn sample_payload(csrf: &str, ts: i64) -> PreviewTokenPayload {
        PreviewTokenPayload {
            operation_id: "config.log_level".to_owned(),
            before:       serde_json::json!("info"),
            after:        serde_json::json!("debug"),
            preview_ts:   ts,
            csrf:         csrf.to_owned(),
        }
    }

    // ----- PreviewToken tests -----

    #[test]
    fn preview_token_round_trip() {
        let now = 1_700_000_000i64;
        let payload = sample_payload("csrf123", now);
        let token = mint_preview_token(&payload, KEY).unwrap();
        let decoded = verify_preview_token(&token, KEY, now + 1, "csrf123").unwrap();
        assert_eq!(decoded.operation_id, "config.log_level");
        assert_eq!(decoded.before, serde_json::json!("info"));
        assert_eq!(decoded.after,  serde_json::json!("debug"));
    }

    #[test]
    fn preview_token_tampered_after_value_rejected() {
        let now = 1_700_000_000i64;
        let payload = sample_payload("csrf123", now);
        let token = mint_preview_token(&payload, KEY).unwrap();

        // Tamper: modify the base64-encoded payload.
        let (json_b64, sig_b64) = token.split_once('.').unwrap();
        let mut json_bytes = URL_SAFE_NO_PAD.decode(json_b64).unwrap();
        // Flip one byte in the payload.
        if let Some(b) = json_bytes.get_mut(10) { *b ^= 0xFF; }
        let bad_token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&json_bytes),
            sig_b64
        );

        let result = verify_preview_token(&bad_token, KEY, now + 1, "csrf123");
        assert!(result.is_err(), "tampered token must be rejected");
    }

    #[test]
    fn preview_token_expired_after_ttl_rejected() {
        let ts = 1_700_000_000i64;
        let payload = sample_payload("csrf123", ts);
        let token = mint_preview_token(&payload, KEY).unwrap();

        // Apply 1 second past the TTL.
        let now = ts + PREVIEW_TOKEN_TTL_SECS + 1;
        let result = verify_preview_token(&token, KEY, now, "csrf123");
        assert!(result.is_err(), "expired token must be rejected");
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn preview_token_accepted_at_ttl_boundary() {
        let ts = 1_700_000_000i64;
        let payload = sample_payload("csrf123", ts);
        let token = mint_preview_token(&payload, KEY).unwrap();
        // Exactly at the boundary.
        let result = verify_preview_token(&token, KEY, ts + PREVIEW_TOKEN_TTL_SECS, "csrf123");
        assert!(result.is_ok(), "token exactly at TTL boundary should be accepted");
    }

    #[test]
    fn preview_token_wrong_csrf_rejected() {
        let ts = 1_700_000_000i64;
        let payload = sample_payload("correct-csrf", ts);
        let token = mint_preview_token(&payload, KEY).unwrap();
        let result = verify_preview_token(&token, KEY, ts + 1, "wrong-csrf");
        assert!(result.is_err(), "mismatched CSRF must be rejected");
        assert!(result.unwrap_err().to_string().contains("CSRF"));
    }

    #[test]
    fn preview_token_malformed_no_dot_rejected() {
        let result = verify_preview_token("nodothere", KEY, 0, "csrf");
        assert!(result.is_err());
    }

    // ----- Impact function tests -----

    #[test]
    fn log_level_impact_info_to_debug_is_medium_severity() {
        let stmt = log_level_impact("info", "debug");
        assert_eq!(stmt.severity, ImpactSeverity::Medium);
        assert!(!stmt.bullets.is_empty());
        assert!(stmt.rollback.contains("info"));
    }

    #[test]
    fn log_level_impact_debug_to_warn_is_low_severity() {
        let stmt = log_level_impact("debug", "warn");
        assert_eq!(stmt.severity, ImpactSeverity::Low);
    }

    #[test]
    fn admin_token_rotation_impact_is_high_severity() {
        let stmt = admin_token_rotation_impact("deploy-key");
        assert_eq!(stmt.severity, ImpactSeverity::High);
        assert!(stmt.bullets.iter().any(|b| b.contains("deploy-key")));
        assert!(!stmt.rollback.is_empty());
    }

    // ----- ImpactSeverity CSS class tests -----

    #[test]
    fn severity_css_classes_are_distinct() {
        let low    = ImpactSeverity::Low.banner_css_class();
        let medium = ImpactSeverity::Medium.banner_css_class();
        let high   = ImpactSeverity::High.banner_css_class();
        assert_ne!(low, medium);
        assert_ne!(medium, high);
        assert_ne!(low, high);
    }

    // ----- DiffEntry tests -----

    #[test]
    fn diff_entry_unchanged_detected() {
        let e = DiffEntry::new("field", "value", "value");
        assert!(e.is_unchanged());
    }

    #[test]
    fn diff_entry_changed_detected() {
        let e = DiffEntry::new("field", "old", "new");
        assert!(!e.is_unchanged());
    }
}
