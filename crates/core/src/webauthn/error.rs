//! Typed WebAuthn error categories for client-facing responses.
//!
//! ## v0.51.1 (RFC 004)
//!
//! `CoreError::WebAuthn(&'static str)` carries diagnostic strings like
//! `"rpIdHash mismatch"` or `"signature invalid"`. These are valuable for
//! server-side logs but useless for clients — a flat HTTP 500 with a generic
//! error body gives no actionable guidance to the user.
//!
//! This module adds a `WebAuthnErrorKind` — a small, **conservative** enum
//! of client-actionable categories. The mapping is centralized in `classify`.
//!
//! **Invariant**: the diagnostic detail string MUST NOT appear on the wire.
//! `kind` is the classification; the detail lives in audit events and
//! `console_error!` logs only. This is enforced by a worker-layer test.

use serde::{Deserialize, Serialize};

/// Client-actionable category for a WebAuthn ceremony failure.
///
/// Each variant maps to a distinct user action. The set is deliberately
/// small — add variants only when a new distinct user action is warranted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebAuthnErrorKind {
    /// The credential the user attempted is not registered for this
    /// account. Client should prompt to try another authenticator or
    /// to register this one.
    UnknownCredential,

    /// The relying-party ID the authenticator signed against doesn't
    /// match what this cesauth instance expects. Almost always a
    /// deployment misconfiguration (wrong `WEBAUTHN_RP_ID`, subdomain
    /// mismatch). Not user-recoverable; client renders an "ask your
    /// administrator" message.
    RelyingPartyMismatch,

    /// The user cancelled or aborted the browser/OS authenticator
    /// prompt. Client should retry by re-issuing the ceremony — no
    /// state was changed.
    UserCancelled,

    /// Signature verification failed, or the sign counter regressed
    /// (replay defense). The authenticator may be cloned or
    /// compromised. Client suggests trying a different authenticator.
    ///
    /// The two underlying causes are deliberately conflated: surfacing
    /// "counter regression" vs "bad signature" would let an attacker
    /// probe whether their forged authenticator's counter value matches
    /// the server's last-seen value.
    SignatureInvalid,

    /// The challenge sent by the browser doesn't match what cesauth
    /// issued. Usually means the ceremony took too long (challenge
    /// expired). Client should re-issue the ceremony from scratch.
    ChallengeMismatch,

    /// An unmapped or unexpected failure. Client renders a generic
    /// "something went wrong" message. The server log carries the
    /// detail string.
    Other,
}

impl WebAuthnErrorKind {
    /// Snake-case string for use in JSON wire responses and audit payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownCredential    => "unknown_credential",
            Self::RelyingPartyMismatch => "relying_party_mismatch",
            Self::UserCancelled        => "user_cancelled",
            Self::SignatureInvalid     => "signature_invalid",
            Self::ChallengeMismatch    => "challenge_mismatch",
            Self::Other                => "other",
        }
    }
}

/// Map a WebAuthn diagnostic detail string to a `WebAuthnErrorKind`.
///
/// The mapping is centralised here so call sites don't need to pattern-match
/// on raw strings. Any diagnostic string not in the match table falls through
/// to `Other` — this is intentional and safe.
///
/// When upgrading dependencies or adding new error paths, audit this list for
/// new diagnostic strings that deserve a specific category.
pub fn classify(detail: &str) -> WebAuthnErrorKind {
    match detail {
        "rpIdHash mismatch"        => WebAuthnErrorKind::RelyingPartyMismatch,
        "credential not found"
        | "credential not registered"
        | "unknown credentialId"   => WebAuthnErrorKind::UnknownCredential,
        "signature invalid"        => WebAuthnErrorKind::SignatureInvalid,
        "counter regression"       => WebAuthnErrorKind::SignatureInvalid,
        "user cancelled"
        | "NotAllowedError"        => WebAuthnErrorKind::UserCancelled,
        "challenge mismatch"
        | "challenge expired"      => WebAuthnErrorKind::ChallengeMismatch,
        _                          => WebAuthnErrorKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_rp_id_hash_mismatch_to_relying_party_mismatch() {
        assert_eq!(classify("rpIdHash mismatch"), WebAuthnErrorKind::RelyingPartyMismatch);
    }

    #[test]
    fn classify_credential_not_found_to_unknown_credential() {
        assert_eq!(classify("credential not found"),       WebAuthnErrorKind::UnknownCredential);
        assert_eq!(classify("credential not registered"),  WebAuthnErrorKind::UnknownCredential);
        assert_eq!(classify("unknown credentialId"),       WebAuthnErrorKind::UnknownCredential);
    }

    #[test]
    fn classify_signature_invalid_to_signature_invalid() {
        assert_eq!(classify("signature invalid"), WebAuthnErrorKind::SignatureInvalid);
    }

    #[test]
    fn classify_counter_regression_also_maps_to_signature_invalid() {
        // Deliberate conflation: client can't distinguish these two
        // without helping an attacker probe sign-counter state.
        assert_eq!(classify("counter regression"), WebAuthnErrorKind::SignatureInvalid);
    }

    #[test]
    fn classify_user_cancelled_to_user_cancelled() {
        assert_eq!(classify("user cancelled"),  WebAuthnErrorKind::UserCancelled);
        assert_eq!(classify("NotAllowedError"), WebAuthnErrorKind::UserCancelled);
    }

    #[test]
    fn classify_challenge_strings_to_challenge_mismatch() {
        assert_eq!(classify("challenge mismatch"), WebAuthnErrorKind::ChallengeMismatch);
        assert_eq!(classify("challenge expired"),  WebAuthnErrorKind::ChallengeMismatch);
    }

    #[test]
    fn classify_unknown_string_falls_to_other() {
        assert_eq!(classify("some unexpected error"), WebAuthnErrorKind::Other);
        assert_eq!(classify(""),                      WebAuthnErrorKind::Other);
    }

    #[test]
    fn kind_as_str_returns_snake_case() {
        assert_eq!(WebAuthnErrorKind::UnknownCredential.as_str(),    "unknown_credential");
        assert_eq!(WebAuthnErrorKind::RelyingPartyMismatch.as_str(), "relying_party_mismatch");
        assert_eq!(WebAuthnErrorKind::UserCancelled.as_str(),        "user_cancelled");
        assert_eq!(WebAuthnErrorKind::SignatureInvalid.as_str(),     "signature_invalid");
        assert_eq!(WebAuthnErrorKind::ChallengeMismatch.as_str(),    "challenge_mismatch");
        assert_eq!(WebAuthnErrorKind::Other.as_str(),                "other");
    }

    #[test]
    fn kind_serializes_snake_case_via_serde() {
        let json = serde_json::to_string(&WebAuthnErrorKind::UnknownCredential).unwrap();
        assert_eq!(json, "\"unknown_credential\"");

        let json = serde_json::to_string(&WebAuthnErrorKind::RelyingPartyMismatch).unwrap();
        assert_eq!(json, "\"relying_party_mismatch\"");
    }

    #[test]
    fn classify_covers_all_known_cesauth_diagnostic_strings() {
        // Pin all diagnostic strings currently emitted by cesauth's
        // webauthn::authentication and webauthn::registration modules.
        // If this test fails after a code change, update classify() to
        // cover the new string.
        let known_strings = [
            ("rpIdHash mismatch",        WebAuthnErrorKind::RelyingPartyMismatch),
            ("credential not found",     WebAuthnErrorKind::UnknownCredential),
            ("credential not registered",WebAuthnErrorKind::UnknownCredential),
            ("unknown credentialId",     WebAuthnErrorKind::UnknownCredential),
            ("signature invalid",        WebAuthnErrorKind::SignatureInvalid),
            ("counter regression",       WebAuthnErrorKind::SignatureInvalid),
            ("user cancelled",           WebAuthnErrorKind::UserCancelled),
            ("NotAllowedError",          WebAuthnErrorKind::UserCancelled),
            ("challenge mismatch",       WebAuthnErrorKind::ChallengeMismatch),
            ("challenge expired",        WebAuthnErrorKind::ChallengeMismatch),
        ];
        for (detail, expected) in &known_strings {
            assert_eq!(
                classify(detail), *expected,
                "classify({detail:?}) should be {expected:?}"
            );
        }
    }
}
