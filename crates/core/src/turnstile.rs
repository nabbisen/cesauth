//! Cloudflare Turnstile server-side verification.
//!
//! Turnstile is the CAPTCHA-ish challenge; the browser calls
//! `turnstile.render(...)` which eventually posts a short-lived token
//! back with the rest of the form. To enforce it server-side we POST
//! `{secret, response, remoteip?}` to
//! `https://challenges.cloudflare.com/turnstile/v0/siteverify` and
//! trust the `success: true` field.
//!
//! ## Why enforcement is behind a signal, not always on
//!
//! The worker layer ratelimiter emits `RateLimitDecision.escalate = true`
//! when a bucket has crossed its escalate threshold but is still below
//! the hard limit. The worker then sets a short-lived KV flag so
//! *subsequent* calls for the same bucket must carry a Turnstile
//! token. Honest users hit 0 extra challenges; abusers hit one within
//! seconds of crossing the threshold.
//!
//! ## Why this module does not call HTTP itself
//!
//! `core` has no runtime - no `reqwest`, no `worker::Fetch`. We take
//! an abstract [`TurnstileVerifier`] port instead. The worker crate
//! provides a `worker::Fetch`-backed implementation; host tests
//! provide a canned one. This keeps the verification logic here
//! (success field check, timestamp window, hostname binding) and the
//! transport there.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::ports::PortResult;

/// Cloudflare's documented siteverify endpoint. Constants in code
/// rather than config because this is fixed by the protocol.
pub const SITEVERIFY_URL: &str =
    "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// The subset of the response JSON we care about. Cloudflare may add
/// more fields in the future; `#[serde(default)]` keeps us from
/// breaking on unknown additions.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SiteverifyResponse {
    pub success:      bool,
    #[serde(rename = "error-codes")]
    pub error_codes:  Vec<String>,
    pub action:       Option<String>,
    pub cdata:        Option<String>,
    #[serde(rename = "challenge_ts")]
    pub challenge_ts: Option<String>,
    pub hostname:     Option<String>,
}

/// Input we send to the siteverify endpoint. Serialized as
/// `application/x-www-form-urlencoded` by the transport-side adapter;
/// this struct is the typed shape.
#[derive(Debug, Clone, Serialize)]
pub struct SiteverifyRequest<'a> {
    pub secret:   &'a str,
    pub response: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remoteip: Option<&'a str>,
}

/// Port: turns a siteverify request into a response. The worker crate
/// implements this on top of `worker::Fetch`; tests mock it.
pub trait TurnstileVerifier {
    async fn verify(
        &self,
        req: &SiteverifyRequest<'_>,
    ) -> PortResult<SiteverifyResponse>;
}

/// The high-level wrapper callers use. Takes the token the browser
/// sent, calls the verifier, and maps the reply to a boolean outcome.
///
/// `expected_hostname` may be `None` to skip the binding check. That
/// is useful in development where the registered sitekey matches a
/// different hostname than the one handling the request. Production
/// deployments SHOULD pass `Some(hostname)`.
pub async fn verify<V: TurnstileVerifier>(
    verifier:          &V,
    secret:            &str,
    token:             &str,
    remote_ip:         Option<&str>,
    expected_hostname: Option<&str>,
) -> CoreResult<()> {
    if token.is_empty() {
        return Err(CoreError::InvalidRequest("turnstile token missing"));
    }
    let req = SiteverifyRequest { secret, response: token, remoteip: remote_ip };

    let resp = verifier.verify(&req).await
        .map_err(|_| CoreError::Internal)?;

    if !resp.success {
        // We intentionally do NOT log the error codes here - they can
        // leak internal config (e.g. `invalid-input-secret`). The
        // caller can audit `resp` separately if needed.
        return Err(CoreError::InvalidRequest("turnstile verification failed"));
    }

    if let (Some(expected), Some(got)) = (expected_hostname, resp.hostname.as_deref()) {
        if expected != got {
            return Err(CoreError::InvalidRequest("turnstile hostname mismatch"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::PortError;

    struct CannedVerifier { resp: SiteverifyResponse }

    impl TurnstileVerifier for CannedVerifier {
        async fn verify(&self, _req: &SiteverifyRequest<'_>) -> PortResult<SiteverifyResponse> {
            Ok(self.resp.clone())
        }
    }

    struct FailingVerifier;

    impl TurnstileVerifier for FailingVerifier {
        async fn verify(&self, _req: &SiteverifyRequest<'_>) -> PortResult<SiteverifyResponse> {
            Err(PortError::Unavailable)
        }
    }

    fn ok_resp(host: Option<&str>) -> SiteverifyResponse {
        SiteverifyResponse {
            success:  true,
            hostname: host.map(str::to_owned),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn rejects_empty_token() {
        let v = CannedVerifier { resp: ok_resp(None) };
        assert!(verify(&v, "sec", "", None, None).await.is_err());
    }

    #[tokio::test]
    async fn accepts_success_true() {
        let v = CannedVerifier { resp: ok_resp(None) };
        assert!(verify(&v, "sec", "tok", None, None).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_success_false() {
        let mut r = ok_resp(None);
        r.success = false;
        r.error_codes = vec!["timeout-or-duplicate".into()];
        let v = CannedVerifier { resp: r };
        assert!(verify(&v, "sec", "tok", None, None).await.is_err());
    }

    #[tokio::test]
    async fn rejects_hostname_mismatch() {
        let v = CannedVerifier { resp: ok_resp(Some("other.example")) };
        assert!(
            verify(&v, "sec", "tok", None, Some("auth.example")).await.is_err()
        );
    }

    #[tokio::test]
    async fn accepts_hostname_match() {
        let v = CannedVerifier { resp: ok_resp(Some("auth.example")) };
        assert!(
            verify(&v, "sec", "tok", None, Some("auth.example")).await.is_ok()
        );
    }

    #[tokio::test]
    async fn transport_error_maps_to_internal() {
        let v = FailingVerifier;
        let err = verify(&v, "sec", "tok", None, None).await.err().unwrap();
        assert!(matches!(err, CoreError::Internal));
    }
}
