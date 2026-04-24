//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

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
