//! Worker-side implementation of `core::turnstile::TurnstileVerifier`.
//!
//! Posts to the official Cloudflare siteverify endpoint using
//! `worker::Fetch`. The verification logic itself (checking the
//! `success` field, binding the hostname, etc.) lives in `core`;
//! this module is just the transport.

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::turnstile::{SITEVERIFY_URL, SiteverifyRequest, SiteverifyResponse, TurnstileVerifier};
use worker::{Fetch, Headers, Method, Request, RequestInit};

/// The HTTP-fetch-backed verifier. Stateless - construct one per
/// request and drop it.
#[derive(Debug, Default)]
pub struct HttpTurnstileVerifier;

impl TurnstileVerifier for HttpTurnstileVerifier {
    async fn verify(&self, req: &SiteverifyRequest<'_>) -> PortResult<SiteverifyResponse> {
        // form-urlencoded body. Cloudflare's endpoint accepts both
        // form and JSON; we stick to the documented form encoding.
        let mut pairs: Vec<(&str, &str)> = vec![
            ("secret",   req.secret),
            ("response", req.response),
        ];
        if let Some(ip) = req.remoteip {
            pairs.push(("remoteip", ip));
        }
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs.iter().map(|(k, v)| (*k, *v)))
            .finish();

        let headers = Headers::new();
        headers.set("content-type", "application/x-www-form-urlencoded")
            .map_err(|_| PortError::Unavailable)?;

        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(body.into()));

        let req = Request::new_with_init(SITEVERIFY_URL, &init)
            .map_err(|_| PortError::Unavailable)?;
        let mut resp = Fetch::Request(req).send().await
            .map_err(|_| PortError::Unavailable)?;

        let parsed: SiteverifyResponse = resp.json().await
            .map_err(|_| PortError::Unavailable)?;
        Ok(parsed)
    }
}
