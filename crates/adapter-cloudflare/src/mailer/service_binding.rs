//! Mailer adapter that delivers via a Cloudflare service binding.
//!
//! cesauth posts a JSON envelope to a binding named `MAGIC_LINK_MAILER`.
//! The operator supplies the mail worker at the other end; cesauth only
//! defines the contract (the JSON body shape).
//!
//! ## wrangler.toml
//!
//! ```toml
//! [[services]]
//! binding     = "MAGIC_LINK_MAILER"
//! service     = "your-mail-worker"
//! environment = "production"
//! ```
//!
//! ## Envelope
//!
//! ```json
//! {
//!   "recipient":  "user@example.com",
//!   "handle":     "handle_abc123",
//!   "code":       "ABCD1234",
//!   "locale":     "ja",
//!   "tenant_id":  "tenant_xyz",
//!   "reason":     "initial_auth"
//! }
//! ```
//!
//! The mail worker receives this envelope and is responsible for rendering
//! and sending the email. cesauth considers delivery successful when the
//! worker returns HTTP 2xx. 4xx → `Permanent`; 5xx / timeout → `Transient`.

use cesauth_core::magic_link::{DeliveryReceipt, MailerError, MagicLinkMailer, MagicLinkPayload};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit};

/// Mailer adapter backed by a Cloudflare service binding.
pub struct ServiceBindingMailer<'a> {
    env: &'a Env,
}

impl<'a> ServiceBindingMailer<'a> {
    /// Construct the adapter. Fails with `MailerError::NotConfigured` if the
    /// `MAGIC_LINK_MAILER` binding is absent.
    pub fn new(env: &'a Env) -> Result<Self, MailerError> {
        // Probe the binding — if it doesn't exist we'd fail at call time
        // anyway, but surfacing here gives a better error kind.
        if env.service("MAGIC_LINK_MAILER").is_err() {
            return Err(MailerError::NotConfigured);
        }
        Ok(Self { env })
    }
}

impl MagicLinkMailer for ServiceBindingMailer<'_> {
    async fn send(
        &self,
        payload: &MagicLinkPayload<'_>,
    ) -> Result<DeliveryReceipt, MailerError> {
        let svc = self.env
            .service("MAGIC_LINK_MAILER")
            .map_err(|_| MailerError::NotConfigured)?;

        let body = serde_json::json!({
            "recipient":  payload.recipient,
            "handle":     payload.handle,
            "code":       payload.code,
            "locale":     payload.locale,
            "tenant_id":  payload.tenant_id,
            "reason":     payload.reason.as_str(),
        })
        .to_string();

        let mut headers = Headers::new();
        headers
            .set("Content-Type", "application/json")
            .map_err(|e| MailerError::Transient(e.to_string()))?;

        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(wasm_bindgen::JsValue::from_str(&body)));

        let req = Request::new_with_init("/", &init)
            .map_err(|e| MailerError::Transient(e.to_string()))?;

        let mut resp = svc
            .fetch_request(req)
            .await
            .map_err(|e| MailerError::Transient(e.to_string()))?;

        let status = resp.status_code();
        if status >= 200 && status < 300 {
            let now = worker::Date::now().as_millis() as i64 / 1000;
            // Provider message ID from response header if present.
            let provider_msg_id = resp
                .headers()
                .get("X-Message-Id")
                .ok()
                .flatten();
            Ok(DeliveryReceipt {
                provider_message_id: provider_msg_id,
                queued_at_unix: now,
            })
        } else if status >= 400 && status < 500 {
            let detail = resp.text().await.unwrap_or_default();
            Err(MailerError::Permanent(format!("service binding HTTP {status}: {detail}")))
        } else {
            let detail = resp.text().await.unwrap_or_default();
            Err(MailerError::Transient(format!("service binding HTTP {status}: {detail}")))
        }
    }
}
