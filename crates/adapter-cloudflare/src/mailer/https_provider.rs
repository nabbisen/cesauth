//! Mailer adapter that POSTs to an operator-supplied HTTPS API.
//!
//! Works with any provider that accepts a JSON POST and Bearer auth —
//! SendGrid, SES (via gateway), Postmark, Resend, Mailgun, etc.
//!
//! ## Required env vars
//!
//! | Variable | Example |
//! |---|---|
//! | `MAILER_PROVIDER_URL` | `https://api.sendgrid.com/v3/mail/send` |
//! | `MAILER_PROVIDER_AUTH_HEADER` | `Bearer SG.xxxx` |
//! | `MAILER_PROVIDER_FROM_ADDRESS` | `noreply@example.com` |
//!
//! ## Optional env vars
//!
//! | Variable | Default | Notes |
//! |---|---|---|
//! | `MAILER_PROVIDER_FROM_NAME` | `""` | Friendly display name |
//!
//! ## Request body
//!
//! The request body is a provider-agnostic JSON envelope:
//!
//! ```json
//! {
//!   "personalizations": [{"to": [{"email": "<recipient>"}]}],
//!   "from": {"email": "<from_address>", "name": "<from_name>"},
//!   "subject": "<subject>",
//!   "content": [{"type": "text/plain", "value": "<body>"}]
//! }
//! ```
//!
//! This shape is compatible with the SendGrid v3 API directly.
//! For other providers, operators may need to set up a thin translation
//! proxy; a full per-provider body builder is a future RFC.
//!
//! ## Timing-attack mitigation
//!
//! The caller uses `waitUntil` to fire the mailer after the HTTP response
//! is already sent. This breaks the timing correlation between delivery
//! success/failure and response latency.

use cesauth_core::magic_link::{
    DeliveryReceipt, MailerError, MagicLinkMailer, MagicLinkPayload, MagicLinkReason,
};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit};

/// Mailer adapter for HTTPS provider APIs.
pub struct HttpsProviderMailer {
    provider_url:    String,
    auth_header:     String,
    from_address:    String,
    from_name:       String,
}

impl HttpsProviderMailer {
    /// Construct from env vars. Returns `Err(NotConfigured)` if any
    /// required var is absent or empty.
    pub fn from_env(env: &Env) -> Result<Self, MailerError> {
        let get = |k: &str| -> Result<String, MailerError> {
            match env.var(k) {
                Ok(v) => {
                    let s = v.to_string();
                    if s.is_empty() {
                        Err(MailerError::NotConfigured)
                    } else {
                        Ok(s)
                    }
                }
                Err(_) => Err(MailerError::NotConfigured),
            }
        };
        Ok(Self {
            provider_url:  get("MAILER_PROVIDER_URL")?,
            auth_header:   get("MAILER_PROVIDER_AUTH_HEADER")?,
            from_address:  get("MAILER_PROVIDER_FROM_ADDRESS")?,
            from_name:     env.var("MAILER_PROVIDER_FROM_NAME")
                              .map(|v| v.to_string())
                              .unwrap_or_default(),
        })
    }

    fn build_subject(&self, payload: &MagicLinkPayload<'_>) -> String {
        // Simple i18n: could be extended to use MessageKey catalog.
        match payload.locale {
            "ja" => "cesauth ログインコード".to_owned(),
            _    => "Your cesauth sign-in code".to_owned(),
        }
    }

    fn build_body(&self, payload: &MagicLinkPayload<'_>) -> String {
        match payload.locale {
            "ja" => format!(
                "以下のコードを使ってサインインしてください。\n\n  {}\n\nこのコードは短時間で有効期限が切れます。\n",
                payload.code
            ),
            _ => format!(
                "Use the following code to sign in to cesauth.\n\n  {}\n\nThis code expires shortly.\n",
                payload.code
            ),
        }
    }
}

impl MagicLinkMailer for HttpsProviderMailer {
    async fn send(
        &self,
        payload: &MagicLinkPayload<'_>,
    ) -> Result<DeliveryReceipt, MailerError> {
        let subject = self.build_subject(payload);
        let body_text = self.build_body(payload);

        // SendGrid v3 compatible envelope.
        let json_body = serde_json::json!({
            "personalizations": [{"to": [{"email": payload.recipient}]}],
            "from": {
                "email": &self.from_address,
                "name":  &self.from_name,
            },
            "subject": subject,
            "content": [{"type": "text/plain", "value": body_text}],
        })
        .to_string();

        let mut headers = Headers::new();
        headers
            .set("Content-Type", "application/json")
            .map_err(|e| MailerError::Transient(e.to_string()))?;
        headers
            .set("Authorization", &self.auth_header)
            .map_err(|e| MailerError::Transient(e.to_string()))?;

        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(wasm_bindgen::JsValue::from_str(&json_body)));

        let req = Request::new_with_init(&self.provider_url, &init)
            .map_err(|e| MailerError::Transient(e.to_string()))?;

        let mut resp = Fetch::Request(req)
            .send()
            .await
            .map_err(|e| MailerError::Transient(e.to_string()))?;

        let status = resp.status_code();
        if status >= 200 && status < 300 {
            let now = worker::Date::now().as_millis() as i64 / 1000;
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
            Err(MailerError::Permanent(format!("provider HTTP {status}: {detail}")))
        } else {
            let detail = resp.text().await.unwrap_or_default();
            Err(MailerError::Transient(format!("provider HTTP {status}: {detail}")))
        }
    }
}

/// Subject line for a reason variant — exported for tests.
pub fn reason_subject_hint(reason: MagicLinkReason) -> &'static str {
    match reason {
        MagicLinkReason::InitialAuth | MagicLinkReason::ReturningUserAuth => "sign-in",
        MagicLinkReason::AnonymousPromote => "account verification",
    }
}
