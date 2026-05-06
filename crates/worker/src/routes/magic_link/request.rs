//! `POST /magic-link/request` handler.

use cesauth_cf::ports::store::{CloudflareAuthChallengeStore, CloudflareRateLimitStore};
use cesauth_core::magic_link;
use cesauth_core::ports::store::{AuthChallengeStore, Challenge, RateLimitStore};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::csrf;
use crate::error::oauth_error_response;
use crate::log::{self, Category, Level};

use super::{
    enforce_turnstile, flag_turnstile_required, MAIL_REQUEST_ESCALATE, MAIL_REQUEST_LIMIT,
    MAIL_REQUEST_WINDOW_SECS, TURNSTILE_FIELD,
};


#[derive(Debug, Deserialize, Default)]
struct RequestBody {
    email: String,
    /// Optional CSRF token; the login page sets one but non-browser
    /// callers may not. We accept either form.
    #[serde(default)]
    csrf:  Option<String>,
    /// Turnstile widget's response. Only consulted when the bucket's
    /// KV flag says Turnstile is mandatory right now.
    #[serde(default, rename = "cf-turnstile-response")]
    turnstile: Option<String>,
}

pub async fn request<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg = Config::from_env(&ctx.env)?;

    // --- CSRF gate ---------------------------------------------------
    //
    // Only form-encoded submissions are subject to CSRF validation.
    // Cross-origin JSON submits from a browser are gated by the
    // same-origin policy / CORS preflight; an attacker page cannot
    // silently emit an `application/json` POST on the user's behalf.
    // See `crate::csrf` for the threat model.
    //
    // We extract the CSRF cookie here, before consuming the body. The
    // form-decode branch below picks the `csrf` form field and the
    // comparison happens immediately after.
    let content_type = req.headers().get("content-type").ok().flatten();
    let is_form = content_type.as_deref()
        .map(|ct| !ct.contains("application/json"))
        .unwrap_or(true);
    let cookie_csrf: Option<String> = if is_form {
        req.headers().get("cookie").ok().flatten()
            .and_then(|h| csrf::extract_from_cookie_header(&h).map(str::to_owned))
    } else {
        None
    };

    // The login form is `application/x-www-form-urlencoded`; a non-form
    // JSON caller works equally well. We accept both shapes.
    let body: RequestBody = match content_type.as_deref() {
        Some(ct) if ct.contains("application/json") => {
            req.json().await.unwrap_or_default()
        }
        _ => {
            let raw = req.text().await.unwrap_or_default();
            let form: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(raw.as_bytes()).into_owned().collect();
            RequestBody {
                email:     form.get("email").cloned().unwrap_or_default(),
                csrf:      form.get("csrf").cloned(),
                turnstile: form.get(TURNSTILE_FIELD).cloned(),
            }
        }
    };

    if is_form {
        // Both sides must be present. An attacker page cannot set the
        // `__Host-cesauth-csrf` cookie cross-origin (that's the point
        // of HttpOnly + SameSite=Strict), and it cannot read it to
        // echo back in the form. So requiring both to match is the
        // whole guard.
        let submitted   = body.csrf.as_deref().unwrap_or("");
        let from_cookie = cookie_csrf.as_deref().unwrap_or("");
        if !csrf::verify(submitted, from_cookie) {
            log::emit(&cfg.log, Level::Warn, Category::Session,
                "csrf mismatch on /magic-link/request", None);
            return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("csrf"));
        }
    }

    // Reject obviously malformed input early, but do NOT leak whether
    // a given email maps to an existing account: success and failure
    // paths produce the same user-visible response.
    if body.email.trim().is_empty() || !body.email.contains('@') {
        return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("email"));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let bucket = format!("ml:req:{}", body.email.to_ascii_lowercase());

    // If Turnstile is flagged for this bucket, verify BEFORE incurring
    // any database / rate-limit side effect - we do not want abusers
    // to be able to churn rate-limit state by replaying tokens.
    if let Err(e) = enforce_turnstile(&ctx.env, &cfg, &bucket, body.turnstile.as_deref()).await {
        log::emit(&cfg.log, Level::Warn, Category::RateLimit,
            &format!("turnstile enforcement failed: {e:?}"), None);
        return oauth_error_response(&e);
    }

    // Rate limit: per-email bucket. If we ever add per-IP we AND them.
    let rate    = CloudflareRateLimitStore::new(&ctx.env);
    let decision = rate.hit(
        &bucket, now, MAIL_REQUEST_WINDOW_SECS, MAIL_REQUEST_LIMIT, MAIL_REQUEST_ESCALATE,
    ).await
        .map_err(|_| worker::Error::RustError("rate-limit unavailable".into()))?;

    if decision.escalate {
        log::emit(&cfg.log, Level::Warn, Category::RateLimit,
            &format!("escalate /magic-link/request bucket={bucket}"), None);
        flag_turnstile_required(&ctx.env, &bucket, MAIL_REQUEST_WINDOW_SECS).await;
    }

    if !decision.allowed {
        // Still respond indistinguishably to the happy path to avoid
        // revealing that this email was the one being probed. A 200
        // with the "check your inbox" page is correct - we just don't
        // send mail.
        return Response::from_html(cesauth_ui::templates::magic_link_sent_page());
    }

    // Mint the OTP. Handle = UUID; user-visible only if we store it
    // as a hidden form field on the "check your inbox" page.
    let issued = match magic_link::issue(now, cfg.magic_link_ttl_secs) {
        Ok(i)  => i,
        Err(e) => return oauth_error_response(&e),
    };
    let handle = Uuid::new_v4().to_string();

    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    let chal  = Challenge::MagicLink {
        email_or_user: body.email.clone(),
        code_hash:     issued.code_hash.clone(),
        attempts:      0,
        expires_at:    issued.expires_at,
    };
    if store.put(&handle, &chal).await.is_err() {
        return oauth_error_response(&cesauth_core::CoreError::Internal);
    }

    // Delivery stub: audit the issuance. The plaintext OTP goes into
    // `reason` ONLY because this handler currently has no real mail
    // provider and we need local dev to work. When production mail is
    // wired in, this line MUST change to log only the handle.
    audit::write_owned(
        &ctx.env, EventKind::MagicLinkIssued,
        Some(body.email.clone()), None,
        Some(format!("dev-delivery handle={handle} code={}", issued.code_plaintext)),
    ).await.ok();

    // Respond with the "check your inbox" page. The form on that page
    // POSTs back to `/magic-link/verify` with `handle` + `code`.
    Response::from_html(cesauth_ui::templates::magic_link_sent_page())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // RequestBody serde — pin contract for the CSRF gate that has
    // protected this route since pre-v0.24.0. v0.24.0's CSRF audit
    // verified the protection is correct; these tests pin the
    // VerifyBody/RequestBody parity so a future refactor of the body
    // shape doesn't silently drop the CSRF field.
    // -----------------------------------------------------------------

    #[test]
    fn requestbody_deserializes_with_csrf_present() {
        let json = r#"{"email":"a@b.test","csrf":"tok"}"#;
        let body: RequestBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.email, "a@b.test");
        assert_eq!(body.csrf.as_deref(), Some("tok"));
    }

    #[test]
    fn requestbody_deserializes_without_csrf() {
        // JSON path doesn't require csrf — the gate skips it for
        // is_form=false. Default Option<String> = None is correct.
        let json = r#"{"email":"a@b.test"}"#;
        let body: RequestBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.email, "a@b.test");
        assert!(body.csrf.is_none());
    }
}
