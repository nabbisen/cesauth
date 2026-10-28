//! `POST /magic-link/request` handler.

use cesauth_cf::ports::repo::CloudflareInvitationRepository;
use cesauth_cf::ports::store::{CloudflareAuthChallengeStore, CloudflareRateLimitStore};
use cesauth_core::invitation::{self, InvitationVerifyOutcome};
use cesauth_core::magic_link::{self, MagicLinkMailer, MagicLinkPayload, MagicLinkReason};
use cesauth_core::ports::store::{AuthChallengeStore, Challenge, RateLimitStore};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result, RouteContext};

use crate::adapter::mailer as mailer_factory;
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
    /// **RFC 153.** Present when this request continues an invitation
    /// acceptance (set by the hidden field on `accept_submit`'s
    /// continue-to-sign-in page). Re-verified against the invitation store
    /// below before being trusted — a client can send any string here.
    #[serde(default)]
    invite_id: Option<String>,
}

/// **RFC 153.** Terminal error for a form-encoded request whose attached
/// `invite_id` did not re-verify as `Valid`. Mirrors
/// `magic_link::verify::html_terminal_error`'s shape (same template, same
/// nonce discipline) — not shared with it directly, since the two files
/// have no existing shared helper module and introducing one for a single
/// call site each would be more machinery than the duplication it avoids.
fn invite_terminal_error(req: &Request) -> Result<Response> {
    let locale = crate::i18n::resolve_locale(req);
    let html = match crate::routes::admin::console::render::render_body_with_nonce(|| {
        cesauth_frontend::templates::error_page_for(
            "Invitation no longer valid",
            "This invitation has expired, was revoked, or was already used. Please ask your admin for a new one.",
            locale,
        )
    }) {
        Ok(h)  => h,
        Err(_) => {
            worker::console_error!("csp_nonce_failure in magic_link::request (invalid invite_id)");
            return Response::error("service temporarily unavailable", 500);
        }
    };
    let mut resp = Response::from_html(html)?.with_status(400);
    let _ = resp.headers_mut().set("cache-control", "no-store");
    Ok(resp)
}

pub async fn request<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg = Config::from_env(&ctx.env)?;

    // **v0.47.0** — negotiate locale once for any
    // "check your inbox" page render that follows.
    // The two render sites below (rate-limit fallback
    // and the success path) both honor it.
    let locale = crate::i18n::resolve_locale(&req);

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
                invite_id: form.get("invite_id").cloned().filter(|s| !s.is_empty()),
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

    // **RFC 153.** Re-verify an attached `invite_id` before parking a
    // challenge for it — the client supplied this string, and the only
    // other place it was supposed to come from (`accept_submit`'s own
    // hidden field) already checked it, but trusting that without
    // re-checking here would mean the first check was decorative.
    // Unlike a wrong code or email (handled identically to avoid an
    // enumeration oracle), an invitation that is not currently `Valid`
    // gets a distinct, honest message: the user has made no commitment
    // yet (no OTP sent), so there is nothing to lose by telling them
    // plainly rather than silently sending an ordinary sign-in code that
    // would not actually complete their invitation.
    if let Some(id) = body.invite_id.as_deref().filter(|s| !s.is_empty()) {
        let inv_repo = CloudflareInvitationRepository::new(&ctx.env);
        match invitation::verify_invitation(&inv_repo, id, &body.email, now).await {
            Ok(InvitationVerifyOutcome::Valid(_)) => {}
            _ => return if is_form {
                invite_terminal_error(&req)
            } else {
                oauth_error_response(&cesauth_core::CoreError::InvalidRequest("invite_id"))
            },
        }
    }

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
        //
        // Render placeholder values for the form fields. A user who
        // typed an OTP into this fake form would get a "verification
        // failed" response from /magic-link/verify, which is the same
        // outcome an expired/invalid handle produces — no information
        // leak about whether the address was probed-as-rate-limited
        // vs. legit-but-bad-OTP.
        let placeholder_handle = Uuid::new_v4().to_string();
        let placeholder_csrf   = cookie_csrf.as_deref().unwrap_or("");
        // RFC 150: this early return used to render without minting a
        // nonce first — the only one of this function's two render sites
        // (the other is at the end, 91 lines below) that didn't. Same
        // shared core as every other fix in this RFC.
        let html = match crate::routes::admin::console::render::render_body_with_nonce(|| {
            cesauth_frontend::templates::magic_link_sent_page_for(&placeholder_handle, placeholder_csrf, None, locale)
        }) {
            Ok(h)  => h,
            Err(_) => {
                worker::console_error!("csp_nonce_failure in magic_link::request (rate-limited path)");
                return Response::error("service temporarily unavailable", 500);
            }
        };
        return Response::from_html(html);
    }

    // Mint the OTP. Handle = UUID; user-visible only if we store it
    // as a hidden form field on the "check your inbox" page.
    let issued = match magic_link::issue(now, cfg.magic_link_ttl_secs) {
        Ok(i)  => i,
        Err(e) => return oauth_error_response(&e),
    };
    let handle = cesauth_core::types::ChallengeHandle::mint();

    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    let chal  = Challenge::MagicLink {
        email_or_user: body.email.clone(),
        code_hash:     issued.code_hash.clone(),
        attempts:      0,
        expires_at:    issued.expires_at,
        invite_id:     body.invite_id.clone(),
    };
    if store.put(&handle, &chal).await.is_err() {
        return oauth_error_response(&cesauth_core::CoreError::Internal);
    }

    // Audit the issuance with handle only. The plaintext OTP MUST NOT
    // appear in the audit log (RFC 008, v0.50.3 — "no token material
    // ever" invariant). Real delivery is via MagicLinkMailer (RFC 010).
    audit::write_owned(
        &ctx.env, EventKind::MagicLinkIssued,
        Some(body.email.clone()), None,
        Some(format!("handle={handle}")),
    ).await.ok();

    // **v0.51.0 (RFC 010)** — deliver the OTP via the mailer port.
    // The factory selects the appropriate adapter from env.
    // On failure: audit the failure kind, log at Error, but still
    // return the normal success-shaped response — differential responses
    // would let an attacker enumerate valid email addresses.
    let mailer = mailer_factory::from_env(&ctx.env);
    let payload = MagicLinkPayload {
        recipient: &body.email,
        handle:    handle.as_str(),
        code:      &issued.delivery_payload,
        locale:    crate::i18n::locale_str(locale),
        tenant_id: None,
        reason:    MagicLinkReason::InitialAuth,
    };
    match mailer.send(&payload).await {
        Ok(receipt) => {
            audit::write_owned(
                &ctx.env, EventKind::MagicLinkDelivered,
                Some(body.email.clone()), None,
                Some(format!(
                    "handle={handle} provider_msg_id={}",
                    receipt.provider_message_id.as_deref().unwrap_or("-")
                )),
            ).await.ok();
        }
        Err(e) => {
            audit::write_owned(
                &ctx.env, EventKind::MagicLinkDeliveryFailed,
                Some(body.email.clone()), None,
                Some(format!("handle={handle} kind={}", e.audit_kind())),
            ).await.ok();
            log::emit(&cfg.log, Level::Error, Category::Magic,
                // RFC 030: log only the error kind, not the full error detail.
                // Full detail (provider response body) could contain the OTP
                // if the provider echoes back the request body on error.
                &format!("magic_link mailer failed: kind={}", e.audit_kind()),
                Some(&body.email));
            // Fall through — same response either way.
        }
    }

    // Respond with the "check your inbox" page. The form on that page
    // POSTs back to `/magic-link/verify` with `handle` + `code` +
    // `csrf`. The handle is the AuthChallenge handle just minted; the
    // csrf token is the existing cookie value (set by /login or
    // /authorize earlier in the flow).
    let csrf_for_form = cookie_csrf.as_deref().unwrap_or("");
    // RFC 006 (v0.52.0): generate per-request CSP nonce
    let csp_nonce = match cesauth_core::security_headers::CspNonce::generate() {
        Ok(n) => n,
        Err(_) => {
            crate::audit::write_owned(
                &ctx.env, crate::audit::EventKind::CsrfRngFailure,
                None, None, Some("csp_nonce_failure".to_owned()),
            ).await.ok();
            return Response::error("service temporarily unavailable", 500);
        }
    };
    cesauth_frontend::set_render_nonce(csp_nonce.as_str());

    Response::from_html(
        cesauth_frontend::templates::magic_link_sent_page_for(handle.as_str(), csrf_for_form, None, locale)
    )
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
