//! `POST /magic-link/verify` handler.

use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_cf::ports::store::{CloudflareAuthChallengeStore, CloudflareRateLimitStore};
use cesauth_core::magic_link;
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::ports::store::{AuthChallengeStore, AuthMethod, Challenge, RateLimitStore};
use cesauth_core::types::{User, UserStatus};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Env, Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::csrf;
use crate::error::oauth_error_response;
use crate::post_auth;

use super::{
    enforce_turnstile, flag_turnstile_required, MAIL_VERIFY_ESCALATE, MAIL_VERIFY_LIMIT,
    MAIL_VERIFY_WINDOW_SECS, TURNSTILE_FIELD,
};

// ── RFC 074 conflated messages, as decision functions (RFC 155) ──────────────
//
// RFC 074 requires that `/magic-link/verify` not reveal which stage failed.
// It was already implemented correctly — these two message-selection
// functions are the whole implementation of that requirement — but nothing
// asserted it: a future split (the "most natural refactor in the world",
// RFC 155) would reintroduce the oracle with no test failing. Asserted
// against these functions directly, not the rendered response, so the test
// fails on a *behaviour* change and survives a *rendering* one (RFC 143's
// `decide_verify_*` split is the precedent for where this boundary goes).

/// `cesauth_core::magic_link::verify` distinguishes an expired code from a
/// wrong one (`CoreError::MagicLinkExpired` vs `::MagicLinkMismatch`) —
/// this function is where that distinction is deliberately thrown away.
/// Both variants must render the identical message, so an attacker
/// submitting a wrong code cannot learn whether it merely expired.
fn incorrect_or_expired_code_message(_err: &cesauth_core::CoreError) -> &'static str {
    "Incorrect or expired code. Please check your email and try again."
}

/// The two ways a challenge lookup can fail before a code is even checked:
/// the handle doesn't resolve to a row at all (`peek` returns `None`), or
/// it resolves to a row of the wrong `Challenge` variant. Both must render
/// the identical message — the handle's mere non-existence must not be
/// distinguishable from "it existed and got used already".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChallengeLookupFailure {
    NotFoundOrAlreadyTaken,
    WrongChallengeVariant,
}

fn challenge_lookup_failure_message(_failure: ChallengeLookupFailure) -> &'static str {
    "This magic link has expired or was already used. Please request a new one."
}

// ── Error response helpers ────────────────────────────────────────────────────

/// Re-render the verify form with an inline error so the user can retry.
/// Used for *retriable* failures (wrong code, rate limit). The CSRF cookie
/// already set by `/magic-link/request` is still valid; we just generate a
/// fresh token for the re-rendered form.
///
/// **RFC 150.** Before this, nothing here set a render nonce, so the
/// template's embedded `nonce` attribute (and the security-headers
/// middleware's CSP, which reads the same global back) carried whatever
/// an *earlier, unrelated* request on this isolate happened to leave
/// behind — measured live, two unrelated requests on the same warm
/// isolate sharing one nonce. `render_body_with_nonce` (RFC 150, shared
/// with every other HTML responder in this crate) mints a fresh one
/// first.
fn form_retry(handle: &str, error_msg: &str, req: &Request) -> Result<Response> {
    let locale = crate::i18n::resolve_locale(req);
    let csrf_token = csrf::mint().unwrap_or_default();
    let set_cookie = csrf::set_cookie_header(&csrf_token);
    let html = match crate::routes::admin::console::render::render_body_with_nonce(|| {
        cesauth_frontend::templates::magic_link_sent_page_for(
            handle, &csrf_token, Some(error_msg), locale,
        )
    }) {
        Ok(h)  => h,
        Err(_) => {
            worker::console_error!("csp_nonce_failure in magic_link::verify::form_retry");
            return Response::error("service temporarily unavailable", 500);
        }
    };
    let mut resp = Response::from_html(html)?;
    resp.headers_mut().append("set-cookie", &set_cookie).ok();
    Ok(resp)
}

/// Render a terminal HTML error page for *non-retriable* failures (expired
/// link, CSRF mismatch, internal errors). The user must request a new link.
///
/// **RFC 150.** Same fix as `form_retry` above — mints a fresh nonce via
/// `render_body_with_nonce` before rendering, instead of inheriting
/// whatever an earlier request left in the render-context global.
fn html_terminal_error(title: &str, detail: &str, req: &Request) -> Result<Response> {
    let locale = crate::i18n::resolve_locale(req);
    let html = match crate::routes::admin::console::render::render_body_with_nonce(|| {
        cesauth_frontend::templates::error_page_for(title, detail, locale)
    }) {
        Ok(h)  => h,
        Err(_) => {
            worker::console_error!("csp_nonce_failure in magic_link::verify::html_terminal_error");
            return Response::error("service temporarily unavailable", 500);
        }
    };
    let mut resp = Response::from_html(html)?.with_status(400);
    let _ = resp.headers_mut().set("cache-control", "no-store");
    Ok(resp)
}


#[derive(Debug, Deserialize, Default)]
struct VerifyBody {
    handle: String,
    code:   String,
    #[serde(default)]
    csrf:   String,
    #[serde(default, rename = "cf-turnstile-response")]
    turnstile: Option<String>,
}

pub async fn verify<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    // Grab the cookie header before we consume the body. We need
    // both the pending-authorize handle (OAuth flow) AND the full
    // header (so complete_auth can read login_next).
    let cookie_header_owned = req.headers().get("cookie").ok().flatten();
    let pending = cookie_header_owned.as_deref()
        .and_then(|h| post_auth::extract_pending_handle(h).map(str::to_owned));

    // Snapshot the CSRF cookie + content-type before body consumption.
    // The form path will compare submitted token against this; the JSON
    // path is exempt (CORS preflight is the defense, same pattern as
    // the OWASP "Use of Custom Request Headers" mitigation).
    let csrf_from_cookie = req.headers().get("cookie").ok().flatten()
        .and_then(|h| csrf::extract_from_cookie_header(&h).map(str::to_owned));
    let is_json = matches!(
        req.headers().get("content-type").ok().flatten().as_deref(),
        Some(ct) if ct.contains("application/json")
    );

    let body: VerifyBody = if is_json {
        req.json().await.unwrap_or_default()
    } else {
        let raw = req.text().await.unwrap_or_default();
        let form: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(raw.as_bytes()).into_owned().collect();
        VerifyBody {
            handle:    form.get("handle").cloned().unwrap_or_default(),
            code:      form.get("code").cloned().unwrap_or_default(),
            csrf:      form.get("csrf").cloned().unwrap_or_default(),
            turnstile: form.get(TURNSTILE_FIELD).cloned(),
        }
    };

    // CSRF check on the form-encoded path.
    if !is_json {
        let cookie = csrf_from_cookie.as_deref().unwrap_or("");
        if !csrf::verify(&body.csrf, cookie) {
            audit::write_owned(
                &ctx.env, EventKind::MagicLinkFailed,
                None, None, Some("csrf_mismatch".into()),
            ).await.ok();
            // Non-retriable: the CSRF cookie / submitted token mismatch means
            // the session state is invalid. Ask the user to restart.
            return html_terminal_error(
                "Verification failed",
                "Your session may have expired. Please request a new magic link.",
                &req,
            );
        }
    }

    if body.handle.is_empty() || body.code.is_empty() {
        return if is_json {
            oauth_error_response(&cesauth_core::CoreError::InvalidRequest("handle or code"))
        } else {
            html_terminal_error("Invalid request", "Missing verification code or handle.", &req)
        };
    }

    let cfg = Config::from_env(&ctx.env)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let bucket = format!("ml:verify:{}", body.handle);

    // Turnstile gate (same logic as /request).
    if let Err(e) = enforce_turnstile(&ctx.env, &cfg, &bucket, body.turnstile.as_deref()).await {
        return if is_json {
            oauth_error_response(&e)
        } else {
            html_terminal_error(
                "Verification required",
                "Please complete the security challenge and try again.",
                &req,
            )
        };
    }

    // Per-handle rate limit for verify.
    let rate   = CloudflareRateLimitStore::new(&ctx.env);
    let decision = rate.hit(
        &bucket, now, MAIL_VERIFY_WINDOW_SECS, MAIL_VERIFY_LIMIT, MAIL_VERIFY_ESCALATE,
    ).await
        .map_err(|_| worker::Error::RustError("rate-limit unavailable".into()))?;

    if decision.escalate {
        flag_turnstile_required(&ctx.env, &bucket, MAIL_VERIFY_WINDOW_SECS).await;
    }

    if !decision.allowed {
        return if is_json {
            oauth_error_response(&cesauth_core::CoreError::MagicLinkMismatch)
        } else {
            form_retry(
                &body.handle,
                "Too many attempts. Please wait a moment and try again.",
                &req,
            )
        };
    }

    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    let _ = store.bump_magic_link_attempts(&cesauth_core::types::ChallengeHandle::from_storage(&body.handle), now).await;

    let chal = match store.peek(&cesauth_core::types::ChallengeHandle::from_storage(&body.handle), now).await {
        Ok(Some(c)) => c,
        _ => return if is_json {
            oauth_error_response(&cesauth_core::CoreError::MagicLinkMismatch)
        } else {
            html_terminal_error(
                "Link expired",
                challenge_lookup_failure_message(ChallengeLookupFailure::NotFoundOrAlreadyTaken),
                &req,
            )
        },
    };

    let (email, code_hash, expires_at) = match chal {
        Challenge::MagicLink { email_or_user, code_hash, expires_at, .. } =>
            (email_or_user, code_hash, expires_at),
        _ => return if is_json {
            oauth_error_response(&cesauth_core::CoreError::MagicLinkMismatch)
        } else {
            html_terminal_error(
                "Link expired",
                challenge_lookup_failure_message(ChallengeLookupFailure::WrongChallengeVariant),
                &req,
            )
        },
    };

    if let Err(e) = magic_link::verify(&body.code, &code_hash, now, expires_at) {
        audit::write_owned(
            &ctx.env, EventKind::MagicLinkFailed,
            Some(email), None, Some(format!("{e:?}")),
        ).await.ok();
        return if is_json {
            oauth_error_response(&e)
        } else {
            // Retriable: user may have mistyped the code; re-render the form.
            form_retry(
                &body.handle,
                incorrect_or_expired_code_message(&e),
                &req,
            )
        };
    }

    // Consume the challenge only on verified success.
    let _ = store.take(&cesauth_core::types::ChallengeHandle::from_storage(&body.handle), now).await;
    audit::write_owned(
        &ctx.env, EventKind::MagicLinkVerified,
        Some(email.clone()), None, None,
    ).await.ok();

    // Resolve (or create) the user. Magic-link is the self-service
    // signup path: first-login mints a User with `email_verified=true`
    // because delivery of the one-time code *is* the verification.
    let user_id = match resolve_or_create_user(&ctx.env, &email, now).await {
        Ok(id)  => id,
        Err(e)  => return if is_json {
            oauth_error_response(&e)
        } else {
            html_terminal_error("Sign-in failed", "Unable to complete sign-in. Please try again.", &req)
        },
    };

    post_auth::complete_auth(
        &ctx.env, &cfg, &user_id, AuthMethod::MagicLink,
        pending.as_deref(), cookie_header_owned.as_deref(),
    ).await
}

/// Look up by email; create if not found. On conflict we do one retry
/// (the conflict means a concurrent request created the same user) and
/// re-query. Returns the resolved user_id.
///
/// **email_verified update**: if the existing user has
/// `email_verified=false` (created by an admin via legacy `POST
/// /admin/users`, for example), a successful magic-link verify
/// flips it to `true`. The OTP delivery is itself proof of email
/// control, so the column should reflect that. New users created
/// via this path always start with `email_verified=true`. See
/// `docs/src/expert/email-verification-audit.md` for the full
/// per-path table.
async fn resolve_or_create_user(
    env:   &Env,
    email: &str,
    now:   i64,
) -> core::result::Result<String, cesauth_core::CoreError> {
    let repo = CloudflareUserRepository::new(env);

    if let Ok(Some(mut u)) = repo.find_by_email(email).await {
        // Existing user: ensure email_verified reflects this
        // successful OTP delivery. Skip the UPDATE if already true
        // to avoid an unnecessary D1 round-trip on the hot login
        // path.
        if !u.email_verified {
            u.email_verified = true;
            u.updated_at     = now;
            // Best-effort. A storage failure here is not fatal —
            // the user still gets a valid session; the next
            // successful login will retry the flip.
            let _ = repo.update(&u).await;
        }
        return Ok(u.id);
    }

    let new = User {
        id:             Uuid::new_v4().to_string(),
        // Magic-link self-signup goes into the bootstrap tenant in
        // 0.4.x. Multi-tenant signup (where the user picks/lands on
        // a tenant first) is a 0.7.0+ design pass.
        tenant_id:      cesauth_core::tenancy::DEFAULT_TENANT_ID.to_owned(),
        email:          Some(email.to_owned()),
        email_verified: true,
        display_name:   None,
        account_type:   cesauth_core::tenancy::AccountType::HumanUser,
        status:         UserStatus::Active,
        created_at:     now,
        updated_at:     now,
    };

    match repo.create(&new).await {
        Ok(()) => Ok(new.id),
        Err(_) => {
            // Conflict (or any other failure) - retry the lookup once
            // in case a concurrent request won the race.
            match repo.find_by_email(email).await {
                Ok(Some(u)) => Ok(u.id),
                _           => Err(cesauth_core::CoreError::Internal),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // RFC 074 / RFC 155 — the conflated failure messages, asserted
    // against the decision functions the handler actually calls, not a
    // rendered response. A future edit that distinguishes either pair
    // (e.g. matching on `CoreError`'s variant to give a more specific
    // message) fails these tests directly, rather than only being
    // caught by eyeballing a diff.
    // -----------------------------------------------------------------

    #[test]
    fn rfc074_expired_and_mismatch_render_the_identical_code_message() {
        let expired  = incorrect_or_expired_code_message(&cesauth_core::CoreError::MagicLinkExpired);
        let mismatch = incorrect_or_expired_code_message(&cesauth_core::CoreError::MagicLinkMismatch);
        assert_eq!(expired, mismatch,
            "a wrong code and an expired code must be indistinguishable to the caller");
        assert_eq!(expired, "Incorrect or expired code. Please check your email and try again.");
    }

    #[test]
    fn rfc074_missing_and_wrong_variant_render_the_identical_challenge_message() {
        let not_found = challenge_lookup_failure_message(ChallengeLookupFailure::NotFoundOrAlreadyTaken);
        let wrong_variant = challenge_lookup_failure_message(ChallengeLookupFailure::WrongChallengeVariant);
        assert_eq!(not_found, wrong_variant,
            "a handle that never existed must be indistinguishable from one that was already used");
        assert_eq!(not_found, "This magic link has expired or was already used. Please request a new one.");
    }

    // -----------------------------------------------------------------
    // VerifyBody deserialization — added in v0.24.0 alongside the
    // CSRF gap fill. Pins that:
    //   - The `csrf` field defaults to "" when missing (JSON callers).
    //   - The `csrf` field is correctly read from form-encoded input.
    //   - JSON callers can omit `csrf` without serde error.
    //
    // The CSRF gate logic itself lives in `crate::csrf::verify` and
    // is tested in `crate::csrf::tests`. These tests pin the
    // *contract* between the form/JSON parser and the gate: an
    // empty submitted token must reach the gate (which then rejects
    // it via `csrf::verify`'s "empty input fails" branch).
    // -----------------------------------------------------------------

    #[test]
    fn verifybody_deserializes_with_csrf_present() {
        let json = r#"{"handle":"h-1","code":"123456","csrf":"tok"}"#;
        let body: VerifyBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.handle, "h-1");
        assert_eq!(body.code, "123456");
        assert_eq!(body.csrf, "tok");
    }

    #[test]
    fn verifybody_deserializes_with_csrf_missing() {
        // JSON callers (curl-style API consumers) don't send csrf.
        // Default-empty is correct and the worker-side gate skips
        // CSRF validation for is_json=true. So an empty csrf reaching
        // the JSON path is harmless; an empty csrf reaching the form
        // path is rejected by `csrf::verify`.
        let json = r#"{"handle":"h-1","code":"123456"}"#;
        let body: VerifyBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.handle, "h-1");
        assert_eq!(body.csrf, "",
            "missing csrf field must default to empty string");
    }

    #[test]
    fn verifybody_form_path_constructs_with_explicit_csrf() {
        // Mirror the form-decode branch in `verify()` — it builds a
        // VerifyBody from a form HashMap. Pin that `csrf:""` is the
        // representation when the form has no csrf field.
        let mut form = std::collections::HashMap::new();
        form.insert("handle".to_owned(), "h-1".to_owned());
        form.insert("code".to_owned(), "123456".to_owned());
        // No csrf in the form (broken form template). The handler
        // builds with `form.get("csrf").cloned().unwrap_or_default()`.
        let body = VerifyBody {
            handle:    form.get("handle").cloned().unwrap_or_default(),
            code:      form.get("code").cloned().unwrap_or_default(),
            csrf:      form.get("csrf").cloned().unwrap_or_default(),
            turnstile: None,
        };
        assert_eq!(body.csrf, "");
        // And the gate's `csrf::verify("", _)` returns false. Pin
        // that here so a regression in csrf::verify (e.g. accepting
        // empty as a "no token submitted" no-op) is caught.
        assert!(!crate::csrf::verify(&body.csrf, "any-cookie-value"));
    }

    #[test]
    fn verifybody_csrf_value_carries_through_form_decode() {
        // Form-decode path: simulate `form.get("csrf")` returning
        // a non-empty value.
        let mut form = std::collections::HashMap::new();
        form.insert("csrf".to_owned(), "abc".to_owned());
        let body = VerifyBody {
            handle:    "h-1".to_owned(),
            code:      "123456".to_owned(),
            csrf:      form.get("csrf").cloned().unwrap_or_default(),
            turnstile: None,
        };
        assert_eq!(body.csrf, "abc");
        // And csrf::verify accepts when both sides match.
        assert!(crate::csrf::verify(&body.csrf, "abc"));
    }
}
