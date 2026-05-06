//! `/me/security/totp/verify` — TOTP gate prompt after successful
//! Magic Link primary auth.
//!
//! GET renders the prompt page. The user has been redirected here
//! by `complete_auth` after their Magic Link verified — at that
//! point the worker parked a `Challenge::PendingTotp` and set the
//! `__Host-cesauth_totp` cookie. The challenge carries the AR
//! fields inline (no chained handle resolution), the auth_method
//! the user used to get this far, and the attempt counter.
//!
//! POST verifies the submitted 6-digit code. On success:
//! - Take (consume) the `PendingTotp` challenge.
//! - Reconstruct `PendingAr` from the carried fields if any.
//! - Call `complete_auth_post_gate` to start the session and
//!   resume the original flow (mint AuthCode + redirect, or
//!   land on `/`).
//!
//! On failure:
//! - Bump the attempt counter, re-park the challenge.
//! - After `MAX_ATTEMPTS` (5), refuse further attempts: clear
//!   the cookie, redirect to `/login` so the user starts over.
//! - Otherwise re-render the verify page with an inline error.
//!
//! Lost-authenticator path: the form has a separate POST to
//! `/me/security/totp/recover` for single-use recovery codes.
//! That handler lives in the sibling `recover` module.

use cesauth_cf::ports::repo::CloudflareTotpAuthenticatorRepository;
use cesauth_cf::ports::store::CloudflareAuthChallengeStore;
use cesauth_core::ports::store::{AuthChallengeStore, AuthMethod, Challenge};
use cesauth_core::totp::{
    aad_for_id, decrypt_secret, parse_code, verify_with_replay_protection,
};
use cesauth_ui::templates;
use time::OffsetDateTime;
use worker::{Request, Response, Result};

use crate::config::{
    Config, load_totp_encryption_key,
};
use crate::csrf;
use crate::post_auth::{
    self, PendingAr, TOTP_GATE_TTL_SECS, complete_auth_post_gate, extract_totp_handle,
};

/// After this many failed attempts the gate-cookie is cleared and
/// the user is sent back to `/login` to restart. The TOTP secret
/// is unchanged on the server; the only state lost is the
/// in-flight `PendingTotp` challenge.
///
/// This is brute-force friction, not a hard lockout. A determined
/// attacker who has compromised the user's Magic Link primary
/// factor still gets 5 guesses per Magic Link verification — but
/// each Magic Link verification requires a fresh OTP, which costs
/// the attacker a round-trip through the user's email. The
/// economics are unfavorable to the attacker.
const MAX_ATTEMPTS: u32 = 5;

/// Pure decision: has this attempts count reached the lockout
/// threshold? Extracted in v0.31.0 PR-9 so the boundary is
/// testable without standing up a `worker::Env`. Used by
/// [`post_handler`] in the wrong-code branch.
///
/// Test pin: returns `true` for `MAX_ATTEMPTS` and above,
/// `false` below. The first wrong code increments to 1, the
/// fifth to 5, and at `>= MAX_ATTEMPTS` we clear the gate.
fn attempts_exhausted(new_attempts: u32) -> bool {
    new_attempts >= MAX_ATTEMPTS
}

/// Outcome of [`decide_verify_get`].
///
/// Used by `get_handler` to map a peeked challenge state into a
/// concrete response: render the verify page, or clear the gate
/// cookie and bounce to /login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyGetDecision {
    /// Challenge is a live PendingTotp. Handler renders the
    /// verify page with a fresh-or-recycled CSRF token.
    RenderPage,
    /// Challenge missing, expired, wrong variant, or store
    /// errored. Handler clears the `__Host-cesauth_totp` cookie
    /// and 302's to /login.
    StaleGate,
}

/// Pure decision logic for `GET /me/security/totp/verify`.
///
/// `peek` (not `take`) — GET is render-only and the challenge
/// must survive into the POST that follows.
///
/// The handler is responsible for the cookie / handle extraction
/// before this is called (those failure modes return a different
/// kind of redirect — the no-cookie path doesn't need to clear
/// any cookie).
pub async fn decide_verify_get<C>(
    totp_handle: &str,
    challenges:  &C,
) -> VerifyGetDecision
where
    C: AuthChallengeStore + ?Sized,
{
    match challenges.peek(totp_handle).await {
        Ok(Some(Challenge::PendingTotp { .. })) => VerifyGetDecision::RenderPage,
        _ => VerifyGetDecision::StaleGate,
    }
}


/// `GET /me/security/totp/verify` — render the prompt page.
pub async fn get_handler(
    req: Request,
    env: worker::Env,
) -> Result<Response> {
    let cookie_header = match req.headers().get("cookie")? {
        Some(h) => h,
        None    => return crate::routes::me::auth::redirect_to_login(),
    };
    let totp_handle = match extract_totp_handle(&cookie_header) {
        Some(h) if !h.is_empty() => h.to_owned(),
        _ => return crate::routes::me::auth::redirect_to_login(),
    };

    let store = CloudflareAuthChallengeStore::new(&env);
    match decide_verify_get(&totp_handle, &store).await {
        VerifyGetDecision::StaleGate => clear_gate_and_redirect("/login"),
        VerifyGetDecision::RenderPage => {
            // CSRF token: mint or reuse from cookie, set cookie if new.
            let existing = csrf::extract_from_cookie_header(&cookie_header).map(str::to_owned);
            let (token, set_cookie) = match existing {
                Some(t) if !t.is_empty() => (t, None),
                _ => {
                    let t = csrf::mint();
                    let h = csrf::set_cookie_header(&t);
                    (t, Some(h))
                }
            };
            let html = templates::totp_verify_page(&token, None);
            let mut resp = Response::from_html(html)?;
            if let Some(h) = set_cookie {
                resp.headers_mut().append("set-cookie", &h).ok();
            }
            Ok(resp)
        }
    }
}


/// Outcome of [`decide_verify_post`].
///
/// Variants encode "what should happen" in domain terms; the
/// handler maps each to a concrete `worker::Response`. Some
/// variants carry data needed by `complete_auth_post_gate` so the
/// handler can resume the original auth flow without re-reading
/// the (already-consumed) challenge.
///
/// Side effects performed BY the decision:
///
/// - `take` on the challenge store (consumes the gate).
/// - `put` to re-park on `BadCode` (preserves the gate for retry).
/// - `update_last_used_step` on `Success` (replay protection).
///
/// Side effects performed BY the handler (after the decision):
///
/// - `complete_auth_post_gate` on `Success` and `NoUserAuthenticator`.
/// - 302 + cookie clear on `Lockout`, `NoChallenge`.
/// - 200 + page render on `BadCode`.
/// - 4xx / 5xx response codes on the failure variants.
#[derive(Debug)]
pub(crate) enum VerifyPostDecision {
    /// CSRF token didn't match. Handler returns 400. No state
    /// is mutated — the challenge is preserved for a retry.
    CsrfFailure,

    /// `take` returned None / wrong variant / store errored. The
    /// gate is unusable. Handler clears the
    /// `__Host-cesauth_totp` cookie and 302's to /login.
    NoChallenge,

    /// User has no active confirmed authenticator (e.g., admin
    /// disabled it between gate-park and now, or the lookup
    /// races with a v0.30.0 disable flow). The TOTP gate
    /// stops gating. Handler invokes `complete_auth_post_gate`
    /// with these fields. This is a "soft" success outcome.
    NoUserAuthenticator {
        user_id:     String,
        auth_method: AuthMethod,
        ar_fields:   Option<PendingAr>,
    },

    /// `find_active_for_user` raised a storage error. Distinct
    /// from NoUserAuthenticator so the handler can surface a 5xx
    /// rather than silently progressing to post_gate. (A storage
    /// outage is operator-fixable, not a user-flow continuation.)
    StorageError,

    /// Decrypt failed for the user's stored secret. Most plausible
    /// cause: TOTP_ENCRYPTION_KEY rotated without re-enrollment
    /// (ADR-009 §Q5 caveat). Handler returns a 5xx.
    DecryptFailed,

    /// Code verified AND `update_last_used_step` succeeded. The
    /// chain replay-protection state is on disk; safe to resume
    /// the auth flow. Handler invokes `complete_auth_post_gate`
    /// with these fields.
    Success {
        user_id:     String,
        auth_method: AuthMethod,
        ar_fields:   Option<PendingAr>,
    },

    /// Code verified, but `update_last_used_step` failed. Refuse
    /// the login rather than allow a verify whose replay-
    /// protection state didn't make it to disk; the next attempt
    /// will succeed if the failure is transient. Handler returns
    /// a 5xx.
    LastStepUpdateFailed,

    /// Wrong code AND `new_attempts >= MAX_ATTEMPTS`. Gate
    /// locked out. Handler clears the gate cookie + 302's to
    /// /login.
    Lockout,

    /// Wrong code under the lockout threshold. Challenge has
    /// been re-parked with bumped attempts. Handler re-renders
    /// the verify page with an inline error.
    BadCode,

    /// Re-park `put` failed on a wrong-code branch. Handler
    /// surfaces as 5xx.
    RepkFailed,
}

/// Pure-ish decision logic for `POST /me/security/totp/verify`.
///
/// "Pure-ish" because it performs port-level IO (challenge
/// store reads/writes, totp_repo reads/writes) — but those are
/// trait-bounded so tests pass in-memory adapters. No Env
/// touching, no `Response` building.
///
/// Calling order:
///
/// 1. **CSRF first.** Failing CSRF must not consume the
///    challenge — the user can retry with a fresh form.
/// 2. **Challenge take.** Past this point any failure clears
///    the gate cookie regardless.
/// 3. **find_active_for_user.** None → soft success
///    (NoUserAuthenticator); error → StorageError.
/// 4. **Decrypt.** Errors → DecryptFailed.
/// 5. **Verify.** Success → update_last_used_step + return
///    Success; failure → check attempts threshold, either
///    Lockout or re-park + BadCode.
pub(crate) async fn decide_verify_post<C, T>(
    csrf_form:      &str,
    csrf_cookie:    &str,
    submitted_code: &str,
    totp_handle:    &str,
    challenges:     &C,
    totp_repo:      &T,
    encryption_key: &[u8],
    now_unix:       i64,
) -> VerifyPostDecision
where
    C: AuthChallengeStore                            + ?Sized,
    T: cesauth_core::totp::storage::TotpAuthenticatorRepository + ?Sized,
{
    if !csrf::verify(csrf_form, csrf_cookie) {
        return VerifyPostDecision::CsrfFailure;
    }

    let challenge = match challenges.take(totp_handle).await {
        Ok(Some(c)) => c,
        _           => return VerifyPostDecision::NoChallenge,
    };

    let (user_id, auth_method, ar_fields, attempts, expires_at) = match challenge {
        Challenge::PendingTotp {
            user_id, auth_method,
            ar_client_id, ar_redirect_uri, ar_scope, ar_state, ar_nonce,
            ar_code_challenge, ar_code_challenge_method,
            attempts, expires_at,
        } => {
            let ar = match (ar_client_id, ar_redirect_uri, ar_code_challenge, ar_code_challenge_method) {
                (Some(client_id), Some(redirect_uri), Some(code_challenge), Some(code_challenge_method)) => {
                    Some(PendingAr {
                        client_id, redirect_uri,
                        scope: ar_scope, state: ar_state, nonce: ar_nonce,
                        code_challenge, code_challenge_method,
                    })
                }
                _ => None,
            };
            (user_id, auth_method, ar, attempts, expires_at)
        }
        _ => return VerifyPostDecision::NoChallenge,
    };

    let auth_row = match totp_repo.find_active_for_user(&user_id).await {
        Ok(Some(row)) => row,
        Ok(None)      => return VerifyPostDecision::NoUserAuthenticator { user_id, auth_method, ar_fields },
        Err(_)        => return VerifyPostDecision::StorageError,
    };

    let aad = aad_for_id(&auth_row.id);
    let secret = match decrypt_secret(
        &auth_row.secret_ciphertext,
        &auth_row.secret_nonce,
        encryption_key,
        &aad,
    ) {
        Ok(s)  => s,
        Err(_) => return VerifyPostDecision::DecryptFailed,
    };

    let parse_outcome  = parse_code(submitted_code);
    let verify_outcome = parse_outcome.and_then(|code|
        verify_with_replay_protection(&secret, code, auth_row.last_used_step, now_unix));

    match verify_outcome {
        Ok(new_step) => {
            if totp_repo.update_last_used_step(&auth_row.id, new_step, now_unix).await.is_err() {
                return VerifyPostDecision::LastStepUpdateFailed;
            }
            VerifyPostDecision::Success { user_id, auth_method, ar_fields }
        }
        Err(_) => {
            let new_attempts = attempts.saturating_add(1);
            if attempts_exhausted(new_attempts) {
                return VerifyPostDecision::Lockout;
            }

            // Re-park with bumped attempts. The challenge handle
            // stays the same so the gate cookie remains valid.
            // We preserve the original deadline (don't refresh)
            // — letting a buggy authenticator extend the gate
            // forever by submitting wrong codes is exactly the
            // kind of soft DoS the lockout is supposed to catch.
            let bumped = Challenge::PendingTotp {
                user_id:                  user_id.clone(),
                auth_method,
                ar_client_id:             ar_fields.as_ref().map(|p| p.client_id.clone()),
                ar_redirect_uri:          ar_fields.as_ref().map(|p| p.redirect_uri.clone()),
                ar_scope:                 ar_fields.as_ref().and_then(|p| p.scope.clone()),
                ar_state:                 ar_fields.as_ref().and_then(|p| p.state.clone()),
                ar_nonce:                 ar_fields.as_ref().and_then(|p| p.nonce.clone()),
                ar_code_challenge:        ar_fields.as_ref().map(|p| p.code_challenge.clone()),
                ar_code_challenge_method: ar_fields.as_ref().map(|p| p.code_challenge_method.clone()),
                attempts:                 new_attempts,
                expires_at:               now_unix + TOTP_GATE_TTL_SECS.min(expires_at - now_unix).max(60),
            };
            if challenges.put(totp_handle, &bumped).await.is_err() {
                return VerifyPostDecision::RepkFailed;
            }
            VerifyPostDecision::BadCode
        }
    }
}


/// `POST /me/security/totp/verify` — verify the submitted 6-digit
/// code, on success resume the original `complete_auth` flow.
pub async fn post_handler(
    mut req: Request,
    env:     worker::Env,
) -> Result<Response> {
    let cfg = Config::from_env(&env)?;

    // Cookie + handle extraction — request-shape concerns,
    // outside the decision's domain.
    let cookie_header = match req.headers().get("cookie")? {
        Some(h) => h,
        None    => return crate::routes::me::auth::redirect_to_login(),
    };
    let totp_handle = match extract_totp_handle(&cookie_header) {
        Some(h) if !h.is_empty() => h.to_owned(),
        _ => return crate::routes::me::auth::redirect_to_login(),
    };

    let form        = req.form_data().await?;
    let csrf_form   = form_get(&form, "csrf").unwrap_or_default();
    let csrf_cookie = csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");
    let submitted   = form_get(&form, "code").unwrap_or_default();

    // Operator-misconfig short circuit — no point invoking the
    // decision if the encryption key is unavailable.
    let key = match load_totp_encryption_key(&env)? {
        Some(k) => k,
        None    => return Err(worker::Error::RustError(
            "TOTP_ENCRYPTION_KEY not configured but a TOTP authenticator exists for this user".into()
        )),
    };

    let store     = CloudflareAuthChallengeStore::new(&env);
    let totp_repo = CloudflareTotpAuthenticatorRepository::new(&env);
    let now_unix  = OffsetDateTime::now_utc().unix_timestamp();

    let decision = decide_verify_post(
        &csrf_form, csrf_cookie, &submitted, &totp_handle,
        &store, &totp_repo, &key, now_unix,
    ).await;

    match decision {
        VerifyPostDecision::CsrfFailure => Response::error("Bad Request", 400),

        VerifyPostDecision::NoChallenge | VerifyPostDecision::Lockout => {
            clear_gate_and_redirect("/login")
        }

        VerifyPostDecision::NoUserAuthenticator { user_id, auth_method, ar_fields }
        | VerifyPostDecision::Success           { user_id, auth_method, ar_fields } => {
            complete_auth_post_gate(
                &env, &cfg, &user_id, auth_method, ar_fields,
                Some(cookie_header.as_str()),
            ).await
        }

        VerifyPostDecision::StorageError => Err(worker::Error::RustError(
            "totp authenticator lookup failed".into()
        )),
        VerifyPostDecision::DecryptFailed => Err(worker::Error::RustError(
            "totp secret decrypt failed".into()
        )),
        VerifyPostDecision::LastStepUpdateFailed => Err(worker::Error::RustError(
            "totp last_used_step update failed".into()
        )),
        VerifyPostDecision::RepkFailed => Err(worker::Error::RustError(
            "totp challenge re-put failed".into()
        )),

        VerifyPostDecision::BadCode => {
            // Re-render the verify page with an inline error.
            // Generic message — don't leak whether the parse or
            // the verify failed (an attacker could otherwise
            // probe whether their code shape was correct).
            //
            // Reuse the existing CSRF cookie's token if present;
            // we don't need a fresh one because the form's
            // submitted token already matched.
            let token = csrf::extract_from_cookie_header(&cookie_header)
                .map(str::to_owned)
                .unwrap_or_else(csrf::mint);
            let html = templates::totp_verify_page(
                &token,
                Some("That code didn't match. Try again."),
            );
            // Status 200 (not 401) — the user IS authenticated
            // for primary; the form is a continuation, not a
            // standalone unauthenticated request.
            Response::from_html(html)
        }
    }
}


/// Best-effort form-data extraction that returns `None` for
/// missing or non-string fields. The TOTP forms send only
/// short string fields (csrf, code), so multi-value or file
/// inputs aren't a concern.
fn form_get(form: &worker::FormData, key: &str) -> Option<String> {
    match form.get(key) {
        Some(worker::FormEntry::Field(v)) => Some(v),
        _ => None,
    }
}


/// 302 to `target` while clearing the `__Host-cesauth_totp`
/// cookie. Used for "your gate is stale, start over" outcomes.
pub(crate) fn clear_gate_and_redirect(target: &str) -> Result<Response> {
    let mut resp = Response::empty()?.with_status(302);
    let h = resp.headers_mut();
    h.set("location", target).ok();
    h.append("set-cookie", &post_auth::clear_totp_cookie_header()).ok();
    Ok(resp)
}


#[cfg(test)]
mod tests;
