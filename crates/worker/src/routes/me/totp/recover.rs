//! `/me/security/totp/recover` — single-use recovery code
//! redemption, alternative to the verify path.
//!
//! Reached from the verify-page form when the user has lost
//! their authenticator. Reads the same `__Host-cesauth_totp`
//! cookie + `Challenge::PendingTotp` parked by `complete_auth`,
//! looks up the submitted code in `totp_recovery_codes` after
//! canonicalizing + hashing, and on a match redeems it (single
//! use) then resumes the original `complete_auth_post_gate`
//! flow.
//!
//! Per ADR-009 §Q6 the recovery path does NOT advance the TOTP
//! authenticator's `last_used_step` — recovery bypasses TOTP,
//! it doesn't use it. The redeemed-code timestamp is the
//! audit record.
//!
//! Per ADR-009 §Q6 once a code is used it's marked redeemed and
//! cannot be reused. The user keeps their other recovery codes
//! and their TOTP authenticator (if they still have it).
//! Disabling TOTP after recovery is a separate user action
//! (the v0.30.0 disable flow).
//!
//! ## Refactor (v0.31.1 P1-B)
//!
//! The decision logic is extracted into [`decide_recover_post`]
//! so handler tests can exercise the branch table with in-memory
//! adapters. The handler is the thin wrapper that does the
//! cookie / form extraction and maps the [`RecoverDecision`] to
//! a `worker::Response` (including the `complete_auth_post_gate`
//! call, which needs the live `worker::Env`).

use cesauth_cf::ports::store::CloudflareAuthChallengeStore;
use cesauth_cf::ports::repo::CloudflareTotpRecoveryCodeRepository;
use cesauth_core::ports::store::{AuthChallengeStore, AuthMethod, Challenge};
use cesauth_core::totp::hash_recovery_code;
use cesauth_core::totp::storage::TotpRecoveryCodeRepository;
use time::OffsetDateTime;
use worker::{Request, Response, Result};

use crate::config::Config;
use crate::csrf;
use crate::flash;
use crate::post_auth::{
    PendingAr, complete_auth_post_gate, extract_totp_handle,
};
use crate::routes::me::totp::verify::clear_gate_and_redirect;


/// Outcome of [`decide_recover_post`].
///
/// Carries enough domain data for the handler to either fail
/// (clear gate + redirect, or 4xx, or 5xx) or resume the
/// post-auth flow with the resolved user_id + auth_method +
/// optional pending AR. The Env-touching pieces
/// (`complete_auth_post_gate`, flash cookie set) live in the
/// handler.
#[derive(Debug)]
pub(crate) enum RecoverDecision {
    /// CSRF token missing or didn't match cookie. Handler returns
    /// 400. The challenge is NOT consumed (we short-circuit before
    /// calling `take`).
    CsrfFailure,

    /// Form's `code` field was empty after CSRF passed. Handler
    /// returns 400 — separated from CsrfFailure so a future
    /// audit log distinguishes the two failure modes.
    EmptyCode,

    /// Challenge `take` returned None, wrong variant, or store
    /// errored. The cookie is now stale; handler clears it and
    /// 302's to /login. We treat all three as "no usable
    /// challenge" because none of them differ in the user's
    /// recovery flow.
    NoChallenge,

    /// Recovery-code lookup raised a storage error (NOT "no
    /// match"). Distinct from NoMatchingCode so the handler can
    /// surface the difference: a storage outage is operator-
    /// fixable, a wrong code is user-fixable.
    StorageError,

    /// Hash didn't match any unredeemed row for this user. Fail
    /// closed: clear gate + 302 /login. We don't re-render the
    /// verify page with an error because recovery is high-friction
    /// — sending the user back to /login discourages brute-force
    /// probing of recovery codes.
    NoMatchingCode,

    /// Mark-redeemed UPDATE failed. Most plausible cause is a
    /// concurrent redemption (two browser tabs racing). Fail
    /// closed: clear gate + 302. Phase 2's audit chain will
    /// record the attempt regardless.
    MarkRedeemedFailed,

    /// All gates passed and the recovery code is now consumed.
    /// Handler invokes `complete_auth_post_gate` with these
    /// fields and sets a `warning.totp_recovered` flash on the
    /// resulting response.
    Success {
        user_id:     String,
        auth_method: AuthMethod,
        ar_fields:   Option<PendingAr>,
    },
}

/// Pure decision logic for `POST /me/security/totp/recover`.
///
/// All Env-touching IO is excluded: the function operates on
/// trait-bounded `&impl` references that tests can satisfy with
/// in-memory adapters from `cesauth-adapter-test`.
///
/// Calling order matters:
///
/// 1. **CSRF check first.** Failing CSRF must NOT consume the
///    challenge — the user can retry with a fresh form.
/// 2. **Empty-code check.** A user submitting an empty form
///    deserves a clean 400, not a take-and-fail.
/// 3. **Challenge take.** This is the destructive step (one-shot
///    consumption). Past this point any failure clears the gate
///    cookie regardless.
/// 4. **Recovery-code lookup.** Storage error vs. no-match are
///    distinguished.
/// 5. **Mark redeemed.** A failure here returns
///    MarkRedeemedFailed (not Success) so we never resume an
///    auth flow with a still-valid recovery code.
pub(crate) async fn decide_recover_post<C, R>(
    csrf_form:      &str,
    csrf_cookie:    &str,
    submitted_code: &str,
    totp_handle:    &str,
    challenges:     &C,
    recovery_repo:  &R,
    now_unix:       i64,
) -> RecoverDecision
where
    C: AuthChallengeStore       + ?Sized,
    R: TotpRecoveryCodeRepository + ?Sized,
{
    if !csrf::verify(csrf_form, csrf_cookie) {
        return RecoverDecision::CsrfFailure;
    }
    if submitted_code.is_empty() {
        return RecoverDecision::EmptyCode;
    }

    let challenge = match challenges.take(totp_handle).await {
        Ok(Some(c)) => c,
        _           => return RecoverDecision::NoChallenge,
    };

    let (user_id, auth_method, ar_fields) = match challenge {
        Challenge::PendingTotp {
            user_id, auth_method,
            ar_client_id, ar_redirect_uri, ar_scope, ar_state, ar_nonce,
            ar_code_challenge, ar_code_challenge_method,
            ..
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
            (user_id, auth_method, ar)
        }
        _ => return RecoverDecision::NoChallenge,
    };

    // Hash with the canonical recovery-code form: uppercase, no
    // whitespace, no dashes. Lets the user paste in any reasonable
    // shape.
    let code_hash = hash_recovery_code(submitted_code);

    let row = match recovery_repo.find_unredeemed_by_hash(&user_id, &code_hash).await {
        Ok(Some(r)) => r,
        Ok(None)    => return RecoverDecision::NoMatchingCode,
        Err(_)      => return RecoverDecision::StorageError,
    };

    if recovery_repo.mark_redeemed(&row.id, now_unix).await.is_err() {
        return RecoverDecision::MarkRedeemedFailed;
    }

    RecoverDecision::Success { user_id, auth_method, ar_fields }
}


/// `POST /me/security/totp/recover` — redeem a recovery code as
/// alternative to the standard TOTP verify.
pub async fn post_handler(
    mut req: Request,
    env:     worker::Env,
) -> Result<Response> {
    let cfg = Config::from_env(&env)?;

    // Cookie + handle extraction — the request-shape concerns.
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

    let store         = CloudflareAuthChallengeStore::new(&env);
    let recovery_repo = CloudflareTotpRecoveryCodeRepository::new(&env);
    let now_unix      = OffsetDateTime::now_utc().unix_timestamp();

    let decision = decide_recover_post(
        &csrf_form, csrf_cookie, &submitted, &totp_handle,
        &store, &recovery_repo, now_unix,
    ).await;

    match decision {
        RecoverDecision::CsrfFailure | RecoverDecision::EmptyCode => {
            Response::error("Bad Request", 400)
        }
        RecoverDecision::NoChallenge | RecoverDecision::MarkRedeemedFailed | RecoverDecision::NoMatchingCode => {
            // All three: clear gate cookie + 302 to /login.
            // NoMatchingCode is silent (anti-brute-force).
            // NoChallenge is a stale/empty cookie. MarkRedeemedFailed
            // is a race we lost. Same outcome at the wire.
            clear_gate_and_redirect("/login")
        }
        RecoverDecision::StorageError => {
            // Operator-fixable. Surface as a worker error so the
            // platform-level logging picks it up.
            Err(worker::Error::RustError(
                "totp recovery lookup failed".into()
            ))
        }
        RecoverDecision::Success { user_id, auth_method, ar_fields } => {
            // Resume the original post-gate flow. Setting the
            // flash on the resulting response (which is either a
            // 302 to the RP's redirect_uri or a 302 to /,
            // depending on whether a PendingAuthorize is in
            // scope) ensures the next page tells the user they
            // just used a recovery code. Plan §3.1 P0-B calls
            // this `warning.totp_recovered` because the user
            // has just consumed a one-time code.
            let mut resp = complete_auth_post_gate(
                &env, &cfg, &user_id, auth_method, ar_fields,
                Some(cookie_header.as_str()),
            ).await?;
            flash::set_on_response(
                &env,
                resp.headers_mut(),
                flash::Flash::new(flash::FlashLevel::Warning, flash::FlashKey::TotpRecovered),
            )?;
            Ok(resp)
        }
    }
}


fn form_get(form: &worker::FormData, key: &str) -> Option<String> {
    match form.get(key) {
        Some(worker::FormEntry::Field(v)) => Some(v),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
