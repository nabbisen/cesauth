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

use cesauth_cf::ports::store::CloudflareAuthChallengeStore;
use cesauth_cf::ports::repo::CloudflareTotpRecoveryCodeRepository;
use cesauth_core::ports::store::{AuthChallengeStore, Challenge};
use cesauth_core::totp::{hash_recovery_code};
use cesauth_core::totp::storage::TotpRecoveryCodeRepository;
use time::OffsetDateTime;
use worker::{Request, Response, Result};

use crate::config::Config;
use crate::csrf;
use crate::post_auth::{
    PendingAr, complete_auth_post_gate, extract_totp_handle,
};
use crate::routes::me::totp::verify::clear_gate_and_redirect;


/// `POST /me/security/totp/recover` — redeem a recovery code as
/// alternative to the standard TOTP verify.
pub async fn post_handler(
    mut req: Request,
    env:     worker::Env,
) -> Result<Response> {
    let cfg = Config::from_env(&env)?;

    // Cookie + CSRF gates.
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
    if !csrf::verify(&csrf_form, csrf_cookie) {
        return Response::error("Bad Request", 400);
    }
    let submitted = form_get(&form, "code").unwrap_or_default();
    if submitted.is_empty() {
        return Response::error("Bad Request", 400);
    }

    // Take the PendingTotp challenge. Recovery is a one-shot
    // operation just like verify; consuming the challenge here
    // ensures a stale gate cookie can't redeem twice.
    let store = CloudflareAuthChallengeStore::new(&env);
    let challenge = match store.take(&totp_handle).await {
        Ok(Some(c)) => c,
        _ => return clear_gate_and_redirect("/login"),
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
        _ => return clear_gate_and_redirect("/login"),
    };

    // Look up the submitted code by SHA-256 of the canonical
    // form. `hash_recovery_code` does whitespace + dash + case
    // canonicalization so the user can paste the code in any
    // reasonable shape (uppercase or lowercase, dash or no dash,
    // with stray spaces).
    let code_hash = hash_recovery_code(&submitted);
    let recovery_repo = CloudflareTotpRecoveryCodeRepository::new(&env);
    let row = match recovery_repo.find_unredeemed_by_hash(&user_id, &code_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            // No matching unredeemed code. Fail closed — bounce
            // to /login. (We could re-render the verify page
            // with an error, but recovery is a high-friction
            // operation; making the user restart from /login
            // discourages brute-force probing of recovery
            // codes.)
            return clear_gate_and_redirect("/login");
        }
        Err(_) => {
            return Err(worker::Error::RustError(
                "totp recovery lookup failed".into()
            ));
        }
    };

    // Mark redeemed. If this fails (e.g., concurrent redemption
    // race lost), fail closed: don't issue a session.
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    if recovery_repo.mark_redeemed(&row.id, now_unix).await.is_err() {
        return clear_gate_and_redirect("/login");
    }

    // Resume the original post-gate flow.
    complete_auth_post_gate(&env, &cfg, &user_id, auth_method, ar_fields).await
}


fn form_get(form: &worker::FormData, key: &str) -> Option<String> {
    match form.get(key) {
        Some(worker::FormEntry::Field(v)) => Some(v),
        _ => None,
    }
}
