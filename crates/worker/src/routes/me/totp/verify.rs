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
use cesauth_core::ports::store::{AuthChallengeStore, Challenge};
use cesauth_core::totp::{
    aad_for_id, decrypt_secret, parse_code, verify_with_replay_protection,
};
use cesauth_core::totp::storage::TotpAuthenticatorRepository;
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


/// `GET /me/security/totp/verify` — render the prompt page.
pub async fn get_handler(
    req: Request,
    env: worker::Env,
) -> Result<Response> {
    // Read the gate cookie. If absent, the user landed here
    // without a parked PendingTotp — bounce to /login to start
    // over.
    let cookie_header = match req.headers().get("cookie")? {
        Some(h) => h,
        None    => return crate::routes::me::auth::redirect_to_login(),
    };
    let totp_handle = match extract_totp_handle(&cookie_header) {
        Some(h) if !h.is_empty() => h.to_owned(),
        _ => return crate::routes::me::auth::redirect_to_login(),
    };

    // Peek (don't consume) — GET is render-only.
    let store = CloudflareAuthChallengeStore::new(&env);
    match store.peek(&totp_handle).await {
        Ok(Some(Challenge::PendingTotp { .. })) => { /* render below */ }
        // Wrong challenge type, expired, or absent — gate cookie
        // is stale. Clear and bounce.
        _ => {
            return clear_gate_and_redirect("/login");
        }
    };

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


/// `POST /me/security/totp/verify` — verify the submitted 6-digit
/// code, on success resume the original `complete_auth` flow.
pub async fn post_handler(
    mut req: Request,
    env:     worker::Env,
) -> Result<Response> {
    let cfg = Config::from_env(&env)?;

    // CSRF + cookie shape gates first; cheap rejections.
    let cookie_header = match req.headers().get("cookie")? {
        Some(h) => h,
        None    => return crate::routes::me::auth::redirect_to_login(),
    };
    let totp_handle = match extract_totp_handle(&cookie_header) {
        Some(h) if !h.is_empty() => h.to_owned(),
        _ => return crate::routes::me::auth::redirect_to_login(),
    };

    let form  = req.form_data().await?;
    let csrf_form   = form_get(&form, "csrf").unwrap_or_default();
    let csrf_cookie = csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");
    if !csrf::verify(&csrf_form, csrf_cookie) {
        return Response::error("Bad Request", 400);
    }
    let submitted = form_get(&form, "code").unwrap_or_default();

    // Take the challenge (consume). If verification succeeds we
    // proceed; if it fails we re-park with bumped attempts.
    let store = CloudflareAuthChallengeStore::new(&env);
    let challenge = match store.take(&totp_handle).await {
        Ok(Some(c)) => c,
        _ => return clear_gate_and_redirect("/login"),
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
                // No AR was parked when the gate fired (user came
                // through `/login` directly, not via OAuth
                // `/authorize`). The post-gate flow lands on `/`
                // with just a session cookie.
                _ => None,
            };
            (user_id, auth_method, ar, attempts, expires_at)
        }
        // Wrong challenge type — cookie was carrying a stale
        // handle pointing at, e.g., a PendingAuthorize or
        // MagicLink challenge from a different flow. Bounce.
        _ => return clear_gate_and_redirect("/login"),
    };

    // Look up the user's confirmed authenticator. If absent
    // (e.g., admin disabled it between gate-park and now), the
    // TOTP gate is no longer required — fall through to
    // post_gate. This is a "soft" outcome: the user proves
    // primary auth, gate stops gating, session starts.
    //
    // Note we do NOT "skip the gate without a TOTP secret to
    // verify against" — if the lookup says None right now, the
    // user has no TOTP enrolled and the prompt was a stale
    // race. We accept the outcome rather than refusing to log
    // them in.
    let totp_repo = CloudflareTotpAuthenticatorRepository::new(&env);
    let auth_row = match totp_repo.find_active_for_user(&user_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return complete_auth_post_gate(&env, &cfg, &user_id, auth_method, ar_fields).await;
        }
        Err(_) => {
            return Err(worker::Error::RustError(
                "totp authenticator lookup failed".into()
            ));
        }
    };

    // Decrypt the secret.
    let key = match load_totp_encryption_key(&env)? {
        Some(k) => k,
        None    => return Err(worker::Error::RustError(
            "TOTP_ENCRYPTION_KEY not configured but a TOTP authenticator exists for this user".into()
        )),
    };
    let aad = aad_for_id(&auth_row.id);
    let secret = match decrypt_secret(
        &auth_row.secret_ciphertext,
        &auth_row.secret_nonce,
        &key,
        &aad,
    ) {
        Ok(s)  => s,
        Err(_) => return Err(worker::Error::RustError(
            "totp secret decrypt failed".into()
        )),
    };

    // Parse and verify the submitted code.
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let parse_outcome = parse_code(&submitted);
    let verify_outcome = parse_outcome.and_then(|code|
        verify_with_replay_protection(&secret, code, auth_row.last_used_step, now_unix));

    match verify_outcome {
        Ok(new_step) => {
            // Persist the advanced step (replay protection) and
            // resume the original flow.
            if totp_repo.update_last_used_step(&auth_row.id, new_step, now_unix).await.is_err() {
                // Persistence failed. Refuse the login rather
                // than allow a verify whose replay-protection
                // state didn't make it to disk; the next attempt
                // will succeed if the failure is transient.
                return Err(worker::Error::RustError(
                    "totp last_used_step update failed".into()
                ));
            }
            complete_auth_post_gate(&env, &cfg, &user_id, auth_method, ar_fields).await
        }
        Err(_) => {
            // Bad code. Re-park the challenge with bumped attempts
            // unless we've crossed MAX_ATTEMPTS.
            let new_attempts = attempts.saturating_add(1);
            if new_attempts >= MAX_ATTEMPTS {
                return clear_gate_and_redirect("/login");
            }

            // Re-construct the same PendingTotp with bumped
            // attempts and re-park under the SAME handle so the
            // gate cookie stays valid. The TTL is preserved from
            // the original park.
            //
            // (We could refresh expires_at here, but that'd let
            // a user with a buggy authenticator keep the gate
            // open forever by submitting wrong codes. Keeping
            // the original TTL means after TOTP_GATE_TTL_SECS
            // the user must restart from /login regardless.)
            let _ = expires_at; // expressly unused — see comment
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
                // Preserve the original deadline rather than
                // refreshing it. See comment above.
                expires_at:               now_unix + TOTP_GATE_TTL_SECS.min(expires_at - now_unix).max(60),
            };
            store.put(&totp_handle, &bumped).await
                .map_err(|_| worker::Error::RustError("totp challenge re-put failed".into()))?;

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
            let resp = Response::from_html(html)?;
            // Status 200 (not 401) — the user IS authenticated
            // for primary; the form is a continuation, not a
            // standalone unauthenticated request.
            Ok(resp)
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
