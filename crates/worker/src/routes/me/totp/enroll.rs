//! `/me/security/totp/enroll` and `/me/security/totp/enroll/confirm`
//! — TOTP enrollment flow.
//!
//! GET creates a fresh secret, encrypts it with `TOTP_ENCRYPTION_KEY`,
//! parks an unconfirmed `totp_authenticators` row, sets the
//! `__Host-cesauth_totp_enroll` cookie carrying the row id, and
//! renders the enrollment page (QR code + manual-entry secret +
//! confirmation form).
//!
//! POST/confirm reads the enrollment cookie + the submitted code,
//! decrypts the row's secret, verifies the code, on success flips
//! `confirmed_at` and (if this is the user's first confirmed
//! authenticator) mints + stores 10 recovery codes. Renders the
//! recovery-codes page once.
//!
//! Per ADR-009 §Q6, recovery codes are minted only at the user's
//! first confirmed enrollment. A user adding a second authenticator
//! (e.g., backup phone) does NOT get fresh recovery codes — they
//! still have their original ones from the first enrollment.

use cesauth_cf::ports::repo::{
    CloudflareTotpAuthenticatorRepository, CloudflareTotpRecoveryCodeRepository,
};
use cesauth_core::ports::PortError;
use cesauth_core::totp::{
    aad_for_id, decrypt_secret, encrypt_secret, generate_recovery_codes,
    hash_recovery_code, otpauth_uri, parse_code, qr,
    verify_with_replay_protection, RecoveryCode, Secret,
};
use cesauth_core::totp::storage::{
    TotpAuthenticator, TotpAuthenticatorRepository,
    TotpRecoveryCodeRepository, TotpRecoveryCodeRow,
};
use cesauth_ui::templates;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::{Request, Response, Result};

use crate::config::{
    load_totp_encryption_key, load_totp_encryption_key_id,
};
use crate::csrf;
use crate::flash;
use crate::post_auth::{
    self, TOTP_ENROLL_TTL_SECS, extract_totp_enroll_id,
    set_totp_enroll_cookie_header,
};
use crate::routes::me::auth as me_auth;


/// Issuer label embedded in the `otpauth://` URI. Authenticator
/// apps display this as the prefix of the entry. We hard-code
/// "cesauth" rather than reading from config because a
/// per-deployment override would surprise users who enrolled at a
/// different deployment of the same product.
const OTPAUTH_ISSUER: &str = "cesauth";


/// Outcome of [`decide_enroll_get`].
///
/// The decision performs the secret encryption + the unconfirmed
/// row insert + the QR SVG render. The handler then maps each
/// variant to a Response, attaching the CSRF + enroll cookies on
/// Success.
#[derive(Debug)]
pub(crate) enum EnrollGetDecision {
    /// AAD-bound encryption of the secret failed. Most plausible
    /// cause: a corrupt encryption key (length mismatch). 500.
    EncryptError,

    /// The unconfirmed row insert failed. Storage outage. 500.
    StoreError,

    /// QR code generation failed. The `qr` crate is robust enough
    /// that this practically never happens, but treating it as a
    /// 500 keeps the handler total. 500.
    QrRenderError,

    /// All steps succeeded. Handler builds the page, sets the
    /// CSRF + enroll cookies.
    Success {
        secret_b32: String,
        qr_svg:     String,
    },
}

/// Pure-ish decision logic for `GET /me/security/totp/enroll`.
///
/// Inputs:
/// - `user_id` / `user_email`: already resolved from the session
///   + a user-row read in the handler. (We pull email up to the
///   handler because the read happens once and the result feeds
///   both the otpauth label and the row's user_id binding.)
/// - `secret` / `row_id`: pre-minted in the handler. Tests pass
///   in deterministic values for predictable assertions; the
///   handler uses CSPRNG-backed `Secret::generate` and UUID v4
///   for row_id.
/// - `encryption_key` / `encryption_key_id`: pulled from `env`
///   in the handler.
/// - `totp_repo`: trait-bounded so tests inject in-memory.
/// - `now_unix`: for the row's `created_at`.
///
/// Returns an `EnrollGetDecision` describing the outcome plus the
/// page-render data on success. Side effects: ONE `create()` call
/// on the repo on the success path (and on the StoreError path it
/// returns before that completes).
pub(crate) async fn decide_enroll_get<T>(
    user_id:           &str,
    user_email:        &str,
    secret:            &Secret,
    row_id:            &str,
    encryption_key:    &[u8],
    encryption_key_id: &str,
    totp_repo:         &T,
    now_unix:          i64,
) -> EnrollGetDecision
where
    T: TotpAuthenticatorRepository + ?Sized,
{
    let aad = aad_for_id(row_id);
    let (ciphertext, nonce) = match encrypt_secret(secret, encryption_key, &aad) {
        Ok(out) => out,
        Err(_)  => return EnrollGetDecision::EncryptError,
    };

    let row = TotpAuthenticator {
        id:                row_id.to_owned(),
        user_id:           user_id.to_owned(),
        secret_ciphertext: ciphertext,
        secret_nonce:      nonce.to_vec(),
        secret_key_id:     encryption_key_id.to_owned(),
        last_used_step:    0,
        name:              None,
        created_at:        now_unix,
        last_used_at:      None,
        confirmed_at:      None,
    };
    if totp_repo.create(&row).await.is_err() {
        return EnrollGetDecision::StoreError;
    }

    let secret_b32 = secret.to_base32();
    let uri = otpauth_uri(OTPAUTH_ISSUER, user_email, secret);
    let qr_svg = match qr::otpauth_to_svg(&uri) {
        Ok(s)  => s,
        Err(_) => return EnrollGetDecision::QrRenderError,
    };

    EnrollGetDecision::Success { secret_b32, qr_svg }
}


/// `GET /me/security/totp/enroll` — start a fresh enrollment.
pub async fn get_handler(
    req: Request,
    env: worker::Env,
) -> Result<Response> {
    let session = match me_auth::resolve_or_redirect(&req, &env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    // Encryption key gate: refuse to start enrollment if the
    // operator hasn't provisioned TOTP_ENCRYPTION_KEY. Otherwise
    // we'd encrypt with `None` and the verify path would have no
    // way to decrypt.
    let key = match load_totp_encryption_key(&env)? {
        Some(k) => k,
        None    => return Response::error(
            "TOTP is not configured by the operator (TOTP_ENCRYPTION_KEY missing)",
            503,
        ),
    };
    let key_id = match load_totp_encryption_key_id(&env) {
        Some(id) => id,
        None     => return Response::error(
            "TOTP is not configured by the operator (TOTP_ENCRYPTION_KEY_ID missing)",
            503,
        ),
    };

    // Look up the user's email for the otpauth label.
    let email = match read_user_email(&env, &session.user_id).await? {
        Some(e) => e,
        None    => return Response::error(
            "Account state inconsistent — no email on file",
            500,
        ),
    };

    // Mint a fresh secret + row id.
    let secret = match Secret::generate() {
        Ok(s)  => s,
        Err(_) => return Response::error("RNG unavailable", 503),
    };
    let row_id = Uuid::new_v4().to_string();
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();

    let totp_repo = CloudflareTotpAuthenticatorRepository::new(&env);

    let decision = decide_enroll_get(
        &session.user_id, &email,
        &secret, &row_id,
        &key, &key_id,
        &totp_repo, now_unix,
    ).await;

    match decision {
        EnrollGetDecision::EncryptError   => Response::error("encryption failed", 500),
        EnrollGetDecision::StoreError     => Response::error("totp authenticator create failed", 500),
        EnrollGetDecision::QrRenderError  => Response::error("qr render failed", 500),
        EnrollGetDecision::Success { secret_b32, qr_svg } => {
            // CSRF token for the confirm POST.
            let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
            let existing = csrf::extract_from_cookie_header(&cookie_header).map(str::to_owned);
            let (csrf_token, csrf_set_cookie) = match existing {
                Some(t) if !t.is_empty() => (t, None),
                _ => {
                    let t = csrf::mint();
                    let h = csrf::set_cookie_header(&t);
                    (t, Some(h))
                }
            };

            let locale = crate::i18n::resolve_locale(&req);
            let html = templates::totp_enroll_page_for(&qr_svg, &secret_b32, &csrf_token, None, locale);
            let mut resp = Response::from_html(html)?;
            let h = resp.headers_mut();
            h.append("set-cookie", &set_totp_enroll_cookie_header(&row_id, TOTP_ENROLL_TTL_SECS)).ok();
            if let Some(s) = csrf_set_cookie {
                h.append("set-cookie", &s).ok();
            }
            Ok(resp)
        }
    }
}


/// Outcome of [`decide_enroll_confirm_post`].
///
/// Captures the full branch table for the enrollment-confirm
/// flow: CSRF / lookup / ownership / already-confirmed /
/// decrypt / verify / confirm-race / recovery-mint.
#[derive(Debug)]
pub(crate) enum EnrollConfirmDecision {
    /// CSRF token mismatch. 400. No state mutated.
    CsrfFailure,

    /// `find_by_id` returned None, OR the row's user_id didn't
    /// match the session's user_id. We collapse the two cases
    /// because they both return 400 with the same generic
    /// "Enrollment session expired" message — distinguishing
    /// them would let an attacker probe whether a given enroll
    /// id exists.
    UnknownEnrollment,

    /// Row was already confirmed (double-submit, back-button
    /// replay). Handler clears the cookie and 302's to /.
    AlreadyConfirmed,

    /// Decryption failed. Most plausible: TOTP_ENCRYPTION_KEY
    /// rotated mid-enrollment. 500.
    DecryptFailed,

    /// Wrong code on the confirmation submit. Handler
    /// re-renders the enroll page with an inline error.
    /// `secret_b32` is carried so the handler doesn't have to
    /// decrypt again.
    WrongCode { secret_b32: String },

    /// `confirm()` returned NotFound — race lost (the row was
    /// already confirmed or deleted by another request between
    /// our find_by_id and our confirm). Handler clears cookie +
    /// 302's to /.
    ConfirmRaceLost,

    /// `confirm()` raised any other error. 500.
    ConfirmFailed,

    /// `generate_recovery_codes` failed (RNG outage). 500.
    RecoveryGenError,

    /// `bulk_create` on the recovery codes failed. The
    /// authenticator IS confirmed at this point (the confirm
    /// already committed) but the user has no recovery codes.
    /// 500 — the user can disable+re-enroll to recover.
    RecoveryStoreError,

    /// First confirmed enrollment for this user. Recovery codes
    /// minted; handler renders the one-shot recovery-codes
    /// page + sets a `success.totp_enabled` flash.
    SuccessFirstEnrollment {
        plaintext_codes: Vec<String>,
    },

    /// User already had recovery codes (this is an additional
    /// authenticator, e.g., a backup). Skip the recovery-codes
    /// page. Handler 302's to /me/security + flash.
    SuccessAdditionalAuthenticator,
}

/// Pure-ish decision logic for `POST /me/security/totp/enroll/confirm`.
///
/// Performs port-level IO (totp_repo + recovery_repo reads/writes,
/// crypto). No Env-touching IO; no `Response` building.
///
/// Calling order:
///
/// 1. CSRF first (cheap reject, no mutation).
/// 2. Look up row + verify user_id ownership.
/// 3. Reject already-confirmed rows.
/// 4. Decrypt secret.
/// 5. Verify code → re-render on wrong-code, OR call
///    `confirm()` on right-code.
/// 6. On confirm success: mint recovery codes IFF first
///    enrollment for this user.
pub(crate) async fn decide_enroll_confirm_post<T, R>(
    user_id:        &str,
    enroll_id:      &str,
    csrf_form:      &str,
    csrf_cookie:    &str,
    submitted_code: &str,
    encryption_key: &[u8],
    totp_repo:      &T,
    recovery_repo:  &R,
    now_unix:       i64,
) -> EnrollConfirmDecision
where
    T: TotpAuthenticatorRepository + ?Sized,
    R: TotpRecoveryCodeRepository  + ?Sized,
{
    if !csrf::verify(csrf_form, csrf_cookie) {
        return EnrollConfirmDecision::CsrfFailure;
    }

    let row = match totp_repo.find_by_id(enroll_id).await {
        Ok(Some(r)) => r,
        _           => return EnrollConfirmDecision::UnknownEnrollment,
    };
    if row.user_id != user_id {
        return EnrollConfirmDecision::UnknownEnrollment;
    }
    if row.confirmed_at.is_some() {
        return EnrollConfirmDecision::AlreadyConfirmed;
    }

    let aad = aad_for_id(&row.id);
    let secret = match decrypt_secret(&row.secret_ciphertext, &row.secret_nonce, encryption_key, &aad) {
        Ok(s)  => s,
        Err(_) => return EnrollConfirmDecision::DecryptFailed,
    };

    let parsed = parse_code(submitted_code);
    let new_step = match parsed.and_then(|c| verify_with_replay_protection(&secret, c, 0, now_unix)) {
        Ok(s)  => s,
        Err(_) => return EnrollConfirmDecision::WrongCode { secret_b32: secret.to_base32() },
    };

    match totp_repo.confirm(&row.id, new_step, now_unix).await {
        Ok(())                                     => {}
        Err(PortError::NotFound)                   => return EnrollConfirmDecision::ConfirmRaceLost,
        Err(_)                                     => return EnrollConfirmDecision::ConfirmFailed,
    }

    // Mint recovery codes ONLY at first confirmed enrollment.
    let existing = recovery_repo.count_remaining(user_id).await.unwrap_or(0);
    if existing > 0 {
        return EnrollConfirmDecision::SuccessAdditionalAuthenticator;
    }

    let codes: Vec<RecoveryCode> = match generate_recovery_codes() {
        Ok(c)  => c,
        Err(_) => return EnrollConfirmDecision::RecoveryGenError,
    };
    let rows: Vec<TotpRecoveryCodeRow> = codes.iter().map(|c| TotpRecoveryCodeRow {
        id:           Uuid::new_v4().to_string(),
        user_id:      user_id.to_owned(),
        code_hash:    hash_recovery_code(c.as_str()),
        redeemed_at:  None,
        created_at:   now_unix,
    }).collect();
    if recovery_repo.bulk_create(&rows).await.is_err() {
        return EnrollConfirmDecision::RecoveryStoreError;
    }

    let plaintext_codes: Vec<String> = codes.iter().map(|c| c.as_str().to_owned()).collect();
    EnrollConfirmDecision::SuccessFirstEnrollment { plaintext_codes }
}


/// `POST /me/security/totp/enroll/confirm` — verify the first code,
/// flip `confirmed_at`, mint recovery codes (at first enrollment),
/// render the recovery-codes page.
pub async fn post_confirm_handler(
    mut req: Request,
    env:     worker::Env,
) -> Result<Response> {
    let session = match me_auth::resolve_or_redirect(&req, &env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let enroll_id = match extract_totp_enroll_id(&cookie_header) {
        Some(id) if !id.is_empty() => id.to_owned(),
        _ => return Response::error("Enrollment session expired — start over", 400),
    };

    let form        = req.form_data().await?;
    let csrf_form   = form_get(&form, "csrf").unwrap_or_default();
    let csrf_cookie = csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");
    let submitted   = form_get(&form, "code").unwrap_or_default();

    let key = match load_totp_encryption_key(&env)? {
        Some(k) => k,
        None    => return Response::error("TOTP is not configured", 503),
    };

    let totp_repo     = CloudflareTotpAuthenticatorRepository::new(&env);
    let recovery_repo = CloudflareTotpRecoveryCodeRepository::new(&env);
    let now_unix      = OffsetDateTime::now_utc().unix_timestamp();

    let decision = decide_enroll_confirm_post(
        &session.user_id, &enroll_id,
        &csrf_form, csrf_cookie, &submitted,
        &key, &totp_repo, &recovery_repo, now_unix,
    ).await;

    match decision {
        EnrollConfirmDecision::CsrfFailure        => Response::error("Bad Request", 400),
        EnrollConfirmDecision::UnknownEnrollment  => Response::error("Enrollment session expired — start over", 400),
        EnrollConfirmDecision::AlreadyConfirmed
        | EnrollConfirmDecision::ConfirmRaceLost  => clear_enroll_cookie_and_redirect("/"),
        EnrollConfirmDecision::DecryptFailed      => Response::error("totp secret decrypt failed", 500),
        EnrollConfirmDecision::ConfirmFailed      => Response::error("totp confirm failed", 500),
        EnrollConfirmDecision::RecoveryGenError   => Response::error("recovery code generation failed", 500),
        EnrollConfirmDecision::RecoveryStoreError => Response::error("recovery code persistence failed", 500),

        EnrollConfirmDecision::WrongCode { secret_b32 } => {
            // Re-render the enroll page so the user can try
            // again with a fresh code from their authenticator.
            // We need email for the otpauth URI label.
            let email = read_user_email(&env, &session.user_id).await?
                .unwrap_or_else(|| session.user_id.clone());
            // Re-build a Secret to feed otpauth_uri. We have the
            // base32 form; round-trip to bytes.
            let secret_for_uri = match Secret::from_base32(&secret_b32) {
                Ok(s)  => s,
                Err(_) => return Response::error("internal error rebuilding secret", 500),
            };
            let uri = otpauth_uri(OTPAUTH_ISSUER, &email, &secret_for_uri);
            let qr_svg = qr::otpauth_to_svg(&uri).unwrap_or_default();
            let token = csrf::extract_from_cookie_header(&cookie_header)
                .map(str::to_owned)
                .unwrap_or_else(csrf::mint);
            // v0.31.0 P0-C: re-render with an inline error so the
            // user knows the previous code didn't match. Same
            // secret — they read the next 6-digit code from their
            // authenticator app and submit again.
            // v0.39.0: locale-aware via the i18n catalog (the
            // wrong-code message was migrated to MessageKey
            // already in v0.36.0; this PR threads the locale
            // through to the page wrapper).
            let locale = crate::i18n::resolve_locale(&req);
            let wrong_code_msg = cesauth_core::i18n::lookup(
                cesauth_core::i18n::MessageKey::TotpEnrollWrongCode,
                locale,
            );
            let html = templates::totp_enroll_page_for(
                &qr_svg,
                &secret_b32,
                &token,
                Some(wrong_code_msg),
                locale,
            );
            Response::from_html(html)
        }

        EnrollConfirmDecision::SuccessAdditionalAuthenticator => {
            // Already had recovery codes from a prior
            // enrollment. Skip the recovery-codes page. The
            // user lands back on the Security Center with a
            // success flash so the new authenticator's
            // "enabled" status is visible.
            clear_enroll_cookie_and_redirect_with_flash(
                &env,
                "/me/security",
                flash::Flash::new(flash::FlashLevel::Success, flash::FlashKey::TotpEnabled),
            )
        }

        EnrollConfirmDecision::SuccessFirstEnrollment { plaintext_codes } => {
            // Render the recovery-codes page once. The
            // "continue" link on this page points to
            // /me/security, where the flash we set here will
            // display the success notice.
            //
            // Setting the flash on the recovery-codes-page
            // response (not a redirect) means the cookie is
            // delivered while the user is reading the codes;
            // their next navigation (whether the continue link
            // or any other) carries it to the index.
            let html = templates::totp_recovery_codes_page(&plaintext_codes);
            let mut resp = Response::from_html(html)?;
            let h = resp.headers_mut();
            h.append("set-cookie", &post_auth::clear_totp_enroll_cookie_header()).ok();
            flash::set_on_response(
                &env,
                h,
                flash::Flash::new(flash::FlashLevel::Success, flash::FlashKey::TotpEnabled),
            )?;
            Ok(resp)
        }
    }
}


/// 302 to `target` while clearing the enroll cookie.
fn clear_enroll_cookie_and_redirect(target: &str) -> Result<Response> {
    let mut resp = Response::empty()?.with_status(302);
    let h = resp.headers_mut();
    h.set("location", target).ok();
    h.append("set-cookie", &post_auth::clear_totp_enroll_cookie_header()).ok();
    Ok(resp)
}

/// 302 to `target` while clearing the enroll cookie AND setting
/// a flash banner for display on the next page. Added in v0.31.0
/// alongside the flash-message infrastructure (P0-B).
fn clear_enroll_cookie_and_redirect_with_flash(
    env:    &worker::Env,
    target: &str,
    f:      flash::Flash,
) -> Result<Response> {
    let mut resp = Response::empty()?.with_status(302);
    let h = resp.headers_mut();
    h.set("location", target).ok();
    h.append("set-cookie", &post_auth::clear_totp_enroll_cookie_header()).ok();
    flash::set_on_response(env, h, f)?;
    Ok(resp)
}


/// Read the user's email address. Used for the `otpauth://`
/// account label so authenticator apps display "cesauth: <email>"
/// rather than "cesauth: <uuid>".
async fn read_user_email(env: &worker::Env, user_id: &str) -> Result<Option<String>> {
    use cesauth_cf::ports::repo::CloudflareUserRepository;
    use cesauth_core::ports::repo::UserRepository;
    let repo = CloudflareUserRepository::new(env);
    match repo.find_by_id(user_id).await {
        Ok(Some(u)) => Ok(u.email),
        Ok(None)    => Ok(None),
        Err(_)      => Err(worker::Error::RustError("user lookup failed".into())),
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
