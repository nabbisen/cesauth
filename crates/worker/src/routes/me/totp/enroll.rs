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


/// `GET /me/security/totp/enroll` — start a fresh enrollment.
pub async fn get_handler(
    req: Request,
    env: worker::Env,
) -> Result<Response> {
    // Authentication gate: must have a live session.
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

    // Look up the user's email for the otpauth label. The
    // session carries `user_id` only; we need to read the user
    // row to get the email.
    let email = match read_user_email(&env, &session.user_id).await? {
        Some(e) => e,
        None    => return Response::error(
            "Account state inconsistent — no email on file",
            500,
        ),
    };

    // Mint a fresh secret. Generate via CSPRNG.
    let secret = match Secret::generate() {
        Ok(s)  => s,
        Err(_) => return Response::error("RNG unavailable", 503),
    };

    // Encrypt at rest. AAD = "totp:" + row id; we generate the
    // id first and bind it.
    let row_id = Uuid::new_v4().to_string();
    let aad = aad_for_id(&row_id);
    let (ciphertext, nonce) = match encrypt_secret(&secret, &key, &aad) {
        Ok(out) => out,
        Err(_)  => return Response::error("encryption failed", 500),
    };

    // Insert the unconfirmed row.
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let row = TotpAuthenticator {
        id:                row_id.clone(),
        user_id:           session.user_id.clone(),
        secret_ciphertext: ciphertext,
        secret_nonce:      nonce.to_vec(),
        secret_key_id:     key_id,
        last_used_step:    0,
        name:              None,
        created_at:        now_unix,
        last_used_at:      None,
        confirmed_at:      None,
    };
    let totp_repo = CloudflareTotpAuthenticatorRepository::new(&env);
    if let Err(_) = totp_repo.create(&row).await {
        return Response::error("totp authenticator create failed", 500);
    }

    // Build the otpauth URI + render to SVG.
    let secret_b32 = secret.to_base32();
    let uri = otpauth_uri(OTPAUTH_ISSUER, &email, &secret);
    let qr_svg = match qr::otpauth_to_svg(&uri) {
        Ok(s)  => s,
        Err(_) => return Response::error("qr render failed", 500),
    };

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

    let html = templates::totp_enroll_page(&qr_svg, &secret_b32, &csrf_token, None);
    let mut resp = Response::from_html(html)?;
    let h = resp.headers_mut();
    h.append("set-cookie", &set_totp_enroll_cookie_header(&row_id, TOTP_ENROLL_TTL_SECS)).ok();
    if let Some(s) = csrf_set_cookie {
        h.append("set-cookie", &s).ok();
    }
    Ok(resp)
}


/// `POST /me/security/totp/enroll/confirm` — verify the first code,
/// flip `confirmed_at`, mint recovery codes (at first enrollment),
/// render the recovery-codes page.
pub async fn post_confirm_handler(
    mut req: Request,
    env:     worker::Env,
) -> Result<Response> {
    // Authentication gate.
    let session = match me_auth::resolve_or_redirect(&req, &env).await? {
        Ok(s)  => s,
        Err(r) => return Ok(r),
    };

    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();

    // Enrollment cookie: which row are we confirming?
    let enroll_id = match extract_totp_enroll_id(&cookie_header) {
        Some(id) if !id.is_empty() => id.to_owned(),
        _ => return Response::error("Enrollment session expired — start over", 400),
    };

    // CSRF.
    let form        = req.form_data().await?;
    let csrf_form   = form_get(&form, "csrf").unwrap_or_default();
    let csrf_cookie = csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");
    if !csrf::verify(&csrf_form, csrf_cookie) {
        return Response::error("Bad Request", 400);
    }
    let submitted = form_get(&form, "code").unwrap_or_default();

    // Look up the enrollment row. Two ownership checks:
    // 1. Row exists.
    // 2. Row's user_id matches the authenticated session's user_id.
    //    This rejects a cookie that points at someone else's
    //    unconfirmed row.
    let totp_repo = CloudflareTotpAuthenticatorRepository::new(&env);
    let row = match totp_repo.find_by_id(&enroll_id).await {
        Ok(Some(r)) => r,
        _ => return Response::error("Enrollment session expired — start over", 400),
    };
    if row.user_id != session.user_id {
        // Forged enrollment cookie. Treat as expired without
        // revealing the cause.
        return Response::error("Enrollment session expired — start over", 400);
    }
    if row.confirmed_at.is_some() {
        // Already confirmed (double-submit, back-button replay).
        // Clear the cookie and bounce to home.
        return clear_enroll_cookie_and_redirect("/");
    }

    // Decrypt the secret and verify the submitted code.
    let key = match load_totp_encryption_key(&env)? {
        Some(k) => k,
        None    => return Response::error("TOTP is not configured", 503),
    };
    let aad = aad_for_id(&row.id);
    let secret = match decrypt_secret(&row.secret_ciphertext, &row.secret_nonce, &key, &aad) {
        Ok(s)  => s,
        Err(_) => return Response::error("totp secret decrypt failed", 500),
    };

    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let parsed   = parse_code(&submitted);
    let verify   = parsed.and_then(|c| verify_with_replay_protection(&secret, c, 0, now_unix));
    let new_step = match verify {
        Ok(s)  => s,
        Err(_) => {
            // Wrong code on first verify. Re-render the enroll
            // page so the user can try again with a fresh code
            // from their authenticator. We need to re-render
            // with the SAME secret — which means decrypting
            // again is unnecessary, we already have it. Re-emit
            // the QR + form.
            let secret_b32 = secret.to_base32();
            let email = read_user_email(&env, &session.user_id).await?
                .unwrap_or_else(|| session.user_id.clone());
            let uri = otpauth_uri(OTPAUTH_ISSUER, &email, &secret);
            let qr_svg = qr::otpauth_to_svg(&uri).unwrap_or_default();
            // Reuse CSRF token from cookie.
            let token = csrf::extract_from_cookie_header(&cookie_header)
                .map(str::to_owned)
                .unwrap_or_else(csrf::mint);
            // v0.31.0 P0-C: re-render with an inline error so the
            // user knows the previous code didn't match. Same
            // secret — they read the next 6-digit code from their
            // authenticator app and submit again.
            let html = templates::totp_enroll_page(
                &qr_svg,
                &secret_b32,
                &token,
                Some(
                    "入力されたコードが一致しませんでした。\
                     Authenticator アプリの最新の 6 桁を入力してください。",
                ),
            );
            let resp = Response::from_html(html)?;
            return Ok(resp);
        }
    };

    // Confirm the row.
    if let Err(e) = totp_repo.confirm(&row.id, new_step, now_unix).await {
        // NotFound here means we lost a concurrency race — the
        // row was already confirmed (or deleted) by another
        // request. Best-effort: redirect home rather than
        // surface the error.
        if matches!(e, PortError::NotFound) {
            return clear_enroll_cookie_and_redirect("/");
        }
        return Response::error("totp confirm failed", 500);
    }

    // Recovery codes: mint at the user's FIRST confirmed
    // enrollment only (ADR-009 §Q6). A user adding a backup
    // authenticator already has codes from their first
    // enrollment.
    let recovery_repo = CloudflareTotpRecoveryCodeRepository::new(&env);
    let existing_count = recovery_repo.count_remaining(&session.user_id).await.unwrap_or(0);
    let plaintext_codes: Vec<String> = if existing_count == 0 {
        let codes: Vec<RecoveryCode> = match generate_recovery_codes() {
            Ok(c)  => c,
            Err(_) => return Response::error("recovery code generation failed", 500),
        };
        let rows: Vec<TotpRecoveryCodeRow> = codes.iter().map(|c| {
            TotpRecoveryCodeRow {
                id:           Uuid::new_v4().to_string(),
                user_id:      session.user_id.clone(),
                code_hash:    hash_recovery_code(c.as_str()),
                redeemed_at:  None,
                created_at:   now_unix,
            }
        }).collect();
        if let Err(_) = recovery_repo.bulk_create(&rows).await {
            return Response::error("recovery code persistence failed", 500);
        }
        codes.iter().map(|c| c.as_str().to_owned()).collect()
    } else {
        // Already have codes from a prior enrollment. Don't
        // mint new ones — the user keeps their original set.
        // The recovery-codes page is skipped; the user lands
        // back on the Security Center with a success flash so
        // the new authenticator's "enabled" status is visible.
        return clear_enroll_cookie_and_redirect_with_flash(
            &env,
            "/me/security",
            flash::Flash::new(flash::FlashLevel::Success, flash::FlashKey::TotpEnabled),
        );
    };

    // Render the recovery-codes page once. The "continue" link
    // on this page points to /me/security, where the flash
    // we set here will display the success notice.
    //
    // Setting the flash on the recovery-codes-page response (not
    // a redirect) means the cookie is delivered while the user
    // is reading the codes; their next navigation (whether the
    // continue link or any other) carries it to the index.
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
