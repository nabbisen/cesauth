//! WebAuthn registration ceremony (`/webauthn/register/{start,finish}`).
//!
//! **RFC 172 (P0, 2026-11-03): the subject comes from the session.**
//! `register_start` used to read the account it was registering a passkey
//! for out of the request body, with no credential check at all —
//! `register_finish` would then write an authenticator for that account
//! and sign the caller in as it (`post_auth::complete_auth`, under the
//! comment "Registration doubles as a first-login"). Given a user id, that
//! was account takeover in two unauthenticated requests. `register_start`
//! now resolves a session first (`me_auth::resolve_or_redirect`) and takes
//! the subject from it; the request body no longer carries one. No live
//! caller existed either way (RFC 152 half D stage 1's own grep, re-
//! confirmed here), so this is not a caller-obligation change.
//!
//! **CSRF (RFC 152 half D stage 1 named `N/A (no ambient credential)`
//! here; RFC 172 supersedes that for `register_start`, which now reads
//! one).** Both routes require `Content-Type: application/json`
//! (`crate::csrf::require_json_content_type`, the same control
//! `authenticate_finish` and `/me/security/delete-account` carry):
//! `register_start` because it now consults the session cookie
//! `resolve_or_redirect` reads; `register_finish` because it already
//! captured `cookie_header` for `post_auth::extract_pending_handle` →
//! `complete_auth`, the identical shape `authenticate_finish` carries the
//! control for — stage 1b left this row for this cycle rather than
//! editing a file RFC 172 was about to rewrite anyway.

use cesauth_cf::ports::repo::CloudflareAuthenticatorRepository;
use cesauth_cf::ports::store::CloudflareAuthChallengeStore;
use cesauth_core::ports::repo::AuthenticatorRepository;
use cesauth_core::ports::store::{AuthChallengeStore, AuthMethod, Challenge};
use cesauth_core::webauthn::registration;
use serde::Deserialize;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::config::Config;
use crate::error::oauth_error_response;
use crate::post_auth;
use crate::routes::me::auth as me_auth;

use super::rp_from_config;

/// `{"error": "not authenticated"}`, 401, `cache-control: no-store` — the
/// same shape `deletions.rs`'s own `json_response` gives, inlined here
/// rather than shared across files for one caller each. RFC 149 §2's
/// ruling: a JSON route answers 401 on an unauthenticated caller, never a
/// 302 — a redirect-following client cannot tell a 302-to-success from a
/// 302-to-failure.
fn not_authenticated() -> Result<Response> {
    let mut resp = Response::from_json(&serde_json::json!({ "error": "not authenticated" }))?
        .with_status(401);
    resp.headers_mut().set("cache-control", "no-store").ok();
    Ok(resp)
}

// -------------------------------------------------------------------------
// POST /webauthn/register/start
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct RegisterStartBody {
    preferred_name: Option<String>,
}

/// **RFC 172's whole fix, as one pure, host-testable decision.** The
/// subject a registration challenge mints for is the session's user id —
/// always, and `RegisterStartBody` is not a parameter here, because it no
/// longer carries anything that could name a different one (the field
/// this function would have had to ignore was deleted, not just unread).
///
/// This exists because the actual call site, `register_start`, needs a
/// real `worker::Request`/`SessionState` and is not host-testable (the
/// same boundary this crate draws everywhere else — see `tenant_admin/
/// overview.rs`'s own `classify_overview_status` for the pattern this
/// follows). RFC 000 §22.2's sibling lesson, restated in this RFC's own
/// §5: *"testing the outcome type is not testing the caller that reports
/// it"* — a `core`-level test of `registration::start` cannot see which
/// argument reached it, only that the function it reached is well-formed;
/// this is the one place in the route layer where RFC 172's own property
/// — the subject a REQUEST can choose — is decided.
fn registration_subject(session_user_id: &cesauth_core::types::UserId) -> Option<String> {
    Some(session_user_id.to_string())
}

pub async fn register_start<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    // RFC 172 (P0, 2026-11-03): the subject comes from the session, never
    // from the caller. This used to read `user_id` straight out of the
    // request body with no credential check at all -- a registration
    // challenge, and after `finish`, a session, for any account whose id
    // an anonymous caller named. Resolved first, before anything else in
    // this handler.
    let session = match me_auth::resolve_or_redirect(&req, &ctx.env).await? {
        Ok(s)  => s,
        Err(_) => return not_authenticated(),
    };
    // This route now reads an ambient credential (the session cookie
    // `resolve_or_redirect` just consulted) for the first time -- the
    // same reason `authenticate_finish`/`delete-account` carry this
    // control applies here too, newly, by the same test RFC 152 half D
    // stage 1b corrected `authenticate_start` with: a route either reads
    // an ambient credential and needs the control, or it doesn't and
    // claiming one would be the same overstatement half D keeps finding.
    if let Some(resp) = crate::csrf::require_json_content_type(&req)? {
        return Ok(resp);
    }

    let cfg  = Config::from_env(&ctx.env)?;
    let rp   = rp_from_config(&cfg);
    let body: RegisterStartBody = req.json().await.unwrap_or_default();

    // `registration::start`'s `user_id: Option<String>` parameter is kept
    // (not removed) and always filled with `Some(..)` here -- the `None`
    // branch mints a UUID with no `users` row behind it, which
    // `register_finish`'s own "the user was created before this challenge
    // was issued" assumption does not survive (RFC 172 §4.1). After this
    // fix the `None` branch has no production caller; it stays for
    // `registration::start`'s own two existing `core` tests, which is a
    // reachability fact for RFC 166 to record, not this fix's to act on.
    let (challenge, state) = match registration::start(&rp, registration_subject(&session.user_id), body.preferred_name.as_deref()) {
        Ok(v)  => v,
        Err(e) => return oauth_error_response(&e),
    };

    let handle = cesauth_core::types::ChallengeHandle::mint();
    let now    = OffsetDateTime::now_utc().unix_timestamp();

    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    let chal  = Challenge::WebauthnRegister {
        user_id:    state.user_id.clone(),
        challenge:  state.inner["challenge"].as_str().unwrap_or_default().to_owned(),
        expires_at: now + 60,
    };
    if store.put(&handle, &chal).await.is_err() {
        return oauth_error_response(&cesauth_core::CoreError::Internal);
    }

    #[derive(serde::Serialize)]
    struct Reply {
        handle:     String,
        public_key: serde_json::Value,
    }
    Response::from_json(&Reply { handle: handle.to_string(), public_key: challenge.public_key })
}

// -------------------------------------------------------------------------
// POST /webauthn/register/finish
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RegisterFinishBody {
    handle:   String,
    response: registration::RegistrationResponse,
}

pub async fn register_finish<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    // RFC 172 (stage 1b left this cell for this cycle): the identical
    // shape `authenticate_finish` already carries the control for. Both
    // capture `cookie_header` below for `post_auth::extract_pending_handle`
    // -> `complete_auth`, which reads `login_next` -- an ambient credential,
    // same as `authenticate_finish`'s.
    if let Some(resp) = crate::csrf::require_json_content_type(&req)? {
        return Ok(resp);
    }

    // RFC 172 §4.1: `register_start`'s fix already binds this ceremony's
    // subject to the session that started it (the challenge can only
    // carry a session-derived `user_id` now). An *additional* "does the
    // current request also carry a valid session" check here was
    // considered and deliberately NOT added: the challenge handle is a
    // single-consumption, 60-second-bound, high-entropy token (the same
    // shape every other challenge/CSRF token in this crate uses) -- not
    // guessable, not replayable -- so nothing short of possessing the
    // handle itself (which only the browser `start` responded to ever
    // saw) can reach this point. A naive "some session exists" check
    // without ALSO verifying it matches the challenge's bound `user_id`
    // would be strictly worse than no check: it would let a second,
    // currently-valid session complete someone else's pending
    // registration and be signed in as THEM via `complete_auth` below,
    // which uses the challenge's subject, not the checking session's.
    // Doing that correctly is a real design decision, not an improvised
    // addition to a P0 fix; left to its own cycle if the owner wants it.
    let cfg  = Config::from_env(&ctx.env)?;
    let rp   = rp_from_config(&cfg);

    // Capture the cookie header before consuming the body. We need
    // the pending handle for OAuth flow continuation AND the full
    // header so complete_auth can read the login_next cookie.
    let cookie_header = req.headers().get("cookie").ok().flatten();
    let pending = cookie_header.as_deref()
        .and_then(|h| post_auth::extract_pending_handle(h).map(str::to_owned));

    let body: RegisterFinishBody = match req.json().await {
        Ok(b)  => b,
        Err(_) => return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("body")),
    };

    // Consume the challenge. After this call, a replay of the same
    // handle returns None; this is the single-consumption guarantee.
    let store = CloudflareAuthChallengeStore::new(&ctx.env);
    // RFC 140: one clock for the request, read before the challenge is
    // taken so the store can enforce its expiry.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let chal  = match store.take(&cesauth_core::types::ChallengeHandle::from_storage(&body.handle), now).await {
        Ok(Some(c)) => c,
        _ => return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("handle")),
    };

    let state = match chal {
        Challenge::WebauthnRegister { user_id, challenge, .. } => registration::RegistrationState {
            inner:   serde_json::json!({ "challenge": challenge }),
            user_id,
        },
        _ => return oauth_error_response(&cesauth_core::CoreError::InvalidRequest("handle not register")),
    };


    // RFC 051: look up tenant_id for the authenticator record.
    // The user was created before this registration challenge was issued;
    // fall back to 'tenant-default' if the lookup fails (defence-in-depth).
    let tenant_id = {
        let user_repo = cesauth_cf::ports::repo::CloudflareUserRepository::new(&ctx.env);
        use cesauth_core::ports::repo::UserRepository;
        user_repo.find_by_id(&state.user_id).await
            .ok().flatten()
            .map(|u| u.tenant_id)
            .unwrap_or_else(|| "tenant-default".to_owned())
    };

    let authn = match registration::finish(&rp, &state, &body.response, &tenant_id, now) {
        Ok(a)  => a,
        Err(e) => {
            audit::write_owned(
                &ctx.env, EventKind::AuthFailed,
                Some(state.user_id.clone()), None,
                Some(format!("webauthn register finish: {e:?}")),
            ).await.ok();
            return oauth_error_response(&e);
        }
    };

    // Persist the authenticator row. On a storage failure we bail
    // without issuing a session - partial registration is worse than
    // asking the user to retry.
    let repo = CloudflareAuthenticatorRepository::new(&ctx.env);
    if let Err(e) = repo.create(&authn).await {
        audit::write_owned(
            &ctx.env, EventKind::AuthFailed,
            Some(authn.user_id.clone()), None,
            Some(format!("authenticator persist: {e:?}")),
        ).await.ok();
        return oauth_error_response(&cesauth_core::CoreError::Internal);
    }

    audit::write_owned(
        &ctx.env, EventKind::WebauthnRegistered,
        Some(authn.user_id.clone()), None, None,
    ).await.ok();

    // Registration doubles as a first-login: issue a session. If a
    // pending `/authorize` handle was carried on the cookie, honor it.
    post_auth::complete_auth(
        &ctx.env, &cfg, &authn.user_id, AuthMethod::Passkey,
        pending.as_deref(), cookie_header.as_deref(),
    ).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesauth_core::types::UserId;

    // RFC 172 §5's own witness requirement: not a reading, the subject a
    // REQUEST can choose. `RegisterStartBody` has no field that could
    // name one (see the struct above -- `user_id` was deleted, not left
    // unread), so the only thing left to pin is that the session's id is
    // what actually reaches `registration::start`.

    #[test]
    fn the_subject_is_always_the_sessions_user_id() {
        let session_id = UserId::from_storage("session-owner-id");
        assert_eq!(
            registration_subject(&session_id),
            Some("session-owner-id".to_owned()),
        );
    }

    #[test]
    fn a_different_session_produces_a_different_subject() {
        // Not a tautology: pins that the function is keyed on the
        // SESSION argument, not a constant -- if a future edit hardcoded
        // a value or ignored the argument, this is the test that would
        // catch it while the one above would not.
        let a = UserId::from_storage("alice");
        let b = UserId::from_storage("bob");
        assert_ne!(registration_subject(&a), registration_subject(&b));
        assert_eq!(registration_subject(&a), Some("alice".to_owned()));
        assert_eq!(registration_subject(&b), Some("bob".to_owned()));
    }
}
