//! `POST /revoke` — RFC 7009 token revocation.
//!
//! v0.27.0 shipped this as a public endpoint that anyone
//! could call with any token to revoke the underlying
//! family. v0.42.0 brings full RFC 7009 conformance:
//!
//! - **Confidential clients** (those with a
//!   `client_secret_hash` on file) MUST authenticate.
//! - **Public clients** revoke by token possession;
//!   client_id form field is still validated against
//!   the token's cid (cross-client revoke prevention).
//! - **Cid binding gate**: the authenticating /
//!   claiming client_id MUST match the token's cid.
//! - **Token type hint** form field is parsed and
//!   passed through (today only refresh-token
//!   revocation has any effect; access-token
//!   revocation is documented as unsupported per RFC
//!   7009 §2 which permits this).
//!
//! The wire response is **always 200 OK with empty
//! body** for well-formed requests, regardless of
//! outcome. RFC 7009 §2.2: "the response is either 200
//! with empty body for unauthorized or invalid token
//! types as well, since revealing them would allow
//! probing".
//!
//! v0.42.0 distinguishes the four outcomes in audit
//! events for operator visibility.

use cesauth_cf::ports::repo::CloudflareClientRepository;
use cesauth_cf::ports::store::CloudflareRefreshTokenFamilyStore;
use cesauth_core::service::revoke::{
    revoke_refresh_token, RevokeAuthMode, RevokeInput, RevokeOutcome,
    TokenTypeHint, UnauthorizedReason,
};
use time::OffsetDateTime;
use worker::{FormEntry, Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::client_auth as client_auth_extract;
use crate::config::Config;
use crate::log::{self, Category, Level};

pub async fn revoke<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let cfg = Config::from_env(&ctx.env)?;

    // RFC 7009 §2.1: the request body is form-encoded.
    let form = match req.form_data().await {
        Ok(f)  => f,
        Err(_) => {
            // Malformed body. RFC 7009 §2.2 says
            // unsupported_token_type / invalid_request
            // can be returned but we keep the
            // existing behavior (silent 200) for
            // robustness against scanner traffic.
            return Response::ok("");
        }
    };

    let token = match form.get("token") {
        Some(FormEntry::Field(v)) if !v.is_empty() => v,
        _ => {
            // Missing/empty token; per RFC 7009 §2.2
            // we could return 400 invalid_request,
            // but cesauth's existing revoke is
            // silent-200 for unrecognized tokens and
            // we keep that pattern.
            return Response::ok("");
        }
    };

    let hint = form.get("token_type_hint")
        .and_then(|e| match e { FormEntry::Field(v) => Some(v), _ => None })
        .and_then(|v| TokenTypeHint::parse(&v));

    // Extract client credentials. Authorization: Basic
    // takes precedence over form body (RFC 6749 §2.3.1).
    let creds = client_auth_extract::extract(req.headers(), &form);

    // Form-body client_id (when no creds present, this
    // is the only signal of who the requestor claims
    // to be — used for the cid-binding gate even on
    // public-client paths).
    let form_client_id = form.get("client_id")
        .and_then(|e| match e { FormEntry::Field(v) => Some(v), _ => None });

    // Resolve the requestor's claimed client_id.
    // Priority: Basic-header creds > form client_id.
    let req_client_id: Option<String> = creds.as_ref()
        .map(|c| c.client_id.clone())
        .or(form_client_id);

    let families = CloudflareRefreshTokenFamilyStore::new(&ctx.env);
    let clients  = CloudflareClientRepository::new(&ctx.env);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let outcome = revoke_refresh_token(&families, &clients, &RevokeInput {
        token:         &token,
        hint,
        client_id:     req_client_id.as_deref(),
        client_secret: creds.as_ref().map(|c| c.client_secret.as_str()),
        now_unix:      now,
    }).await
        .map_err(|e| worker::Error::RustError(format!("revoke failed: {e:?}")))?;

    // Audit: emit one event per request with outcome
    // attribution. The wire response is always
    // identical (200 empty); the audit stream is
    // where operators see the four-way breakdown.
    let (kind, payload_obj) = audit_payload_for(&outcome, req_client_id.as_deref());
    if let Some(payload_str) = payload_obj {
        audit::write_owned(
            &ctx.env, kind,
            None,                              // user_id not directly
                                               // available; the family DO
                                               // peek surfaced it but we
                                               // don't carry it through to
                                               // the audit row to keep the
                                               // privacy invariant
                                               // identical with the
                                               // public-client path.
            req_client_id.clone(),
            Some(payload_str),
        ).await.ok();
    }

    // Log line for operator dashboards.
    let log_msg = match &outcome {
        RevokeOutcome::Revoked { family_id, client_id, auth_mode } => format!(
            "revoke: ok family={family_id} client={client_id} auth={}",
            match auth_mode {
                RevokeAuthMode::PublicClient       => "public",
                RevokeAuthMode::ConfidentialClient => "confidential",
            },
        ),
        RevokeOutcome::NotRevocable  => "revoke: not_revocable".to_owned(),
        RevokeOutcome::UnknownFamily => "revoke: unknown_family".to_owned(),
        RevokeOutcome::Unauthorized { reason } => format!(
            "revoke: unauthorized reason={}",
            match reason {
                UnauthorizedReason::ConfidentialAuthFailed => "auth_failed",
                UnauthorizedReason::ClientIdCidMismatch    => "cid_mismatch",
            },
        ),
    };
    log::emit(&cfg.log, Level::Info, Category::Auth, &log_msg, req_client_id.as_deref());

    // RFC 7009 §2.2: always 200 empty body.
    Response::ok("")
}

/// Build the audit payload + select the audit kind for
/// a given outcome. Returns `(kind, Some(json))` for
/// outcomes worth recording; `(kind, None)` for cases
/// the audit chain can skip (NotRevocable carries no
/// useful information beyond "scanner traffic" and
/// would just bloat the chain — same call cesauth's
/// /token endpoint has been making since v0.4 for
/// malformed inputs).
fn audit_payload_for(outcome: &RevokeOutcome, req_client_id: Option<&str>) -> (EventKind, Option<String>) {
    let kind = EventKind::RevocationRequested;
    let payload = match outcome {
        RevokeOutcome::Revoked { family_id, client_id, auth_mode } => {
            let auth_str = match auth_mode {
                RevokeAuthMode::PublicClient       => "public",
                RevokeAuthMode::ConfidentialClient => "confidential",
            };
            Some(serde_json::json!({
                "outcome":   "revoked",
                "family_id": family_id,
                "client_id": client_id,
                "auth_mode": auth_str,
            }).to_string())
        }
        RevokeOutcome::Unauthorized { reason } => {
            let reason_str = match reason {
                UnauthorizedReason::ConfidentialAuthFailed => "auth_failed",
                UnauthorizedReason::ClientIdCidMismatch    => "cid_mismatch",
            };
            Some(serde_json::json!({
                "outcome":          "unauthorized",
                "reason":           reason_str,
                "req_client_id":    req_client_id,
            }).to_string())
        }
        RevokeOutcome::UnknownFamily => {
            // Operator-visible: "someone is replaying
            // an old refresh token whose family was
            // already swept". Not an attack, but a
            // useful signal of clock-skew or stale
            // client integrations. Emit so it's
            // countable.
            Some(serde_json::json!({
                "outcome": "unknown_family",
            }).to_string())
        }
        RevokeOutcome::NotRevocable => None,
    };
    (kind, payload)
}
