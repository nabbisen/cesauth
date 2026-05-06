//! `GET /admin/console/audit/chain` — chain verification status.
//! `POST /admin/console/audit/chain/verify` — operator-triggered
//! full re-verification.
//!
//! Phase 2 of ADR-010 (v0.33.0). The cron at 04:00 UTC runs an
//! incremental verification daily and writes the outcome to the
//! KV checkpoint store. This handler renders that outcome plus
//! a button for an immediate full re-walk.
//!
//! The chain status is read-only so any role with
//! `AdminAction::ViewConsole` is allowed. The verify-now button
//! also gates on `ViewConsole` (no separate permission) because
//! a full re-walk is a non-destructive read operation that
//! produces a fresher status; an attacker who triggers it gains
//! nothing — the result is what the chain says, not what the
//! attacker says.

use cesauth_cf::ports::audit::CloudflareAuditEventRepository;
use cesauth_cf::ports::audit_chain::CloudflareAuditChainCheckpointStore;
use cesauth_core::admin::types::{AdminAction, AuditChainStatus};
use cesauth_core::audit::verifier::verify_chain_full;
use cesauth_core::ports::audit::AuditEventRepository;
use cesauth_core::ports::audit_chain::AuditChainCheckpointStore;
use cesauth_ui as ui;
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::csrf;
use crate::routes::admin::auth;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ViewConsole) {
        return Ok(r);
    }

    let status = read_status(&ctx.env).await?;

    // CSRF for the verify-now POST below. Mint or reuse.
    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let existing = csrf::extract_from_cookie_header(&cookie_header).map(str::to_owned);
    let (csrf_token, set_cookie) = match existing {
        Some(t) if !t.is_empty() => (t, None),
        _ => {
            let t = match csrf::mint() {
            Ok(tok) => tok,
            Err(_) => {
                crate::audit::write_owned(
                    &ctx.env, crate::audit::EventKind::CsrfRngFailure,
                    None, None, Some("route=/admin/console/audit/chain".to_owned()),
                ).await.ok();
                return Response::error("service temporarily unavailable", 500);
            }
        };
            let h = csrf::set_cookie_header(&t);
            (t, Some(h))
        }
    };


    // **v0.52.0 (RFC 006)** — generate per-request CSP nonce and register
    // it with the UI render layer before calling any template function.
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
    cesauth_ui::set_render_nonce(csp_nonce.as_str());
    let html = ui::admin::audit_chain_status_page(&principal, &status, &csrf_token);
    let mut resp = Response::from_html(html)?;
    if let Some(h) = set_cookie {
        resp.headers_mut().append("set-cookie", &h).ok();
    }
    Ok(resp)
}

pub async fn verify_now<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ViewConsole) {
        return Ok(r);
    }

    // CSRF.
    let cookie_header = req.headers().get("cookie").ok().flatten().unwrap_or_default();
    let form = req.form_data().await?;
    let csrf_form = match form.get("csrf") {
        Some(worker::FormEntry::Field(v)) => v,
        _ => String::new(),
    };
    let csrf_cookie = csrf::extract_from_cookie_header(&cookie_header).unwrap_or("");
    if !csrf::verify(&csrf_form, csrf_cookie) {
        return Response::error("Bad Request", 400);
    }

    let repo        = CloudflareAuditEventRepository::new(&ctx.env);
    let checkpoints = CloudflareAuditChainCheckpointStore::new(&ctx.env);
    let now_unix    = OffsetDateTime::now_utc().unix_timestamp();

    // Ignore errors at this layer — the result (success or
    // failure) is persisted by `verify_chain_full` itself, and
    // the redirect lands the operator on the status page where
    // they see what happened. A propagated error would just
    // produce a 500 with no useful info.
    let _ = verify_chain_full(&repo, &checkpoints, now_unix).await;

    let mut resp = Response::empty()?.with_status(302);
    resp.headers_mut().set("location", "/admin/console/audit/chain").ok();
    Ok(resp)
}

async fn read_status(env: &worker::Env) -> Result<AuditChainStatus> {
    let repo        = CloudflareAuditEventRepository::new(env);
    let checkpoints = CloudflareAuditChainCheckpointStore::new(env);

    let tail = repo.tail().await
        .map_err(|e| worker::Error::RustError(format!("audit tail read failed: {e:?}")))?;
    let last = checkpoints.read_last_result().await
        .map_err(|e| worker::Error::RustError(format!("checkpoint last_result read failed: {e:?}")))?;
    let cp = checkpoints.read_checkpoint().await
        .map_err(|e| worker::Error::RustError(format!("checkpoint read failed: {e:?}")))?;

    let current_chain_length = tail.as_ref().map(|t| t.seq).unwrap_or(0);
    let growth_since_checkpoint = match (cp.as_ref(), tail.as_ref()) {
        (Some(c), Some(t)) => t.seq > c.last_verified_seq,
        // No checkpoint yet → growth is "everything", show the
        // hint only if there are rows to walk.
        (None, Some(_))    => current_chain_length > 0,
        _                  => false,
    };

    Ok(AuditChainStatus {
        current_chain_length,
        last_run_at:               last.as_ref().map(|r| r.run_at),
        last_run_valid:            last.as_ref().map(|r| r.valid),
        last_run_first_mismatch:   last.as_ref().and_then(|r| r.first_mismatch_seq),
        last_run_checkpoint_match: last.as_ref().and_then(|r| r.checkpoint_consistent),
        last_run_rows_walked:      last.as_ref().map(|r| r.rows_walked),
        checkpoint_seq:            cp.as_ref().map(|c| c.last_verified_seq),
        checkpoint_chain_hash:     cp.as_ref().map(|c| c.chain_hash.clone()),
        checkpoint_at:             cp.as_ref().map(|c| c.verified_at),
        growth_since_checkpoint,
    })
}
