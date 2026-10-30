//! `GET /admin/console/audit/chain` — chain verification status.
//! `POST /admin/console/audit/chain/verify` — operator-triggered
//! full re-verification.
//!
//! Phase 2 of ADR-010 (v0.33.0). The cron at 04:00 UTC runs an
//! incremental verification daily and writes the outcome to the
//! KV checkpoint store. **`GET /admin/console/audit/chain` serves the
//! Leptos shell only** — rendering that outcome and a button for an
//! immediate full re-walk is the part this doc used to claim and the
//! handler doesn't do. See RFC 161.
//!
//! `POST /admin/console/audit/chain/verify` is real and unaffected by
//! the above, and the rest of this comment describes it:
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
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::csrf;
use crate::routes::admin::auth;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "監査チェーン — cesauth").await
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
