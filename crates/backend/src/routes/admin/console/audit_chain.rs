//! `GET /admin/console/audit/chain` — chain verification status.
//! `GET /admin/console/audit/chain.json` — the status as JSON
//! (RFC 131 §0 slice 2).
//! `POST /admin/console/audit/chain/verify` — operator-triggered
//! full re-verification.
//!
//! Phase 2 of ADR-010 (v0.33.0). The cron at 04:00 UTC runs an
//! incremental verification daily and writes the outcome to the
//! KV checkpoint store. `read_status` assembles that outcome;
//! until this slice it had no caller at all — `cargo check`
//! printed `function read_status is never used` since `580eeba`.
//!
//! Both GET handlers call [`auth::ensure_role_allows`] with
//! `AdminAction::ViewConsole` (RFC 161 §6.3's first dropped
//! control — same reasoning as slice 1's `audit.rs`). `page`
//! additionally writes `EventKind::AdminConsoleViewed`
//! (RFC 161 §6.3's second control, best-effort — a failed write
//! must not block the render). `page_json` does not write one:
//! `page` already recorded this navigation, and a re-fetch from
//! the component (e.g. after verify-now's redirect) is continued
//! use of an already-recorded view, same discipline as slice 1's
//! `audit.json`.
//!
//! **Deliberately not routed through `operator_json_api::shell`**,
//! for both GET handlers — that helper discards the resolved
//! principal and has no role-check/audit-write hook; widening its
//! contract would land on the other five not-yet-built consoles
//! too, unreviewed. See slice 1's `audit.rs:16-21`, whose reasoning
//! carries unchanged.
//!
//! `POST /admin/console/audit/chain/verify` gates on
//! `AdminAction::ViewConsole`, same as the two GET handlers — **this
//! is a write, not a read.** It triggers a full re-walk
//! (`verify_chain_full`) that persists a fresh
//! `AuditVerificationResult` and, on success, advances the chain-head
//! checkpoint. RFC 184 found that premise stated backwards in this
//! module's own prior doc comment ("a full re-walk is a non-destructive
//! read operation"): a re-walk writes, and because that write was
//! unconditional, anyone who could reach this route — `ViewConsole` is
//! every valid role, `Role::ReadOnly` included — could silently replace
//! a detected `valid: false` alarm with a clean result and re-baseline
//! the checkpoint over it, one button press, no confirmation, no
//! record. `ViewConsole` is kept on this route anyway (RFC 184 §5.5,
//! owner-accepted): what makes that safe now is not the permission, but
//! that `cesauth_core::audit::verifier::persist_result` refuses to let
//! a later run erase an unacknowledged alarm or advance the checkpoint
//! over one (RFC 184 §3.1/§3.2) — the button can no longer destroy
//! anything, so gating it no tighter than "may look at this page" is
//! defensible again. Every invocation is audited
//! (`EventKind::AdminAuditChainVerified`), which this module's prior
//! version also did not do despite `route-contracts.md` having claimed
//! it under the name `audit_chain_verified` since RFC 131 §0 slice 2.
//!
//! `POST /admin/console/audit/chain/acknowledge` is the one route that
//! CAN clear a standing alarm (RFC 184 §3.3) — it requires
//! `AdminAction::AcknowledgeTamperAlarm` (Security+, not `ReadOnly`),
//! matching `VerifyBucketSafety`'s tier: asserting that a tamper
//! finding has been dealt with is not an inspection, the same
//! reasoning that action's own doc comment gives. It is a no-op (no
//! write, no audit event) when there is nothing unacknowledged to
//! clear, so pressing it twice, or pressing it when the chain is
//! currently clean, is harmless.
//!
//! **RFC 184 round 2.** `verify_now`'s audit detail used to be built
//! from `persist_result`'s return value directly — which, on a refusal,
//! is the standing alarm, not what this press's own walk found. That
//! made "the walk found the same tamper again" and "the walk found the
//! chain clean, and the write was refused" produce byte-identical audit
//! rows, discarding exactly the signature a wholesale rewrite leaves
//! (a standing alarm plus an independently-clean full walk). The detail
//! below now reads `outcome.refused_clean_walk` and says so explicitly
//! when it is `Some`.

use cesauth_cf::ports::audit::CloudflareAuditEventRepository;
use cesauth_cf::ports::audit_chain::CloudflareAuditChainCheckpointStore;
use cesauth_core::admin::types::{AdminAction, AuditChainStatus};
use cesauth_core::audit::verifier::verify_chain_full;
use cesauth_core::ports::audit::AuditEventRepository;
use cesauth_core::ports::audit_chain::{AuditChainCheckpointStore, AuditVerificationResult};
use time::OffsetDateTime;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::csrf;
use crate::require_system_admin;
use crate::routes::admin::auth;

// -------------------------------------------------------------------------
// GET /admin/console/audit/chain
// -------------------------------------------------------------------------

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    require_system_admin!(req, ctx, principal, AdminAction::ViewConsole);

    // Best-effort, same discipline as slice 1's `audit.rs::page` —
    // the operator already has the data; losing the record of
    // having looked is the lesser failure.
    audit::write_owned(&ctx.env, EventKind::AdminConsoleViewed, Some(principal.id.clone()), None, None)
        .await.ok();

    // RFC 185 §5.3 screen 2 — this route now negotiates: `resolve_locale`
    // reads `Accept-Language` instead of a hardcoded `Locale::Ja`, same
    // pattern as slice 1's `audit.rs::page`.
    let locale = crate::i18n::resolve_locale(&req);
    let title = format!("{} — cesauth", cesauth_core::i18n::lookup(cesauth_core::i18n::MessageKey::AuditChainPageTitle, locale));
    crate::routes::leptos_shell::leptos_html_shell(&req, &ctx.env, &title, locale).await
}

// -------------------------------------------------------------------------
// GET /admin/console/audit/chain.json
// -------------------------------------------------------------------------

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    require_system_admin!(req, ctx, _principal, AdminAction::ViewConsole);

    let status = match read_status(&ctx.env).await {
        Ok(s)  => s,
        Err(e) => return Response::error(format!("chain status read failed: {e}"), 500),
    };

    let csrf_token = csrf::mint()
        .map_err(|_| worker::Error::RustError("csrf rng failed".into()))?;
    let set_cookie = csrf::set_cookie_header(&csrf_token);

    let mut payload = serde_json::to_value(&status)
        .map_err(|e| worker::Error::RustError(format!("chain status serialize failed: {e}")))?;
    if let serde_json::Value::Object(ref mut map) = payload {
        map.insert("csrf_token".to_owned(), serde_json::Value::String(csrf_token));
    }

    let mut resp = Response::from_json(&payload)?;
    resp.headers_mut().append("set-cookie", &set_cookie).ok();
    resp.headers_mut().set("cache-control", "no-store").ok();
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
    //
    // RFC 184 round 2 §2 — the audit detail must distinguish "the
    // walk found the same tamper again" from "the walk found the
    // chain clean, and the write was refused": a standing alarm
    // plus an independently-clean full walk is the signature of a
    // wholesale rewrite, and the two cases used to produce
    // byte-identical details. `outcome.refused_clean_walk` carries
    // the fresh verdict `persist_result` threw away everywhere
    // else, so this handler can say what THIS press actually found.
    if let Ok(outcome) = verify_chain_full(&repo, &checkpoints, now_unix).await {
        let detail = match &outcome.refused_clean_walk {
            None => format!(
                "valid={} first_mismatch_seq={:?} rows_walked={}",
                outcome.stored.valid, outcome.stored.first_mismatch_seq, outcome.stored.rows_walked,
            ),
            Some(fresh) => format!(
                "valid={} first_mismatch_seq={:?} rows_walked={} \
                 refused_clean_walk=true fresh_valid={} fresh_rows_walked={} fresh_chain_length={}",
                outcome.stored.valid, outcome.stored.first_mismatch_seq, outcome.stored.rows_walked,
                fresh.valid, fresh.rows_walked, fresh.chain_length,
            ),
        };
        audit::write_owned(
            &ctx.env,
            EventKind::AdminAuditChainVerified,
            Some(principal.id.clone()),
            None,
            Some(detail),
        ).await.ok();
    }

    let mut resp = Response::empty()?.with_status(302);
    resp.headers_mut().set("location", "/admin/console/audit/chain").ok();
    Ok(resp)
}

// -------------------------------------------------------------------------
// POST /admin/console/audit/chain/acknowledge
// -------------------------------------------------------------------------

/// **RFC 184 §3.3.** The only route that can clear a standing tamper
/// alarm. Requires `AdminAction::AcknowledgeTamperAlarm` — Security+,
/// not `ReadOnly` — because this is an assertion that a finding has
/// been dealt with, not an inspection of the chain. A no-op when there
/// is nothing unacknowledged to clear: no write, no audit event,
/// idempotent redirect.
pub async fn acknowledge<D>(mut req: Request, ctx: RouteContext<D>) -> Result<Response> {
    require_system_admin!(req, ctx, principal, AdminAction::AcknowledgeTamperAlarm);

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

    let checkpoints = CloudflareAuditChainCheckpointStore::new(&ctx.env);
    let current = checkpoints.read_last_result().await
        .map_err(|e| worker::Error::RustError(format!("checkpoint last_result read failed: {e:?}")))?;

    if let Some(r) = current {
        if !r.valid && !r.acknowledged {
            let first_mismatch_seq = r.first_mismatch_seq;
            let run_at             = r.run_at;
            let acked = AuditVerificationResult {
                acknowledged: true,
                ..r
            };
            checkpoints.write_last_result(&acked).await
                .map_err(|e| worker::Error::RustError(format!("checkpoint last_result write failed: {e:?}")))?;

            audit::write_owned(
                &ctx.env,
                EventKind::AdminAuditChainAlarmAcknowledged,
                Some(principal.id.clone()),
                None,
                Some(format!(
                    "acknowledged_run_at={run_at} first_mismatch_seq={first_mismatch_seq:?}",
                )),
            ).await.ok();
        }
        // `r.valid` or already `r.acknowledged` — nothing to do.
    }

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
        last_run_acknowledged:     last.as_ref().map(|r| r.acknowledged),
        last_run_rows_walked:      last.as_ref().map(|r| r.rows_walked),
        checkpoint_seq:            cp.as_ref().map(|c| c.last_verified_seq),
        checkpoint_chain_hash:     cp.as_ref().map(|c| c.chain_hash.clone()),
        checkpoint_at:             cp.as_ref().map(|c| c.verified_at),
        growth_since_checkpoint,
    })
}
