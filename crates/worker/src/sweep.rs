//! Daily retention sweeps. Triggered by Cloudflare Workers Cron
//! Trigger (configured in `wrangler.toml` `[triggers]`, schedule
//! `0 4 * * *` = 04:00 UTC daily).
//!
//! Two sweep passes run in sequence on each cron tick:
//!
//! 1. **Anonymous-trial retention** (v0.18.0, ADR-004 Phase 3).
//!    Lists every anonymous user row past the 7-day retention
//!    window, emits one `AnonymousExpired` audit event per row,
//!    and deletes the row. FK CASCADEs clean up
//!    `anonymous_sessions`, memberships, role assignments.
//! 2. **TOTP unconfirmed-enrollment cleanup** (v0.30.0,
//!    ADR-009 §Q9). Drops `totp_authenticators` rows where
//!    `confirmed_at IS NULL AND created_at < now - 24h`. The
//!    user abandoned enrollment; their next attempt produces a
//!    fresh row with a new secret. No audit per row — TOTP is
//!    a credential, not a principal, so there's no audit-trail
//!    invariant to preserve.
//!
//! ## Why both in one cron entry
//!
//! Two cron entries (one per sweep) would mean two cold-starts
//! per day, two log lines for "nothing to do", and two operator
//! checkboxes for "is this scheduled to run". Both sweeps are
//! cheap (<100 ms typical) so combining them is cleaner.
//!
//! ## List-then-delete shape
//!
//! Both sweeps use list-then-delete rather than a bare
//! `DELETE FROM ... WHERE`. For the anonymous sweep, this is to
//! emit one audit row per principal removed (ADR-004 §Q5). For
//! the TOTP sweep, no audit is emitted — but the same shape
//! makes the code uniform and lets the per-row failure mode
//! (one bad delete, log and continue) match across both sweeps.
//!
//! ## Failure semantics
//!
//! The sweep is **best-effort, not transactional**. If individual
//! row deletes fail, the handler logs and continues with the next
//! row; the next day's sweep retries the survivors. We do not
//! abort on first failure because the alternative (one bad row
//! blocking the whole sweep indefinitely) is worse for storage
//! growth than partial progress. Persistent failures show up as a
//! growing residual count visible to operators via the diagnostic
//! query in the operator runbook.

use cesauth_cf::ports::repo::CloudflareUserRepository;
use cesauth_core::anonymous::ANONYMOUS_USER_RETENTION_SECONDS;
use cesauth_core::ports::repo::UserRepository;
use time::OffsetDateTime;
use worker::Env;

use crate::audit::{self, EventKind};
use crate::log::{self, Category, Level};

/// Run one pass of the retention sweep. Called from the
/// `#[event(scheduled)]` handler. Returns `Ok(swept_count)` so the
/// caller can log a single summary line.
pub async fn run(env: &Env) -> worker::Result<usize> {
    let cfg = match crate::config::Config::from_env(env) {
        Ok(c)  => c,
        Err(e) => {
            // No config = no log level. Use the default (Info)
            // so the failure shows up at all.
            worker::console_error!("anonymous sweep config load failed: {e:?}");
            return Err(e);
        }
    };

    let now    = OffsetDateTime::now_utc().unix_timestamp();
    let cutoff = now - ANONYMOUS_USER_RETENTION_SECONDS;

    let users = CloudflareUserRepository::new(env);
    let expired = match users.list_anonymous_expired(cutoff).await {
        Ok(v)  => v,
        Err(e) => {
            log::emit(&cfg.log, Level::Error, Category::Storage,
                &format!("anonymous sweep list failed: {e:?}"), None);
            return Ok(0);
        }
    };

    if expired.is_empty() {
        log::emit(&cfg.log, Level::Info, Category::Storage,
            "anonymous sweep: nothing to do", None);
        return Ok(0);
    }

    let total = expired.len();
    let mut swept = 0_usize;
    for u in &expired {
        // Audit BEFORE delete — the audit log persistently records
        // the principal we're about to remove. If the delete then
        // fails for storage reasons, the audit row tells the
        // operator a principal was *intended* to be swept; the
        // diagnostic query then shows whether the row actually
        // disappeared. ADR-004 §Q5: audit trail integrity over
        // delete-then-audit ordering.
        audit::write_owned(
            env, EventKind::AnonymousExpired,
            Some(u.id.clone()),
            None,
            Some(format!(
                "via=anonymous-sweep,age_secs={}",
                now.saturating_sub(u.created_at),
            )),
        ).await.ok();

        match users.delete_by_id(&u.id).await {
            Ok(()) => {
                swept += 1;
            }
            Err(e) => {
                // Continue rather than abort — see module doc on
                // best-effort failure semantics. One row's
                // storage failure should not strand the rest of
                // the batch for another 24h.
                log::emit(&cfg.log, Level::Warn, Category::Storage,
                    &format!("anonymous sweep delete user_id={} failed: {e:?}",
                        u.id),
                    Some(&u.id));
            }
        }
    }

    log::emit(&cfg.log, Level::Info, Category::Storage,
        &format!("anonymous sweep complete: {swept}/{total} rows deleted"),
        None);

    // -- TOTP unconfirmed-enrollment sweep (v0.30.0, ADR-009 §Q9) --
    //
    // A user who starts TOTP enrollment but never confirms (closed
    // the tab, switched devices, etc.) leaves a row in
    // `totp_authenticators` with `confirmed_at IS NULL`. Per
    // ADR-009 §Q9 we prune these after 24 hours: long enough that
    // a user who got distracted can come back the same day, short
    // enough that abandoned enrollment doesn't pollute storage
    // indefinitely. The cleanup runs as a follow-up to the
    // anonymous-trial sweep (same cron entry — no separate
    // schedule needed; both are cheap).
    //
    // The partial index `idx_totp_authenticators_unconfirmed`
    // (created in migration 0007) keeps the lookup query cheap
    // even at large scale: SQLite uses the partial index because
    // the WHERE clause matches its filter exactly.
    //
    // Same best-effort failure semantics as the anonymous sweep:
    // per-row delete failures are logged and skipped; the next
    // day's run retries. No audit emission per row — unlike
    // anonymous user deletion (which removes a principal), TOTP
    // cleanup removes a half-finished credential the user
    // explicitly abandoned. The before/after row counts are
    // visible to operators in the log line below.
    let totp_swept = totp_unconfirmed_sweep(env, &cfg, now).await;
    log::emit(&cfg.log, Level::Info, Category::Storage,
        &format!("totp unconfirmed sweep complete: {totp_swept} rows deleted"),
        None);

    Ok(swept)
}

/// 24-hour TOTP unconfirmed-enrollment retention window. ADR-009 §Q9.
///
/// Generous enough that a user who starts enrollment, gets
/// distracted, and comes back the next day finds their flow is
/// clean (the abandoned row was pruned and a fresh GET produces
/// a new row with a new secret). Tight enough that abandoned
/// enrollments don't accumulate forever.
const TOTP_UNCONFIRMED_RETENTION_SECONDS: i64 = 86_400;

/// Inner helper for the TOTP cron extension. Lists rows where
/// `confirmed_at IS NULL AND created_at < cutoff`, then deletes
/// them one by one. Returns the count that were actually
/// deleted.
///
/// Best-effort: per-row delete failures are logged and skipped.
/// The function never returns an error to the caller — the
/// outer `run` keeps the anonymous-sweep return value as its
/// result. Storage failures during list will surface as
/// `totp_swept = 0` and a log line; storage failures during
/// individual deletes will not change the return value of the
/// sibling anonymous sweep.
async fn totp_unconfirmed_sweep(
    env: &Env,
    cfg: &crate::config::Config,
    now: i64,
) -> usize {
    use cesauth_cf::ports::repo::CloudflareTotpAuthenticatorRepository;
    use cesauth_core::totp::storage::TotpAuthenticatorRepository;

    let repo = CloudflareTotpAuthenticatorRepository::new(env);
    let cutoff = now - TOTP_UNCONFIRMED_RETENTION_SECONDS;

    let ids = match repo.list_unconfirmed_older_than(cutoff).await {
        Ok(v)  => v,
        Err(e) => {
            log::emit(&cfg.log, Level::Error, Category::Storage,
                &format!("totp unconfirmed sweep list failed: {e:?}"), None);
            return 0;
        }
    };

    if ids.is_empty() {
        return 0;
    }

    let mut deleted = 0_usize;
    for id in &ids {
        match repo.delete(id).await {
            Ok(()) => { deleted += 1; }
            Err(e) => {
                // Skip and continue — same best-effort policy
                // as the anonymous sweep. Persistent failures
                // show up as a non-zero residual in the daily
                // log line.
                log::emit(&cfg.log, Level::Warn, Category::Storage,
                    &format!("totp unconfirmed sweep delete id={id} failed: {e:?}"),
                    None);
            }
        }
    }

    deleted
}
