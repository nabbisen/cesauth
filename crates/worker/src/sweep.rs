//! Anonymous-trial daily retention sweep (v0.18.0, ADR-004 Phase 3).
//!
//! Triggered by Cloudflare Workers Cron Trigger (configured in
//! `wrangler.toml` `[triggers]`, schedule `0 4 * * *` = 04:00 UTC
//! daily). The handler:
//!
//! 1. Lists every anonymous user row past the retention window
//!    (`account_type='anonymous' AND email IS NULL AND
//!    created_at < now - 7d`).
//! 2. Emits one `AnonymousExpired` audit event per row.
//! 3. Deletes each row. FK CASCADEs clean up
//!    `anonymous_sessions`, memberships, role assignments.
//!
//! The list-then-delete shape is deliberate: it gives us one audit
//! row per principal removed (not just a row count), and it makes
//! the sweep idempotent — a second run within the same 24h window
//! finds nothing new and emits nothing. ADR-004 §Q3 + §Q5 are
//! the load-bearing design references.
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
//!
//! ## Why not a single SQL DELETE
//!
//! `DELETE FROM users WHERE ... ` would be one round-trip, but it
//! gives us no per-row audit and no operator-visible signal of
//! *which* principals were swept. Audit trail integrity (ADR-004
//! §Q5: the user_id is queryable across the row's lifetime, even
//! after deletion) is worth the extra round-trips. For the
//! expected steady-state volume (anonymous trials per day in the
//! tens-to-hundreds), the cost is irrelevant.

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

    Ok(swept)
}
