//! Cloudflare D1 adapter for `SessionIndexRepo` (v0.49.0,
//! ADR-012 §Q1.5).
//!
//! Reads + repairs against the `user_sessions` D1 table.
//! Used by the v0.49.0 `audit_repair_cron` pass to bring
//! the D1 mirror in line with the DO state.
//!
//! ## Why a dedicated adapter file
//!
//! Pre-v0.49.0 the reconcile cron's D1 reads were inline
//! in `crates/worker/src/session_index_audit.rs` (see
//! `fetch_active_rows`). v0.49.0 introduces the
//! `SessionIndexRepo` port in core, so the read +
//! mutation methods live in this adapter instead. The
//! reconcile cron will switch to using the port too as
//! a follow-up — for v0.49.0 we leave `fetch_active_rows`
//! as is to keep the repair-pass change minimally
//! invasive.

use cesauth_core::ports::session_index::{SessionIndexRepo, SessionIndexRow};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::Env;

use super::repo::{d1_int, db, run_err};

/// Cloudflare D1-backed implementation. The lifetime is
/// borrowed against the `Env` passed in by the worker
/// runtime.
pub struct CloudflareSessionIndexRepo<'a> {
    env: &'a Env,
}

impl<'a> CloudflareSessionIndexRepo<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }
}

#[derive(Deserialize)]
struct DbRow {
    session_id: String,
    user_id:    String,
    created_at: i64,
    revoked_at: Option<i64>,
}

impl DbRow {
    fn into_domain(self) -> SessionIndexRow {
        SessionIndexRow {
            session_id: self.session_id,
            user_id:    self.user_id,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
        }
    }
}

impl SessionIndexRepo for CloudflareSessionIndexRepo<'_> {
    async fn list_active(&self, limit: u32) -> PortResult<Vec<SessionIndexRow>> {
        let db = db(self.env)?;
        // Same shape as the v0.40.0 inline reconcile read,
        // ordered oldest-first so long-pending drifts
        // surface even on busy deployments.
        let limit_val = limit.min(10_000) as i64;
        let stmt = db.prepare(
            "SELECT session_id, user_id, created_at, revoked_at \
             FROM user_sessions \
             WHERE revoked_at IS NULL \
             ORDER BY created_at ASC \
             LIMIT ?1",
        )
        .bind(&[d1_int(limit_val)])
        .map_err(|e| run_err("session_index.list_active bind", e))?;

        let result = stmt.all().await.map_err(|_| PortError::Unavailable)?;
        let rows = result.results::<DbRow>().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(DbRow::into_domain).collect())
    }

    async fn delete_row(&self, session_id: &str) -> PortResult<()> {
        let db = db(self.env)?;
        let stmt = db.prepare(
            "DELETE FROM user_sessions WHERE session_id = ?1",
        )
        .bind(&[worker::wasm_bindgen::JsValue::from_str(session_id)])
        .map_err(|e| run_err("session_index.delete_row bind", e))?;
        stmt.run().await.map_err(|_| PortError::Unavailable)?;
        Ok(())
    }

    async fn mark_revoked(&self, session_id: &str, revoked_at: i64) -> PortResult<()> {
        let db = db(self.env)?;
        // **Critical guard**: the WHERE clause includes
        // `revoked_at IS NULL` so a row that's already
        // revoked is NOT overwritten. The port contract
        // says repair must not rewrite history; this is
        // where that guard lives. A row that hits this
        // already-revoked path produces no error (UPDATE
        // affecting 0 rows is success in D1) — the
        // counter logic in the pure service relies on
        // this idempotence.
        let stmt = db.prepare(
            "UPDATE user_sessions SET revoked_at = ?1 \
             WHERE session_id = ?2 AND revoked_at IS NULL",
        )
        .bind(&[
            d1_int(revoked_at),
            worker::wasm_bindgen::JsValue::from_str(session_id),
        ])
        .map_err(|e| run_err("session_index.mark_revoked bind", e))?;
        stmt.run().await.map_err(|_| PortError::Unavailable)?;
        Ok(())
    }
}
