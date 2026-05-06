//! `TotpRecoveryCodeRepository` D1 adapter.
//!
//! Mirrors the in-memory adapter's semantics. Schema in migration
//! 0007. ADR-009 §Q6 covers the recovery code design.
//!
//! `bulk_create` uses D1's batch API for atomicity: either every row
//! lands or none. The schema's PRIMARY KEY constraint on `id` is the
//! mechanism — if any row in the batch conflicts with an existing
//! id, the transaction rolls back and the rest don't land.

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::totp::storage::{TotpRecoveryCodeRepository, TotpRecoveryCodeRow};
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;
use worker::Env;

use super::{d1_int, db, run_err};


pub struct CloudflareTotpRecoveryCodeRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareTotpRecoveryCodeRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareTotpRecoveryCodeRepository")
            .finish_non_exhaustive()
    }
}

impl<'a> CloudflareTotpRecoveryCodeRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct RecoveryRow {
    id:           String,
    user_id:      String,
    code_hash:    String,
    redeemed_at:  Option<i64>,
    created_at:   i64,
}

#[allow(dead_code)] // populated by D1, only some fields read by domain code
impl RecoveryRow {
    fn into_domain(self) -> TotpRecoveryCodeRow {
        TotpRecoveryCodeRow {
            id:           self.id,
            user_id:      self.user_id,
            code_hash:    self.code_hash,
            redeemed_at:  self.redeemed_at,
            created_at:   self.created_at,
        }
    }
}

impl TotpRecoveryCodeRepository for CloudflareTotpRecoveryCodeRepository<'_> {
    async fn bulk_create(&self, rows: &[TotpRecoveryCodeRow]) -> PortResult<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let db = db(self.env)?;

        // Build a batch of prepared statements. D1's `batch()` runs
        // them in a single transaction: if any fails, all are rolled
        // back. This is what makes our atomicity guarantee real on
        // top of D1 without requiring our own transaction protocol.
        let mut stmts = Vec::with_capacity(rows.len());
        for r in rows {
            let stmt = db.prepare(
                "INSERT INTO totp_recovery_codes \
                 (id, user_id, code_hash, redeemed_at, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)"
            )
                .bind(&[
                    r.id.clone().into(),
                    r.user_id.clone().into(),
                    r.code_hash.clone().into(),
                    r.redeemed_at.map(d1_int).unwrap_or(JsValue::NULL),
                    d1_int(r.created_at),
                ])
                .map_err(|e| run_err("totp_recovery_codes.bulk_create bind", e))?;
            stmts.push(stmt);
        }

        // `batch` returns `Vec<D1Result>`. Any failure in the batch
        // bubbles up through the Result. The PRIMARY KEY constraint
        // catches duplicate ids; UNIQUE constraint failures map to
        // PortError::Conflict for the caller.
        match db.batch(stmts).await {
            Ok(_)  => Ok(()),
            Err(e) => {
                // Best-effort error classification. D1 surfaces
                // constraint-failure messages textually; if the
                // message mentions "UNIQUE" or "constraint", it's
                // a Conflict, otherwise generic Unavailable.
                let msg = format!("{e}");
                if msg.contains("UNIQUE") || msg.contains("constraint") {
                    Err(PortError::Conflict)
                } else {
                    Err(run_err("totp_recovery_codes.bulk_create batch", e))
                }
            }
        }
    }

    async fn find_unredeemed_by_hash(&self, user_id: &str, code_hash: &str)
        -> PortResult<Option<TotpRecoveryCodeRow>>
    {
        let db = db(self.env)?;
        let stmt = db.prepare(
                "SELECT id, user_id, code_hash, redeemed_at, created_at \
                 FROM totp_recovery_codes \
                 WHERE user_id = ?1 AND code_hash = ?2 AND redeemed_at IS NULL \
                 LIMIT 1"
            )
            .bind(&[user_id.into(), code_hash.into()])
            .map_err(|_| PortError::Unavailable)?;
        match stmt.first::<RecoveryRow>(None).await {
            Ok(Some(row)) => Ok(Some(row.into_domain())),
            Ok(None)      => Ok(None),
            Err(_)        => Err(PortError::Unavailable),
        }
    }

    async fn mark_redeemed(&self, id: &str, now: i64) -> PortResult<()> {
        // Atomic UPDATE with WHERE redeemed_at IS NULL pinning the
        // single-redeem property. A concurrent redemption race
        // resolves with whoever's UPDATE lands first; the loser
        // sees changes=0 and gets NotFound.
        let db = db(self.env)?;
        let result = db.prepare(
            "UPDATE totp_recovery_codes \
             SET redeemed_at = ?1 \
             WHERE id = ?2 AND redeemed_at IS NULL"
        )
            .bind(&[d1_int(now), id.into()])
            .map_err(|e| run_err("totp_recovery_codes.mark_redeemed bind", e))?
            .run().await
            .map_err(|e| run_err("totp_recovery_codes.mark_redeemed run", e))?;

        let changes = result.meta()
            .map(|m| m.and_then(|m| m.changes).unwrap_or(0))
            .unwrap_or(0);
        if changes == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }

    async fn count_remaining(&self, user_id: &str) -> PortResult<u32> {
        let db = db(self.env)?;
        let stmt = db.prepare(
                "SELECT COUNT(*) AS c FROM totp_recovery_codes \
                 WHERE user_id = ?1 AND redeemed_at IS NULL"
            )
            .bind(&[user_id.into()])
            .map_err(|_| PortError::Unavailable)?;

        #[derive(Deserialize)]
        struct CountRow { c: i64 }

        match stmt.first::<CountRow>(None).await {
            Ok(Some(row)) => Ok(u32::try_from(row.c.max(0)).unwrap_or(u32::MAX)),
            Ok(None)      => Ok(0),
            Err(_)        => Err(PortError::Unavailable),
        }
    }

    async fn delete_all_for_user(&self, user_id: &str) -> PortResult<()> {
        let db = db(self.env)?;
        // No row-count check: deleting zero rows is a valid outcome
        // (user had no codes, e.g., never enrolled). The trait
        // contract here is "after this, no codes for this user
        // exist", which is also true if there were none to start.
        db.prepare("DELETE FROM totp_recovery_codes WHERE user_id = ?1")
            .bind(&[user_id.into()])
            .map_err(|e| run_err("totp_recovery_codes.delete_all_for_user bind", e))?
            .run().await
            .map_err(|e| run_err("totp_recovery_codes.delete_all_for_user run", e))?;
        Ok(())
    }
}
