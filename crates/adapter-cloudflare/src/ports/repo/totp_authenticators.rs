//! `TotpAuthenticatorRepository` D1 adapter.
//!
//! Mirrors the in-memory adapter in `cesauth-adapter-test`. The schema
//! lives in migration 0007. See ADR-009 §Q4 for why TOTP gets a
//! separate table from WebAuthn's `authenticators`.
//!
//! The two BLOB columns (`secret_ciphertext`, `secret_nonce`) bind as
//! `Uint8Array` on the JS side per worker-rs's D1 conventions, the
//! same pattern as `authenticators.public_key`.

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::totp::storage::{TotpAuthenticator, TotpAuthenticatorRepository};
use serde::Deserialize;
use worker::js_sys::Uint8Array;
use worker::wasm_bindgen::JsValue;
use worker::Env;

use super::{d1_int, db, run_err};


pub struct CloudflareTotpAuthenticatorRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareTotpAuthenticatorRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareTotpAuthenticatorRepository")
            .finish_non_exhaustive()
    }
}

impl<'a> CloudflareTotpAuthenticatorRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct TotpRow {
    id:                 String,
    user_id:            String,
    secret_ciphertext:  Vec<u8>,
    secret_nonce:       Vec<u8>,
    secret_key_id:      String,
    last_used_step:     i64,
    name:               Option<String>,
    created_at:         i64,
    last_used_at:       Option<i64>,
    confirmed_at:       Option<i64>,
}

impl TotpRow {
    fn into_domain(self) -> PortResult<TotpAuthenticator> {
        Ok(TotpAuthenticator {
            id:                self.id,
            user_id:           self.user_id,
            secret_ciphertext: self.secret_ciphertext,
            secret_nonce:      self.secret_nonce,
            secret_key_id:     self.secret_key_id,
            // last_used_step is stored as INTEGER but the domain
            // type is u64 (TOTP step counter, monotonic). Negative
            // values shouldn't occur (step 0 = epoch, fresh rows
            // get 0 from the schema default); clamp to 0 if a
            // negative slipped in via direct SQL surgery.
            last_used_step:    self.last_used_step.max(0) as u64,
            name:              self.name,
            created_at:        self.created_at,
            last_used_at:      self.last_used_at,
            confirmed_at:      self.confirmed_at,
        })
    }
}

const SELECT_COLS: &str = "id, user_id, secret_ciphertext, secret_nonce, secret_key_id, \
                           last_used_step, name, created_at, last_used_at, confirmed_at";

impl TotpAuthenticatorRepository for CloudflareTotpAuthenticatorRepository<'_> {
    async fn create(&self, row: &TotpAuthenticator) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "INSERT INTO totp_authenticators \
             (id, user_id, secret_ciphertext, secret_nonce, secret_key_id, \
              last_used_step, name, created_at, last_used_at, confirmed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        )
            .bind(&[
                row.id.clone().into(),
                row.user_id.clone().into(),
                // BLOB columns: Uint8Array from byte slice.
                Uint8Array::from(row.secret_ciphertext.as_slice()).into(),
                Uint8Array::from(row.secret_nonce.as_slice()).into(),
                row.secret_key_id.clone().into(),
                d1_int(row.last_used_step as i64),
                row.name.clone().map(Into::into).unwrap_or(JsValue::NULL),
                d1_int(row.created_at),
                row.last_used_at.map(d1_int).unwrap_or(JsValue::NULL),
                row.confirmed_at.map(d1_int).unwrap_or(JsValue::NULL),
            ])
            .map_err(|e| run_err("totp_authenticators.create bind", e))?
            .run().await
            .map_err(|e| run_err("totp_authenticators.create run", e))?;
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> PortResult<Option<TotpAuthenticator>> {
        let db = db(self.env)?;
        let stmt = db.prepare(&format!(
                "SELECT {SELECT_COLS} FROM totp_authenticators WHERE id = ?1"
            ))
            .bind(&[id.into()])
            .map_err(|_| PortError::Unavailable)?;
        match stmt.first::<TotpRow>(None).await {
            Ok(Some(row)) => Ok(Some(row.into_domain()?)),
            Ok(None)      => Ok(None),
            Err(_)        => Err(PortError::Unavailable),
        }
    }

    async fn find_active_for_user(&self, user_id: &str)
        -> PortResult<Option<TotpAuthenticator>>
    {
        // Most-recently-confirmed semantic per the in-memory adapter.
        // ORDER BY confirmed_at DESC LIMIT 1, filtered to confirmed
        // rows only.
        let db = db(self.env)?;
        let stmt = db.prepare(&format!(
                "SELECT {SELECT_COLS} FROM totp_authenticators \
                 WHERE user_id = ?1 AND confirmed_at IS NOT NULL \
                 ORDER BY confirmed_at DESC LIMIT 1"
            ))
            .bind(&[user_id.into()])
            .map_err(|_| PortError::Unavailable)?;
        match stmt.first::<TotpRow>(None).await {
            Ok(Some(row)) => Ok(Some(row.into_domain()?)),
            Ok(None)      => Ok(None),
            Err(_)        => Err(PortError::Unavailable),
        }
    }

    async fn confirm(&self, id: &str, last_used_step: u64, now: i64)
        -> PortResult<()>
    {
        // The in-memory adapter rejects double-confirm with
        // NotFound. SQL equivalent: UPDATE ... WHERE id = ?
        // AND confirmed_at IS NULL, then check rowcount.
        let db = db(self.env)?;
        let result = db.prepare(
            "UPDATE totp_authenticators \
             SET confirmed_at = ?1, last_used_step = ?2, last_used_at = ?3 \
             WHERE id = ?4 AND confirmed_at IS NULL"
        )
            .bind(&[
                d1_int(now),
                d1_int(last_used_step as i64),
                d1_int(now),
                id.into(),
            ])
            .map_err(|e| run_err("totp_authenticators.confirm bind", e))?
            .run().await
            .map_err(|e| run_err("totp_authenticators.confirm run", e))?;

        // D1 surfaces affected-row counts via meta(). If 0 rows
        // changed, the row was missing OR already confirmed; both
        // map to NotFound per the trait contract.
        let meta = result.meta().map_err(|_| PortError::Unavailable)?;
        let changes = meta.and_then(|m| m.changes).unwrap_or(0);
        if changes == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }

    async fn update_last_used_step(&self, id: &str, last_used_step: u64, now: i64)
        -> PortResult<()>
    {
        let db = db(self.env)?;
        let result = db.prepare(
            "UPDATE totp_authenticators \
             SET last_used_step = ?1, last_used_at = ?2 \
             WHERE id = ?3"
        )
            .bind(&[
                d1_int(last_used_step as i64),
                d1_int(now),
                id.into(),
            ])
            .map_err(|e| run_err("totp_authenticators.update_last_used_step bind", e))?
            .run().await
            .map_err(|e| run_err("totp_authenticators.update_last_used_step run", e))?;

        let meta = result.meta().map_err(|_| PortError::Unavailable)?;
        let changes = meta.and_then(|m| m.changes).unwrap_or(0);
        if changes == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }

    async fn delete(&self, id: &str) -> PortResult<()> {
        let db = db(self.env)?;
        let result = db.prepare("DELETE FROM totp_authenticators WHERE id = ?1")
            .bind(&[id.into()])
            .map_err(|e| run_err("totp_authenticators.delete bind", e))?
            .run().await
            .map_err(|e| run_err("totp_authenticators.delete run", e))?;
        let meta = result.meta().map_err(|_| PortError::Unavailable)?;
        let changes = meta.and_then(|m| m.changes).unwrap_or(0);
        if changes == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }

    async fn list_unconfirmed_older_than(&self, cutoff_unix: i64)
        -> PortResult<Vec<String>>
    {
        // Cron-sweep helper. The partial index
        // `idx_totp_authenticators_unconfirmed` (created in
        // migration 0007) makes this query cheap — it covers
        // exactly the subset we filter on.
        let db = db(self.env)?;
        let stmt = db.prepare(
                "SELECT id FROM totp_authenticators \
                 WHERE confirmed_at IS NULL AND created_at < ?1"
            )
            .bind(&[d1_int(cutoff_unix)])
            .map_err(|_| PortError::Unavailable)?;

        #[derive(Deserialize)]
        struct IdRow { id: String }

        let rows = stmt.all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<IdRow> = rows.results()
            .map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(|r| r.id).collect())
    }
}
