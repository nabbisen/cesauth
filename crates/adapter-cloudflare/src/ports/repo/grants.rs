//! `GrantRepository` D1 adapter.

use cesauth_core::ports::repo::{Grant, GrantRepository};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;
use worker::Env;

use super::{d1_int, db, run_err};


pub struct CloudflareGrantRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareGrantRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareGrantRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareGrantRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct GrantRow {
    id:         String,
    user_id:    String,
    client_id:  String,
    scopes:     String,
    issued_at:  i64,
    revoked_at: Option<i64>,
}

impl GrantRow {
    fn into_domain(self) -> PortResult<Grant> {
        Ok(Grant {
            id:         self.id,
            user_id:    self.user_id,
            client_id:  self.client_id,
            scopes:     serde_json::from_str(&self.scopes)?,
            issued_at:  self.issued_at,
            revoked_at: self.revoked_at,
        })
    }
}

impl GrantRepository for CloudflareGrantRepository<'_> {
    async fn create(&self, grant: &Grant) -> PortResult<()> {
        let db = db(self.env)?;
        let scopes = serde_json::to_string(&grant.scopes).map_err(|_| PortError::Serialization)?;
        db.prepare(
            "INSERT INTO grants (id, user_id, client_id, scopes, issued_at, revoked_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
            .bind(&[
                grant.id.clone().into(),
                grant.user_id.clone().into(),
                grant.client_id.clone().into(),
                scopes.into(),
                d1_int(grant.issued_at),
                grant.revoked_at.map(d1_int).unwrap_or(JsValue::NULL),
            ])
            .map_err(|e| run_err("grants.create bind", e))?
            .run()
            .await
            .map_err(|e| run_err("grants.create run", e))?;
        Ok(())
    }

    async fn list_active_for_user(&self, user_id: &str) -> PortResult<Vec<Grant>> {
        let db   = db(self.env)?;
        let stmt = db.prepare(
            "SELECT id, user_id, client_id, scopes, issued_at, revoked_at \
             FROM grants WHERE user_id = ?1 AND revoked_at IS NULL"
        )
            .bind(&[user_id.into()])
            .map_err(|_| PortError::Unavailable)?;
        let rows = stmt.all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<GrantRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(GrantRow::into_domain).collect()
    }

    async fn mark_revoked(&self, grant_id: &str, now_unix: i64) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare("UPDATE grants SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL")
            .bind(&[grant_id.into(), d1_int(now_unix)])
            .map_err(|e| run_err("grants.mark_revoked bind", e))?
            .run()
            .await
            .map_err(|e| run_err("grants.mark_revoked run", e))?;
        Ok(())
    }
}
