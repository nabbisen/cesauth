//! `AdminTokenRepository` D1 adapter.

use cesauth_core::admin::ports::AdminTokenRepository;
use cesauth_core::admin::types::{AdminPrincipal, Role};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use uuid::Uuid;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareAdminTokenRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareAdminTokenRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareAdminTokenRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareAdminTokenRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct TokenRow {
    id:      String,
    role:    String,
    name:    Option<String>,
    /// v0.11.0: nullable, populated by migration `0005`. v0.11.0
    /// reads it through but does not gate authorization on it.
    /// See ADR-002.
    user_id: Option<String>,
}

impl TokenRow {
    fn into_domain(self) -> PortResult<AdminPrincipal> {
        let role = Role::from_str(&self.role)
            .ok_or(PortError::PreconditionFailed("unknown role on admin_tokens row"))?;
        Ok(AdminPrincipal { id: self.id, name: self.name, role, user_id: self.user_id })
    }
}

impl AdminTokenRepository for CloudflareAdminTokenRepository<'_> {
    async fn list(&self) -> PortResult<Vec<AdminPrincipal>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT id, role, name, user_id FROM admin_tokens \
             WHERE disabled_at IS NULL ORDER BY created_at DESC"
        ).all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<TokenRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(TokenRow::into_domain).collect()
    }

    async fn create(
        &self,
        token_hash: &str,
        role:       Role,
        name:       Option<&str>,
        now_unix:   i64,
    ) -> PortResult<AdminPrincipal> {
        let db = db(self.env)?;
        let id = Uuid::new_v4().to_string();
        let name_owned = name.map(str::to_owned);
        db.prepare(
            "INSERT INTO admin_tokens (id, token_hash, role, name, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)"
        )
            .bind(&[
                id.clone().into(),
                token_hash.into(),
                role.as_str().into(),
                match &name_owned {
                    Some(s) => s.clone().into(),
                    None    => worker::wasm_bindgen::JsValue::NULL,
                },
                d1_int(now_unix),
            ])
            .map_err(|e| run_err("admin_tokens.create bind", e))?
            .run().await.map_err(|e| run_err("admin_tokens.create run", e))?;
        // v0.11.0: tokens minted via this repo are still system-admin
        // tokens (no user binding). v0.13.0 introduces a separate
        // `create_user_bound` entry point to mint user-as-bearer
        // tokens. Adding it now would be premature — there's no
        // resolution path for the result yet.
        Ok(AdminPrincipal { id, name: name_owned, role, user_id: None })
    }

    async fn disable(&self, id: &str, now_unix: i64) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "UPDATE admin_tokens SET disabled_at = ?2 \
             WHERE id = ?1 AND disabled_at IS NULL"
        )
            .bind(&[id.into(), d1_int(now_unix)])
            .map_err(|e| run_err("admin_tokens.disable bind", e))?
            .run().await.map_err(|e| run_err("admin_tokens.disable run", e))?;
        Ok(())
    }
}
