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
        // System-admin tokens (no user binding); user-bound tokens
        // are minted via `create_user_bound` (added in v0.13.0).
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

    async fn create_user_bound(
        &self,
        token_hash: &str,
        role:       Role,
        name:       Option<&str>,
        user_id:    &str,
        now_unix:   i64,
    ) -> PortResult<AdminPrincipal> {
        let db = db(self.env)?;
        let id = Uuid::new_v4().to_string();
        let name_owned  = name.map(str::to_owned);
        let user_id_owned = user_id.to_owned();
        // Note: application-layer FK enforcement, consistent with the
        // rest of the schema. The caller is responsible for verifying
        // the user_id exists before minting; an orphan user_id here
        // would still resolve to None on principal lookup (see
        // principal_resolver.rs) but would clutter audit history.
        db.prepare(
            "INSERT INTO admin_tokens (id, token_hash, role, name, user_id, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
            .bind(&[
                id.clone().into(),
                token_hash.into(),
                role.as_str().into(),
                match &name_owned {
                    Some(s) => s.clone().into(),
                    None    => worker::wasm_bindgen::JsValue::NULL,
                },
                user_id_owned.clone().into(),
                d1_int(now_unix),
            ])
            .map_err(|e| run_err("admin_tokens.create_user_bound bind", e))?
            .run().await.map_err(|e| run_err("admin_tokens.create_user_bound run", e))?;
        Ok(AdminPrincipal {
            id,
            name: name_owned,
            role,
            user_id: Some(user_id_owned),
        })
    }
}
