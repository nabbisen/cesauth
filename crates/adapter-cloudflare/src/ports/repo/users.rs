//! `UserRepository` D1 adapter.

use cesauth_core::ports::repo::UserRepository;
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::types::{User, UserStatus};
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;
use worker::Env;

use super::{d1_int, db, run_err};


pub struct CloudflareUserRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareUserRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareUserRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareUserRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct UserRow {
    id:              String,
    tenant_id:       String,
    email:           Option<String>,
    email_verified:  i64,
    display_name:    Option<String>,
    account_type:    String,
    status:          String,
    created_at:      i64,
    updated_at:      i64,
}

impl UserRow {
    fn into_domain(self) -> PortResult<User> {
        let status = match self.status.as_str() {
            "active"   => UserStatus::Active,
            "disabled" => UserStatus::Disabled,
            "deleted"  => UserStatus::Deleted,
            _          => return Err(PortError::Serialization),
        };
        let account_type = cesauth_core::tenancy::AccountType::from_str(&self.account_type)
            .ok_or(PortError::Serialization)?;
        Ok(User {
            id:             self.id,
            tenant_id:      self.tenant_id,
            email:          self.email,
            email_verified: self.email_verified != 0,
            display_name:   self.display_name,
            account_type,
            status,
            created_at:     self.created_at,
            updated_at:     self.updated_at,
        })
    }
}

impl UserRepository for CloudflareUserRepository<'_> {
    async fn find_by_id(&self, id: &str) -> PortResult<Option<User>> {
        let db   = db(self.env)?;
        let stmt = db.prepare("SELECT id, tenant_id, email, email_verified, display_name, account_type, status, created_at, updated_at FROM users WHERE id = ?1")
            .bind(&[id.into()])
            .map_err(|_| PortError::Unavailable)?;
        match stmt.first::<UserRow>(None).await {
            Ok(Some(row)) => Ok(Some(row.into_domain()?)),
            Ok(None)      => Ok(None),
            Err(_)        => Err(PortError::Unavailable),
        }
    }

    async fn find_by_email(&self, email: &str) -> PortResult<Option<User>> {
        // The column is `COLLATE NOCASE` so a direct equality compares
        // case-insensitively. We still lowercase in the adapter-test
        // impl for parity; here the DB handles it.
        //
        // Note: post-0.6.0 email is unique PER TENANT, not globally.
        // This method's contract — "find any user with this email" —
        // becomes ambiguous in a multi-tenant deployment. For 0.6.0
        // we keep the global lookup (returning the first match) so
        // existing magic-link / OIDC flows continue to work for the
        // single bootstrap tenant. A `find_by_email_in_tenant`
        // variant lands with the multi-tenant login flow (deferred).
        let db   = db(self.env)?;
        let stmt = db.prepare("SELECT id, tenant_id, email, email_verified, display_name, account_type, status, created_at, updated_at FROM users WHERE email = ?1 LIMIT 1")
            .bind(&[email.into()])
            .map_err(|_| PortError::Unavailable)?;
        match stmt.first::<UserRow>(None).await {
            Ok(Some(row)) => Ok(Some(row.into_domain()?)),
            Ok(None)      => Ok(None),
            Err(_)        => Err(PortError::Unavailable),
        }
    }

    async fn create(&self, user: &User) -> PortResult<()> {
        let db   = db(self.env)?;
        let status_s = match user.status {
            UserStatus::Active   => "active",
            UserStatus::Disabled => "disabled",
            UserStatus::Deleted  => "deleted",
        };
        let result = db.prepare(
            "INSERT INTO users (id, tenant_id, email, email_verified, display_name, account_type, status, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
        )
            .bind(&[
                user.id.clone().into(),
                user.tenant_id.clone().into(),
                user.email.clone().map(Into::into).unwrap_or(JsValue::NULL),
                d1_int(user.email_verified as i64),
                user.display_name.clone().map(Into::into).unwrap_or(JsValue::NULL),
                user.account_type.as_str().into(),
                status_s.into(),
                d1_int(user.created_at),
                d1_int(user.updated_at),
            ])
            .map_err(|_| PortError::Unavailable)?
            .run()
            .await;
        match result {
            Ok(_)  => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("UNIQUE") || msg.contains("constraint failed") {
                    Err(PortError::Conflict)
                } else {
                    worker::console_error!("d1 users.create: {msg}");
                    Err(PortError::Unavailable)
                }
            }
        }
    }

    async fn update(&self, user: &User) -> PortResult<()> {
        let db = db(self.env)?;
        let status_s = match user.status {
            UserStatus::Active   => "active",
            UserStatus::Disabled => "disabled",
            UserStatus::Deleted  => "deleted",
        };
        // tenant_id is intentionally NOT updatable — moving a user
        // between tenants is a destructive operation that needs its
        // own dedicated path with audit trail. account_type IS
        // updatable (operators may re-grade an account from
        // `human_user` to `service_account`).
        let result = db.prepare(
            "UPDATE users SET email = ?2, email_verified = ?3, display_name = ?4, account_type = ?5, status = ?6, updated_at = ?7 \
             WHERE id = ?1"
        )
            .bind(&[
                user.id.clone().into(),
                user.email.clone().map(Into::into).unwrap_or(JsValue::NULL),
                d1_int(user.email_verified as i64),
                user.display_name.clone().map(Into::into).unwrap_or(JsValue::NULL),
                user.account_type.as_str().into(),
                status_s.into(),
                d1_int(user.updated_at),
            ])
            .map_err(|e| run_err("users.update bind", e))?
            .run()
            .await
            .map_err(|e| run_err("users.update run", e))?;
        // D1 reports rows-changed through meta; if missing, we optimistically
        // assume success (NotFound is surfaced by the caller re-reading).
        let _ = result;
        Ok(())
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> PortResult<Vec<User>> {
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT id, tenant_id, email, email_verified, display_name, \
                    account_type, status, created_at, updated_at \
             FROM users \
             WHERE tenant_id = ?1 AND status != 'deleted' \
             ORDER BY id"
        )
            .bind(&[tenant_id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<UserRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn list_anonymous_expired(
        &self,
        cutoff_unix: cesauth_core::types::UnixSeconds,
    ) -> PortResult<Vec<User>> {
        // The SQL mirrors the v0.18.0 sweep contract exactly. Note
        // the `email IS NULL` clause: promoted users carry an
        // email after the promotion path UPDATE, so they're
        // structurally exempt from the sweep.
        let db = db(self.env)?;
        let rows = db.prepare(
            "SELECT id, tenant_id, email, email_verified, display_name, \
                    account_type, status, created_at, updated_at \
             FROM users \
             WHERE account_type = 'anonymous' \
               AND email IS NULL \
               AND created_at < ?1 \
             ORDER BY id"
        )
            .bind(&[d1_int(cutoff_unix)])
            .map_err(|e| run_err("users.list_anon_expired bind", e))?
            .all().await
            .map_err(|_| PortError::Unavailable)?;
        let rows: Vec<UserRow> = rows.results()
            .map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(|r| r.into_domain()).collect()
    }

    async fn delete_by_id(&self, id: &str) -> PortResult<()> {
        // FK CASCADEs (anonymous_sessions via 0006, memberships and
        // role_assignments via 0003) clean up dependent rows.
        // Missing-row deletes are not an error — the sweep is
        // idempotent.
        let db = db(self.env)?;
        let _ = db.prepare("DELETE FROM users WHERE id = ?1")
            .bind(&[id.into()])
            .map_err(|e| run_err("users.delete_by_id bind", e))?
            .run().await
            .map_err(|e| run_err("users.delete_by_id run", e))?;
        Ok(())
    }
}
