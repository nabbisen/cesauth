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
    email:           Option<String>,
    email_verified:  i64,
    display_name:    Option<String>,
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
        Ok(User {
            id:             self.id,
            email:          self.email,
            email_verified: self.email_verified != 0,
            display_name:   self.display_name,
            status,
            created_at:     self.created_at,
            updated_at:     self.updated_at,
        })
    }
}

impl UserRepository for CloudflareUserRepository<'_> {
    async fn find_by_id(&self, id: &str) -> PortResult<Option<User>> {
        let db   = db(self.env)?;
        let stmt = db.prepare("SELECT id, email, email_verified, display_name, status, created_at, updated_at FROM users WHERE id = ?1")
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
        let db   = db(self.env)?;
        let stmt = db.prepare("SELECT id, email, email_verified, display_name, status, created_at, updated_at FROM users WHERE email = ?1")
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
            "INSERT INTO users (id, email, email_verified, display_name, status, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        )
            .bind(&[
                user.id.clone().into(),
                user.email.clone().map(Into::into).unwrap_or(JsValue::NULL),
                d1_int(user.email_verified as i64),
                user.display_name.clone().map(Into::into).unwrap_or(JsValue::NULL),
                status_s.into(),
                d1_int(user.created_at),
                d1_int(user.updated_at),
            ])
            .map_err(|_| PortError::Unavailable)?
            .run()
            .await;
        match result {
            Ok(_)  => Ok(()),
            // D1 returns a generic error on UNIQUE violations; we can't
            // distinguish conflict from other failure modes without
            // inspecting the error string. Do so narrowly.
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("UNIQUE") || msg.contains("constraint failed") {
                    Err(PortError::Conflict)
                } else {
                    // Surface the underlying message once here - the
                    // worker-side `log` module doesn't reach into the
                    // adapter, and `PortError::Unavailable` carries no
                    // payload. Without this, operators see only
                    // "storage error" at the HTTP layer.
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
        let result = db.prepare(
            "UPDATE users SET email = ?2, email_verified = ?3, display_name = ?4, status = ?5, updated_at = ?6 \
             WHERE id = ?1"
        )
            .bind(&[
                user.id.clone().into(),
                user.email.clone().map(Into::into).unwrap_or(JsValue::NULL),
                d1_int(user.email_verified as i64),
                user.display_name.clone().map(Into::into).unwrap_or(JsValue::NULL),
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
}
