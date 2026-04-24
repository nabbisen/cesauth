//! `AdminPrincipalResolver` D1 adapter.
//!
//! Resolution order:
//!
//! 1. If the presented bearer matches the `ADMIN_API_KEY` secret byte-for-byte
//!    (constant-time compare), return a synthetic Super-bootstrap
//!    principal. This preserves the pre-0.3 bootstrap path: a fresh
//!    deployment with only `ADMIN_API_KEY` set, and no rows in
//!    `admin_tokens`, still lets the operator into the console.
//!
//! 2. Otherwise, hash the bearer with SHA-256 (lower hex) and look up
//!    the hash in `admin_tokens`. Rows with `disabled_at IS NOT NULL`
//!    are treated as unknown.
//!
//! Token *plaintext* is never stored. The CLI / manual-INSERT flow
//! (documented in the v0.3 admin-console chapter of the mdBook) mints
//! a random token, hashes it, inserts the hash, and hands the plaintext
//! to the operator exactly once.

use cesauth_core::admin::ports::AdminPrincipalResolver;
use cesauth_core::admin::types::{AdminPrincipal, Role};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareAdminPrincipalResolver<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareAdminPrincipalResolver<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareAdminPrincipalResolver").finish_non_exhaustive()
    }
}

impl<'a> CloudflareAdminPrincipalResolver<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct AdminTokenRow {
    id:          String,
    role:        String,
    name:        Option<String>,
    disabled_at: Option<i64>,
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hash_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

impl AdminPrincipalResolver for CloudflareAdminPrincipalResolver<'_> {
    async fn resolve(&self, bearer: &str) -> PortResult<AdminPrincipal> {
        if bearer.is_empty() {
            return Err(PortError::NotFound);
        }

        // 1) ADMIN_API_KEY bootstrap path.
        if let Ok(secret) = self.env.secret("ADMIN_API_KEY") {
            let expected = secret.to_string();
            if !expected.is_empty()
                && constant_time_eq(bearer.as_bytes(), expected.as_bytes())
            {
                return Ok(AdminPrincipal {
                    id:   "super-bootstrap".to_owned(),
                    name: Some("bootstrap".to_owned()),
                    role: Role::Super,
                });
            }
        }

        // 2) admin_tokens lookup by SHA-256(bearer).
        let hash = hash_hex(bearer.as_bytes());
        let db = db(self.env)?;
        let stmt = db.prepare(
            "SELECT id, role, name, disabled_at \
             FROM admin_tokens WHERE token_hash = ?1"
        )
            .bind(&[hash.into()])
            .map_err(|_| PortError::Unavailable)?;
        let rows = stmt.all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<AdminTokenRow> = rows.results().map_err(|_| PortError::Serialization)?;

        let row = rows.into_iter().next().ok_or(PortError::NotFound)?;
        if row.disabled_at.is_some() {
            return Err(PortError::PreconditionFailed("token disabled"));
        }
        let role = Role::from_str(&row.role)
            .ok_or(PortError::PreconditionFailed("unknown role on token row"))?;

        Ok(AdminPrincipal { id: row.id, name: row.name, role })
    }

    async fn touch_last_used(&self, principal_id: &str, now_unix: i64) -> PortResult<()> {
        // Bootstrap principal has no D1 row; nothing to touch.
        if principal_id == "super-bootstrap" {
            return Ok(());
        }
        let db = db(self.env)?;
        db.prepare("UPDATE admin_tokens SET last_used_at = ?2 WHERE id = ?1")
            .bind(&[principal_id.into(), d1_int(now_unix)])
            .map_err(|e| run_err("admin_tokens.touch bind", e))?
            .run()
            .await
            .map_err(|e| run_err("admin_tokens.touch run", e))?;
        Ok(())
    }
}
