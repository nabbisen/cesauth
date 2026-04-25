//! `PermissionRepository` D1 adapter.
//!
//! The `permissions` table is read-only at runtime — the migration
//! seeds the catalog and operators may insert their own rows
//! out-of-band. We intentionally do not expose write methods.

use cesauth_core::authz::ports::PermissionRepository;
use cesauth_core::authz::types::Permission;
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::db;

pub struct CloudflarePermissionRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflarePermissionRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflarePermissionRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflarePermissionRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct PermissionRow { name: String }

impl PermissionRepository for CloudflarePermissionRepository<'_> {
    async fn list_all(&self) -> PortResult<Vec<Permission>> {
        let db = db(self.env)?;
        let rows = db.prepare("SELECT name FROM permissions ORDER BY name")
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<PermissionRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(|r| Permission::new(r.name)).collect())
    }

    async fn exists(&self, name: &str) -> PortResult<bool> {
        let db = db(self.env)?;
        let rows = db.prepare("SELECT name FROM permissions WHERE name = ?1")
            .bind(&[name.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<PermissionRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(!rows.is_empty())
    }
}
