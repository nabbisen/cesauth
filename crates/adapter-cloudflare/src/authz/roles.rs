//! `RoleRepository` D1 adapter.
//!
//! `roles.permissions` is stored as a comma-separated string. D1
//! has no JSON1 extension; the alternative would be a join-table
//! `role_permissions(role_id, permission_name)` which is cleaner
//! schema-wise but requires an N+1 read on the hot authorization
//! path. The comma-list shape lets us load every relevant role with
//! one SELECT and parse in the adapter.
//!
//! The cost of this shape is that we never insert commas into a
//! permission name. The `PermissionCatalog` constants don't, and
//! migration 0003 seeds them as-is. Operator-defined permissions
//! must follow the same convention; the comma is treated as a
//! reserved separator.

use cesauth_core::authz::ports::RoleRepository;
use cesauth_core::authz::types::{Permission, Role};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareRoleRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareRoleRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareRoleRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareRoleRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct RoleRow {
    id:           String,
    tenant_id:    Option<String>,
    slug:         String,
    display_name: String,
    permissions:  String,
    created_at:   i64,
    updated_at:   i64,
}

impl RoleRow {
    fn into_domain(self) -> Role {
        let permissions = if self.permissions.is_empty() {
            Vec::new()
        } else {
            self.permissions.split(',')
                .map(|s| Permission::new(s.trim().to_owned()))
                .filter(|p| !p.as_str().is_empty())
                .collect()
        };
        Role {
            id: self.id, tenant_id: self.tenant_id, slug: self.slug,
            display_name: self.display_name, permissions,
            created_at: self.created_at, updated_at: self.updated_at,
        }
    }
}

fn encode_permissions(ps: &[Permission]) -> String {
    ps.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(",")
}

const COLS: &str = "id, tenant_id, slug, display_name, permissions, created_at, updated_at";

impl RoleRepository for CloudflareRoleRepository<'_> {
    async fn create(&self, r: &Role) -> PortResult<()> {
        let db = db(self.env)?;
        let tenant_js: worker::wasm_bindgen::JsValue = match r.tenant_id.as_deref() {
            Some(s) => s.into(),
            None    => worker::wasm_bindgen::JsValue::NULL,
        };
        db.prepare(
            "INSERT INTO roles \
             (id, tenant_id, slug, display_name, permissions, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        )
            .bind(&[
                r.id.as_str().into(), tenant_js,
                r.slug.as_str().into(), r.display_name.as_str().into(),
                encode_permissions(&r.permissions).as_str().into(),
                d1_int(r.created_at), d1_int(r.updated_at),
            ])
            .map_err(|e| run_err("role.create bind", e))?
            .run().await
            .map_err(|e| {
                let msg = format!("{e}").to_ascii_lowercase();
                if msg.contains("unique") || msg.contains("constraint") {
                    PortError::Conflict
                } else {
                    run_err("role.create run", e)
                }
            })?;
        Ok(())
    }

    async fn get(&self, id: &str) -> PortResult<Option<Role>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!("SELECT {COLS} FROM roles WHERE id = ?1"))
            .bind(&[id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<RoleRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().next().map(RoleRow::into_domain))
    }

    async fn find_by_slug(
        &self,
        tenant_id: Option<&str>,
        slug:      &str,
    ) -> PortResult<Option<Role>> {
        let db = db(self.env)?;
        // Two distinct queries because IS NULL doesn't bind through
        // SQLite's parameter machinery cleanly.
        let rows = match tenant_id {
            None => db.prepare(&format!(
                "SELECT {COLS} FROM roles WHERE tenant_id IS NULL AND slug = ?1"
            ))
                .bind(&[slug.into()]).map_err(|_| PortError::Unavailable)?
                .all().await.map_err(|_| PortError::Unavailable)?,
            Some(t) => db.prepare(&format!(
                "SELECT {COLS} FROM roles WHERE tenant_id = ?1 AND slug = ?2"
            ))
                .bind(&[t.into(), slug.into()]).map_err(|_| PortError::Unavailable)?
                .all().await.map_err(|_| PortError::Unavailable)?,
        };
        let rows: Vec<RoleRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().next().map(RoleRow::into_domain))
    }

    async fn list_visible_to_tenant(&self, tenant_id: &str) -> PortResult<Vec<Role>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!(
            "SELECT {COLS} FROM roles \
             WHERE tenant_id IS NULL OR tenant_id = ?1 \
             ORDER BY tenant_id IS NULL DESC, slug"
        ))
            .bind(&[tenant_id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<RoleRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(RoleRow::into_domain).collect())
    }

    async fn list_system_roles(&self) -> PortResult<Vec<Role>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!(
            "SELECT {COLS} FROM roles WHERE tenant_id IS NULL ORDER BY slug"
        )).all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<RoleRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(RoleRow::into_domain).collect())
    }
}
