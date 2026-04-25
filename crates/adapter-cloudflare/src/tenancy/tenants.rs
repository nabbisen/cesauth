//! `TenantRepository` D1 adapter.

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::tenancy::ports::TenantRepository;
use cesauth_core::tenancy::types::{Tenant, TenantStatus};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareTenantRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareTenantRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareTenantRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareTenantRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct TenantRow {
    id:           String,
    slug:         String,
    display_name: String,
    status:       String,
    created_at:   i64,
    updated_at:   i64,
}

fn parse_status(s: &str) -> PortResult<TenantStatus> {
    Ok(match s {
        "pending"   => TenantStatus::Pending,
        "active"    => TenantStatus::Active,
        "suspended" => TenantStatus::Suspended,
        "deleted"   => TenantStatus::Deleted,
        _           => return Err(PortError::Serialization),
    })
}

fn status_str(s: TenantStatus) -> &'static str {
    match s {
        TenantStatus::Pending   => "pending",
        TenantStatus::Active    => "active",
        TenantStatus::Suspended => "suspended",
        TenantStatus::Deleted   => "deleted",
    }
}

impl TenantRow {
    fn into_domain(self) -> PortResult<Tenant> {
        Ok(Tenant {
            id:           self.id,
            slug:         self.slug,
            display_name: self.display_name,
            status:       parse_status(&self.status)?,
            created_at:   self.created_at,
            updated_at:   self.updated_at,
        })
    }
}

const COLS: &str = "id, slug, display_name, status, created_at, updated_at";

impl TenantRepository for CloudflareTenantRepository<'_> {
    async fn create(&self, t: &Tenant) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "INSERT INTO tenants (id, slug, display_name, status, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
            .bind(&[
                t.id.as_str().into(), t.slug.as_str().into(),
                t.display_name.as_str().into(), status_str(t.status).into(),
                d1_int(t.created_at), d1_int(t.updated_at),
            ])
            .map_err(|e| run_err("tenant.create bind", e))?
            .run().await
            .map_err(|e| {
                // Slug collision surfaces as a SQLite UNIQUE-violation
                // string. We map it to Conflict so the service layer
                // can react; everything else stays Unavailable.
                let msg = format!("{e}").to_ascii_lowercase();
                if msg.contains("unique") || msg.contains("constraint") {
                    PortError::Conflict
                } else {
                    run_err("tenant.create run", e)
                }
            })?;
        Ok(())
    }

    async fn get(&self, id: &str) -> PortResult<Option<Tenant>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!("SELECT {COLS} FROM tenants WHERE id = ?1"))
            .bind(&[id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<TenantRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().next().map(TenantRow::into_domain).transpose()
    }

    async fn find_by_slug(&self, slug: &str) -> PortResult<Option<Tenant>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!("SELECT {COLS} FROM tenants WHERE slug = ?1"))
            .bind(&[slug.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<TenantRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().next().map(TenantRow::into_domain).transpose()
    }

    async fn list_active(&self) -> PortResult<Vec<Tenant>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!(
            "SELECT {COLS} FROM tenants WHERE status != 'deleted' ORDER BY created_at DESC"
        )).all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<TenantRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(TenantRow::into_domain).collect()
    }

    async fn set_status(
        &self,
        id: &str,
        status: TenantStatus,
        now_unix: i64,
    ) -> PortResult<()> {
        let db = db(self.env)?;
        let res = db.prepare(
            "UPDATE tenants SET status = ?2, updated_at = ?3 WHERE id = ?1"
        )
            .bind(&[id.into(), status_str(status).into(), d1_int(now_unix)])
            .map_err(|e| run_err("tenant.set_status bind", e))?
            .run().await
            .map_err(|e| run_err("tenant.set_status run", e))?;
        if res.meta().ok().flatten().and_then(|m| m.changes).unwrap_or(0) == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }

    async fn update_display_name(
        &self,
        id: &str,
        display_name: &str,
        now_unix: i64,
    ) -> PortResult<()> {
        let db = db(self.env)?;
        let res = db.prepare(
            "UPDATE tenants SET display_name = ?2, updated_at = ?3 WHERE id = ?1"
        )
            .bind(&[id.into(), display_name.into(), d1_int(now_unix)])
            .map_err(|e| run_err("tenant.update_display_name bind", e))?
            .run().await
            .map_err(|e| run_err("tenant.update_display_name run", e))?;
        if res.meta().ok().flatten().and_then(|m| m.changes).unwrap_or(0) == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }
}
