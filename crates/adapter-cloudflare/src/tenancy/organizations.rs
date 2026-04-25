//! `OrganizationRepository` D1 adapter.

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::tenancy::ports::OrganizationRepository;
use cesauth_core::tenancy::types::{Organization, OrganizationStatus};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareOrganizationRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareOrganizationRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareOrganizationRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareOrganizationRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct OrgRow {
    id:                     String,
    tenant_id:              String,
    slug:                   String,
    display_name:           String,
    status:                 String,
    parent_organization_id: Option<String>,
    created_at:             i64,
    updated_at:             i64,
}

fn parse_status(s: &str) -> PortResult<OrganizationStatus> {
    Ok(match s {
        "active"    => OrganizationStatus::Active,
        "suspended" => OrganizationStatus::Suspended,
        "deleted"   => OrganizationStatus::Deleted,
        _           => return Err(PortError::Serialization),
    })
}

fn status_str(s: OrganizationStatus) -> &'static str {
    match s {
        OrganizationStatus::Active    => "active",
        OrganizationStatus::Suspended => "suspended",
        OrganizationStatus::Deleted   => "deleted",
    }
}

impl OrgRow {
    fn into_domain(self) -> PortResult<Organization> {
        Ok(Organization {
            id:                    self.id,
            tenant_id:             self.tenant_id,
            slug:                  self.slug,
            display_name:          self.display_name,
            status:                parse_status(&self.status)?,
            parent_organization_id: self.parent_organization_id,
            created_at:            self.created_at,
            updated_at:            self.updated_at,
        })
    }
}

const COLS: &str = "id, tenant_id, slug, display_name, status, parent_organization_id, created_at, updated_at";

impl OrganizationRepository for CloudflareOrganizationRepository<'_> {
    async fn create(&self, o: &Organization) -> PortResult<()> {
        let db = db(self.env)?;
        let parent: worker::wasm_bindgen::JsValue = match o.parent_organization_id.as_deref() {
            Some(s) => s.into(),
            None    => worker::wasm_bindgen::JsValue::NULL,
        };
        db.prepare(
            "INSERT INTO organizations \
             (id, tenant_id, slug, display_name, status, parent_organization_id, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        )
            .bind(&[
                o.id.as_str().into(), o.tenant_id.as_str().into(),
                o.slug.as_str().into(), o.display_name.as_str().into(),
                status_str(o.status).into(), parent,
                d1_int(o.created_at), d1_int(o.updated_at),
            ])
            .map_err(|e| run_err("organization.create bind", e))?
            .run().await
            .map_err(|e| {
                let msg = format!("{e}").to_ascii_lowercase();
                if msg.contains("unique") || msg.contains("constraint") {
                    PortError::Conflict
                } else {
                    run_err("organization.create run", e)
                }
            })?;
        Ok(())
    }

    async fn get(&self, id: &str) -> PortResult<Option<Organization>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!("SELECT {COLS} FROM organizations WHERE id = ?1"))
            .bind(&[id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<OrgRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().next().map(OrgRow::into_domain).transpose()
    }

    async fn find_by_slug(&self, tenant_id: &str, slug: &str) -> PortResult<Option<Organization>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!(
            "SELECT {COLS} FROM organizations WHERE tenant_id = ?1 AND slug = ?2"
        ))
            .bind(&[tenant_id.into(), slug.into()])
            .map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<OrgRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().next().map(OrgRow::into_domain).transpose()
    }

    async fn list_for_tenant(&self, tenant_id: &str) -> PortResult<Vec<Organization>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!(
            "SELECT {COLS} FROM organizations \
             WHERE tenant_id = ?1 AND status != 'deleted' ORDER BY created_at DESC"
        ))
            .bind(&[tenant_id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<OrgRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(OrgRow::into_domain).collect()
    }

    async fn set_status(&self, id: &str, s: OrganizationStatus, now: i64) -> PortResult<()> {
        let db = db(self.env)?;
        let res = db.prepare(
            "UPDATE organizations SET status = ?2, updated_at = ?3 WHERE id = ?1"
        )
            .bind(&[id.into(), status_str(s).into(), d1_int(now)])
            .map_err(|e| run_err("organization.set_status bind", e))?
            .run().await.map_err(|e| run_err("organization.set_status run", e))?;
        if res.meta().ok().flatten().and_then(|m| m.changes).unwrap_or(0) == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }

    async fn update_display_name(&self, id: &str, name: &str, now: i64) -> PortResult<()> {
        let db = db(self.env)?;
        let res = db.prepare(
            "UPDATE organizations SET display_name = ?2, updated_at = ?3 WHERE id = ?1"
        )
            .bind(&[id.into(), name.into(), d1_int(now)])
            .map_err(|e| run_err("organization.update_display_name bind", e))?
            .run().await.map_err(|e| run_err("organization.update_display_name run", e))?;
        if res.meta().ok().flatten().and_then(|m| m.changes).unwrap_or(0) == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }
}
