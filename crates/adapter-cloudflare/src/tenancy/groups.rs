//! `GroupRepository` D1 adapter.

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::tenancy::ports::GroupRepository;
use cesauth_core::tenancy::types::{Group, GroupParent, GroupStatus};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareGroupRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareGroupRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareGroupRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareGroupRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct GroupRow {
    id:               String,
    tenant_id:        String,
    parent_kind:      String,
    organization_id:  Option<String>,
    slug:             String,
    display_name:     String,
    status:           String,
    parent_group_id:  Option<String>,
    created_at:       i64,
    updated_at:       i64,
}

impl GroupRow {
    fn into_domain(self) -> PortResult<Group> {
        let parent = match (self.parent_kind.as_str(), self.organization_id) {
            ("tenant",       None)        => GroupParent::Tenant,
            ("organization", Some(o))     => GroupParent::Organization { organization_id: o },
            // CHECK in 0003 prevents these but defend anyway.
            _ => return Err(PortError::Serialization),
        };
        let status = match self.status.as_str() {
            "active"  => GroupStatus::Active,
            "deleted" => GroupStatus::Deleted,
            _         => return Err(PortError::Serialization),
        };
        Ok(Group {
            id: self.id, tenant_id: self.tenant_id,
            parent, slug: self.slug, display_name: self.display_name,
            status, parent_group_id: self.parent_group_id,
            created_at: self.created_at, updated_at: self.updated_at,
        })
    }
}

const COLS: &str = "id, tenant_id, parent_kind, organization_id, slug, display_name, status, parent_group_id, created_at, updated_at";

impl GroupRepository for CloudflareGroupRepository<'_> {
    async fn create(&self, g: &Group) -> PortResult<()> {
        let db = db(self.env)?;
        let (parent_kind, org_id_js) = match &g.parent {
            GroupParent::Tenant => ("tenant", worker::wasm_bindgen::JsValue::NULL),
            GroupParent::Organization { organization_id } => (
                "organization",
                organization_id.as_str().into(),
            ),
        };
        let parent_group: worker::wasm_bindgen::JsValue = match g.parent_group_id.as_deref() {
            Some(s) => s.into(),
            None    => worker::wasm_bindgen::JsValue::NULL,
        };
        let status_s = match g.status {
            GroupStatus::Active  => "active",
            GroupStatus::Deleted => "deleted",
        };
        db.prepare(
            "INSERT INTO groups \
             (id, tenant_id, parent_kind, organization_id, slug, display_name, status, parent_group_id, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        )
            .bind(&[
                g.id.as_str().into(), g.tenant_id.as_str().into(),
                parent_kind.into(), org_id_js,
                g.slug.as_str().into(), g.display_name.as_str().into(),
                status_s.into(), parent_group,
                d1_int(g.created_at), d1_int(g.updated_at),
            ])
            .map_err(|e| run_err("group.create bind", e))?
            .run().await
            .map_err(|e| {
                let msg = format!("{e}").to_ascii_lowercase();
                if msg.contains("unique") || msg.contains("constraint") {
                    PortError::Conflict
                } else {
                    run_err("group.create run", e)
                }
            })?;
        Ok(())
    }

    async fn get(&self, id: &str) -> PortResult<Option<Group>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!("SELECT {COLS} FROM groups WHERE id = ?1"))
            .bind(&[id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<GroupRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().next().map(GroupRow::into_domain).transpose()
    }

    async fn list_tenant_scoped(&self, tenant_id: &str) -> PortResult<Vec<Group>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!(
            "SELECT {COLS} FROM groups \
             WHERE tenant_id = ?1 AND parent_kind = 'tenant' AND status != 'deleted' \
             ORDER BY created_at DESC"
        ))
            .bind(&[tenant_id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<GroupRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(GroupRow::into_domain).collect()
    }

    async fn list_for_organization(&self, org_id: &str) -> PortResult<Vec<Group>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!(
            "SELECT {COLS} FROM groups \
             WHERE organization_id = ?1 AND parent_kind = 'organization' AND status != 'deleted' \
             ORDER BY created_at DESC"
        ))
            .bind(&[org_id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<GroupRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(GroupRow::into_domain).collect()
    }

    async fn delete(&self, id: &str, now: i64) -> PortResult<()> {
        let db = db(self.env)?;
        let res = db.prepare(
            "UPDATE groups SET status = 'deleted', updated_at = ?2 WHERE id = ?1"
        )
            .bind(&[id.into(), d1_int(now)])
            .map_err(|e| run_err("group.delete bind", e))?
            .run().await.map_err(|e| run_err("group.delete run", e))?;
        if res.meta().ok().flatten().and_then(|m| m.changes).unwrap_or(0) == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }
}
