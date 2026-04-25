//! `RoleAssignmentRepository` D1 adapter.
//!
//! `list_for_user` is the authz hot path. The `idx_ra_user` index in
//! 0003_tenancy.sql ensures it stays cheap.

use cesauth_core::authz::ports::RoleAssignmentRepository;
use cesauth_core::authz::types::{RoleAssignment, Scope};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareRoleAssignmentRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareRoleAssignmentRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareRoleAssignmentRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareRoleAssignmentRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct AssignmentRow {
    id:         String,
    user_id:    String,
    role_id:    String,
    scope_type: String,
    scope_id:   Option<String>,
    granted_by: String,
    granted_at: i64,
    expires_at: Option<i64>,
}

impl AssignmentRow {
    fn into_domain(self) -> PortResult<RoleAssignment> {
        let scope = match (self.scope_type.as_str(), self.scope_id) {
            ("system",       None)        => Scope::System,
            ("tenant",       Some(id))    => Scope::Tenant       { tenant_id:       id },
            ("organization", Some(id))    => Scope::Organization { organization_id: id },
            ("group",        Some(id))    => Scope::Group        { group_id:        id },
            ("user",         Some(id))    => Scope::User         { user_id:         id },
            // The CHECK in 0003 forbids these but defend anyway.
            _ => return Err(PortError::Serialization),
        };
        Ok(RoleAssignment {
            id: self.id, user_id: self.user_id, role_id: self.role_id, scope,
            granted_by: self.granted_by, granted_at: self.granted_at,
            expires_at: self.expires_at,
        })
    }
}

fn encode_scope(s: &Scope) -> (&'static str, worker::wasm_bindgen::JsValue) {
    use worker::wasm_bindgen::JsValue;
    match s {
        Scope::System                                  => ("system",       JsValue::NULL),
        Scope::Tenant       { tenant_id:       id }    => ("tenant",       id.as_str().into()),
        Scope::Organization { organization_id: id }    => ("organization", id.as_str().into()),
        Scope::Group        { group_id:        id }    => ("group",        id.as_str().into()),
        Scope::User         { user_id:         id }    => ("user",         id.as_str().into()),
    }
}

const COLS: &str = "id, user_id, role_id, scope_type, scope_id, granted_by, granted_at, expires_at";

impl RoleAssignmentRepository for CloudflareRoleAssignmentRepository<'_> {
    async fn create(&self, a: &RoleAssignment) -> PortResult<()> {
        let db = db(self.env)?;
        let (st, sid) = encode_scope(&a.scope);
        let exp_js: worker::wasm_bindgen::JsValue = match a.expires_at {
            Some(t) => d1_int(t),
            None    => worker::wasm_bindgen::JsValue::NULL,
        };
        db.prepare(
            "INSERT INTO role_assignments \
             (id, user_id, role_id, scope_type, scope_id, granted_by, granted_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        )
            .bind(&[
                a.id.as_str().into(), a.user_id.as_str().into(),
                a.role_id.as_str().into(), st.into(), sid,
                a.granted_by.as_str().into(), d1_int(a.granted_at), exp_js,
            ])
            .map_err(|e| run_err("role_assignment.create bind", e))?
            .run().await
            .map_err(|e| run_err("role_assignment.create run", e))?;
        Ok(())
    }

    async fn delete(&self, id: &str) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare("DELETE FROM role_assignments WHERE id = ?1")
            .bind(&[id.into()])
            .map_err(|e| run_err("role_assignment.delete bind", e))?
            .run().await.map_err(|e| run_err("role_assignment.delete run", e))?;
        // Idempotent: no NotFound on missing.
        Ok(())
    }

    async fn list_for_user(&self, user_id: &str) -> PortResult<Vec<RoleAssignment>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!(
            "SELECT {COLS} FROM role_assignments WHERE user_id = ?1"
        ))
            .bind(&[user_id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<AssignmentRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(AssignmentRow::into_domain).collect()
    }

    async fn list_in_scope(&self, scope: &Scope) -> PortResult<Vec<RoleAssignment>> {
        let db = db(self.env)?;
        let (st, sid) = encode_scope(scope);
        let rows = match scope {
            Scope::System => db.prepare(&format!(
                "SELECT {COLS} FROM role_assignments \
                 WHERE scope_type = 'system' AND scope_id IS NULL"
            )).all().await.map_err(|_| PortError::Unavailable)?,
            _ => db.prepare(&format!(
                "SELECT {COLS} FROM role_assignments \
                 WHERE scope_type = ?1 AND scope_id = ?2"
            ))
                .bind(&[st.into(), sid]).map_err(|_| PortError::Unavailable)?
                .all().await.map_err(|_| PortError::Unavailable)?,
        };
        let rows: Vec<AssignmentRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(AssignmentRow::into_domain).collect()
    }

    async fn purge_expired(&self, now_unix: i64) -> PortResult<u64> {
        let db = db(self.env)?;
        let res = db.prepare(
            "DELETE FROM role_assignments WHERE expires_at IS NOT NULL AND expires_at <= ?1"
        )
            .bind(&[d1_int(now_unix)])
            .map_err(|e| run_err("role_assignment.purge_expired bind", e))?
            .run().await.map_err(|e| run_err("role_assignment.purge_expired run", e))?;
        let n = res.meta().ok().flatten().and_then(|m| m.changes).unwrap_or(0);
        Ok(n.max(0) as u64)
    }
}
