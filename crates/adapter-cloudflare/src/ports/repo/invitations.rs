//! `InvitationRepository` D1 adapter — RFC 046.

use cesauth_core::invitation::{Invitation, InvitationRepository};
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::types::UnixSeconds;
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;
use worker::Env;

use super::{d1_int, db, run_err};

pub struct CloudflareInvitationRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareInvitationRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareInvitationRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareInvitationRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct InvRow {
    id:          String,
    tenant_id:   String,
    email:       String,
    role:        String,
    issued_by:   String,
    issued_at:   i64,
    expires_at:  i64,
    #[serde(default)]
    accepted_at: Option<i64>,
    #[serde(default)]
    accepted_by: Option<String>,
    #[serde(default)]
    revoked_at:  Option<i64>,
    #[serde(default)]
    revoked_by:  Option<String>,
}

impl InvRow {
    fn into_domain(self) -> Invitation {
        Invitation {
            id:          self.id,
            tenant_id:   self.tenant_id,
            email:       self.email,
            role:        self.role,
            issued_by:   self.issued_by,
            issued_at:   self.issued_at,
            expires_at:  self.expires_at,
            accepted_at: self.accepted_at,
            accepted_by: self.accepted_by,
            revoked_at:  self.revoked_at,
            revoked_by:  self.revoked_by,
        }
    }
}

impl InvitationRepository for CloudflareInvitationRepository<'_> {
    async fn create(&self, inv: &Invitation) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "INSERT INTO invitation_tokens \
             (id, tenant_id, email, role, issued_by, issued_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        )
        .bind(&[
            inv.id.clone().into(),
            inv.tenant_id.clone().into(),
            inv.email.clone().into(),
            inv.role.clone().into(),
            inv.issued_by.clone().into(),
            d1_int(inv.issued_at),
            d1_int(inv.expires_at),
        ])
        .map_err(|e| run_err("invitation_tokens.create bind", e))?
        .run()
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("UNIQUE") { PortError::Conflict } else { run_err("invitation_tokens.create run", e) }
        })?;
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> PortResult<Option<Invitation>> {
        let db = db(self.env)?;
        let row = db
            .prepare("SELECT * FROM invitation_tokens WHERE id = ?1")
            .bind(&[id.into()])
            .map_err(|e| run_err("invitation.find_by_id bind", e))?
            .first::<InvRow>(None)
            .await
            .map_err(|e| run_err("invitation.find_by_id query", e))?;
        Ok(row.map(InvRow::into_domain))
    }

    async fn find_pending_by_tenant_email(
        &self,
        tenant_id: &str,
        email:     &str,
        now:       UnixSeconds,
    ) -> PortResult<Option<Invitation>> {
        let db = db(self.env)?;
        let row = db
            .prepare(
                "SELECT * FROM invitation_tokens \
                 WHERE tenant_id = ?1 AND email = ?2 \
                   AND accepted_at IS NULL AND revoked_at IS NULL \
                   AND expires_at >= ?3 \
                 LIMIT 1"
            )
            .bind(&[tenant_id.into(), email.into(), d1_int(now)])
            .map_err(|e| run_err("invitation.find_pending bind", e))?
            .first::<InvRow>(None)
            .await
            .map_err(|e| run_err("invitation.find_pending query", e))?;
        Ok(row.map(InvRow::into_domain))
    }

    async fn mark_accepted(&self, id: &str, user_id: &str, now: UnixSeconds) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "UPDATE invitation_tokens \
             SET accepted_at = ?1, accepted_by = ?2 \
             WHERE id = ?3"
        )
        .bind(&[d1_int(now), user_id.into(), id.into()])
        .map_err(|e| run_err("invitation.mark_accepted bind", e))?
        .run()
        .await
        .map_err(|e| run_err("invitation.mark_accepted run", e))?;
        Ok(())
    }

    async fn mark_revoked(&self, id: &str, revoked_by: &str, now: UnixSeconds) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "UPDATE invitation_tokens \
             SET revoked_at = ?1, revoked_by = ?2 \
             WHERE id = ?3"
        )
        .bind(&[d1_int(now), revoked_by.into(), id.into()])
        .map_err(|e| run_err("invitation.mark_revoked bind", e))?
        .run()
        .await
        .map_err(|e| run_err("invitation.mark_revoked run", e))?;
        Ok(())
    }

    async fn list_pending_by_tenant(
        &self,
        tenant_id: &str,
        now:       UnixSeconds,
    ) -> PortResult<Vec<Invitation>> {
        let db = db(self.env)?;
        let results = db
            .prepare(
                "SELECT * FROM invitation_tokens \
                 WHERE tenant_id = ?1 \
                   AND accepted_at IS NULL AND revoked_at IS NULL \
                   AND expires_at >= ?2 \
                 ORDER BY issued_at DESC"
            )
            .bind(&[tenant_id.into(), d1_int(now)])
            .map_err(|e| run_err("invitation.list_pending bind", e))?
            .all()
            .await
            .map_err(|e| run_err("invitation.list_pending query", e))?;
        results
            .results::<InvRow>()
            .map(|rows| rows.into_iter().map(InvRow::into_domain).collect())
            .map_err(|e| run_err("invitation.list_pending deserialize", e))
    }
}
