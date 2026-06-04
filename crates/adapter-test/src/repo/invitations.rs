//! In-memory `InvitationRepository` implementation for tests.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cesauth_core::invitation::{Invitation, InvitationRepository};
use cesauth_core::ports::PortResult;
use cesauth_core::types::UnixSeconds;

/// Thread-safe in-memory invitation store for integration tests.
#[derive(Debug, Default, Clone)]
pub struct InMemoryInvitationRepository {
    rows: Arc<Mutex<HashMap<String, Invitation>>>,
}

impl InvitationRepository for InMemoryInvitationRepository {
    async fn create(&self, inv: &Invitation) -> PortResult<()> {
        self.rows.lock().unwrap().insert(inv.id.clone(), inv.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> PortResult<Option<Invitation>> {
        Ok(self.rows.lock().unwrap().get(id).cloned())
    }

    async fn find_pending_by_tenant_email(
        &self,
        tenant_id: &str,
        email:     &str,
        now:       UnixSeconds,
    ) -> PortResult<Option<Invitation>> {
        Ok(self.rows.lock().unwrap().values()
            .find(|i| {
                i.tenant_id == tenant_id
                    && i.email.eq_ignore_ascii_case(email)
                    && i.is_valid_at(now)
            })
            .cloned())
    }

    async fn mark_accepted(
        &self,
        id:      &str,
        user_id: &str,
        now:     UnixSeconds,
    ) -> PortResult<()> {
        if let Some(inv) = self.rows.lock().unwrap().get_mut(id) {
            inv.accepted_at = Some(now);
            inv.accepted_by = Some(user_id.to_owned());
        }
        Ok(())
    }

    async fn mark_revoked(
        &self,
        id:         &str,
        revoked_by: &str,
        now:        UnixSeconds,
    ) -> PortResult<()> {
        if let Some(inv) = self.rows.lock().unwrap().get_mut(id) {
            inv.revoked_at = Some(now);
            inv.revoked_by = Some(revoked_by.to_owned());
        }
        Ok(())
    }

    async fn list_pending_by_tenant(
        &self,
        tenant_id: &str,
        now:       UnixSeconds,
    ) -> PortResult<Vec<Invitation>> {
        Ok(self.rows.lock().unwrap().values()
            .filter(|i| i.tenant_id == tenant_id && i.is_valid_at(now))
            .cloned()
            .collect())
    }
}
