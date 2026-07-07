//! In-memory `RefreshTokenFamilyStore`.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::store::{
    FamilyInit, FamilyState, RefreshTokenFamilyStore, RotateOutcome,
};
use cesauth_core::ports::{PortError, PortResult};


const RETIRED_RING_SIZE: usize = 16;

#[derive(Debug, Default)]
pub struct InMemoryRefreshTokenFamilyStore {
    map: Mutex<HashMap<cesauth_core::types::FamilyId, FamilyState>>,
}

impl RefreshTokenFamilyStore for InMemoryRefreshTokenFamilyStore {
    async fn init(&self, init: &FamilyInit) -> PortResult<()> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        if m.contains_key(&init.family_id) {
            return Err(PortError::Conflict);
        }
        m.insert(
            init.family_id.clone(),
            FamilyState {
                family_id:       init.family_id.clone(),
                user_id:         init.user_id.clone(),
                client_id:       init.client_id.clone(),
                scopes:          init.scopes.clone(),
                current_jti:     init.first_jti.clone(),
                retired_jtis:    Vec::new(),
                created_at:      init.now_unix,
                last_rotated_at: init.now_unix,
                revoked_at:      None,
                auth_time:       0,
                reused_jti:        None,
                reused_at:         None,
                reuse_was_retired: None,
            },
        );
        Ok(())
    }

    async fn rotate(
        &self,
        family_id:     &cesauth_core::types::FamilyId,
        presented_jti: &cesauth_core::types::Jti,
        new_jti:       &cesauth_core::types::Jti,
        now_unix:      i64,
    ) -> PortResult<RotateOutcome> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let fam = m.get_mut(family_id).ok_or(PortError::NotFound)?;

        if fam.revoked_at.is_some() {
            return Ok(RotateOutcome::AlreadyRevoked);
        }

        if presented_jti == &fam.current_jti {
            // Rotation.
            let old = std::mem::replace(&mut fam.current_jti, new_jti.clone());
            fam.retired_jtis.push(old);
            if fam.retired_jtis.len() > RETIRED_RING_SIZE {
                fam.retired_jtis.remove(0);
            }
            fam.last_rotated_at = now_unix;
            Ok(RotateOutcome::Rotated { new_current_jti: new_jti.clone() })
        } else {
            // Reuse or unknown — burn the family. v0.34.0: capture
            // forensic fields before the put, so the post-revoke
            // peek surfaces the cause + timing for audit triage.
            //
            // `was_retired` distinguishes the two reuse subcases:
            // a presented jti found in `retired_jtis` is a
            // real-but-rotated-out token, which is the classic
            // RFC 9700 §4.14.2 reuse pattern; an entirely-unknown
            // jti is more likely forged or a shotgun-style attack
            // where the attacker doesn't know any valid jti.
            let was_retired = fam.retired_jtis.iter().any(|j| j == presented_jti);

            fam.revoked_at        = Some(now_unix);
            fam.reused_jti        = Some(presented_jti.clone());
            fam.reused_at         = Some(now_unix);
            fam.reuse_was_retired = Some(was_retired);

            Ok(RotateOutcome::ReusedAndRevoked {
                reused_jti: presented_jti.clone(),
                was_retired,
            })
        }
    }

    async fn revoke(&self, family_id: &cesauth_core::types::FamilyId, now_unix: i64) -> PortResult<()> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let fam = m.get_mut(family_id).ok_or(PortError::NotFound)?;
        if fam.revoked_at.is_none() {
            fam.revoked_at = Some(now_unix);
        }
        Ok(())
    }

    async fn peek(&self, family_id: &cesauth_core::types::FamilyId) -> PortResult<Option<FamilyState>> {
        let m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(family_id).cloned())
    }
}
