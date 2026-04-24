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
    map: Mutex<HashMap<String, FamilyState>>,
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
            },
        );
        Ok(())
    }

    async fn rotate(
        &self,
        family_id:     &str,
        presented_jti: &str,
        new_jti:       &str,
        now_unix:      i64,
    ) -> PortResult<RotateOutcome> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let fam = m.get_mut(family_id).ok_or(PortError::NotFound)?;

        if fam.revoked_at.is_some() {
            return Ok(RotateOutcome::AlreadyRevoked);
        }

        if presented_jti == fam.current_jti {
            // Rotation.
            let old = std::mem::replace(&mut fam.current_jti, new_jti.to_owned());
            fam.retired_jtis.push(old);
            if fam.retired_jtis.len() > RETIRED_RING_SIZE {
                fam.retired_jtis.remove(0);
            }
            fam.last_rotated_at = now_unix;
            Ok(RotateOutcome::Rotated { new_current_jti: new_jti.to_owned() })
        } else {
            // Reuse or unknown. Either way, burn the family.
            fam.revoked_at = Some(now_unix);
            Ok(RotateOutcome::ReusedAndRevoked)
        }
    }

    async fn revoke(&self, family_id: &str, now_unix: i64) -> PortResult<()> {
        let mut m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        let fam = m.get_mut(family_id).ok_or(PortError::NotFound)?;
        if fam.revoked_at.is_none() {
            fam.revoked_at = Some(now_unix);
        }
        Ok(())
    }

    async fn peek(&self, family_id: &str) -> PortResult<Option<FamilyState>> {
        let m = self.map.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.get(family_id).cloned())
    }
}
