//! In-memory `TotpRecoveryCodeRepository` for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::totp::storage::{TotpRecoveryCodeRepository, TotpRecoveryCodeRow};


#[derive(Debug, Default)]
pub struct InMemoryTotpRecoveryCodeRepository {
    by_id: Mutex<HashMap<String, TotpRecoveryCodeRow>>,
}

impl TotpRecoveryCodeRepository for InMemoryTotpRecoveryCodeRepository {
    async fn bulk_create(&self, rows: &[TotpRecoveryCodeRow]) -> PortResult<()> {
        let mut m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        // Two-pass: validate first (no overlapping ids), then
        // insert. This makes the operation transactional in the
        // in-memory adapter; the D1 adapter uses BEGIN..COMMIT
        // for the same property.
        for r in rows {
            if m.contains_key(&r.id) {
                return Err(PortError::Conflict);
            }
        }
        for r in rows {
            m.insert(r.id.clone(), r.clone());
        }
        Ok(())
    }

    async fn find_unredeemed_by_hash(&self, user_id: &str, code_hash: &str)
        -> PortResult<Option<TotpRecoveryCodeRow>>
    {
        let m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        Ok(m.values()
            .find(|r| r.user_id == user_id
                   && r.code_hash == code_hash
                   && r.redeemed_at.is_none())
            .cloned())
    }

    async fn mark_redeemed(&self, id: &str, now: i64) -> PortResult<()> {
        let mut m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        let row = m.get_mut(id).ok_or(PortError::NotFound)?;
        if row.redeemed_at.is_some() {
            // Already redeemed — concurrent redeem race; the
            // second caller fails closed. The HTTP layer maps
            // this to "code already used" which is correct UX.
            return Err(PortError::NotFound);
        }
        row.redeemed_at = Some(now);
        Ok(())
    }

    async fn count_remaining(&self, user_id: &str) -> PortResult<u32> {
        let m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        let count = m.values()
            .filter(|r| r.user_id == user_id && r.redeemed_at.is_none())
            .count();
        Ok(count as u32)
    }

    async fn delete_all_for_user(&self, user_id: &str) -> PortResult<()> {
        let mut m = self.by_id.lock().map_err(|_| PortError::Unavailable)?;
        m.retain(|_, r| r.user_id != user_id);
        Ok(())
    }
}
