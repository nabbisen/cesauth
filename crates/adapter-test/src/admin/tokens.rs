//! In-memory `AdminTokenRepository` for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::admin::ports::AdminTokenRepository;
use cesauth_core::admin::types::{AdminPrincipal, Role};
use cesauth_core::ports::{PortError, PortResult};

/// The row carries a bit more than `AdminPrincipal` so we can surface
/// `disabled_at` and token-hash uniqueness.
#[derive(Debug, Clone)]
struct Row {
    principal:    AdminPrincipal,
    token_hash:   String,
    disabled_at:  Option<i64>,
}

#[derive(Debug, Default)]
pub struct InMemoryAdminTokenRepository {
    inner: Mutex<HashMap<String, Row>>,
}

impl AdminTokenRepository for InMemoryAdminTokenRepository {
    async fn list(&self) -> PortResult<Vec<AdminPrincipal>> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let mut out: Vec<AdminPrincipal> = m.values()
            .filter(|r| r.disabled_at.is_none())
            .map(|r| r.principal.clone())
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn create(
        &self,
        token_hash: &str,
        role:       Role,
        name:       Option<&str>,
        _now_unix:  i64,
    ) -> PortResult<AdminPrincipal> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        if m.values().any(|r| r.token_hash == token_hash) {
            return Err(PortError::Conflict);
        }
        let id = format!("inmem-{}", m.len() + 1);
        let p  = AdminPrincipal {
            id: id.clone(),
            name: name.map(str::to_owned),
            role,
            user_id: None,  // v0.11.0: system-admin token (no user binding)
        };
        m.insert(id, Row {
            principal:    p.clone(),
            token_hash:   token_hash.to_owned(),
            disabled_at:  None,
        });
        Ok(p)
    }

    async fn disable(&self, id: &str, now_unix: i64) -> PortResult<()> {
        let mut m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        let r = m.get_mut(id).ok_or(PortError::NotFound)?;
        r.disabled_at = Some(now_unix);
        Ok(())
    }
}
