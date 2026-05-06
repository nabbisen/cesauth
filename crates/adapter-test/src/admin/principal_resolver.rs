//! In-memory `AdminPrincipalResolver` for tests.
//!
//! Stores `(plaintext_token, AdminPrincipal)` pairs. The cloudflare
//! adapter stores only `token_hash`; this in-memory impl keeps the
//! plaintext for simplicity since it never hits a wire. Tests must
//! therefore supply the plaintext when asking the resolver to match.

use std::collections::HashMap;
use std::sync::Mutex;

use cesauth_core::admin::ports::AdminPrincipalResolver;
use cesauth_core::admin::types::{AdminPrincipal, Role};
use cesauth_core::ports::{PortError, PortResult};

#[derive(Debug, Default)]
pub struct InMemoryAdminPrincipalResolver {
    inner: Mutex<HashMap<String, AdminPrincipal>>,
}

impl InMemoryAdminPrincipalResolver {
    pub fn add(&self, token: &str, name: &str, role: Role) {
        self.inner.lock().unwrap().insert(
            token.to_owned(),
            AdminPrincipal {
                id: format!("inmem-{name}"),
                name: Some(name.to_owned()),
                role,
                user_id: None,
            },
        );
    }

    pub fn disable(&self, token: &str) {
        self.inner.lock().unwrap().remove(token);
    }
}

impl AdminPrincipalResolver for InMemoryAdminPrincipalResolver {
    async fn resolve(&self, bearer: &str) -> PortResult<AdminPrincipal> {
        let m = self.inner.lock().map_err(|_| PortError::Unavailable)?;
        m.get(bearer).cloned().ok_or(PortError::NotFound)
    }

    async fn touch_last_used(&self, _principal_id: &str, _now_unix: i64) -> PortResult<()> {
        Ok(())
    }
}
