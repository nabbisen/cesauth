use std::collections::HashSet;
use std::sync::Mutex;

use cesauth_core::authz::ports::PermissionRepository;
use cesauth_core::authz::types::{Permission, PermissionCatalog};
use cesauth_core::ports::PortResult;

#[derive(Debug)]
pub struct InMemoryPermissionRepository {
    rows: Mutex<HashSet<String>>,
}

impl InMemoryPermissionRepository {
    /// Construct pre-seeded with the shipped catalog. Tests that want
    /// a custom set can `Default::default()` instead and add via the
    /// (pub-crate) `insert` helper.
    pub fn with_default_catalog() -> Self {
        let mut rows: HashSet<String> = HashSet::new();
        for p in PermissionCatalog::ALL { rows.insert((*p).to_owned()); }
        Self { rows: Mutex::new(rows) }
    }
}

impl Default for InMemoryPermissionRepository {
    fn default() -> Self { Self { rows: Mutex::new(HashSet::new()) } }
}

impl PermissionRepository for InMemoryPermissionRepository {
    async fn list_all(&self) -> PortResult<Vec<Permission>> {
        let g = self.rows.lock().unwrap();
        let mut out: Vec<Permission> = g.iter().map(|s| Permission::new(s.clone())).collect();
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(out)
    }
    async fn exists(&self, name: &str) -> PortResult<bool> {
        Ok(self.rows.lock().unwrap().contains(name))
    }
}
