//! Repository ports for the authorization domain.

use crate::ports::PortResult;
use crate::types::{Id, UnixSeconds};

use super::types::{Permission, Role, RoleAssignment, Scope};

// ---------------------------------------------------------------------
// Permissions catalog
// ---------------------------------------------------------------------

/// Read-only view over the `permissions` D1 table.
///
/// The catalog is seeded by migration 0003 and is mostly static —
/// operators may add rows, but nothing in cesauth's code path writes
/// here at runtime. The port exists so the service can list-all
/// without hardcoding against the in-memory [`PermissionCatalog`] in
/// [`super::types`]. (That constant is the shipped-with-0.4.0 set;
/// operators can extend the table past it.)
pub trait PermissionRepository {
    /// Every permission in the catalog.
    async fn list_all(&self) -> PortResult<Vec<Permission>>;

    /// Does the given permission string exist in the catalog?
    /// Used by the service when assigning roles — refuse to create a
    /// role that references a permission not in the catalog.
    async fn exists(&self, name: &str) -> PortResult<bool>;
}

// ---------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------

pub trait RoleRepository {
    async fn create(&self, role: &Role) -> PortResult<()>;

    async fn get(&self, id: &str) -> PortResult<Option<Role>>;

    /// Look up by slug, optionally scoped to a tenant. `None` means
    /// "system role" (cesauth-shipped or operator-defined at system
    /// scope); `Some(t)` means "within this tenant".
    async fn find_by_slug(
        &self,
        tenant_id: Option<&str>,
        slug:      &str,
    ) -> PortResult<Option<Role>>;

    /// List all roles visible to a tenant: its own custom roles plus
    /// every system role. Used by the "assign role" admin screen.
    async fn list_visible_to_tenant(&self, tenant_id: &str) -> PortResult<Vec<Role>>;

    /// List every system role (`tenant_id IS NULL`).
    async fn list_system_roles(&self) -> PortResult<Vec<Role>>;
}

// ---------------------------------------------------------------------
// Role assignments
// ---------------------------------------------------------------------

/// The hot-path port: [`super::service::check_permission`] calls
/// `list_for_user` on every authz check. Adapter implementors should
/// ensure this is indexed and cheap.
pub trait RoleAssignmentRepository {
    async fn create(&self, a: &RoleAssignment) -> PortResult<()>;

    /// Remove an assignment. `Ok(())` even if the row did not exist
    /// — callers generally treat unassign as idempotent.
    async fn delete(&self, id: &str) -> PortResult<()>;

    /// All role assignments held by a single user, regardless of
    /// scope. The hot path for permission checks.
    async fn list_for_user(&self, user_id: &str) -> PortResult<Vec<RoleAssignment>>;

    /// All assignments within one scope, for the "who can access
    /// this?" inverse query. Used by the admin-console audit page.
    async fn list_in_scope(&self, scope: &Scope) -> PortResult<Vec<RoleAssignment>>;

    /// Remove expired rows. Returns the number purged. Called by a
    /// background sweep (future) and from unit tests.
    async fn purge_expired(&self, now_unix: UnixSeconds) -> PortResult<u64>;
}

/// Input for `assign_role`. See [`super::service::assign_role`].
#[derive(Debug, Clone)]
pub struct AssignRoleInput<'a> {
    pub user_id:    &'a str,
    pub role_id:    &'a str,
    pub scope:      Scope,
    pub granted_by: &'a str,
    pub expires_at: Option<UnixSeconds>,
}

// Implementation note: Id is re-exported here purely so this file's
// use-statements read as a single include. It's otherwise unused in
// the trait signatures above.
#[allow(dead_code)]
type _IdAlias = Id;
