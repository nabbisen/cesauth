//! Authorization value types.

use serde::{Deserialize, Serialize};

use crate::types::{Id, UnixSeconds};

// ---------------------------------------------------------------------
// Permission
// ---------------------------------------------------------------------

/// An atomic capability.
///
/// Stored as a string rather than an enum: the catalog grows as
/// features land, and a closed enum would force a migration every
/// time. The [`PermissionCatalog`] constant lists the ones we ship
/// with 0.5.0; operators may add rows to the `permissions` table for
/// their own use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Permission(pub String);

impl Permission {
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn as_str(&self) -> &str { &self.0 }
}

impl From<&str> for Permission {
    fn from(s: &str) -> Self { Permission(s.to_owned()) }
}

/// The permission set cesauth ships with. Seeded into the
/// `permissions` D1 table by migration 0003. Naming pattern is
/// `<noun>:<action>` or `<noun>:<subresource>:<action>`.
#[derive(Debug)]
pub struct PermissionCatalog;
impl PermissionCatalog {
    // Tenant scope
    pub const TENANT_READ:    &'static str = "tenant:read";
    pub const TENANT_UPDATE:  &'static str = "tenant:update";
    pub const TENANT_SUSPEND: &'static str = "tenant:suspend";
    pub const TENANT_DELETE:  &'static str = "tenant:delete";

    // Organization
    pub const ORGANIZATION_CREATE: &'static str = "organization:create";
    pub const ORGANIZATION_READ:   &'static str = "organization:read";
    pub const ORGANIZATION_UPDATE: &'static str = "organization:update";
    pub const ORGANIZATION_DELETE: &'static str = "organization:delete";
    pub const ORGANIZATION_MEMBER_ADD:    &'static str = "organization:member:add";
    pub const ORGANIZATION_MEMBER_REMOVE: &'static str = "organization:member:remove";

    // Group
    pub const GROUP_CREATE: &'static str = "group:create";
    pub const GROUP_READ:   &'static str = "group:read";
    pub const GROUP_UPDATE: &'static str = "group:update";
    pub const GROUP_DELETE: &'static str = "group:delete";
    pub const GROUP_MEMBER_ADD:    &'static str = "group:member:add";
    pub const GROUP_MEMBER_REMOVE: &'static str = "group:member:remove";

    // User
    pub const USER_READ:    &'static str = "user:read";
    pub const USER_INVITE:  &'static str = "user:invite";
    pub const USER_DISABLE: &'static str = "user:disable";
    pub const USER_DELETE:  &'static str = "user:delete";

    // Roles / permissions
    pub const ROLE_ASSIGN:   &'static str = "role:assign";
    pub const ROLE_UNASSIGN: &'static str = "role:unassign";

    // Subscription
    pub const SUBSCRIPTION_READ:   &'static str = "subscription:read";
    pub const SUBSCRIPTION_UPDATE: &'static str = "subscription:update";

    // Audit
    pub const AUDIT_READ: &'static str = "audit:read";

    /// Every permission shipped with 0.5.0. Order is stable, so test
    /// snapshots of the catalog stay stable too.
    pub const ALL: &'static [&'static str] = &[
        Self::TENANT_READ, Self::TENANT_UPDATE, Self::TENANT_SUSPEND, Self::TENANT_DELETE,
        Self::ORGANIZATION_CREATE, Self::ORGANIZATION_READ,
        Self::ORGANIZATION_UPDATE, Self::ORGANIZATION_DELETE,
        Self::ORGANIZATION_MEMBER_ADD, Self::ORGANIZATION_MEMBER_REMOVE,
        Self::GROUP_CREATE, Self::GROUP_READ, Self::GROUP_UPDATE, Self::GROUP_DELETE,
        Self::GROUP_MEMBER_ADD, Self::GROUP_MEMBER_REMOVE,
        Self::USER_READ, Self::USER_INVITE, Self::USER_DISABLE, Self::USER_DELETE,
        Self::ROLE_ASSIGN, Self::ROLE_UNASSIGN,
        Self::SUBSCRIPTION_READ, Self::SUBSCRIPTION_UPDATE,
        Self::AUDIT_READ,
    ];
}

// ---------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------

/// A named bundle of permissions.
///
/// `tenant_id` is `None` for **system roles** — the built-ins cesauth
/// ships with that are usable across all tenants (typically for the
/// SaaS operator's own staff). `Some(id)` means a tenant-defined
/// custom role, only visible inside that tenant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Role {
    pub id:          Id,
    pub tenant_id:   Option<Id>,
    pub slug:        String,
    pub display_name: String,
    pub permissions: Vec<Permission>,
    pub created_at:  UnixSeconds,
    pub updated_at:  UnixSeconds,
}

/// Stable slugs for the built-in system roles. Seeded by 0003.
#[derive(Debug)]
pub struct SystemRole;
impl SystemRole {
    /// Full permissions across every tenant. Analogous to the 0.3.x
    /// `Role::Super` admin principal; assignable to
    /// system-operator accounts.
    pub const SYSTEM_ADMIN: &'static str = "system_admin";
    /// Read-only across every tenant. Analogous to 0.3.x ReadOnly.
    pub const SYSTEM_READONLY: &'static str = "system_readonly";

    /// Full tenant-scoped permissions. Assigned to the tenant owner
    /// at tenant-creation time.
    pub const TENANT_ADMIN: &'static str = "tenant_admin";
    /// Read-only within one tenant.
    pub const TENANT_READONLY: &'static str = "tenant_readonly";

    /// Full permissions within one organization.
    pub const ORGANIZATION_ADMIN: &'static str = "organization_admin";
    /// Read-only within one organization.
    pub const ORGANIZATION_MEMBER: &'static str = "organization_member";
}

// ---------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------

/// Where a role assignment (or a permission check) applies.
///
/// Scopes are a strict containment lattice: a `System` grant implies
/// permission in every tenant; a `Tenant` grant implies permission
/// in every org under that tenant; an `Organization` grant implies
/// permission in every group under that org. [`check_permission`]
/// walks the lattice upward — if the caller has the permission at
/// any ancestor scope, the check passes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case", tag = "scope")]
pub enum Scope {
    /// cesauth-wide. Only system-operator accounts ever get a role
    /// assignment at this scope.
    System,
    Tenant       { tenant_id:       Id },
    Organization { organization_id: Id },
    Group        { group_id:        Id },
    /// Per-user self-service (e.g. "edit own profile"). Rarely used
    /// in role assignments directly; appears mainly as a query-side
    /// scope when checking "can user X edit user Y's own data".
    User         { user_id:         Id },
}

impl Scope {
    pub fn is_system(&self) -> bool { matches!(self, Scope::System) }
}

/// Borrow-form of [`Scope`] for the check-permission entry point. Avoids
/// cloning tenant/org/group ids just to hand them to the authorizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRef<'a> {
    System,
    Tenant       { tenant_id:       &'a str },
    Organization { organization_id: &'a str },
    Group        { group_id:        &'a str },
    User         { user_id:         &'a str },
}

// ---------------------------------------------------------------------
// RoleAssignment
// ---------------------------------------------------------------------

/// One row from `role_assignments`. Says: user U has role R in scope S.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleAssignment {
    pub id:       Id,
    pub user_id:  Id,
    pub role_id:  Id,
    pub scope:    Scope,
    /// Who granted this assignment, for audit. References a user id.
    pub granted_by: Id,
    pub granted_at: UnixSeconds,
    /// Optional expiration (unix seconds). `None` means indefinite.
    pub expires_at: Option<UnixSeconds>,
}
