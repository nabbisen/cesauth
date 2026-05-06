//! Tenancy value types.
//!
//! These are the pure data shapes that repositories round-trip and
//! that the service layer composes into business operations. Nothing
//! in here knows about Cloudflare, HTTP, or rendering.
//!
//! Every type that appears on the wire derives `Serialize` +
//! `Deserialize`. State enums are `#[serde(rename_all = "snake_case")]`
//! so their string form matches the D1 column's CHECK constraint.

use serde::{Deserialize, Serialize};

use crate::types::{Id, UnixSeconds};

/// Bootstrap tenant id used by migration 0003 to house rows that
/// existed before the multi-tenant model was introduced.
///
/// The value is a stable sentinel, not a UUID — operators can grep
/// the D1 schema for it. New deployments may keep using it as their
/// single tenant if they don't need the multi-tenant surface.
pub const DEFAULT_TENANT_ID: &str = "tenant-default";

// ---------------------------------------------------------------------
// Tenant
// ---------------------------------------------------------------------

/// The outermost logical boundary. All tenant-scoped data carries a
/// `tenant_id` pointing to a row in this table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tenant {
    pub id:          Id,
    /// Short machine-readable key. Stable across renames; used in URL
    /// paths like `/t/<slug>/…` when the routing layer lands.
    pub slug:        String,
    /// Operator-facing display name.
    pub display_name: String,
    pub status:      TenantStatus,
    pub created_at:  UnixSeconds,
    pub updated_at:  UnixSeconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    /// Newly-created, not yet confirmed / activated. The tenant exists
    /// but no sign-in flow is enabled against it. Used during the
    /// invitation flow (future); new tenants created by a system
    /// admin jump straight to `Active`.
    Pending,
    Active,
    /// Suspended by an operator (billing issue, ToS, etc.). Data is
    /// retained; sign-in and API access are blocked.
    Suspended,
    /// Soft-deleted. `updated_at` marks the deletion moment; a
    /// background job removes the row after the retention window.
    Deleted,
}

// ---------------------------------------------------------------------
// Organization
// ---------------------------------------------------------------------

/// A business unit within a tenant. Spec §3.2.
///
/// For 0.5.0 organizations are flat — no parent/child hierarchy. The
/// `parent_organization_id` column exists in D1 (NULLable) so a
/// follow-up can wire hierarchy without a schema change, but the
/// service layer today ignores it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Organization {
    pub id:           Id,
    pub tenant_id:    Id,
    pub slug:         String,
    pub display_name: String,
    pub status:       OrganizationStatus,
    /// Present for hierarchy in a future release; always `None` today.
    pub parent_organization_id: Option<Id>,
    pub created_at:   UnixSeconds,
    pub updated_at:   UnixSeconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationStatus {
    Active,
    Suspended,
    Deleted,
}

// ---------------------------------------------------------------------
// Group
// ---------------------------------------------------------------------

/// A group. Used both for "these people belong together" (membership)
/// and for "grant this role to these people at once" (authorization).
/// Spec §3.3 is careful to note that the USE-case must be clear; the
/// data model does not enforce a distinction, but callers should not
/// overload a group for both at once.
///
/// A group belongs either to a tenant directly (tenant-wide group) or
/// to an organization (org-scoped group). See [`GroupParent`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub id:           Id,
    pub tenant_id:    Id,
    pub parent:       GroupParent,
    pub slug:         String,
    pub display_name: String,
    pub status:       GroupStatus,
    /// Hierarchy placeholder, same story as `Organization`.
    pub parent_group_id: Option<Id>,
    pub created_at:   UnixSeconds,
    pub updated_at:   UnixSeconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupStatus {
    Active,
    Deleted,
}

/// Where a group sits in the tenancy tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum GroupParent {
    /// Group is directly under a tenant (e.g. "all-staff", "admins").
    Tenant,
    /// Group is under an organization (e.g. "engineering-dept", "ops-oncall").
    Organization { organization_id: Id },
}

impl GroupParent {
    pub fn is_tenant_scoped(&self) -> bool {
        matches!(self, GroupParent::Tenant)
    }
    pub fn organization_id(&self) -> Option<&str> {
        match self {
            GroupParent::Organization { organization_id } => Some(organization_id.as_str()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------
// AccountType  (§5)
// ---------------------------------------------------------------------

/// Kind of principal this user represents. Deliberately separate from
/// role/permission — a `SystemOperator` account type does NOT imply
/// admin capability; capability comes exclusively from role
/// assignments (spec §5: "user_type のみで admin 判定を行わない").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountType {
    /// Anonymous trial principal. Not a permanent user in the sense
    /// of `HumanUser`; lifecycle is bounded, data retention is
    /// narrow. The promotion flow (anonymous → human_user) is a
    /// 0.16.0-or-later item.
    Anonymous,
    /// Ordinary end-user, created by self-registration or invitation.
    HumanUser,
    /// Machine principal for API integrations. No password; bearer
    /// tokens or client credentials only.
    ServiceAccount,
    /// System-level operator — for cesauth's own operators, distinct
    /// from a tenant's admins. Spec §5 says these are valid account
    /// types, but permissions still come from roles.
    SystemOperator,
    /// External IdP-federated user. Credentials live elsewhere; the
    /// local row exists to carry role assignments and audit history.
    /// Federation wiring is unscheduled at this time — tracked in
    /// ROADMAP under "Explicitly out-of-scope (for now)".
    ExternalFederatedUser,
}

impl AccountType {
    pub fn as_str(self) -> &'static str {
        match self {
            AccountType::Anonymous             => "anonymous",
            AccountType::HumanUser             => "human_user",
            AccountType::ServiceAccount        => "service_account",
            AccountType::SystemOperator        => "system_operator",
            AccountType::ExternalFederatedUser => "external_federated_user",
        }
    }
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "anonymous"               => AccountType::Anonymous,
            "human_user"              => AccountType::HumanUser,
            "service_account"         => AccountType::ServiceAccount,
            "system_operator"         => AccountType::SystemOperator,
            "external_federated_user" => AccountType::ExternalFederatedUser,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------
// Memberships (relations, not attributes — §2 principle 4)
// ---------------------------------------------------------------------

/// `user_tenant_memberships` row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantMembership {
    pub tenant_id: Id,
    pub user_id:   Id,
    /// Non-authz role describing the user's relationship to the tenant.
    /// Authz comes from [`crate::authz::RoleAssignment`]; this field
    /// is for UX hints like "this person owns the tenant" and for the
    /// initial bootstrap before any role_assignments exist.
    pub role:       TenantMembershipRole,
    pub joined_at:  UnixSeconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantMembershipRole {
    /// Created the tenant. Typically exactly one per tenant.
    Owner,
    /// Has administrative responsibility within the tenant.
    Admin,
    /// Ordinary member.
    Member,
}

/// `user_organization_memberships` row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationMembership {
    pub organization_id: Id,
    pub user_id:         Id,
    pub role:            OrganizationRole,
    pub joined_at:       UnixSeconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRole {
    Admin,
    Member,
}

/// `user_group_memberships` row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMembership {
    pub group_id:  Id,
    pub user_id:   Id,
    pub joined_at: UnixSeconds,
}
