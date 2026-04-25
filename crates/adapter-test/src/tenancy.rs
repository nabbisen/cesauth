//! In-memory tenancy port implementations.

pub mod groups;
pub mod memberships;
pub mod organizations;
pub mod tenants;

pub use groups::InMemoryGroupRepository;
pub use memberships::InMemoryMembershipRepository;
pub use organizations::InMemoryOrganizationRepository;
pub use tenants::InMemoryTenantRepository;

#[cfg(test)]
mod tests;
