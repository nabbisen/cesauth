//! Cloudflare D1 adapters for the authorization domain.

pub mod assignments;
pub mod permissions;
pub mod roles;

pub use assignments::CloudflareRoleAssignmentRepository;
pub use permissions::CloudflarePermissionRepository;
pub use roles::CloudflareRoleRepository;
