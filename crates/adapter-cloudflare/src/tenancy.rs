//! Cloudflare D1 adapters for the tenancy domain.
//!
//! One submodule per port, mirroring `adapter-test::tenancy`. The
//! schema these read from is in `migrations/0003_tenancy.sql`.

pub mod groups;
pub mod memberships;
pub mod organizations;
pub mod tenants;

pub use groups::CloudflareGroupRepository;
pub use memberships::CloudflareMembershipRepository;
pub use organizations::CloudflareOrganizationRepository;
pub use tenants::CloudflareTenantRepository;
