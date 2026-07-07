//! Shared fixtures for tenant_admin test submodules.
//!
//! Split out from the monolithic tests.rs in v0.77.0 (test-file
//! modularization track). Every fixture is `pub(super)` so all
//! sibling test modules can reach it via `use super::common::*`.

use super::super::affordances::Affordances;
use cesauth_core::admin::types::{AdminPrincipal, Role};
use cesauth_core::tenancy::AccountType;
use cesauth_core::tenancy::types::{Tenant, TenantStatus};
use cesauth_core::types::{User, UserStatus};

// ---------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------

pub(super) fn principal() -> AdminPrincipal {
    AdminPrincipal {
        id:      "tk-1".into(),
        name:    Some("alice".into()),
        role:    Role::Operations,
        user_id: Some("u-alice".into()),
    }
}

pub(super) fn tenant() -> Tenant {
    Tenant {
        id:           "t-acme".into(),
        slug:         "acme".into(),
        display_name: "Acme Corporation".into(),
        status:       TenantStatus::Active,
        created_at:   0,
        updated_at:   0,
    }
}

pub(super) fn user(id: &str, name: &str) -> User {
    User {
        id:             id.into(),
        tenant_id:      "t-acme".into(),
        email:          Some(format!("{name}@acme.example")),
        email_verified: true,
        display_name:   Some(name.into()),
        account_type:   AccountType::HumanUser,
        status:         UserStatus::Active,
        created_at:     0,
        updated_at:     0,
    }
}

// ---------------------------------------------------------------------
