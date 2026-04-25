//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;
use cesauth_core::ports::repo::UserRepository;
use cesauth_core::ports::PortError;
use cesauth_core::types::{User, UserStatus};

fn u(id: &str, email: Option<&str>) -> User {
    User {
        id: id.into(),
        tenant_id: cesauth_core::tenancy::DEFAULT_TENANT_ID.to_owned(),
        email: email.map(str::to_owned),
        email_verified: false,
        display_name: None,
        account_type: cesauth_core::tenancy::AccountType::HumanUser,
        status: UserStatus::Active,
        created_at: 0,
        updated_at: 0,
    }
}

#[tokio::test]
async fn email_lookup_is_case_insensitive() {
    let repo = InMemoryUserRepository::default();
    repo.create(&u("1", Some("A@Example.com"))).await.unwrap();
    assert!(repo.find_by_email("a@example.com").await.unwrap().is_some());
    assert!(repo.find_by_email("A@EXAMPLE.COM").await.unwrap().is_some());
}

#[tokio::test]
async fn email_unique_across_case() {
    let repo = InMemoryUserRepository::default();
    repo.create(&u("1", Some("a@example.com"))).await.unwrap();
    assert!(matches!(
        repo.create(&u("2", Some("A@Example.COM"))).await,
        Err(PortError::Conflict)
    ));
}
