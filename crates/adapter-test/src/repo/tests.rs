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

// ---------------------------------------------------------------------
// v0.18.0 — anonymous retention sweep support
// ---------------------------------------------------------------------

fn anon_user(id: &str, created_at: i64, email: Option<&str>) -> User {
    User {
        id: id.into(),
        tenant_id: cesauth_core::tenancy::DEFAULT_TENANT_ID.to_owned(),
        email: email.map(str::to_owned),
        email_verified: email.is_some(),
        display_name: Some("Anon".into()),
        account_type: cesauth_core::tenancy::AccountType::Anonymous,
        status: UserStatus::Active,
        created_at,
        updated_at: created_at,
    }
}

#[tokio::test]
async fn list_anonymous_expired_returns_only_expired_unpromoted() {
    let repo = InMemoryUserRepository::default();
    // Three rows along the lifecycle:
    //   - young: not yet expired.
    //   - old + unpromoted: subject of the sweep.
    //   - old + promoted (email present): MUST survive.
    repo.create(&anon_user("young",     1_000, None)).await.unwrap();
    repo.create(&anon_user("expired",     100, None)).await.unwrap();
    repo.create(&anon_user("promoted",    100, Some("alice@example.com"))).await.unwrap();
    // And one human user, also old but obviously not anonymous.
    repo.create(&u("human", Some("bob@example.com"))).await.unwrap();

    // Cutoff at 500: rows with created_at < 500 are expired.
    let out = repo.list_anonymous_expired(500).await.unwrap();
    let ids: Vec<&str> = out.iter().map(|u| u.id.as_str()).collect();
    assert_eq!(ids, vec!["expired"]);
}

#[tokio::test]
async fn list_anonymous_expired_empty_when_nothing_due() {
    let repo = InMemoryUserRepository::default();
    repo.create(&anon_user("young", 1_000, None)).await.unwrap();
    let out = repo.list_anonymous_expired(500).await.unwrap();
    assert!(out.is_empty(),
        "rows newer than the cutoff must not appear");
}

#[tokio::test]
async fn delete_by_id_is_idempotent() {
    // The sweep may race with itself across cron invocations or
    // with a concurrent admin-driven delete. Missing-row delete
    // is `Ok(())`, never an error.
    let repo = InMemoryUserRepository::default();
    repo.create(&u("1", Some("a@x.com"))).await.unwrap();

    repo.delete_by_id("1").await.unwrap();
    // Second call: row already gone.
    repo.delete_by_id("1").await.unwrap();
    // Calling on a nonexistent id at all: also Ok.
    repo.delete_by_id("never-existed").await.unwrap();

    assert!(repo.find_by_id("1").await.unwrap().is_none());
}

#[tokio::test]
async fn delete_by_id_removes_email_uniqueness_lock() {
    // After delete, the email becomes available for re-registration.
    // Important for the promotion-then-re-trial pattern: a visitor
    // who promoted, then returned for a fresh anonymous trial,
    // should not be blocked from claiming a new email.
    let repo = InMemoryUserRepository::default();
    repo.create(&u("1", Some("a@x.com"))).await.unwrap();
    repo.delete_by_id("1").await.unwrap();
    // Same email, different id, must succeed.
    repo.create(&u("2", Some("a@x.com"))).await.unwrap();
}

#[tokio::test]
async fn list_anonymous_expired_skips_human_users_even_if_old() {
    // Defense in depth: a `human_user` row past any conceivable
    // age must NEVER be returned by the sweep. The query filter
    // is `account_type='anonymous'` and the sweep relies on it.
    let repo = InMemoryUserRepository::default();
    repo.create(&u("human-ancient", Some("ancient@example.com"))).await.unwrap();
    let out = repo.list_anonymous_expired(i64::MAX).await.unwrap();
    assert!(out.is_empty(),
        "human users must never appear in the anonymous-expired list");
}
