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

// =====================================================================
// TOTP authenticator + recovery code in-memory tests (v0.27.0).
// =====================================================================

mod totp {
    use super::super::{
        InMemoryTotpAuthenticatorRepository, InMemoryTotpRecoveryCodeRepository,
    };
    use cesauth_core::ports::PortError;
    use cesauth_core::totp::storage::{
        TotpAuthenticator, TotpAuthenticatorRepository,
        TotpRecoveryCodeRepository, TotpRecoveryCodeRow,
    };

    fn auth(id: &str, user_id: &str, confirmed_at: Option<i64>) -> TotpAuthenticator {
        TotpAuthenticator {
            id:                id.into(),
            user_id:           user_id.into(),
            secret_ciphertext: vec![1, 2, 3],
            secret_nonce:      vec![4; 12],
            secret_key_id:     "k1".into(),
            last_used_step:    0,
            name:              None,
            created_at:        100,
            last_used_at:      None,
            confirmed_at,
        }
    }

    #[tokio::test]
    async fn create_and_find_by_id() {
        let r = InMemoryTotpAuthenticatorRepository::default();
        r.create(&auth("a1", "u1", None)).await.unwrap();
        let found = r.find_by_id("a1").await.unwrap().unwrap();
        assert_eq!(found.id, "a1");
        assert_eq!(found.confirmed_at, None);
    }

    #[tokio::test]
    async fn create_rejects_duplicate_id() {
        let r = InMemoryTotpAuthenticatorRepository::default();
        r.create(&auth("a1", "u1", None)).await.unwrap();
        assert!(matches!(r.create(&auth("a1", "u2", None)).await, Err(PortError::Conflict)));
    }

    #[tokio::test]
    async fn find_active_returns_only_confirmed() {
        let r = InMemoryTotpAuthenticatorRepository::default();
        r.create(&auth("unconf", "u1", None)).await.unwrap();
        // No confirmed authenticators yet.
        assert!(r.find_active_for_user("u1").await.unwrap().is_none());

        r.create(&auth("conf",   "u1", Some(200))).await.unwrap();
        let active = r.find_active_for_user("u1").await.unwrap().unwrap();
        assert_eq!(active.id, "conf");
    }

    #[tokio::test]
    async fn find_active_returns_most_recently_confirmed() {
        // ADR-009 §Q4 Q8: a user can have multiple TOTP
        // authenticators (phone + tablet). The verify gate
        // returns the most recently confirmed one.
        let r = InMemoryTotpAuthenticatorRepository::default();
        r.create(&auth("a1", "u1", Some(100))).await.unwrap();
        r.create(&auth("a2", "u1", Some(200))).await.unwrap();
        r.create(&auth("a3", "u1", Some(150))).await.unwrap();
        let active = r.find_active_for_user("u1").await.unwrap().unwrap();
        assert_eq!(active.id, "a2", "should pick the latest confirmed_at");
    }

    #[tokio::test]
    async fn find_active_does_not_cross_users() {
        let r = InMemoryTotpAuthenticatorRepository::default();
        r.create(&auth("a1", "u1", Some(100))).await.unwrap();
        assert!(r.find_active_for_user("u2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn confirm_flips_confirmed_at_and_advances_step() {
        let r = InMemoryTotpAuthenticatorRepository::default();
        r.create(&auth("a1", "u1", None)).await.unwrap();
        r.confirm("a1", 42, 999).await.unwrap();

        let row = r.find_by_id("a1").await.unwrap().unwrap();
        assert_eq!(row.confirmed_at,    Some(999));
        assert_eq!(row.last_used_step,  42);
        assert_eq!(row.last_used_at,    Some(999));
    }

    #[tokio::test]
    async fn confirm_rejects_already_confirmed() {
        let r = InMemoryTotpAuthenticatorRepository::default();
        r.create(&auth("a1", "u1", Some(100))).await.unwrap();
        // Already confirmed → second confirm fails closed.
        assert!(matches!(r.confirm("a1", 1, 200).await, Err(PortError::NotFound)));
    }

    #[tokio::test]
    async fn confirm_rejects_missing() {
        let r = InMemoryTotpAuthenticatorRepository::default();
        assert!(matches!(r.confirm("missing", 1, 1).await, Err(PortError::NotFound)));
    }

    #[tokio::test]
    async fn update_last_used_step_advances() {
        let r = InMemoryTotpAuthenticatorRepository::default();
        r.create(&auth("a1", "u1", Some(100))).await.unwrap();
        r.update_last_used_step("a1", 99, 200).await.unwrap();

        let row = r.find_by_id("a1").await.unwrap().unwrap();
        assert_eq!(row.last_used_step, 99);
        assert_eq!(row.last_used_at,   Some(200));
    }

    #[tokio::test]
    async fn delete_removes_row() {
        let r = InMemoryTotpAuthenticatorRepository::default();
        r.create(&auth("a1", "u1", Some(100))).await.unwrap();
        r.delete("a1").await.unwrap();
        assert!(r.find_by_id("a1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_unconfirmed_older_than_filters_correctly() {
        let r = InMemoryTotpAuthenticatorRepository::default();
        // Unconfirmed + old → IN
        r.create(&auth("old-unconf", "u1", None)).await.unwrap();
        // Confirmed + old → OUT (already enrolled, don't prune)
        r.create(&auth("old-conf", "u2", Some(50))).await.unwrap();
        // Unconfirmed + new → OUT (still in 24h grace window)
        let mut new_unconf = auth("new-unconf", "u3", None);
        new_unconf.created_at = 999_999;
        r.create(&new_unconf).await.unwrap();

        let out = r.list_unconfirmed_older_than(500).await.unwrap();
        assert_eq!(out, vec!["old-unconf".to_owned()]);
    }

    // -- recovery codes -----------------------------------------------

    fn rec(id: &str, user_id: &str, hash: &str, redeemed_at: Option<i64>)
        -> TotpRecoveryCodeRow
    {
        TotpRecoveryCodeRow {
            id:           id.into(),
            user_id:      user_id.into(),
            code_hash:    hash.into(),
            redeemed_at,
            created_at:   100,
        }
    }

    #[tokio::test]
    async fn bulk_create_inserts_all() {
        let r = InMemoryTotpRecoveryCodeRepository::default();
        let rows = vec![
            rec("r1", "u1", "h1", None),
            rec("r2", "u1", "h2", None),
            rec("r3", "u1", "h3", None),
        ];
        r.bulk_create(&rows).await.unwrap();
        assert_eq!(r.count_remaining("u1").await.unwrap(), 3);
    }

    #[tokio::test]
    async fn bulk_create_is_atomic_on_id_conflict() {
        // Pin the all-or-nothing property. If any row in the
        // batch conflicts, none should land.
        let r = InMemoryTotpRecoveryCodeRepository::default();
        r.bulk_create(&[rec("r1", "u1", "h1", None)]).await.unwrap();

        let result = r.bulk_create(&[
            rec("r2", "u1", "h2", None),
            rec("r1", "u1", "h-dup", None), // conflicts
            rec("r3", "u1", "h3", None),
        ]).await;
        assert!(matches!(result, Err(PortError::Conflict)));
        assert_eq!(r.count_remaining("u1").await.unwrap(), 1,
            "atomic rollback: r2 and r3 must NOT land if r1 conflicts");
    }

    #[tokio::test]
    async fn find_unredeemed_by_hash_skips_redeemed() {
        let r = InMemoryTotpRecoveryCodeRepository::default();
        r.bulk_create(&[
            rec("r1", "u1", "h1", Some(50)), // already redeemed
            rec("r2", "u1", "h2", None),
        ]).await.unwrap();

        assert!(r.find_unredeemed_by_hash("u1", "h1").await.unwrap().is_none(),
            "redeemed code must not be returned");
        assert!(r.find_unredeemed_by_hash("u1", "h2").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn find_unredeemed_does_not_cross_users() {
        let r = InMemoryTotpRecoveryCodeRepository::default();
        r.bulk_create(&[rec("r1", "u1", "h1", None)]).await.unwrap();
        // Same hash but wrong user → None.
        assert!(r.find_unredeemed_by_hash("u2", "h1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mark_redeemed_flips_timestamp() {
        let r = InMemoryTotpRecoveryCodeRepository::default();
        r.bulk_create(&[rec("r1", "u1", "h1", None)]).await.unwrap();
        r.mark_redeemed("r1", 200).await.unwrap();

        // Now finding by hash returns None (filter excludes
        // redeemed).
        assert!(r.find_unredeemed_by_hash("u1", "h1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mark_redeemed_rejects_already_redeemed() {
        let r = InMemoryTotpRecoveryCodeRepository::default();
        r.bulk_create(&[rec("r1", "u1", "h1", Some(100))]).await.unwrap();
        // Concurrent redeem race: second caller fails closed.
        assert!(matches!(r.mark_redeemed("r1", 200).await, Err(PortError::NotFound)));
    }

    #[tokio::test]
    async fn count_remaining_excludes_redeemed() {
        let r = InMemoryTotpRecoveryCodeRepository::default();
        r.bulk_create(&[
            rec("r1", "u1", "h1", None),
            rec("r2", "u1", "h2", Some(50)),
            rec("r3", "u1", "h3", None),
        ]).await.unwrap();
        assert_eq!(r.count_remaining("u1").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn delete_all_for_user_scopes_correctly() {
        let r = InMemoryTotpRecoveryCodeRepository::default();
        r.bulk_create(&[
            rec("r1", "u1", "h1", None),
            rec("r2", "u2", "h2", None),
        ]).await.unwrap();

        r.delete_all_for_user("u1").await.unwrap();
        assert_eq!(r.count_remaining("u1").await.unwrap(), 0);
        assert_eq!(r.count_remaining("u2").await.unwrap(), 1,
            "deletion must not cross user boundary");
    }
}
