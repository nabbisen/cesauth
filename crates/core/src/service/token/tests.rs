//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn refresh_round_trip() {
    let encoded = encode_refresh(&crate::types::FamilyId::from_storage("fam"), &crate::types::Jti::from_storage("jti-1"));
    let (fam, jti) = decode_refresh(&encoded).unwrap();
    assert_eq!(fam.as_str(), "fam");
    assert_eq!(jti.as_str(), "jti-1");
}

#[test]
fn decode_rejects_garbage() {
    assert!(decode_refresh("!!!").is_err());
}

// ====================================================================
// RFC 001: id_token integration tests using lightweight inline stubs
// ====================================================================

#[cfg(test)]
mod id_token_tests {
    use super::{exchange_code, rotate_refresh, ExchangeCodeInput, RotateRefreshInput, TokenDeps, TokenConfig};
    use super::encode_refresh;

    use std::cell::RefCell;
    use std::collections::HashMap;

    use crate::error::{CoreError, CoreResult};
    use crate::jwt::{AccessTokenClaims, JwtSigner};
    use crate::oidc::id_token::IdTokenClaims;
    use crate::oidc::token::TokenResponse;
    use crate::ports::{PortError, PortResult};
    use crate::ports::repo::{
        ClientAuthView, ClientRepository, Grant, GrantRepository, UserRepository,
    };
    use crate::ports::store::{
        AuthChallengeStore, Challenge, FamilyInit, FamilyState, RateLimitDecision,
        RateLimitStore, RefreshTokenFamilyStore, RotateOutcome,
    };
    use crate::types::{
        ClientType, OidcClient, Scopes, TokenAuthMethod, User, UserStatus,
    };
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use pkcs8::EncodePrivateKey;

    // ── helpers ─────────────────────────────────────────────────────

    fn test_signer() -> JwtSigner {
        let sk = SigningKey::from_bytes(&[0xABu8; 32]);
        let pem = sk.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap();
        JwtSigner::from_pem("kid-t".to_owned(), pem.as_bytes(), "https://t.test".to_owned()).unwrap()
    }

    fn test_client(id: &str) -> OidcClient {
        OidcClient {
            id:                id.to_owned(),
            name:              id.to_owned(),
            client_type:       ClientType::Confidential,
            redirect_uris:     vec!["https://app.test/cb".to_owned()],
            allowed_scopes:    vec!["openid".to_owned(), "email".to_owned()],
            token_auth_method: TokenAuthMethod::ClientSecretBasic,
            require_pkce:      true,
            audience:          None,
        }
    }

    /// The secret every confidential test client authenticates with.
    const TEST_SECRET: &str = "test-client-secret-0123456789abcdef";

    /// A **valid** confidential client: `client_type = Confidential` with a
    /// stored hash. RFC 137 §12.5: the fixture previously carried no hash —
    /// exactly the case `/token` now rejects — so the fixture is corrected
    /// and every assertion below is unchanged.
    fn confidential_client(id: &str) -> (OidcClient, Option<String>) {
        (test_client(id), Some(crate::service::client_auth::sha256_hex(TEST_SECRET.as_bytes())))
    }

    /// A public PKCE-only client, shaped like the beginner guide's `demo-cli`:
    /// `client_type = Public`, no stored hash, `token_auth_method = none`.
    fn public_client(id: &str) -> (OidcClient, Option<String>) {
        let mut c = test_client(id);
        c.client_type       = ClientType::Public;
        c.token_auth_method = TokenAuthMethod::None;
        (c, None)
    }

    fn test_user(id: &str) -> User {
        User {
            id:             id.to_owned(),
            tenant_id:      "t-default".to_owned(),
            email:          Some(format!("{id}@test.com")),
            email_verified: true,
            display_name:   Some("Test".to_owned()),
            account_type:   crate::tenancy::AccountType::HumanUser,
            status:         UserStatus::Active,
            created_at:     0,
            updated_at:     0,
        }
    }

    fn decode_id_claims(token: &str) -> IdTokenClaims {
        let b64 = token.split('.').nth(1).expect("3-part JWT");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── stubs ────────────────────────────────────────────────────────

    /// Client plus its stored secret hash, as `oidc_clients` holds them.
    struct StubClients(HashMap<String, (OidcClient, Option<String>)>);
    impl ClientRepository for StubClients {
        async fn find(&self, id: &str) -> PortResult<Option<OidcClient>> {
            Ok(self.0.get(id).map(|(c, _)| c.clone()))
        }
        async fn client_secret_hash(&self, id: &str) -> PortResult<Option<String>> {
            Ok(self.0.get(id).and_then(|(_, h)| h.clone()))
        }
        async fn find_auth_view(&self, id: &str) -> PortResult<Option<ClientAuthView>> {
            Ok(self.0.get(id).map(|(c, h)| ClientAuthView {
                client_id: c.id.clone(),
                client_type: c.client_type,
                client_secret_hash: h.clone(),
                audience: c.audience.clone(),
                token_auth_method: c.token_auth_method,
            }))
        }
        async fn create(&self, _: &OidcClient, _: Option<&str>) -> PortResult<()> { Ok(()) }
    }

    struct StubCodes(RefCell<HashMap<String, Challenge>>);
    impl AuthChallengeStore for StubCodes {
        async fn put(&self, code: &crate::types::ChallengeHandle, ch: &Challenge) -> PortResult<()> {
            self.0.borrow_mut().insert(code.as_str().to_owned(), ch.clone());
            Ok(())
        }
        // RFC 140 T3: a store, so it implements the port's expiry rule —
        // expired iff `now_unix >= expires_at()`. A stub that ignored expiry
        // would make the expired-code test unpassable.
        async fn peek(&self, code: &crate::types::ChallengeHandle, now_unix: i64) -> PortResult<Option<Challenge>> {
            Ok(self.0.borrow().get(code.as_str()).filter(|c| now_unix < c.expires_at()).cloned())
        }
        async fn take(&self, code: &crate::types::ChallengeHandle, now_unix: i64) -> PortResult<Option<Challenge>> {
            Ok(self.0.borrow_mut().remove(code.as_str()).filter(|c| now_unix < c.expires_at()))
        }
        async fn bump_magic_link_attempts(&self, _: &crate::types::ChallengeHandle, _: i64) -> PortResult<u32> { Ok(0) }
    }

    struct StubFamilies(RefCell<HashMap<crate::types::FamilyId, FamilyState>>);
    impl RefreshTokenFamilyStore for StubFamilies {
        async fn init(&self, init: &FamilyInit) -> PortResult<()> {
            self.0.borrow_mut().insert(init.family_id.clone(), FamilyState {
                family_id:       init.family_id.clone(),
                user_id:         init.user_id.clone(),
                client_id:       init.client_id.clone(),
                scopes:          init.scopes.clone(),
                current_jti:     init.first_jti.clone(),
                retired_jtis:    vec![],
                created_at:      init.now_unix,
                last_rotated_at: init.now_unix,
                revoked_at:      None,
                reused_jti:      None,
                reused_at:       None,
                reuse_was_retired: None,
                expired:           None,
                auth_time:       init.auth_time,
            });
            Ok(())
        }
        async fn rotate(&self, family_id: &crate::types::FamilyId, presented_jti: &crate::types::Jti, new_jti: &crate::types::Jti, now: i64, lifetime: &crate::ports::store::RefreshLifetime) -> PortResult<RotateOutcome> {
            let mut m = self.0.borrow_mut();
            if let Some(fam) = m.get_mut(family_id) {
                // RFC 137 T5: honour revocation first, as the real family DO
                // (`adapter-cloudflare/src/refresh_token_family.rs:103`) and
                // the in-memory store (`adapter-test/src/store/
                // refresh_token_family.rs:56`) both do. This stub previously
                // rotated a revoked family, so no test that revocation stops
                // the owner's next refresh could have passed against it.
                if fam.revoked_at.is_some() {
                    return Ok(RotateOutcome::AlreadyRevoked);
                }
                // RFC 139: a store, so it enforces the lifetime policy in the
                // port's order — revoked, lifetime (core's function), then jti.
                if let crate::ports::store::Lifetime::Expired(kind) = fam.lifetime(now, lifetime) {
                    fam.revoked_at = Some(now);
                    fam.expired    = Some(kind);
                    return Ok(RotateOutcome::Expired(kind));
                }
                if &fam.current_jti != presented_jti {
                    return Ok(RotateOutcome::ReusedAndRevoked { reused_jti: presented_jti.clone(), was_retired: false });
                }
                fam.retired_jtis.push(fam.current_jti.clone());
                fam.current_jti = new_jti.clone();
                fam.last_rotated_at = now;
                Ok(RotateOutcome::Rotated { new_current_jti: new_jti.clone() })
            } else {
                Ok(RotateOutcome::AlreadyRevoked)
            }
        }
        async fn revoke(&self, family_id: &crate::types::FamilyId, _: i64) -> PortResult<()> {
            if let Some(f) = self.0.borrow_mut().get_mut(family_id) {
                f.revoked_at = Some(0);
            }
            Ok(())
        }
        async fn peek(&self, family_id: &crate::types::FamilyId) -> PortResult<Option<FamilyState>> {
            Ok(self.0.borrow().get(family_id).cloned())
        }
    }

    struct StubGrants;
    impl GrantRepository for StubGrants {
        async fn create(&self, _: &Grant) -> PortResult<()> { Ok(()) }
        async fn list_active_for_user(&self, _: &str) -> PortResult<Vec<Grant>> { Ok(vec![]) }
        async fn mark_revoked(&self, _: &str, _: i64) -> PortResult<()> { Ok(()) }
    }

    struct StubUsers(HashMap<String, User>);
    impl UserRepository for StubUsers {
        async fn find_by_id(&self, id: &str) -> PortResult<Option<User>> {
            Ok(self.0.get(id).cloned())
        }
        async fn find_by_email(&self, _: &str) -> PortResult<Option<User>> { Ok(None) }
        async fn create(&self, _: &User) -> PortResult<()> { Ok(()) }
        async fn update(&self, _: &User) -> PortResult<()> { Ok(()) }
        async fn list_by_tenant(&self, _: &str) -> PortResult<Vec<User>> { Ok(vec![]) }
        async fn list_anonymous_expired(&self, _: crate::types::UnixSeconds) -> PortResult<Vec<User>> { Ok(vec![]) }
        async fn delete_by_id(&self, _: &str) -> PortResult<()> { Ok(()) }
    }

    struct StubRates;
    impl RateLimitStore for StubRates {
        async fn hit(&self, _: &str, _: i64, _: i64, limit: u32, _: u32) -> PortResult<RateLimitDecision> {
            Ok(RateLimitDecision { allowed: true, count: 0, limit, resets_in: 60, escalate: false })
        }
        async fn reset(&self, _: &str) -> PortResult<()> { Ok(()) }
    }

    // ── PKCE helper ──────────────────────────────────────────────────

    fn s256_challenge(verifier: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
    }

    fn stub_exchange_setup(scopes: &[&str], auth_time: i64, verifier: &str)
        -> (StubClients, StubCodes, StubFamilies, StubGrants, StubUsers)
    {
        let mut clients = HashMap::new();
        clients.insert("c-1".to_owned(), confidential_client("c-1"));
        let mut users = HashMap::new();
        users.insert("u-1".to_owned(), test_user("u-1"));

        let codes = StubCodes(RefCell::new(HashMap::new()));
        let code_ch = Challenge::AuthCode {
            client_id: "c-1".to_owned(),
            redirect_uri:          "https://app.test/cb".to_owned(),
            user_id: "u-1".to_owned(),
            scopes:                Scopes(scopes.iter().map(|s| s.to_string()).collect()),
            nonce:                 None,
            code_challenge:        s256_challenge(verifier),
            code_challenge_method: "S256".to_owned(),
            issued_at:             1_700_000_000,
            expires_at:            1_700_000_300,
            auth_time,
        };
        codes.0.borrow_mut().insert("code-1".to_owned(), code_ch);

        (
            StubClients(clients),
            codes,
            StubFamilies(RefCell::new(HashMap::new())),
            StubGrants,
            StubUsers(users),
        )
    }


    fn make_deps_cfg<'a>(
        clients:  &'a StubClients,
        codes:    &'a StubCodes,
        families: &'a StubFamilies,
        grants:   &'a StubGrants,
        users:    &'a StubUsers,
        rates:    &'a StubRates,
        iss:      &'a str,
    ) -> (TokenDeps<'a, StubClients, StubCodes, StubFamilies, StubGrants, StubUsers, StubRates>, TokenConfig<'a>) {
        let deps = TokenDeps { clients, codes, families, grants, users, rates };
        let cfg  = TokenConfig { access_ttl_secs: 3600, refresh_lifetime: crate::ports::store::RefreshLifetime::new(2_592_000, crate::ports::store::DEFAULT_REFRESH_IDLE_TIMEOUT_SECS).unwrap(), iss };
        (deps, cfg)
    }

    async fn run_exchange(scopes: &[&str], auth_time: i64) -> TokenResponse {
        let (clients, codes, families, grants, users) =
            stub_exchange_setup(scopes, auth_time, "test-verifier-padded-to-exactly-43chars-xxx");
        let signer = test_signer();
        let _code_handle = crate::types::ChallengeHandle::from_storage("code-1");
        let input = ExchangeCodeInput {
            code:          &_code_handle,
            redirect_uri:  "https://app.test/cb",
            client_id:     "c-1",
            client_secret: Some(TEST_SECRET),
            code_verifier: "test-verifier-padded-to-exactly-43chars-xxx",
            now_unix:      1_700_000_000,
        };
        let (deps, tok_cfg) = make_deps_cfg(&clients, &codes, &families, &grants, &users, &StubRates, "https://t.test");
        exchange_code(&deps, &signer, &tok_cfg, &input).await.unwrap()
    }

    /// `exchange_code` on `stub_exchange_setup`'s code (expires at
    /// 1_700_000_300), presenting `code` at `now_unix`, returning the error.
    async fn exchange_err(code: &str, now_unix: i64) -> CoreError {
        let verifier = "test-verifier-padded-to-exactly-43chars-xxx";
        let (clients, codes, families, grants, users) = stub_exchange_setup(&["openid"], 1_699_999_900, verifier);
        let handle = crate::types::ChallengeHandle::from_storage(code);
        let input = ExchangeCodeInput {
            code:          &handle,
            redirect_uri:  "https://app.test/cb",
            client_id:     "c-1",
            client_secret: Some(TEST_SECRET),
            code_verifier: verifier,
            now_unix,
        };
        let (deps, tok_cfg) = make_deps_cfg(&clients, &codes, &families, &grants, &users, &StubRates, "https://t.test");
        match exchange_code(&deps, &test_signer(), &tok_cfg, &input).await {
            Ok(_)  => panic!("expected an error for code {code:?} at {now_unix}"),
            Err(e) => e,
        }
    }

    /// RFC 140 test 5: an expired code is indistinguishable on the wire from
    /// an unknown one — the same variant **and the same message**. Compared
    /// with each other, not with two literals.
    #[tokio::test]
    async fn rfc140_expired_code_is_the_same_invalid_grant_as_an_unknown_code() {
        let expired = exchange_err("code-1", 1_700_000_300).await; // == expires_at
        let unknown = exchange_err("no-such-code", 1_700_000_000).await;
        match (&expired, &unknown) {
            (CoreError::InvalidGrant(a), CoreError::InvalidGrant(b)) => assert_eq!(a, b),
            _ => panic!("both must be InvalidGrant: expired={expired:?} unknown={unknown:?}"),
        }
    }

    // ── tests ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn exchange_code_with_openid_scope_returns_id_token() {
        let resp = run_exchange(&["openid"], 1_699_999_900).await;
        assert!(resp.id_token.is_some(), "openid scope must yield id_token");
    }

    #[tokio::test]
    async fn exchange_code_without_openid_scope_does_not_return_id_token() {
        let resp = run_exchange(&["email", "profile"], 0).await;
        assert!(resp.id_token.is_none(), "no openid → no id_token");
    }

    #[tokio::test]
    async fn exchange_code_id_token_aud_equals_client_id() {
        let resp = run_exchange(&["openid"], 0).await;
        let c = decode_id_claims(resp.id_token.as_deref().unwrap());
        assert_eq!(c.aud, "c-1");
    }

    #[tokio::test]
    async fn exchange_code_id_token_sub_equals_user_id() {
        let resp = run_exchange(&["openid"], 0).await;
        let c = decode_id_claims(resp.id_token.as_deref().unwrap());
        assert_eq!(c.sub, "u-1");
    }

    #[tokio::test]
    async fn exchange_code_id_token_auth_time_matches_challenge_auth_time() {
        let auth_t = 1_699_999_800i64;
        let resp = run_exchange(&["openid"], auth_t).await;
        let c = decode_id_claims(resp.id_token.as_deref().unwrap());
        assert_eq!(c.auth_time, auth_t, "auth_time must match challenge auth_time");
    }

    #[tokio::test]
    async fn rotate_refresh_with_openid_scope_returns_id_token() {
        let mut client_map = HashMap::new();
        client_map.insert("c-r".to_owned(), confidential_client("c-r"));
        let mut user_map = HashMap::new();
        user_map.insert("u-r".to_owned(), test_user("u-r"));
        let orig_auth_time = 1_699_900_000i64;
        let families = StubFamilies(RefCell::new(HashMap::new()));
        let init = FamilyInit {
            family_id: crate::types::FamilyId::from_storage("fam-r"),
            user_id: crate::types::UserId::from_storage("u-r"),
            client_id: crate::types::ClientId::from_storage("c-r"),
            scopes:    vec!["openid".to_owned()],
            first_jti: crate::types::Jti::from_storage("j-first"),
            now_unix:  1_700_000_000,
            auth_time: orig_auth_time,
        };
        families.init(&init).await.unwrap();
        let rt = encode_refresh(&crate::types::FamilyId::from_storage("fam-r"), &crate::types::Jti::from_storage("j-first"));
        let input = RotateRefreshInput {
            refresh_token: &rt,
            client_id:     "c-r",
            client_secret: Some(TEST_SECRET),
            scope:         None,
            now_unix:      1_700_000_050,
            rate_limit_threshold:   0,
            rate_limit_window_secs: 60,
        };
        let resp = {
            let clients_s = StubClients(client_map);
            let users_s   = StubUsers(user_map);
            let codes_s   = StubCodes(RefCell::new(HashMap::new()));
            let deps = TokenDeps { clients: &clients_s, codes: &codes_s, families: &families, grants: &StubGrants, users: &users_s, rates: &StubRates };
            let tok_cfg = TokenConfig { access_ttl_secs: 3600, refresh_lifetime: crate::ports::store::RefreshLifetime::new(2_592_000, crate::ports::store::DEFAULT_REFRESH_IDLE_TIMEOUT_SECS).unwrap(), iss: "https://t.test" };
            rotate_refresh(&deps, &test_signer(), &tok_cfg, &input).await
        }.unwrap();
        assert!(resp.id_token.is_some(), "rotate openid → id_token");
    }

    #[tokio::test]
    async fn rotate_refresh_id_token_auth_time_preserves_family_auth_time() {
        let mut client_map = HashMap::new();
        client_map.insert("c-at".to_owned(), confidential_client("c-at"));
        let mut user_map = HashMap::new();
        user_map.insert("u-at".to_owned(), test_user("u-at"));
        let orig_auth_time = 1_699_900_000i64;
        let families = StubFamilies(RefCell::new(HashMap::new()));
        families.init(&FamilyInit {
            family_id: crate::types::FamilyId::from_storage("fam-at"),
            user_id: crate::types::UserId::from_storage("u-at"),
            client_id: crate::types::ClientId::from_storage("c-at"),
            scopes:    vec!["openid".to_owned()],
            first_jti: crate::types::Jti::from_storage("j-at"),
            now_unix:  1_700_000_000,
            auth_time: orig_auth_time,
        }).await.unwrap();
        let rt = encode_refresh(&crate::types::FamilyId::from_storage("fam-at"), &crate::types::Jti::from_storage("j-at"));
        let input = RotateRefreshInput {
            refresh_token:        &rt,
            client_id:            "c-at",
            client_secret:        Some(TEST_SECRET),
            scope:                None,
            now_unix:             1_700_001_000, // 1000 seconds later
            rate_limit_threshold:   0,
            rate_limit_window_secs: 60,
        };
        let resp = {
            let clients_s = StubClients(client_map);
            let users_s   = StubUsers(user_map);
            let codes_s   = StubCodes(RefCell::new(HashMap::new()));
            let deps = TokenDeps { clients: &clients_s, codes: &codes_s, families: &families, grants: &StubGrants, users: &users_s, rates: &StubRates };
            let tok_cfg = TokenConfig { access_ttl_secs: 3600, refresh_lifetime: crate::ports::store::RefreshLifetime::new(2_592_000, crate::ports::store::DEFAULT_REFRESH_IDLE_TIMEOUT_SECS).unwrap(), iss: "https://t.test" };
            rotate_refresh(&deps, &test_signer(), &tok_cfg, &input).await
        }.unwrap();
        let c = decode_id_claims(resp.id_token.as_deref().unwrap());
        assert_eq!(c.auth_time, orig_auth_time,
            "auth_time must be ORIGINAL auth time, not rotation time");
        assert_ne!(c.iat, orig_auth_time, "iat should be rotation time, not auth_time");
    }

    #[tokio::test]
    async fn rotate_refresh_without_openid_no_id_token() {
        let mut client_map = HashMap::new();
        client_map.insert("c-no".to_owned(), confidential_client("c-no"));
        let mut user_map = HashMap::new();
        user_map.insert("u-no".to_owned(), test_user("u-no"));
        let families = StubFamilies(RefCell::new(HashMap::new()));
        families.init(&FamilyInit {
            family_id: crate::types::FamilyId::from_storage("fam-no"),
            user_id: crate::types::UserId::from_storage("u-no"),
            client_id: crate::types::ClientId::from_storage("c-no"),
            scopes:    vec!["profile".to_owned()],
            first_jti: crate::types::Jti::from_storage("j-no"),
            now_unix:  1_700_000_000,
            auth_time: 0,
        }).await.unwrap();
        let rt = encode_refresh(&crate::types::FamilyId::from_storage("fam-no"), &crate::types::Jti::from_storage("j-no"));
        let input = RotateRefreshInput {
            refresh_token:        &rt,
            client_id:            "c-no",
            client_secret:        Some(TEST_SECRET),
            scope:                None,
            now_unix:             1_700_000_010,
            rate_limit_threshold:   0,
            rate_limit_window_secs: 60,
        };
        let resp = {
            let clients_s = StubClients(client_map);
            let users_s   = StubUsers(user_map);
            let codes_s   = StubCodes(RefCell::new(HashMap::new()));
            let deps = TokenDeps { clients: &clients_s, codes: &codes_s, families: &families, grants: &StubGrants, users: &users_s, rates: &StubRates };
            let tok_cfg = TokenConfig { access_ttl_secs: 3600, refresh_lifetime: crate::ports::store::RefreshLifetime::new(2_592_000, crate::ports::store::DEFAULT_REFRESH_IDLE_TIMEOUT_SECS).unwrap(), iss: "https://t.test" };
            rotate_refresh(&deps, &test_signer(), &tok_cfg, &input).await
        }.unwrap();
        assert!(resp.id_token.is_none(), "no openid → no id_token on refresh");
    }

    #[tokio::test]
    async fn exchange_code_id_token_carries_nonce_when_authorize_had_one() {
        // RFC 033 / OIDC Core §3.1.3.6
        let verifier = "test-verifier-padded-to-exactly-43chars-xxx";
        let (clients, codes, families, grants, users) =
            stub_exchange_setup(&["openid"], 1_699_999_900, verifier);

        // Replace the challenge with one that has a nonce.
        let nonce_val = "unique-nonce-abc-123";
        use sha2::{Digest, Sha256};
        use base64::Engine;
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize());
        codes.0.borrow_mut().insert("code-1".to_owned(), Challenge::AuthCode {
            client_id: "c-1".to_owned(),
            redirect_uri:          "https://app.test/cb".to_owned(),
            user_id: "u-1".to_owned(),
            scopes:                Scopes(vec!["openid".to_owned()]),
            nonce:                 Some(nonce_val.to_owned()),
            code_challenge:        challenge_b64,
            code_challenge_method: "S256".to_owned(),
            issued_at:             1_700_000_000,
            expires_at:            1_700_000_300,
            auth_time:             1_699_999_900,
        });

        let signer = test_signer();
        let _code_handle = crate::types::ChallengeHandle::from_storage("code-1");
        let input = ExchangeCodeInput {
            code:          &_code_handle,
            redirect_uri:  "https://app.test/cb",
            client_id:     "c-1",
            client_secret: Some(TEST_SECRET),
            code_verifier: verifier,
            now_unix:      1_700_000_000,
        };
        let resp = {
            let (deps, tok_cfg) = make_deps_cfg(&clients, &codes, &families, &grants, &users, &StubRates, "https://t.test");
            exchange_code(&deps, &signer, &tok_cfg, &input).await.unwrap()
        };

        let c = decode_id_claims(resp.id_token.as_deref().unwrap());
        assert_eq!(c.nonce.as_deref(), Some(nonce_val),
            "RFC 033: nonce from authorize request must appear in id_token");
    }

    #[tokio::test]
    async fn exchange_code_id_token_omits_nonce_when_authorize_had_none() {
        // nonce=None → id_token must not carry nonce claim
        let resp = run_exchange(&["openid"], 1_699_999_900).await;
        let c = decode_id_claims(resp.id_token.as_deref().unwrap());
        assert!(c.nonce.is_none(),
            "RFC 033: nonce must be absent when authorize did not include one");
    }

    // ── RFC 137: client authentication and binding on /token ─────────

    const VERIFIER: &str = "test-verifier-padded-to-exactly-43chars-xxx";

    /// A code store holding one code, `code-1`, issued to `issued_to`.
    fn codes_issued_to(issued_to: &str) -> StubCodes {
        let codes = StubCodes(RefCell::new(HashMap::new()));
        codes.0.borrow_mut().insert("code-1".to_owned(), Challenge::AuthCode {
            client_id:             issued_to.to_owned(),
            redirect_uri:          "https://app.test/cb".to_owned(),
            user_id:               "u-1".to_owned(),
            scopes:                Scopes(vec!["openid".to_owned()]),
            nonce:                 None,
            code_challenge:        s256_challenge(VERIFIER),
            code_challenge_method: "S256".to_owned(),
            issued_at:             1_700_000_000,
            expires_at:            1_700_000_300,
            auth_time:             1_699_999_900,
        });
        codes
    }

    fn clients_of(entries: Vec<(&str, (OidcClient, Option<String>))>) -> StubClients {
        StubClients(entries.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    fn users_with_u1() -> StubUsers {
        let mut users = HashMap::new();
        users.insert("u-1".to_owned(), test_user("u-1"));
        StubUsers(users)
    }

    /// Redeem `code-1` as `client_id`, presenting `secret`, with the correct
    /// verifier and redirect URI — so only client identity can fail it.
    async fn redeem(
        clients:   &StubClients,
        codes:     &StubCodes,
        client_id: &str,
        secret:    Option<&str>,
    ) -> CoreResult<TokenResponse> {
        let families = StubFamilies(RefCell::new(HashMap::new()));
        let users    = users_with_u1();
        let handle   = crate::types::ChallengeHandle::from_storage("code-1");
        let input = ExchangeCodeInput {
            code:          &handle,
            redirect_uri:  "https://app.test/cb",
            client_id,
            client_secret: secret,
            code_verifier: VERIFIER,
            now_unix:      1_700_000_000,
        };
        let (deps, cfg) = make_deps_cfg(clients, codes, &families, &StubGrants, &users, &StubRates, "https://t.test");
        exchange_code(&deps, &test_signer(), &cfg, &input).await
    }

    /// A family `fam-x` issued to `issued_to`, current jti `j-1`, and the
    /// refresh token that presents it.
    async fn family_issued_to(issued_to: &str) -> (StubFamilies, String) {
        let families = StubFamilies(RefCell::new(HashMap::new()));
        families.init(&FamilyInit {
            family_id: crate::types::FamilyId::from_storage("fam-x"),
            user_id:   crate::types::UserId::from_storage("u-1"),
            client_id: crate::types::ClientId::from_storage(issued_to),
            scopes:    vec!["openid".to_owned()],
            first_jti: crate::types::Jti::from_storage("j-1"),
            now_unix:  1_700_000_000,
            auth_time: 1_699_999_900,
        }).await.unwrap();
        let rt = encode_refresh(&crate::types::FamilyId::from_storage("fam-x"), &crate::types::Jti::from_storage("j-1"));
        (families, rt)
    }

    async fn refresh(
        clients:       &StubClients,
        families:      &StubFamilies,
        refresh_token: &str,
        client_id:     &str,
        secret:        Option<&str>,
    ) -> CoreResult<TokenResponse> {
        let users = users_with_u1();
        let codes = StubCodes(RefCell::new(HashMap::new()));
        let input = RotateRefreshInput {
            refresh_token,
            client_id,
            client_secret:          secret,
            scope:                  None,
            now_unix:               1_700_000_050,
            rate_limit_threshold:   0,
            rate_limit_window_secs: 60,
        };
        let deps = TokenDeps { clients, codes: &codes, families, grants: &StubGrants, users: &users, rates: &StubRates };
        let cfg  = TokenConfig { access_ttl_secs: 3600, refresh_lifetime: crate::ports::store::RefreshLifetime::new(2_592_000, crate::ports::store::DEFAULT_REFRESH_IDLE_TIMEOUT_SECS).unwrap(), iss: "https://t.test" };
        rotate_refresh(&deps, &test_signer(), &cfg, &input).await
    }

    fn fam_x() -> crate::types::FamilyId { crate::types::FamilyId::from_storage("fam-x") }

    // ── RFC 139: the refresh grant under a lifetime policy ──

    /// `refresh`, at an explicit clock and lifetime policy.
    async fn refresh_at(
        clients:       &StubClients,
        families:      &StubFamilies,
        refresh_token: &str,
        client_id:     &str,
        secret:        Option<&str>,
        now_unix:      i64,
        lifetime:      crate::ports::store::RefreshLifetime,
    ) -> CoreResult<TokenResponse> {
        let users = users_with_u1();
        let codes = StubCodes(RefCell::new(HashMap::new()));
        let input = RotateRefreshInput {
            refresh_token,
            client_id,
            client_secret:          secret,
            scope:                  None,
            now_unix,
            rate_limit_threshold:   0,
            rate_limit_window_secs: 60,
        };
        let deps = TokenDeps { clients, codes: &codes, families, grants: &StubGrants, users: &users, rates: &StubRates };
        let cfg  = TokenConfig { access_ttl_secs: 3600, refresh_lifetime: lifetime, iss: "https://t.test" };
        rotate_refresh(&deps, &test_signer(), &cfg, &input).await
    }

    /// RFC 139 test 8 — `/token` refresh on an expired family is `InvalidGrant`
    /// (the variant a revoked family gets, so the same wire code — pinned in
    /// the backend's `error.rs`), and the store revoked it recording why. One
    /// second earlier it rotates.
    #[tokio::test]
    async fn rfc139_refresh_on_an_expired_family_is_invalid_grant() {
        use crate::ports::store::{LifetimeExpiry, RefreshLifetime};
        let clients = clients_of(vec![("c-a", confidential_client("c-a"))]);
        let policy  = RefreshLifetime::new(86_400, 3_600).unwrap(); // idle 1 h

        let (live, rt_live) = family_issued_to("c-a").await; // created 1_700_000_000
        refresh_at(&clients, &live, &rt_live, "c-a", Some(TEST_SECRET), 1_700_000_000 + 3_599, policy).await
            .expect("one second before the idle deadline the family rotates");

        let (families, rt) = family_issued_to("c-a").await;
        let err = refresh_at(&clients, &families, &rt, "c-a", Some(TEST_SECRET), 1_700_000_000 + 3_600, policy).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidGrant(_)), "got {err:?}");
        let fam = families.peek(&fam_x()).await.unwrap().unwrap();
        assert!(fam.revoked_at.is_some(), "expiry revokes the family");
        assert_eq!(fam.expired, Some(LifetimeExpiry::Idle));
    }

    /// RFC 139 test 9 — lowering the policy shortens a live family: rotated
    /// under 30 days, the family is then expired under a 1-day policy once
    /// `created_at + 1 d` has passed (§9.2's incident property).
    #[tokio::test]
    async fn rfc139_lowering_the_policy_shortens_a_live_family() {
        use crate::ports::store::{LifetimeExpiry, RefreshLifetime, DEFAULT_REFRESH_IDLE_TIMEOUT_SECS};
        let clients = clients_of(vec![("c-a", confidential_client("c-a"))]);
        let thirty_days = RefreshLifetime::new(2_592_000, DEFAULT_REFRESH_IDLE_TIMEOUT_SECS).unwrap();
        let one_day     = RefreshLifetime::new(86_400, 0).unwrap();

        let (families, rt) = family_issued_to("c-a").await; // created 1_700_000_000
        let resp = refresh_at(&clients, &families, &rt, "c-a", Some(TEST_SECRET), 1_700_000_100, thirty_days).await
            .expect("live under the 30-day policy");
        let rt2 = resp.refresh_token.expect("rotation returns a new refresh token");

        let err = refresh_at(&clients, &families, &rt2, "c-a", Some(TEST_SECRET), 1_700_000_000 + 86_400, one_day).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidGrant(_)), "got {err:?}");
        let fam = families.peek(&fam_x()).await.unwrap().unwrap();
        assert_eq!(fam.expired, Some(LifetimeExpiry::Absolute),
            "the lowered cap applies to a family created under the old one");
    }

    /// RFC 139 test 13 (token decoder) — exactly two parts; a three-part token,
    /// the pre-RFC 139 format, is malformed.
    #[test]
    fn rfc139_token_decoder_accepts_exactly_two_parts() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let fid = crate::types::FamilyId::from_storage("fam");
        let jti = crate::types::Jti::from_storage("jti");
        let (f, j) = crate::service::token::decode_refresh(&crate::service::token::encode_refresh(&fid, &jti))
            .expect("encode/decode round-trip");
        assert_eq!((f.as_str(), j.as_str()), ("fam", "jti"));
        assert!(matches!(crate::service::token::decode_refresh(&URL_SAFE_NO_PAD.encode("fam.jti.1700000000")),
            Err(CoreError::InvalidGrant(_))), "three parts must be malformed");
        assert!(crate::service::token::decode_refresh(&URL_SAFE_NO_PAD.encode("fam")).is_err(), "one part");
    }

    // ── code grant ──

    /// Test 1 — a code issued to A, redeemed by B holding valid credentials,
    /// the correct verifier and the correct redirect URI, is refused.
    #[tokio::test]
    async fn code_issued_to_one_client_is_refused_to_another() {
        let clients = clients_of(vec![("c-a", confidential_client("c-a")), ("c-b", confidential_client("c-b"))]);
        let codes   = codes_issued_to("c-a");
        let err = redeem(&clients, &codes, "c-b", Some(TEST_SECRET)).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidGrant(_)),
            "a code redeemed by a client it was not issued to must be invalid_grant, got {err:?}");
    }

    /// Test 2 — the refused attempt consumed the code, so A's correct
    /// redemption afterwards fails too.
    #[tokio::test]
    async fn wrong_client_redemption_consumes_the_code() {
        let clients = clients_of(vec![("c-a", confidential_client("c-a")), ("c-b", confidential_client("c-b"))]);
        let codes   = codes_issued_to("c-a");
        let _ = redeem(&clients, &codes, "c-b", Some(TEST_SECRET)).await.unwrap_err();
        let err = redeem(&clients, &codes, "c-a", Some(TEST_SECRET)).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidGrant(_)),
            "the wrong-client attempt must have consumed the code, got {err:?}");
    }

    /// Test 3 — confidential client, wrong secret. Authentication precedes the
    /// code, so the failed attempt must not consume it.
    #[tokio::test]
    async fn confidential_client_with_wrong_secret_is_invalid_client() {
        let clients = clients_of(vec![("c-a", confidential_client("c-a"))]);
        let codes   = codes_issued_to("c-a");
        let err = redeem(&clients, &codes, "c-a", Some("not-the-secret")).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidClient), "got {err:?}");
        assert!(codes.0.borrow().contains_key("code-1"),
            "a failed authentication must not consume the code");
    }

    /// Test 4 — confidential client, no secret presented.
    #[tokio::test]
    async fn confidential_client_without_a_secret_is_invalid_client() {
        let clients = clients_of(vec![("c-a", confidential_client("c-a"))]);
        let codes   = codes_issued_to("c-a");
        let err = redeem(&clients, &codes, "c-a", None).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidClient), "got {err:?}");
    }

    /// Test 5 — a confidential client with **no stored hash** is rejected
    /// (RFC 137 §12.2), whether or not it presents a secret. This is the case
    /// `check_client_credentials_from_view` alone would have admitted as
    /// `PublicOrUnknown`.
    #[tokio::test]
    async fn confidential_client_with_no_stored_hash_is_rejected() {
        let clients = clients_of(vec![("c-a", (test_client("c-a"), None))]);
        let codes   = codes_issued_to("c-a");
        let with_secret = redeem(&clients, &codes, "c-a", Some(TEST_SECRET)).await.unwrap_err();
        assert!(matches!(with_secret, CoreError::InvalidClient), "got {with_secret:?}");
        let without = redeem(&clients, &codes, "c-a", None).await.unwrap_err();
        assert!(matches!(without, CoreError::InvalidClient), "got {without:?}");
        assert!(codes.0.borrow().contains_key("code-1"),
            "rejected authentication must not consume the code");
    }

    /// Test 6 — a public client shaped like the beginner guide's `demo-cli`,
    /// presenting no secret, redeems its own code.
    #[tokio::test]
    async fn public_client_without_a_secret_redeems_its_own_code() {
        let clients = clients_of(vec![("demo-cli", public_client("demo-cli"))]);
        let codes   = codes_issued_to("demo-cli");
        let resp = redeem(&clients, &codes, "demo-cli", None).await
            .expect("a public client must redeem its own code without a secret");
        assert!(resp.refresh_token.is_some());
    }

    // ── refresh grant ──

    /// Test 7 — a family issued to A, rotated by B holding valid
    /// credentials, is refused.
    #[tokio::test]
    async fn refresh_family_issued_to_one_client_is_refused_to_another() {
        let clients = clients_of(vec![("c-a", confidential_client("c-a")), ("c-b", confidential_client("c-b"))]);
        let (families, rt) = family_issued_to("c-a").await;
        let err = refresh(&clients, &families, &rt, "c-b", Some(TEST_SECRET)).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidGrant(_)),
            "a refresh token presented by a client it was not issued to must be invalid_grant, got {err:?}");
    }

    /// Test 8 — the mismatch **revokes the family**: A's own correct refresh
    /// afterwards fails (RFC 137 §12.4).
    #[tokio::test]
    async fn wrong_client_refresh_revokes_the_family() {
        let clients = clients_of(vec![("c-a", confidential_client("c-a")), ("c-b", confidential_client("c-b"))]);
        let (families, rt) = family_issued_to("c-a").await;
        let _ = refresh(&clients, &families, &rt, "c-b", Some(TEST_SECRET)).await.unwrap_err();

        let fam = families.peek(&fam_x()).await.unwrap().expect("family still exists");
        assert!(fam.revoked_at.is_some(), "a wrong-client refresh must revoke the family");

        let err = refresh(&clients, &families, &rt, "c-a", Some(TEST_SECRET)).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidGrant(_)),
            "the owner's refresh must fail once the family is revoked, got {err:?}");
    }

    /// Test 9 — confidential client, wrong secret: `InvalidClient`, and the
    /// family is **untouched**, because authentication precedes the family.
    #[tokio::test]
    async fn refresh_with_wrong_secret_leaves_the_family_untouched() {
        let clients = clients_of(vec![("c-a", confidential_client("c-a"))]);
        let (families, rt) = family_issued_to("c-a").await;
        let before = families.peek(&fam_x()).await.unwrap().unwrap();

        let err = refresh(&clients, &families, &rt, "c-a", Some("not-the-secret")).await.unwrap_err();
        assert!(matches!(err, CoreError::InvalidClient), "got {err:?}");

        let after = families.peek(&fam_x()).await.unwrap().unwrap();
        assert_eq!(after.current_jti,     before.current_jti,     "family must not have rotated");
        assert_eq!(after.retired_jtis,    before.retired_jtis,    "family must not have rotated");
        assert_eq!(after.last_rotated_at, before.last_rotated_at, "family must not have rotated");
        assert_eq!(after.revoked_at,      before.revoked_at,      "family must not have been revoked");
    }

    /// Test 10 — a public client, no secret, rotates its own family.
    #[tokio::test]
    async fn public_client_without_a_secret_rotates_its_own_family() {
        let clients = clients_of(vec![("demo-cli", public_client("demo-cli"))]);
        let (families, rt) = family_issued_to("demo-cli").await;
        let resp = refresh(&clients, &families, &rt, "demo-cli", None).await
            .expect("a public client must rotate its own family without a secret");
        assert!(resp.refresh_token.is_some());
        let fam = families.peek(&fam_x()).await.unwrap().unwrap();
        assert_ne!(fam.current_jti.as_str(), "j-1", "the family must have rotated");
    }

    // ── RFC 137 C1-137: a Basic-only confidential client, no body client_id ──

    fn basic_only_request(grant_type: &str, refresh_token: Option<&str>) -> crate::oidc::token::TokenRequest {
        crate::oidc::token::TokenRequest {
            grant_type:    grant_type.to_owned(),
            code:          Some("code-1".to_owned()),
            redirect_uri:  Some("https://app.test/cb".to_owned()),
            client_id:     None,
            client_secret: None,
            code_verifier: Some(VERIFIER.to_owned()),
            refresh_token: refresh_token.map(str::to_owned),
            scope:         None,
        }
    }

    /// The `/token` request path as the route runs it — classify, then resolve —
    /// for a client that sends HTTP Basic and no body `client_id`.
    fn resolve_basic_only(req: &crate::oidc::token::TokenRequest) -> (String, Option<String>) {
        use crate::oidc::token::TokenGrant;
        let body_client_id = match req.classify_with_authorization(true).expect("classify") {
            TokenGrant::AuthorizationCode(g) => g.client_id,
            TokenGrant::RefreshToken(g)      => g.client_id,
        };
        assert_eq!(body_client_id, None, "the request carries no body client_id");
        crate::service::client_auth::resolve_token_client_credentials(
            true, Some(("c-a", TEST_SECRET)), body_client_id, req.client_secret.as_deref(),
        ).expect("resolve")
    }

    #[tokio::test]
    async fn basic_only_confidential_client_redeems_a_code_without_a_body_client_id() {
        let clients = clients_of(vec![("c-a", confidential_client("c-a"))]);
        let codes   = codes_issued_to("c-a");
        let (client_id, secret) = resolve_basic_only(&basic_only_request("authorization_code", None));
        let resp = redeem(&clients, &codes, &client_id, secret.as_deref()).await
            .expect("a Basic-only confidential client must redeem its code");
        assert!(resp.refresh_token.is_some());
    }

    #[tokio::test]
    async fn basic_only_confidential_client_rotates_a_family_without_a_body_client_id() {
        let clients = clients_of(vec![("c-a", confidential_client("c-a"))]);
        let (families, rt) = family_issued_to("c-a").await;
        let (client_id, secret) = resolve_basic_only(&basic_only_request("refresh_token", Some(&rt)));
        let resp = refresh(&clients, &families, &rt, &client_id, secret.as_deref()).await
            .expect("a Basic-only confidential client must rotate its family");
        assert!(resp.refresh_token.is_some());
        let fam = families.peek(&fam_x()).await.unwrap().unwrap();
        assert_ne!(fam.current_jti.as_str(), "j-1", "the family must have rotated");
    }
}
