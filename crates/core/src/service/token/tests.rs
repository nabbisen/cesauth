//! Unit tests for the parent module. Extracted to keep the
//! parent file focused on production code.

use super::*;

#[test]
fn refresh_round_trip() {
    let encoded = encode_refresh("fam", "jti-1", 3600, 1_000_000);
    let (fam, jti) = decode_refresh(&encoded).unwrap();
    assert_eq!(fam, "fam");
    assert_eq!(jti, "jti-1");
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

    struct StubClients(HashMap<String, OidcClient>);
    impl ClientRepository for StubClients {
        async fn find(&self, id: &str) -> PortResult<Option<OidcClient>> {
            Ok(self.0.get(id).cloned())
        }
        async fn client_secret_hash(&self, _: &str) -> PortResult<Option<String>> { Ok(None) }
        async fn find_auth_view(&self, id: &str) -> PortResult<Option<ClientAuthView>> {
            Ok(self.0.get(id).map(|c| ClientAuthView {
                client_id: c.id.clone(),
                client_secret_hash: None,
                audience: c.audience.clone(),
                token_auth_method: c.token_auth_method,
            }))
        }
        async fn create(&self, _: &OidcClient, _: Option<&str>) -> PortResult<()> { Ok(()) }
    }

    struct StubCodes(RefCell<HashMap<String, Challenge>>);
    impl AuthChallengeStore for StubCodes {
        async fn put(&self, code: &str, ch: &Challenge) -> PortResult<()> {
            self.0.borrow_mut().insert(code.to_owned(), ch.clone());
            Ok(())
        }
        async fn peek(&self, code: &str) -> PortResult<Option<Challenge>> {
            Ok(self.0.borrow().get(code).cloned())
        }
        async fn take(&self, code: &str) -> PortResult<Option<Challenge>> {
            Ok(self.0.borrow_mut().remove(code))
        }
        async fn bump_magic_link_attempts(&self, _: &str) -> PortResult<u32> { Ok(0) }
    }

    struct StubFamilies(RefCell<HashMap<String, FamilyState>>);
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
                auth_time:       init.auth_time,
            });
            Ok(())
        }
        async fn rotate(&self, family_id: &str, presented_jti: &str, new_jti: &str, now: i64) -> PortResult<RotateOutcome> {
            let mut m = self.0.borrow_mut();
            if let Some(fam) = m.get_mut(family_id) {
                if fam.current_jti != presented_jti {
                    return Ok(RotateOutcome::ReusedAndRevoked { reused_jti: presented_jti.to_owned(), was_retired: false });
                }
                fam.retired_jtis.push(fam.current_jti.clone());
                fam.current_jti = new_jti.to_owned();
                fam.last_rotated_at = now;
                Ok(RotateOutcome::Rotated { new_current_jti: new_jti.to_owned() })
            } else {
                Ok(RotateOutcome::AlreadyRevoked)
            }
        }
        async fn revoke(&self, family_id: &str, _: i64) -> PortResult<()> {
            if let Some(f) = self.0.borrow_mut().get_mut(family_id) {
                f.revoked_at = Some(0);
            }
            Ok(())
        }
        async fn peek(&self, family_id: &str) -> PortResult<Option<FamilyState>> {
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
        clients.insert("c-1".to_owned(), test_client("c-1"));
        let mut users = HashMap::new();
        users.insert("u-1".to_owned(), test_user("u-1"));

        let codes = StubCodes(RefCell::new(HashMap::new()));
        let code_ch = Challenge::AuthCode {
            client_id:             "c-1".to_owned(),
            redirect_uri:          "https://app.test/cb".to_owned(),
            user_id:               "u-1".to_owned(),
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
        let cfg  = TokenConfig { access_ttl_secs: 3600, refresh_ttl_secs: 86400, iss };
        (deps, cfg)
    }

    async fn run_exchange(scopes: &[&str], auth_time: i64) -> TokenResponse {
        let (clients, codes, families, grants, users) =
            stub_exchange_setup(scopes, auth_time, "test-verifier-padded-to-exactly-43chars-xxx");
        let signer = test_signer();
        let input = ExchangeCodeInput {
            code:          "code-1",
            redirect_uri:  "https://app.test/cb",
            client_id:     "c-1",
            code_verifier: "test-verifier-padded-to-exactly-43chars-xxx",
            now_unix:      1_700_000_000,
        };
        let (deps, tok_cfg) = make_deps_cfg(&clients, &codes, &families, &grants, &users, &StubRates, "https://t.test");
        exchange_code(&deps, &signer, &tok_cfg, &input).await.unwrap()
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
        client_map.insert("c-r".to_owned(), test_client("c-r"));
        let mut user_map = HashMap::new();
        user_map.insert("u-r".to_owned(), test_user("u-r"));
        let orig_auth_time = 1_699_900_000i64;
        let families = StubFamilies(RefCell::new(HashMap::new()));
        let init = FamilyInit {
            family_id: "fam-r".to_owned(),
            user_id:   "u-r".to_owned(),
            client_id: "c-r".to_owned(),
            scopes:    vec!["openid".to_owned()],
            first_jti: "j-first".to_owned(),
            now_unix:  1_700_000_000,
            auth_time: orig_auth_time,
        };
        families.init(&init).await.unwrap();
        let rt = encode_refresh("fam-r", "j-first", 86400, 1_700_000_000);
        let input = RotateRefreshInput {
            refresh_token: &rt,
            client_id:     "c-r",
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
            let tok_cfg = TokenConfig { access_ttl_secs: 3600, refresh_ttl_secs: 86400, iss: "https://t.test" };
            rotate_refresh(&deps, &test_signer(), &tok_cfg, &input).await
        }.unwrap();
        assert!(resp.id_token.is_some(), "rotate openid → id_token");
    }

    #[tokio::test]
    async fn rotate_refresh_id_token_auth_time_preserves_family_auth_time() {
        let mut client_map = HashMap::new();
        client_map.insert("c-at".to_owned(), test_client("c-at"));
        let mut user_map = HashMap::new();
        user_map.insert("u-at".to_owned(), test_user("u-at"));
        let orig_auth_time = 1_699_900_000i64;
        let families = StubFamilies(RefCell::new(HashMap::new()));
        families.init(&FamilyInit {
            family_id: "fam-at".to_owned(),
            user_id:   "u-at".to_owned(),
            client_id: "c-at".to_owned(),
            scopes:    vec!["openid".to_owned()],
            first_jti: "j-at".to_owned(),
            now_unix:  1_700_000_000,
            auth_time: orig_auth_time,
        }).await.unwrap();
        let rt = encode_refresh("fam-at", "j-at", 86400, 1_700_000_000);
        let input = RotateRefreshInput {
            refresh_token:        &rt,
            client_id:            "c-at",
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
            let tok_cfg = TokenConfig { access_ttl_secs: 3600, refresh_ttl_secs: 86400, iss: "https://t.test" };
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
        client_map.insert("c-no".to_owned(), test_client("c-no"));
        let mut user_map = HashMap::new();
        user_map.insert("u-no".to_owned(), test_user("u-no"));
        let families = StubFamilies(RefCell::new(HashMap::new()));
        families.init(&FamilyInit {
            family_id: "fam-no".to_owned(),
            user_id:   "u-no".to_owned(),
            client_id: "c-no".to_owned(),
            scopes:    vec!["profile".to_owned()],
            first_jti: "j-no".to_owned(),
            now_unix:  1_700_000_000,
            auth_time: 0,
        }).await.unwrap();
        let rt = encode_refresh("fam-no", "j-no", 86400, 1_700_000_000);
        let input = RotateRefreshInput {
            refresh_token:        &rt,
            client_id:            "c-no",
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
            let tok_cfg = TokenConfig { access_ttl_secs: 3600, refresh_ttl_secs: 86400, iss: "https://t.test" };
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
            client_id:             "c-1".to_owned(),
            redirect_uri:          "https://app.test/cb".to_owned(),
            user_id:               "u-1".to_owned(),
            scopes:                Scopes(vec!["openid".to_owned()]),
            nonce:                 Some(nonce_val.to_owned()),
            code_challenge:        challenge_b64,
            code_challenge_method: "S256".to_owned(),
            issued_at:             1_700_000_000,
            expires_at:            1_700_000_300,
            auth_time:             1_699_999_900,
        });

        let signer = test_signer();
        let input = ExchangeCodeInput {
            code:          "code-1",
            redirect_uri:  "https://app.test/cb",
            client_id:     "c-1",
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
}
