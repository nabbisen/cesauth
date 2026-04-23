//! D1-shaped CRUD repositories.
//!
//! Each trait in this module targets exactly one D1 table (or a small
//! set of very tightly related rows). Nothing here is expected to
//! guarantee serialization of concurrent writes across instances -
//! that is the job of the [`super::store`] traits. If you find
//! yourself wanting a method here that "must be atomic with another
//! method here", that need belongs in `store`, not `repo`.

use super::PortResult;
use crate::types::{OidcClient, User};
use crate::webauthn::StoredAuthenticator;

/// `users` table.
pub trait UserRepository {
    async fn find_by_id(&self, id: &str) -> PortResult<Option<User>>;

    /// Case-insensitive lookup. Adapters must pass the query through
    /// whatever collation maps to SQL `COLLATE NOCASE`.
    async fn find_by_email(&self, email: &str) -> PortResult<Option<User>>;

    /// Insert. Returns `Conflict` if the email is already taken.
    async fn create(&self, user: &User) -> PortResult<()>;

    /// Replace mutable fields (display_name, status, email_verified,
    /// updated_at). Returns `NotFound` if the id does not exist.
    async fn update(&self, user: &User) -> PortResult<()>;
}

/// `oidc_clients` table.
pub trait ClientRepository {
    async fn find(&self, client_id: &str) -> PortResult<Option<OidcClient>>;

    /// For client authentication methods that use a secret, adapters
    /// store only a verifier hash. This method returns the hash (or
    /// `None` for public PKCE-only clients) so `core` can do constant-
    /// time verification without the hash format crossing the boundary.
    async fn client_secret_hash(&self, client_id: &str) -> PortResult<Option<String>>;

    async fn create(&self, client: &OidcClient, secret_hash: Option<&str>) -> PortResult<()>;
}

/// `authenticators` table (WebAuthn credentials).
pub trait AuthenticatorRepository {
    async fn find_by_credential_id(
        &self,
        credential_id: &str,
    ) -> PortResult<Option<StoredAuthenticator>>;

    async fn list_by_user(&self, user_id: &str) -> PortResult<Vec<StoredAuthenticator>>;

    async fn create(&self, authn: &StoredAuthenticator) -> PortResult<()>;

    /// Update sign_count and last_used_at after a successful assertion.
    /// Separate from a generic `update` because those two columns are
    /// the only ones that mutate on the hot path.
    async fn touch(
        &self,
        credential_id: &str,
        new_sign_count: u32,
        last_used_at: i64,
    ) -> PortResult<()>;

    async fn delete(&self, credential_id: &str) -> PortResult<()>;
}

/// `grants` table - the enumerable record of issued refresh families.
///
/// The transactional *state* of each family lives in a
/// `RefreshTokenFamilyStore`. This repo exists so admin operations
/// like "list all active grants for user X" can be answered without
/// scanning every DO, and so "revoke all of user X's tokens" can be
/// implemented as a walk of this table followed by N store revocations.
pub trait GrantRepository {
    async fn create(&self, grant: &Grant) -> PortResult<()>;

    async fn list_active_for_user(&self, user_id: &str) -> PortResult<Vec<Grant>>;

    /// Mark a single grant revoked. Does NOT touch the DO state -
    /// callers are expected to revoke the corresponding
    /// `RefreshTokenFamilyStore` entry as well.
    async fn mark_revoked(&self, grant_id: &str, now_unix: i64) -> PortResult<()>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Grant {
    pub id:         String,
    pub user_id:    String,
    pub client_id:  String,
    pub scopes:     Vec<String>,
    pub issued_at:  i64,
    pub revoked_at: Option<i64>,
}

/// `jwt_signing_keys` table. Listing active keys is what drives JWKS
/// output (the secret material lives in Workers Secrets).
pub trait SigningKeyRepository {
    async fn list_active(&self) -> PortResult<Vec<PublicSigningKey>>;

    async fn register(&self, key: &PublicSigningKey) -> PortResult<()>;

    /// Mark retired. The row stays for the JWKS grace window so old
    /// tokens remain verifiable.
    async fn retire(&self, kid: &str, retired_at: i64) -> PortResult<()>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicSigningKey {
    pub kid:            String,
    pub public_key_b64: String,
    pub alg:            String,
    pub created_at:     i64,
    pub retired_at:     Option<i64>,
}
