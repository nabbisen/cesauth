//! D1-backed repository adapters.
//!
//! These are the simplest adapters: each method compiles to one or two
//! parameterized queries against the schema in `migrations/0001_initial.sql`.
//! We use `prepare(...).bind(&[...])` rather than string interpolation
//! so that parameter binding is never the place a SQL injection lands.
//!
//! JSON columns (scopes, redirect_uris, transports) are serialized by
//! core's types and carried as TEXT. We deserialize on the way out and
//! surface `PortError::Serialization` if the stored value is malformed
//! (which would indicate either a botched migration or manual DB edit).
//!
//! ## The `i64 -> JsValue` pitfall
//!
//! `wasm_bindgen` provides `JsValue: From<i64>` - but that impl
//! produces a JavaScript **BigInt**, not a Number. D1's runtime
//! `bind()` (per the `@cloudflare/workers-types` definitions) only
//! accepts `string | number | boolean | ArrayBuffer | null`; a BigInt
//! causes the prepared statement to fail at bind time with an opaque
//! "Unavailable" on our side. Every integer bound here **must** go
//! through `d1_int()`, which does the `as f64` cast. This matches
//! what worker-rs's own `D1Type::Integer` does internally.
//!
//! If you see `storage error`/`Unavailable` from an INSERT or UPDATE:
//! look for a freshly-added `i64.into()` in `bind(&[...])` and wrap
//! it with `d1_int()`.

use cesauth_core::ports::repo::{
    AuthenticatorRepository, ClientRepository, Grant, GrantRepository, PublicSigningKey,
    SigningKeyRepository, UserRepository,
};
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::types::{ClientType, OidcClient, TokenAuthMethod, User, UserStatus};
use cesauth_core::webauthn::StoredAuthenticator;
use serde::Deserialize;
use worker::js_sys::Uint8Array;
use worker::wasm_bindgen::JsValue;
use worker::{D1Database, Env};

fn db<'a>(env: &'a Env) -> PortResult<D1Database> {
    env.d1("DB").map_err(|_| PortError::Unavailable)
}

/// Convert an `i64` into a `JsValue` that D1's `bind()` will accept.
///
/// `wasm_bindgen`'s default `From<i64>` produces a JavaScript BigInt,
/// which D1 rejects. We cast through `f64` the way worker-rs's
/// `D1Type::Integer` does. Timestamps and counters used here all fit
/// comfortably within `Number.MAX_SAFE_INTEGER` (2^53 - 1), so the
/// cast is lossless for every value we actually bind.
#[inline]
fn d1_int(v: i64) -> JsValue {
    JsValue::from_f64(v as f64)
}

/// Map a worker-side D1 error to `PortError::Unavailable` after
/// surfacing the underlying message once to the operational log.
/// `PortError::Unavailable` carries no payload of its own, so without
/// this helper every D1 failure arrives at the HTTP layer as an opaque
/// "storage error" with no breadcrumbs in `wrangler tail`.
///
/// Use at `.run().await` sites (INSERT/UPDATE/DELETE) where the extra
/// line is worth paying; SELECT sites use the plain
/// `map_err(|_| PortError::Unavailable)` because a failing read is
/// usually the route handler's first clue anyway.
#[inline]
fn run_err(context: &'static str, e: worker::Error) -> PortError {
    worker::console_error!("d1 {}: {}", context, e);
    PortError::Unavailable
}

// -------------------------------------------------------------------------
// UserRepository
// -------------------------------------------------------------------------

pub struct CloudflareUserRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareUserRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareUserRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareUserRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct UserRow {
    id:              String,
    email:           Option<String>,
    email_verified:  i64,
    display_name:    Option<String>,
    status:          String,
    created_at:      i64,
    updated_at:      i64,
}

impl UserRow {
    fn into_domain(self) -> PortResult<User> {
        let status = match self.status.as_str() {
            "active"   => UserStatus::Active,
            "disabled" => UserStatus::Disabled,
            "deleted"  => UserStatus::Deleted,
            _          => return Err(PortError::Serialization),
        };
        Ok(User {
            id:             self.id,
            email:          self.email,
            email_verified: self.email_verified != 0,
            display_name:   self.display_name,
            status,
            created_at:     self.created_at,
            updated_at:     self.updated_at,
        })
    }
}

impl UserRepository for CloudflareUserRepository<'_> {
    async fn find_by_id(&self, id: &str) -> PortResult<Option<User>> {
        let db   = db(self.env)?;
        let stmt = db.prepare("SELECT id, email, email_verified, display_name, status, created_at, updated_at FROM users WHERE id = ?1")
            .bind(&[id.into()])
            .map_err(|_| PortError::Unavailable)?;
        match stmt.first::<UserRow>(None).await {
            Ok(Some(row)) => Ok(Some(row.into_domain()?)),
            Ok(None)      => Ok(None),
            Err(_)        => Err(PortError::Unavailable),
        }
    }

    async fn find_by_email(&self, email: &str) -> PortResult<Option<User>> {
        // The column is `COLLATE NOCASE` so a direct equality compares
        // case-insensitively. We still lowercase in the adapter-test
        // impl for parity; here the DB handles it.
        let db   = db(self.env)?;
        let stmt = db.prepare("SELECT id, email, email_verified, display_name, status, created_at, updated_at FROM users WHERE email = ?1")
            .bind(&[email.into()])
            .map_err(|_| PortError::Unavailable)?;
        match stmt.first::<UserRow>(None).await {
            Ok(Some(row)) => Ok(Some(row.into_domain()?)),
            Ok(None)      => Ok(None),
            Err(_)        => Err(PortError::Unavailable),
        }
    }

    async fn create(&self, user: &User) -> PortResult<()> {
        let db   = db(self.env)?;
        let status_s = match user.status {
            UserStatus::Active   => "active",
            UserStatus::Disabled => "disabled",
            UserStatus::Deleted  => "deleted",
        };
        let result = db.prepare(
            "INSERT INTO users (id, email, email_verified, display_name, status, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        )
            .bind(&[
                user.id.clone().into(),
                user.email.clone().map(Into::into).unwrap_or(JsValue::NULL),
                d1_int(user.email_verified as i64),
                user.display_name.clone().map(Into::into).unwrap_or(JsValue::NULL),
                status_s.into(),
                d1_int(user.created_at),
                d1_int(user.updated_at),
            ])
            .map_err(|_| PortError::Unavailable)?
            .run()
            .await;
        match result {
            Ok(_)  => Ok(()),
            // D1 returns a generic error on UNIQUE violations; we can't
            // distinguish conflict from other failure modes without
            // inspecting the error string. Do so narrowly.
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("UNIQUE") || msg.contains("constraint failed") {
                    Err(PortError::Conflict)
                } else {
                    // Surface the underlying message once here - the
                    // worker-side `log` module doesn't reach into the
                    // adapter, and `PortError::Unavailable` carries no
                    // payload. Without this, operators see only
                    // "storage error" at the HTTP layer.
                    worker::console_error!("d1 users.create: {msg}");
                    Err(PortError::Unavailable)
                }
            }
        }
    }

    async fn update(&self, user: &User) -> PortResult<()> {
        let db = db(self.env)?;
        let status_s = match user.status {
            UserStatus::Active   => "active",
            UserStatus::Disabled => "disabled",
            UserStatus::Deleted  => "deleted",
        };
        let result = db.prepare(
            "UPDATE users SET email = ?2, email_verified = ?3, display_name = ?4, status = ?5, updated_at = ?6 \
             WHERE id = ?1"
        )
            .bind(&[
                user.id.clone().into(),
                user.email.clone().map(Into::into).unwrap_or(JsValue::NULL),
                d1_int(user.email_verified as i64),
                user.display_name.clone().map(Into::into).unwrap_or(JsValue::NULL),
                status_s.into(),
                d1_int(user.updated_at),
            ])
            .map_err(|e| run_err("users.update bind", e))?
            .run()
            .await
            .map_err(|e| run_err("users.update run", e))?;
        // D1 reports rows-changed through meta; if missing, we optimistically
        // assume success (NotFound is surfaced by the caller re-reading).
        let _ = result;
        Ok(())
    }
}

// -------------------------------------------------------------------------
// ClientRepository
// -------------------------------------------------------------------------

pub struct CloudflareClientRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareClientRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareClientRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareClientRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct ClientRow {
    id:                 String,
    name:               String,
    client_type:        String,
    redirect_uris:      String,   // JSON array
    allowed_scopes:     String,   // JSON array
    token_auth_method:  String,
    require_pkce:       i64,
}

impl ClientRow {
    fn into_domain(self) -> PortResult<OidcClient> {
        let client_type = match self.client_type.as_str() {
            "public"       => ClientType::Public,
            "confidential" => ClientType::Confidential,
            _              => return Err(PortError::Serialization),
        };
        let token_auth_method = match self.token_auth_method.as_str() {
            "none"                 => TokenAuthMethod::None,
            "client_secret_basic"  => TokenAuthMethod::ClientSecretBasic,
            "client_secret_post"   => TokenAuthMethod::ClientSecretPost,
            _                      => return Err(PortError::Serialization),
        };
        let redirect_uris: Vec<String>  = serde_json::from_str(&self.redirect_uris)?;
        let allowed_scopes: Vec<String> = serde_json::from_str(&self.allowed_scopes)?;
        Ok(OidcClient {
            id:                 self.id,
            name:               self.name,
            client_type,
            redirect_uris,
            allowed_scopes,
            token_auth_method,
            require_pkce:       self.require_pkce != 0,
        })
    }
}

impl ClientRepository for CloudflareClientRepository<'_> {
    async fn find(&self, client_id: &str) -> PortResult<Option<OidcClient>> {
        let db   = db(self.env)?;
        let stmt = db.prepare(
            "SELECT id, name, client_type, redirect_uris, allowed_scopes, token_auth_method, require_pkce \
             FROM oidc_clients WHERE id = ?1"
        )
            .bind(&[client_id.into()])
            .map_err(|_| PortError::Unavailable)?;
        match stmt.first::<ClientRow>(None).await {
            Ok(Some(row)) => Ok(Some(row.into_domain()?)),
            Ok(None)      => Ok(None),
            Err(_)        => Err(PortError::Unavailable),
        }
    }

    async fn client_secret_hash(&self, client_id: &str) -> PortResult<Option<String>> {
        let db   = db(self.env)?;
        let stmt = db.prepare("SELECT client_secret_hash FROM oidc_clients WHERE id = ?1")
            .bind(&[client_id.into()])
            .map_err(|_| PortError::Unavailable)?;
        #[derive(Deserialize)]
        struct Row { client_secret_hash: Option<String> }
        match stmt.first::<Row>(None).await {
            Ok(Some(r)) => Ok(r.client_secret_hash),
            Ok(None)    => Err(PortError::NotFound),
            Err(_)      => Err(PortError::Unavailable),
        }
    }

    async fn create(&self, client: &OidcClient, secret_hash: Option<&str>) -> PortResult<()> {
        let db = db(self.env)?;
        let client_type_s = match client.client_type {
            ClientType::Public       => "public",
            ClientType::Confidential => "confidential",
        };
        let tam_s = match client.token_auth_method {
            TokenAuthMethod::None              => "none",
            TokenAuthMethod::ClientSecretBasic => "client_secret_basic",
            TokenAuthMethod::ClientSecretPost  => "client_secret_post",
        };
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let redirect_uris  = serde_json::to_string(&client.redirect_uris).map_err(|_| PortError::Serialization)?;
        let allowed_scopes = serde_json::to_string(&client.allowed_scopes).map_err(|_| PortError::Serialization)?;

        db.prepare(
            "INSERT INTO oidc_clients \
             (id, name, client_type, client_secret_hash, redirect_uris, allowed_scopes, token_auth_method, require_pkce, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        )
            .bind(&[
                client.id.clone().into(),
                client.name.clone().into(),
                client_type_s.into(),
                secret_hash.map(Into::into).unwrap_or(JsValue::NULL),
                redirect_uris.into(),
                allowed_scopes.into(),
                tam_s.into(),
                d1_int(client.require_pkce as i64),
                d1_int(now),
                d1_int(now),
            ])
            .map_err(|e| run_err("oidc_clients.create bind", e))?
            .run()
            .await
            .map_err(|e| run_err("oidc_clients.create run", e))?;
        Ok(())
    }
}

// -------------------------------------------------------------------------
// AuthenticatorRepository  (abbreviated - same shape as above)
// -------------------------------------------------------------------------

pub struct CloudflareAuthenticatorRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareAuthenticatorRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareAuthenticatorRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareAuthenticatorRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct AuthnRow {
    id:              String,
    user_id:         String,
    credential_id:   String,
    public_key:      Vec<u8>,
    sign_count:      i64,
    transports:      Option<String>,
    aaguid:          Option<String>,
    backup_eligible: i64,
    backup_state:    i64,
    name:            Option<String>,
    created_at:      i64,
    last_used_at:    Option<i64>,
}

impl AuthnRow {
    fn into_domain(self) -> PortResult<StoredAuthenticator> {
        let transports: Option<Vec<String>> = match self.transports {
            Some(s) => serde_json::from_str(&s).map_err(|_| PortError::Serialization)?,
            None    => None,
        };
        Ok(StoredAuthenticator {
            id:              self.id,
            user_id:         self.user_id,
            credential_id:   self.credential_id,
            public_key:      self.public_key,
            sign_count:      u32::try_from(self.sign_count).unwrap_or(u32::MAX),
            transports,
            aaguid:          self.aaguid,
            backup_eligible: self.backup_eligible != 0,
            backup_state:    self.backup_state != 0,
            name:            self.name,
            created_at:      self.created_at,
            last_used_at:    self.last_used_at,
        })
    }
}

const AUTHN_COLUMNS: &str =
    "id, user_id, credential_id, public_key, sign_count, transports, aaguid, \
     backup_eligible, backup_state, name, created_at, last_used_at";

impl AuthenticatorRepository for CloudflareAuthenticatorRepository<'_> {
    async fn find_by_credential_id(
        &self,
        credential_id: &str,
    ) -> PortResult<Option<StoredAuthenticator>> {
        let db   = db(self.env)?;
        let stmt = db.prepare(&format!(
            "SELECT {AUTHN_COLUMNS} FROM authenticators WHERE credential_id = ?1"
        ))
            .bind(&[credential_id.into()])
            .map_err(|_| PortError::Unavailable)?;
        match stmt.first::<AuthnRow>(None).await {
            Ok(Some(row)) => Ok(Some(row.into_domain()?)),
            Ok(None)      => Ok(None),
            Err(_)        => Err(PortError::Unavailable),
        }
    }

    async fn list_by_user(&self, user_id: &str) -> PortResult<Vec<StoredAuthenticator>> {
        let db   = db(self.env)?;
        let stmt = db.prepare(&format!(
            "SELECT {AUTHN_COLUMNS} FROM authenticators WHERE user_id = ?1"
        ))
            .bind(&[user_id.into()])
            .map_err(|_| PortError::Unavailable)?;
        let rows = stmt.all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<AuthnRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(AuthnRow::into_domain).collect()
    }

    async fn create(&self, authn: &StoredAuthenticator) -> PortResult<()> {
        let db = db(self.env)?;
        let transports = match &authn.transports {
            Some(v) => Some(serde_json::to_string(v).map_err(|_| PortError::Serialization)?),
            None    => None,
        };
        db.prepare(
            "INSERT INTO authenticators \
             (id, user_id, credential_id, public_key, sign_count, transports, aaguid, \
              backup_eligible, backup_state, name, created_at, last_used_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
        )
            .bind(&[
                authn.id.clone().into(),
                authn.user_id.clone().into(),
                authn.credential_id.clone().into(),
                // `public_key` is a byte vector (the COSE key encoding).
                // D1's BLOB column wants a Uint8Array on the JS side.
                Uint8Array::from(authn.public_key.as_slice()).into(),
                d1_int(authn.sign_count as i64),
                transports.map(Into::into).unwrap_or(JsValue::NULL),
                authn.aaguid.clone().map(Into::into).unwrap_or(JsValue::NULL),
                d1_int(authn.backup_eligible as i64),
                d1_int(authn.backup_state    as i64),
                authn.name.clone().map(Into::into).unwrap_or(JsValue::NULL),
                d1_int(authn.created_at),
                authn.last_used_at.map(d1_int).unwrap_or(JsValue::NULL),
            ])
            .map_err(|e| run_err("authenticators.create bind", e))?
            .run()
            .await
            .map_err(|e| run_err("authenticators.create run", e))?;
        Ok(())
    }

    async fn touch(
        &self,
        credential_id:  &str,
        new_sign_count: u32,
        last_used_at:   i64,
    ) -> PortResult<()> {
        let db = db(self.env)?;
        // Enforce counter monotonicity in SQL so a concurrent assertion
        // cannot accidentally roll back the counter. Also serves as a
        // last-line cloning check.
        let result = db.prepare(
            "UPDATE authenticators SET sign_count = ?2, last_used_at = ?3 \
             WHERE credential_id = ?1 AND (?2 = 0 OR ?2 > sign_count)"
        )
            .bind(&[
                credential_id.into(),
                d1_int(new_sign_count as i64),
                d1_int(last_used_at),
            ])
            .map_err(|e| run_err("authenticators.touch bind", e))?
            .run()
            .await
            .map_err(|e| run_err("authenticators.touch run", e))?;
        // If zero rows changed, either the credential doesn't exist or
        // the counter was non-monotonic. We cannot cheaply distinguish
        // these in D1 without another query, so surface the less-alarming
        // PreconditionFailed; the caller can re-query to disambiguate.
        if result.meta().map(|m| m.and_then(|m| m.changes).unwrap_or(0)).unwrap_or(0) == 0 {
            return Err(PortError::PreconditionFailed("sign_count not monotonic or credential missing"));
        }
        Ok(())
    }

    async fn delete(&self, credential_id: &str) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare("DELETE FROM authenticators WHERE credential_id = ?1")
            .bind(&[credential_id.into()])
            .map_err(|e| run_err("authenticators.delete bind", e))?
            .run()
            .await
            .map_err(|e| run_err("authenticators.delete run", e))?;
        Ok(())
    }
}

// -------------------------------------------------------------------------
// GrantRepository  (minimal)
// -------------------------------------------------------------------------

pub struct CloudflareGrantRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareGrantRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareGrantRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareGrantRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct GrantRow {
    id:         String,
    user_id:    String,
    client_id:  String,
    scopes:     String,
    issued_at:  i64,
    revoked_at: Option<i64>,
}

impl GrantRow {
    fn into_domain(self) -> PortResult<Grant> {
        Ok(Grant {
            id:         self.id,
            user_id:    self.user_id,
            client_id:  self.client_id,
            scopes:     serde_json::from_str(&self.scopes)?,
            issued_at:  self.issued_at,
            revoked_at: self.revoked_at,
        })
    }
}

impl GrantRepository for CloudflareGrantRepository<'_> {
    async fn create(&self, grant: &Grant) -> PortResult<()> {
        let db = db(self.env)?;
        let scopes = serde_json::to_string(&grant.scopes).map_err(|_| PortError::Serialization)?;
        db.prepare(
            "INSERT INTO grants (id, user_id, client_id, scopes, issued_at, revoked_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
            .bind(&[
                grant.id.clone().into(),
                grant.user_id.clone().into(),
                grant.client_id.clone().into(),
                scopes.into(),
                d1_int(grant.issued_at),
                grant.revoked_at.map(d1_int).unwrap_or(JsValue::NULL),
            ])
            .map_err(|e| run_err("grants.create bind", e))?
            .run()
            .await
            .map_err(|e| run_err("grants.create run", e))?;
        Ok(())
    }

    async fn list_active_for_user(&self, user_id: &str) -> PortResult<Vec<Grant>> {
        let db   = db(self.env)?;
        let stmt = db.prepare(
            "SELECT id, user_id, client_id, scopes, issued_at, revoked_at \
             FROM grants WHERE user_id = ?1 AND revoked_at IS NULL"
        )
            .bind(&[user_id.into()])
            .map_err(|_| PortError::Unavailable)?;
        let rows = stmt.all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<GrantRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(GrantRow::into_domain).collect()
    }

    async fn mark_revoked(&self, grant_id: &str, now_unix: i64) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare("UPDATE grants SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL")
            .bind(&[grant_id.into(), d1_int(now_unix)])
            .map_err(|e| run_err("grants.mark_revoked bind", e))?
            .run()
            .await
            .map_err(|e| run_err("grants.mark_revoked run", e))?;
        Ok(())
    }
}

// -------------------------------------------------------------------------
// SigningKeyRepository
// -------------------------------------------------------------------------

pub struct CloudflareSigningKeyRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareSigningKeyRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareSigningKeyRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareSigningKeyRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct KeyRow {
    kid:        String,
    public_key: String,
    alg:        String,
    created_at: i64,
    retired_at: Option<i64>,
}

impl SigningKeyRepository for CloudflareSigningKeyRepository<'_> {
    async fn list_active(&self) -> PortResult<Vec<PublicSigningKey>> {
        let db   = db(self.env)?;
        let rows = db.prepare(
            "SELECT kid, public_key, alg, created_at, retired_at \
             FROM jwt_signing_keys ORDER BY created_at DESC"
        )
            .all()
            .await
            .map_err(|_| PortError::Unavailable)?;
        let rows: Vec<KeyRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(|r| PublicSigningKey {
            kid:            r.kid,
            public_key_b64: r.public_key,
            alg:            r.alg,
            created_at:     r.created_at,
            retired_at:     r.retired_at,
        }).collect())
    }

    async fn register(&self, key: &PublicSigningKey) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "INSERT INTO jwt_signing_keys (kid, public_key, alg, created_at, retired_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)"
        )
            .bind(&[
                key.kid.clone().into(),
                key.public_key_b64.clone().into(),
                key.alg.clone().into(),
                d1_int(key.created_at),
                key.retired_at.map(d1_int).unwrap_or(JsValue::NULL),
            ])
            .map_err(|e| run_err("jwt_signing_keys.register bind", e))?
            .run()
            .await
            .map_err(|e| run_err("jwt_signing_keys.register run", e))?;
        Ok(())
    }

    async fn retire(&self, kid: &str, retired_at: i64) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare("UPDATE jwt_signing_keys SET retired_at = ?2 WHERE kid = ?1 AND retired_at IS NULL")
            .bind(&[kid.into(), d1_int(retired_at)])
            .map_err(|e| run_err("jwt_signing_keys.retire bind", e))?
            .run()
            .await
            .map_err(|e| run_err("jwt_signing_keys.retire run", e))?;
        Ok(())
    }
}
