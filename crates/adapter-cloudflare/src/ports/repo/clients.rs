//! `ClientRepository` D1 adapter.

use cesauth_core::ports::repo::ClientRepository;
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::types::{ClientType, OidcClient, TokenAuthMethod};
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;
use worker::Env;

use super::{d1_int, db, run_err};


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
