//! `AuthenticatorRepository` D1 adapter.
//!
//! The one non-obvious bind is `public_key`: the COSE-encoded key is a
//! `Vec<u8>`, but D1's BLOB column accepts a Uint8Array on the JS side,
//! not a plain byte array. We wrap via `Uint8Array::from(...).into()`.

use cesauth_core::ports::repo::AuthenticatorRepository;
use cesauth_core::ports::{PortError, PortResult};
use cesauth_core::webauthn::StoredAuthenticator;
use serde::Deserialize;
use worker::js_sys::Uint8Array;
use worker::wasm_bindgen::JsValue;
use worker::Env;

use super::{d1_int, db, run_err};


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
