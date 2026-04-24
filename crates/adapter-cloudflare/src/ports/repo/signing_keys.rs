//! `SigningKeyRepository` D1 adapter.

use cesauth_core::ports::repo::{PublicSigningKey, SigningKeyRepository};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;
use worker::Env;

use super::{d1_int, db, run_err};


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
