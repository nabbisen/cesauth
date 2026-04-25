//! `SubscriptionHistoryRepository` D1 adapter.

use cesauth_core::billing::ports::SubscriptionHistoryRepository;
use cesauth_core::billing::types::{SubscriptionHistoryEntry, SubscriptionStatus};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

use super::subscriptions::{parse_status, status_str};

pub struct CloudflareSubscriptionHistoryRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareSubscriptionHistoryRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareSubscriptionHistoryRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareSubscriptionHistoryRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct HistoryRow {
    id:               String,
    subscription_id:  String,
    tenant_id:        String,
    event:            String,
    from_plan_id:     Option<String>,
    to_plan_id:       Option<String>,
    from_status:      Option<String>,
    to_status:        Option<String>,
    actor:            String,
    occurred_at:      i64,
}

impl HistoryRow {
    fn into_domain(self) -> PortResult<SubscriptionHistoryEntry> {
        let from_status = self.from_status.as_deref().map(parse_status).transpose()?;
        let to_status   = self.to_status  .as_deref().map(parse_status).transpose()?;
        Ok(SubscriptionHistoryEntry {
            id: self.id, subscription_id: self.subscription_id,
            tenant_id: self.tenant_id, event: self.event,
            from_plan_id: self.from_plan_id, to_plan_id: self.to_plan_id,
            from_status, to_status,
            actor: self.actor, occurred_at: self.occurred_at,
        })
    }
}

const COLS: &str = "id, subscription_id, tenant_id, event, from_plan_id, to_plan_id, from_status, to_status, actor, occurred_at";

fn opt_str_js(s: Option<&str>) -> worker::wasm_bindgen::JsValue {
    match s { Some(v) => v.into(), None => worker::wasm_bindgen::JsValue::NULL }
}

fn opt_status_js(s: Option<SubscriptionStatus>) -> worker::wasm_bindgen::JsValue {
    match s {
        Some(s) => status_str(s).into(),
        None    => worker::wasm_bindgen::JsValue::NULL,
    }
}

impl SubscriptionHistoryRepository for CloudflareSubscriptionHistoryRepository<'_> {
    async fn append(&self, e: &SubscriptionHistoryEntry) -> PortResult<()> {
        let db = db(self.env)?;
        db.prepare(
            "INSERT INTO subscription_history \
             (id, subscription_id, tenant_id, event, from_plan_id, to_plan_id, \
              from_status, to_status, actor, occurred_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        )
            .bind(&[
                e.id.as_str().into(), e.subscription_id.as_str().into(),
                e.tenant_id.as_str().into(), e.event.as_str().into(),
                opt_str_js(e.from_plan_id.as_deref()),
                opt_str_js(e.to_plan_id.as_deref()),
                opt_status_js(e.from_status),
                opt_status_js(e.to_status),
                e.actor.as_str().into(), d1_int(e.occurred_at),
            ])
            .map_err(|err| run_err("subscription_history.append bind", err))?
            .run().await.map_err(|err| run_err("subscription_history.append run", err))?;
        Ok(())
    }

    async fn list_for_subscription(
        &self,
        subscription_id: &str,
    ) -> PortResult<Vec<SubscriptionHistoryEntry>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!(
            "SELECT {COLS} FROM subscription_history \
             WHERE subscription_id = ?1 ORDER BY occurred_at"
        ))
            .bind(&[subscription_id.into()])
            .map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<HistoryRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().map(HistoryRow::into_domain).collect()
    }
}
