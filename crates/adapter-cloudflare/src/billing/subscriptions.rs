//! `SubscriptionRepository` D1 adapter.

use cesauth_core::billing::ports::SubscriptionRepository;
use cesauth_core::billing::types::{
    Subscription, SubscriptionLifecycle, SubscriptionStatus,
};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::{d1_int, db, run_err};

pub struct CloudflareSubscriptionRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflareSubscriptionRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareSubscriptionRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflareSubscriptionRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct SubRow {
    id:                  String,
    tenant_id:           String,
    plan_id:             String,
    lifecycle:           String,
    status:              String,
    started_at:          i64,
    current_period_end:  Option<i64>,
    trial_ends_at:       Option<i64>,
    status_changed_at:   i64,
    updated_at:          i64,
}

fn parse_lifecycle(s: &str) -> PortResult<SubscriptionLifecycle> {
    Ok(match s {
        "trial" => SubscriptionLifecycle::Trial,
        "paid"  => SubscriptionLifecycle::Paid,
        "grace" => SubscriptionLifecycle::Grace,
        _       => return Err(PortError::Serialization),
    })
}
pub(super) fn parse_status(s: &str) -> PortResult<SubscriptionStatus> {
    Ok(match s {
        "active"    => SubscriptionStatus::Active,
        "past_due"  => SubscriptionStatus::PastDue,
        "cancelled" => SubscriptionStatus::Cancelled,
        "expired"   => SubscriptionStatus::Expired,
        _           => return Err(PortError::Serialization),
    })
}
fn lifecycle_str(l: SubscriptionLifecycle) -> &'static str {
    match l {
        SubscriptionLifecycle::Trial => "trial",
        SubscriptionLifecycle::Paid  => "paid",
        SubscriptionLifecycle::Grace => "grace",
    }
}
pub(super) fn status_str(s: SubscriptionStatus) -> &'static str {
    match s {
        SubscriptionStatus::Active    => "active",
        SubscriptionStatus::PastDue   => "past_due",
        SubscriptionStatus::Cancelled => "cancelled",
        SubscriptionStatus::Expired   => "expired",
    }
}

impl SubRow {
    fn into_domain(self) -> PortResult<Subscription> {
        Ok(Subscription {
            id: self.id, tenant_id: self.tenant_id, plan_id: self.plan_id,
            lifecycle:          parse_lifecycle(&self.lifecycle)?,
            status:             parse_status(&self.status)?,
            started_at:         self.started_at,
            current_period_end: self.current_period_end,
            trial_ends_at:      self.trial_ends_at,
            status_changed_at:  self.status_changed_at,
            updated_at:         self.updated_at,
        })
    }
}

const COLS: &str = "id, tenant_id, plan_id, lifecycle, status, started_at, current_period_end, trial_ends_at, status_changed_at, updated_at";

impl SubscriptionRepository for CloudflareSubscriptionRepository<'_> {
    async fn create(&self, s: &Subscription) -> PortResult<()> {
        let db = db(self.env)?;
        let cpe: worker::wasm_bindgen::JsValue = match s.current_period_end {
            Some(t) => d1_int(t), None => worker::wasm_bindgen::JsValue::NULL,
        };
        let trial: worker::wasm_bindgen::JsValue = match s.trial_ends_at {
            Some(t) => d1_int(t), None => worker::wasm_bindgen::JsValue::NULL,
        };
        db.prepare(
            "INSERT INTO subscriptions \
             (id, tenant_id, plan_id, lifecycle, status, started_at, \
              current_period_end, trial_ends_at, status_changed_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        )
            .bind(&[
                s.id.as_str().into(), s.tenant_id.as_str().into(),
                s.plan_id.as_str().into(),
                lifecycle_str(s.lifecycle).into(),
                status_str(s.status).into(),
                d1_int(s.started_at), cpe, trial,
                d1_int(s.status_changed_at), d1_int(s.updated_at),
            ])
            .map_err(|e| run_err("subscription.create bind", e))?
            .run().await
            .map_err(|e| {
                let msg = format!("{e}").to_ascii_lowercase();
                if msg.contains("unique") || msg.contains("constraint") {
                    PortError::Conflict
                } else {
                    run_err("subscription.create run", e)
                }
            })?;
        Ok(())
    }

    async fn current_for_tenant(&self, tenant_id: &str) -> PortResult<Option<Subscription>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!("SELECT {COLS} FROM subscriptions WHERE tenant_id = ?1"))
            .bind(&[tenant_id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<SubRow> = rows.results().map_err(|_| PortError::Serialization)?;
        rows.into_iter().next().map(SubRow::into_domain).transpose()
    }

    async fn set_plan(&self, id: &str, plan_id: &str, now: i64) -> PortResult<()> {
        let db = db(self.env)?;
        let res = db.prepare(
            "UPDATE subscriptions SET plan_id = ?2, updated_at = ?3 WHERE id = ?1"
        )
            .bind(&[id.into(), plan_id.into(), d1_int(now)])
            .map_err(|e| run_err("subscription.set_plan bind", e))?
            .run().await.map_err(|e| run_err("subscription.set_plan run", e))?;
        if res.meta().ok().flatten().and_then(|m| m.changes).unwrap_or(0) == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }

    async fn set_status(&self, id: &str, status: SubscriptionStatus, now: i64) -> PortResult<()> {
        let db = db(self.env)?;
        let res = db.prepare(
            "UPDATE subscriptions SET status = ?2, status_changed_at = ?3, updated_at = ?3 \
             WHERE id = ?1"
        )
            .bind(&[id.into(), status_str(status).into(), d1_int(now)])
            .map_err(|e| run_err("subscription.set_status bind", e))?
            .run().await.map_err(|e| run_err("subscription.set_status run", e))?;
        if res.meta().ok().flatten().and_then(|m| m.changes).unwrap_or(0) == 0 {
            return Err(PortError::NotFound);
        }
        Ok(())
    }
}
