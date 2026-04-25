//! `PlanRepository` D1 adapter.
//!
//! Like roles, `features` is stored as a comma-separated string and
//! `quotas` as `name=value,name=value`. D1 has no JSON1 extension; a
//! join-table for catalog data this stable is overkill.

use cesauth_core::billing::ports::PlanRepository;
use cesauth_core::billing::types::{FeatureFlag, Plan, Quota};
use cesauth_core::ports::{PortError, PortResult};
use serde::Deserialize;
use worker::Env;

use crate::ports::repo::db;

pub struct CloudflarePlanRepository<'a> {
    env: &'a Env,
}

impl std::fmt::Debug for CloudflarePlanRepository<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflarePlanRepository").finish_non_exhaustive()
    }
}

impl<'a> CloudflarePlanRepository<'a> {
    pub fn new(env: &'a Env) -> Self { Self { env } }
}

#[derive(Deserialize)]
struct PlanRow {
    id:                String,
    slug:              String,
    display_name:      String,
    active:            i64,
    features:          String,
    quotas:            String,
    price_description: Option<String>,
    created_at:        i64,
    updated_at:        i64,
}

fn parse_features(s: &str) -> Vec<FeatureFlag> {
    if s.is_empty() { return Vec::new(); }
    s.split(',')
        .map(|f| FeatureFlag::new(f.trim().to_owned()))
        .filter(|f| !f.as_str().is_empty())
        .collect()
}

/// Decode `name=value,name=value` into `Vec<Quota>`. Missing `=` or
/// non-integer values are skipped (the migration writes well-formed
/// rows; this is just defense in depth against an operator typing
/// the column manually).
fn parse_quotas(s: &str) -> Vec<Quota> {
    if s.is_empty() { return Vec::new(); }
    s.split(',').filter_map(|p| {
        let (n, v) = p.split_once('=')?;
        let v = v.trim().parse::<i64>().ok()?;
        Some(Quota { name: n.trim().to_owned(), value: v })
    }).collect()
}

impl PlanRow {
    fn into_domain(self) -> Plan {
        Plan {
            id: self.id, slug: self.slug, display_name: self.display_name,
            active: self.active != 0,
            features: parse_features(&self.features),
            quotas:   parse_quotas(&self.quotas),
            price_description: self.price_description,
            created_at: self.created_at, updated_at: self.updated_at,
        }
    }
}

const COLS: &str = "id, slug, display_name, active, features, quotas, price_description, created_at, updated_at";

impl PlanRepository for CloudflarePlanRepository<'_> {
    async fn get(&self, id: &str) -> PortResult<Option<Plan>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!("SELECT {COLS} FROM plans WHERE id = ?1"))
            .bind(&[id.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<PlanRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().next().map(PlanRow::into_domain))
    }

    async fn find_by_slug(&self, slug: &str) -> PortResult<Option<Plan>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!("SELECT {COLS} FROM plans WHERE slug = ?1"))
            .bind(&[slug.into()]).map_err(|_| PortError::Unavailable)?
            .all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<PlanRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().next().map(PlanRow::into_domain))
    }

    async fn list_active(&self) -> PortResult<Vec<Plan>> {
        let db = db(self.env)?;
        let rows = db.prepare(&format!(
            "SELECT {COLS} FROM plans WHERE active = 1 ORDER BY slug"
        )).all().await.map_err(|_| PortError::Unavailable)?;
        let rows: Vec<PlanRow> = rows.results().map_err(|_| PortError::Serialization)?;
        Ok(rows.into_iter().map(PlanRow::into_domain).collect())
    }
}
