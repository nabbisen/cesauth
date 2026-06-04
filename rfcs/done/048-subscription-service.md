# RFC 048 — Subscription + plan quota service

**Status**: Implemented  
**Priority**: P2 (SaaS guide §6.7)  
**Size**: Medium (~200 LOC core)  
**Depends on**: RFC 043 (SCHEMA_VERSION context)

## Problem

`plans` and `subscriptions` tables ship in 0003_tenancy.sql but have no
service layer. There is no way to:
- Check a tenant's current plan quotas
- Enforce feature flags at the service layer
- Record plan changes with history

## Work

- `cesauth_core::billing` module (extend/replace existing stub):
  - `FeatureFlag` enum
  - `Quota { name, limit }` — -1 = unlimited
  - `Plan` struct with `features: Vec<FeatureFlag>` and `quotas: Vec<Quota>`
  - `Subscription` struct aligned with the schema
  - `is_feature_enabled(tenant, flag)` pure check
  - `check_quota(tenant, name, current_count)` — returns `Ok(())` or `Err(QuotaExceeded)`
  - `change_plan(tenant_id, to_plan_id, actor, now)` — writes subscription_history row
- `SubscriptionRepository` and `PlanRepository` port traits
- 15+ unit tests
