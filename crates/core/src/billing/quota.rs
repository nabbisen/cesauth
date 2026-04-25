//! Quota-decision pure function.
//!
//! Given a plan (or absence thereof), a quota name, and the current
//! count, decide whether one more would fit. Pure over its inputs;
//! the route layer reads the plan + count from D1 and feeds them in.
//!
//! Spec §6.7 calls for "クォータ管理"; this is the decision step.
//! Enforcement (mapping a decision to an HTTP response) lives in the
//! worker. Counting (running the COUNT(*) SQL) lives in the worker.
//! Just the rule lives here.

use super::types::{Plan, Quota};

/// Outcome of a quota check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaDecision {
    /// One more is allowed (no plan, no quota row, unlimited, or
    /// `current < limit`).
    Allowed,
    /// One more would exceed the limit. Carries the limit and the
    /// observed count so the caller can include them in the error.
    Denied { name: String, limit: i64, current: i64 },
}

impl QuotaDecision {
    pub fn is_allowed(&self) -> bool { matches!(self, QuotaDecision::Allowed) }
}

/// Decide whether `current + 1` would exceed the named quota under
/// `plan`.
///
/// `plan = None` means "no subscription on file" — operator-
/// provisioned tenants may run without a subscription, in which case
/// quota does not apply (allow). A quota row whose value is
/// [`Quota::UNLIMITED`] (`-1`) also allows.
pub fn quota_decision(
    plan:       Option<&Plan>,
    quota_name: &str,
    current:    i64,
) -> QuotaDecision {
    let Some(plan) = plan else { return QuotaDecision::Allowed; };
    let Some(quota) = plan.quotas.iter().find(|q| q.name == quota_name) else {
        return QuotaDecision::Allowed;
    };
    if quota.is_unlimited() {
        return QuotaDecision::Allowed;
    }
    if current >= quota.value {
        QuotaDecision::Denied {
            name:    quota_name.to_owned(),
            limit:   quota.value,
            current,
        }
    } else {
        QuotaDecision::Allowed
    }
}

// Re-export for callers that need the unlimited sentinel.
#[allow(dead_code)]
const _UNLIMITED: i64 = Quota::UNLIMITED;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::types::{FeatureFlag, Plan, Quota};

    fn plan_with_quotas(quotas: Vec<Quota>) -> Plan {
        Plan {
            id: "p".into(), slug: "test".into(), display_name: "Test".into(),
            active: true,
            features: vec![FeatureFlag::new("core")],
            quotas,
            price_description: None,
            created_at: 0, updated_at: 0,
        }
    }

    #[test]
    fn no_plan_allows() {
        assert_eq!(quota_decision(None, "max_users", 9_999), QuotaDecision::Allowed);
    }

    #[test]
    fn no_matching_quota_row_allows() {
        // Plan exists, quota name absent -> the spec is silent on
        // it, so the answer is "allow".
        let plan = plan_with_quotas(vec![
            Quota { name: "max_groups".into(), value: 5 },
        ]);
        assert_eq!(quota_decision(Some(&plan), "max_users", 9_999), QuotaDecision::Allowed);
    }

    #[test]
    fn unlimited_quota_allows_at_any_count() {
        let plan = plan_with_quotas(vec![
            Quota { name: "max_users".into(), value: Quota::UNLIMITED },
        ]);
        assert_eq!(quota_decision(Some(&plan), "max_users", 1_000_000), QuotaDecision::Allowed);
    }

    #[test]
    fn current_below_limit_allows() {
        let plan = plan_with_quotas(vec![
            Quota { name: "max_users".into(), value: 5 },
        ]);
        assert_eq!(quota_decision(Some(&plan), "max_users", 4), QuotaDecision::Allowed);
    }

    #[test]
    fn current_at_limit_denies() {
        let plan = plan_with_quotas(vec![
            Quota { name: "max_users".into(), value: 5 },
        ]);
        let decision = quota_decision(Some(&plan), "max_users", 5);
        match decision {
            QuotaDecision::Denied { name, limit, current } => {
                assert_eq!(name, "max_users");
                assert_eq!(limit, 5);
                assert_eq!(current, 5);
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn current_above_limit_denies() {
        // Should not happen in practice (we check before insert) but
        // the function must still report Denied — never panic.
        let plan = plan_with_quotas(vec![
            Quota { name: "max_users".into(), value: 5 },
        ]);
        assert!(matches!(
            quota_decision(Some(&plan), "max_users", 9999),
            QuotaDecision::Denied { .. }
        ));
    }
}
