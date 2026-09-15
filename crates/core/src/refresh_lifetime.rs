//! **RFC 139** — refresh-family lifetime policy and the single function that
//! decides whether a family is still live.
//!
//! A family is live only while **both** deadlines are in the future:
//!
//! ```text
//! absolute:  created_at      + absolute_secs
//! idle:      last_rotated_at + idle_secs        (idle_secs = 0 disables it)
//! ```
//!
//! Expired iff `now_unix >= deadline` (the same boundary as RFC 140). No
//! deadline is stored: they are computed at check time from the family's
//! `created_at` / `last_rotated_at` and the **current** policy, so lowering
//! the configured lifetime shortens every live family at once (RFC 139 §9.2).
//!
//! **This is the only place the arithmetic lives.** The Durable Object, the
//! in-memory oracle and introspection all call [`FamilyState::lifetime`] /
//! [`FamilyState::deadline`]; a second copy is a place they could disagree.

use serde::{Deserialize, Serialize};

use crate::ports::store::FamilyState;

/// Default idle window: 14 days (RFC 139 §9.1).
pub const DEFAULT_REFRESH_IDLE_TIMEOUT_SECS: i64 = 14 * 24 * 60 * 60;

/// The configured lifetime policy. Fields are private: the only way to build
/// one is [`RefreshLifetime::new`], which refuses a policy that would disable
/// the absolute cap (RFC 139 handoff §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshLifetime {
    absolute_secs: i64,
    idle_secs:     i64,
}

/// Why a lifetime policy was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshLifetimeError {
    /// The absolute cap must be positive; it cannot be disabled.
    AbsoluteNotPositive { absolute_secs: i64 },
    /// The idle window must be `0` (disabled) or positive.
    IdleNegative { idle_secs: i64 },
    /// An idle window longer than the absolute cap can never fire.
    IdleExceedsAbsolute { idle_secs: i64, absolute_secs: i64 },
}

impl std::fmt::Display for RefreshLifetimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AbsoluteNotPositive { absolute_secs } => write!(f,
                "REFRESH_TOKEN_TTL_SECS must be positive (got {absolute_secs})"),
            Self::IdleNegative { idle_secs } => write!(f,
                "REFRESH_TOKEN_IDLE_TIMEOUT_SECS must be 0 (disabled) or positive (got {idle_secs})"),
            Self::IdleExceedsAbsolute { idle_secs, absolute_secs } => write!(f,
                "REFRESH_TOKEN_IDLE_TIMEOUT_SECS ({idle_secs}) must not exceed REFRESH_TOKEN_TTL_SECS ({absolute_secs})"),
        }
    }
}

impl std::error::Error for RefreshLifetimeError {}

impl RefreshLifetime {
    /// Validate and build a policy. Refused if `absolute_secs <= 0`,
    /// `idle_secs < 0`, or `idle_secs > absolute_secs` (RFC 139 §9.1).
    pub fn new(absolute_secs: i64, idle_secs: i64) -> Result<Self, RefreshLifetimeError> {
        if absolute_secs <= 0 {
            return Err(RefreshLifetimeError::AbsoluteNotPositive { absolute_secs });
        }
        if idle_secs < 0 {
            return Err(RefreshLifetimeError::IdleNegative { idle_secs });
        }
        if idle_secs > absolute_secs {
            return Err(RefreshLifetimeError::IdleExceedsAbsolute { idle_secs, absolute_secs });
        }
        Ok(Self { absolute_secs, idle_secs })
    }

    pub fn absolute_secs(&self) -> i64 { self.absolute_secs }

    /// `0` means the idle check is disabled.
    pub fn idle_secs(&self) -> i64 { self.idle_secs }
}

/// Which deadline ended a family. Stored on the family when the store expires
/// it (RFC 139 §10.1), so it is part of the persisted shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifetimeExpiry {
    Idle,
    Absolute,
}

/// The decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    Live,
    Expired(LifetimeExpiry),
}

impl FamilyState {
    /// Is this family live at `now_unix` under `policy`? The absolute cap is
    /// checked before the idle window, so a family past both is
    /// `Expired(Absolute)`.
    pub fn lifetime(&self, now_unix: i64, policy: &RefreshLifetime) -> Lifetime {
        if now_unix >= self.absolute_deadline(policy) {
            return Lifetime::Expired(LifetimeExpiry::Absolute);
        }
        match self.idle_deadline(policy) {
            Some(idle) if now_unix >= idle => Lifetime::Expired(LifetimeExpiry::Idle),
            _ => Lifetime::Live,
        }
    }

    /// The earlier of the two deadlines — the instant the family stops being
    /// live if nothing rotates it first. Only the absolute term when idle is
    /// disabled. Introspection reports this as `exp`.
    pub fn deadline(&self, policy: &RefreshLifetime) -> i64 {
        let absolute = self.absolute_deadline(policy);
        self.idle_deadline(policy).map_or(absolute, |idle| idle.min(absolute))
    }

    // The two sums. Saturating, so an extreme `created_at` cannot wrap a
    // deadline into the past or panic in a debug build.
    fn absolute_deadline(&self, policy: &RefreshLifetime) -> i64 {
        self.created_at.saturating_add(policy.absolute_secs)
    }

    fn idle_deadline(&self, policy: &RefreshLifetime) -> Option<i64> {
        (policy.idle_secs > 0).then(|| self.last_rotated_at.saturating_add(policy.idle_secs))
    }
}

#[cfg(test)]
mod tests;
