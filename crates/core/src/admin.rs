//! Admin console domain.
//!
//! This module adds *read + limited-write* surface for operators: the
//! Cost & Data Safety Admin Console introduced in v0.3.0. It is
//! deliberately separate from the user-facing authentication flows
//! (`core::oidc`, `core::webauthn`, `core::magic_link`) - the spec at
//! `cesauth-拡張開発指示書-CostDataSafetyAdminConsole.md` §10 asks that
//! the monitoring and management code not mix into the authentication
//! core, and that Cloudflare-specific state stay in the worker /
//! adapter layers.
//!
//! What's here:
//!
//! * [`types`]   - role enum, snapshot shapes, report structures, alert
//!                 kinds. All `Serialize`/`Deserialize` where it helps
//!                 the adapters carry state, but the types otherwise
//!                 know nothing about their storage.
//! * [`policy`]  - pure functions: "does this role allow this action?",
//!                 "does this snapshot cross this threshold?". Testable
//!                 on the host with no async.
//! * [`ports`]   - trait-based persistence interfaces. An adapter for
//!                 each concrete Cloudflare primitive (D1, R2, KV) lives
//!                 in `cesauth-adapter-cloudflare::admin`.
//! * [`service`] - composes ports to build the payload behind each
//!                 admin-console page.
//!
//! Per the spec's §7 ("重要設定の変更の扱い"), every change operation
//! funnels through [`service::apply_bucket_safety_change`] etc., which:
//!
//!   1. reads the current state,
//!   2. validates the caller's role via [`policy::role_allows`],
//!   3. emits an `Admin*` audit event,
//!   4. persists the change, and
//!   5. returns a `ChangeOutcome` describing before/after.
//!
//! Two-step confirmation (preview nonce -> apply nonce) is implemented
//! in the worker route layer; core doesn't need to know about nonces.

pub mod policy;
pub mod ports;
pub mod service;
pub mod types;

#[cfg(test)]
mod tests;
