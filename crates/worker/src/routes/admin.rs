//! Admin surface.
//!
//! The admin API has two generations in this crate:
//!
//! * [`legacy`] - the narrow pre-0.3 API: `POST /admin/users` and
//!   `DELETE /admin/sessions/:id`. Still the canonical way to create a
//!   user / kill a session; now role-gated via the new [`auth`] module.
//! * [`console`] - the v0.3 Cost & Data Safety Admin Console described
//!   in `cesauth-拡張開発指示書-CostDataSafetyAdminConsole.md`. Six
//!   read-only dashboard pages plus a small set of write endpoints for
//!   the attestation workflow.
//!
//! Every admin request flows through the same principal-resolution step
//! in [`auth::resolve_from_request`]: check `Authorization: Bearer ...`
//! against `ADMIN_API_KEY` (super bootstrap) first, else look up in the
//! D1 `admin_tokens` table. The matched principal's role is then
//! checked against the action the handler is about to perform via
//! [`cesauth_core::admin::policy::role_allows`].
//!
//! The old `create_user` / `revoke_session` handlers are re-exported at
//! this module's top level so `lib.rs`'s router wiring didn't have to
//! change when the refactor landed.

pub mod auth;
pub mod console;
pub mod legacy;
pub mod tenancy_console;

pub use legacy::{create_user, revoke_session};
