//! Mutation HTML forms for the SaaS console (v0.9.0).
//!
//! Every form here matches one of the `/api/v1/...` JSON endpoints
//! v0.7.0 already exposes — the HTML is just the operator-friendly
//! wrapper. The two-step preview/confirm pattern is the same one
//! v0.4.0 introduced for bucket safety: low-risk mutations go in
//! one click, destructive mutations re-render the form with a diff
//! and a separate "Confirm" button before committing.
//!
//! ## What's "destructive"
//!
//! - Tenant / organization status change (suspend or delete).
//! - Group delete (soft delete, but immediate visibility loss).
//! - Subscription plan / status change (billing impact).
//!
//! Everything else (creates, display-name updates, role grants
//! within a single tenant, membership add/remove) is one-click.
//! The pattern keeps the operator's "I just clicked a button by
//! accident" failure mode small.
//!
//! ## Auth
//!
//! Forms POST same-origin and the bearer rides on the
//! `Authorization` header — same as the read pages and same as the
//! v0.3.x edit forms. Operators must use a tool that sets the
//! header (curl, browser extension, or — once it lands — the
//! v0.10.0+ user-as-bearer cookie path). The forms themselves carry
//! no CSRF token because the bearer header is already a same-origin
//! credential a third-party site cannot forge.
//!
//! ## What's NOT here (still deferred to 0.10.0+)
//!
//! - Tenant-scoped admin surface (where tenant admins administer
//!   their own tenant rather than the cesauth operator
//!   administering every tenant). Requires user-as-bearer auth +
//!   login → tenant resolution + cookie auth. **0.10.0+.**
//!
//! 0.10.0 added the membership add/remove and role grant/revoke
//! forms that 0.9.0 had carved out — the 0.9.0 docstring listed
//! them as deferred; they are now available.

pub mod group_create;
pub mod group_delete;
pub mod membership_add;
pub mod membership_remove;
pub mod organization_create;
pub mod organization_set_status;
pub mod role_assignment_create;
pub mod role_assignment_delete;
pub mod subscription_set_plan;
pub mod subscription_set_status;
pub mod tenant_create;
pub mod tenant_set_status;
