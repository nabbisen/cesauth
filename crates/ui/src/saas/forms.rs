//! Mutation HTML forms for the SaaS console (v0.4.4).
//!
//! Every form here matches one of the `/api/v1/...` JSON endpoints
//! v0.4.2 already exposes — the HTML is just the operator-friendly
//! wrapper. The two-step preview/confirm pattern is the same one
//! v0.3.1 introduced for bucket safety: low-risk mutations go in
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
//! v0.4.5+ user-as-bearer cookie path). The forms themselves carry
//! no CSRF token because the bearer header is already a same-origin
//! credential a third-party site cannot forge.
//!
//! ## What's NOT here (still deferred)
//!
//! - Role grant / revoke forms.
//! - Membership add / remove forms.
//! - Subscription history filtering forms.
//!
//! These ship with the next iteration. The 0.4.2 JSON API continues
//! to handle them; operators script through curl until the HTML
//! catches up.

pub mod group_create;
pub mod group_delete;
pub mod organization_create;
pub mod organization_set_status;
pub mod subscription_set_plan;
pub mod subscription_set_status;
pub mod tenant_create;
pub mod tenant_set_status;
