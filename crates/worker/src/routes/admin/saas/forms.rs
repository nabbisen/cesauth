//! HTML mutation form handlers for the SaaS console (v0.4.4).
//!
//! Every handler here runs the same prelude: resolve the bearer,
//! gate on `AdminAction::ManageTenancy` (Operations+), and parse
//! the form body. The work itself delegates to the existing
//! v0.4.0/0.4.1 service-layer ports — no new domain code lives
//! here.

pub mod common;

pub mod group_create;
pub mod group_delete;
pub mod organization_create;
pub mod organization_set_status;
pub mod subscription_set_plan;
pub mod subscription_set_status;
pub mod tenant_create;
pub mod tenant_set_status;
