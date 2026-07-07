//! Tenant-admin console page components (`/admin/t/:slug/*`).
//!
//! Migrated in v0.79.6.  Each module corresponds to one URL path.
//!
//! All components follow the same data-fetch pattern:
//!  1. Extract `:slug` from the URL with `use_params_map()`
//!  2. Fetch `GET /admin/t/<slug>/<page>.json` via Resource + Suspense
//!  3. Render the data or a typed error
//!
//! POST actions (create, delete, status change) continue to use regular
//! HTML `<form>` submissions.  The CSRF token comes from the `.json`
//! fetch and is embedded in form hidden fields.

pub mod overview;
pub mod users;
pub mod organizations;
pub mod subscription;
pub mod invitations;
pub mod forms;
