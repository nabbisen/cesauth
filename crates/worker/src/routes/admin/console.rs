//! Cost & Data Safety Admin Console — the v0.3 admin surface.
//!
//! Each submodule owns one of the six pages from §4 of the spec plus
//! the small set of write endpoints that sit under them:
//!
//! | Path                                    | Module       | Min role   |
//! |-----------------------------------------|--------------|------------|
//! | `GET  /admin/console`                   | [`overview`] | ReadOnly   |
//! | `GET  /admin/console/cost`              | [`cost`]     | ReadOnly   |
//! | `GET  /admin/console/safety`            | [`safety`]   | ReadOnly   |
//! | `POST /admin/console/safety/:b/verify`  | [`safety`]   | Security   |
//! | `GET  /admin/console/audit`             | [`audit`]    | ReadOnly   |
//! | `GET  /admin/console/config`            | [`config`]   | ReadOnly   |
//! | `POST /admin/console/config/:b/preview` | [`config`]   | Operations |
//! | `POST /admin/console/config/:b/apply`   | [`config`]   | Operations |
//! | `GET  /admin/console/alerts`            | [`alerts`]   | ReadOnly   |
//! | `POST /admin/console/thresholds/:name`  | [`actions`]  | Operations |
//!
//! Every GET handler is `Accept`-aware: responses default to HTML (the
//! browser path) but return JSON when the client sends
//! `Accept: application/json`. This makes the same surface scriptable
//! from `curl` without exposing a second parallel JSON API.
//!
//! Write handlers always return JSON; the HTML forms in v0.3.0 just
//! POST through and re-navigate to the matching GET page. (The two-step
//! confirm-UI flow for dangerous edits is a 0.3.1 item — for now the
//! preview/apply pair is scripted from JSON.)

pub mod actions;
pub mod alerts;
pub mod audit;
pub mod config;
pub mod cost;
pub mod overview;
pub mod render;
pub mod safety;
