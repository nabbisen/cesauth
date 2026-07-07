//! `GET /admin/console/audit` — Audit Log viewer (RFC 109, v0.71.0).
//!
//! Query parameters (all optional):
//!
//! | Param      | Meaning                                                |
//! |------------|--------------------------------------------------------|
//! | `prefix`   | Legacy R2 key prefix (v0.31.x compat — D1 ignores it). |
//! | `limit`    | Max number of matches. Hard-capped in adapter.         |
//! | `kind`     | Substring match on `kind` (legacy field).              |
//! | `subject`  | Substring match on `subject` (user / session id).      |
//! | `actor`    | Alias for `subject` — RFC 109 form-field name.         |
//! | `event`    | Exact match on `kind` (RFC 109 dropdown).              |
//! | `from`     | RFC 3339 UTC lower bound (inclusive). Maps to `since`. |
//! | `to`       | RFC 3339 UTC upper bound (inclusive). Maps to `until`. |
//! | `cursor`   | Opaque base64url pagination cursor (server-issued).    |
//!
//! Parsing notes (RFC 109):
//!
//! - `actor` and `subject` are accepted both. The form posts `actor`;
//!   the legacy URL still works.
//! - `from` and `to` are parsed via
//!   [`audit_pagination::parse_rfc3339_to_unix`]. Invalid timestamps
//!   are dropped silently rather than rejected with 400 — the operator
//!   sees the filter not applied; the rest of the page still renders.
//! - `cursor` is passed through verbatim; the adapter calls
//!   `decode_cursor` itself.

use cesauth_cf::admin::CloudflareAuditQuerySource;
use cesauth_core::admin::service::audit_pagination;
use cesauth_core::admin::service::search_audit;
use cesauth_core::admin::types::{AdminAction, AuditQuery};
use cesauth_frontend as ui;
use worker::{Request, Response, Result, RouteContext};

use crate::audit::{self, EventKind};
use crate::routes::admin::auth;
use crate::routes::admin::console::render;

pub async fn page<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    crate::routes::admin::operator_json_api::shell(&req, &ctx, "監査ログ — cesauth").await
}

pub async fn page_json<D>(req: Request, ctx: RouteContext<D>) -> Result<Response> {
    let _admin = match crate::routes::admin::operator_json_api::resolve_admin(&req, &ctx).await? {
        Ok(a)  => a,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    crate::routes::admin::operator_json_api::csrf_json()
}
