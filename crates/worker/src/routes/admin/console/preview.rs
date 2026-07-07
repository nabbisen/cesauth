//! `POST /admin/console/config/:b/preview` — dry-run preview of a
//! configuration operation before `apply`.
//!
//! **Stub.** The handler body is env-blocked (wasm32 compile target
//! required for full implementation). The module declaration in
//! `console.rs` requires this file to exist; the route itself is
//! registered but returns 501 Not Implemented until the full
//! implementation ships.

use worker::{Request, Response, Result, RouteContext};

/// Dry-run preview of a config operation.  Returns 501 until implemented.
pub async fn handler<D>(_req: Request, _ctx: RouteContext<D>) -> Result<Response> {
    Response::error("preview not yet implemented", 501)
}
