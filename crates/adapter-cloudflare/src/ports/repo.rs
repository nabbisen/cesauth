//! D1-backed repository adapters.
//!
//! Each submodule is one port trait's adapter. The parent file keeps
//! only the shared helpers (`db`, `d1_int`, `run_err`) that every
//! repository uses, plus the module declarations and re-exports.
//!
//! ## The `i64 -> JsValue` pitfall
//!
//! `wasm_bindgen` provides `JsValue: From<i64>` - but that impl
//! produces a JavaScript **BigInt**, not a Number. D1's runtime
//! `bind()` (per the `@cloudflare/workers-types` definitions) only
//! accepts `string | number | boolean | ArrayBuffer | null`; a BigInt
//! causes the prepared statement to fail at bind time with an opaque
//! "Unavailable" on our side. Every integer bound here **must** go
//! through `d1_int()`, which does the `as f64` cast. This matches
//! what worker-rs's own `D1Type::Integer` does internally.
//!
//! If you see `storage error`/`Unavailable` from an INSERT or UPDATE:
//! look for a freshly-added `i64.into()` in `bind(&[...])` and wrap
//! it with `d1_int()`.

use cesauth_core::ports::{PortError, PortResult};
use worker::wasm_bindgen::JsValue;
use worker::{D1Database, Env};

mod authenticators;
mod clients;
mod grants;
mod signing_keys;
mod users;

pub use authenticators::CloudflareAuthenticatorRepository;
pub use clients::CloudflareClientRepository;
pub use grants::CloudflareGrantRepository;
pub use signing_keys::CloudflareSigningKeyRepository;
pub use users::CloudflareUserRepository;

fn db<'a>(env: &'a Env) -> PortResult<D1Database> {
    env.d1("DB").map_err(|_| PortError::Unavailable)
}

/// Convert an `i64` into a `JsValue` that D1's `bind()` will accept.
///
/// `wasm_bindgen`'s default `From<i64>` produces a JavaScript BigInt,
/// which D1 rejects. We cast through `f64` the way worker-rs's
/// `D1Type::Integer` does. Timestamps and counters used here all fit
/// comfortably within `Number.MAX_SAFE_INTEGER` (2^53 - 1), so the
/// cast is lossless for every value we actually bind.
#[inline]
fn d1_int(v: i64) -> JsValue {
    JsValue::from_f64(v as f64)
}

/// Map a worker-side D1 error to `PortError::Unavailable` after
/// surfacing the underlying message once to the operational log.
/// `PortError::Unavailable` carries no payload of its own, so without
/// this helper every D1 failure arrives at the HTTP layer as an opaque
/// "storage error" with no breadcrumbs in `wrangler tail`.
///
/// Use at `.run().await` sites (INSERT/UPDATE/DELETE) where the extra
/// line is worth paying; SELECT sites use the plain
/// `map_err(|_| PortError::Unavailable)` because a failing read is
/// usually the route handler's first clue anyway.
#[inline]
fn run_err(context: &'static str, e: worker::Error) -> PortError {
    worker::console_error!("d1 {}: {}", context, e);
    PortError::Unavailable
}
