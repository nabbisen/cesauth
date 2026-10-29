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
mod deletions;
mod grants;
mod invitations;
mod signing_keys;
mod totp_authenticators;
mod totp_recovery_codes;
mod users;

pub use authenticators::CloudflareAuthenticatorRepository;
pub use clients::CloudflareClientRepository;
pub use deletions::CloudflareDeletionRequestRepository;
pub use grants::CloudflareGrantRepository;
pub use invitations::CloudflareInvitationRepository;
pub use signing_keys::CloudflareSigningKeyRepository;
pub use totp_authenticators::CloudflareTotpAuthenticatorRepository;
pub use totp_recovery_codes::CloudflareTotpRecoveryCodeRepository;
pub use users::CloudflareUserRepository;

pub(crate) fn db<'a>(env: &'a Env) -> PortResult<D1Database> {
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
pub(crate) fn d1_int(v: i64) -> JsValue {
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
pub(crate) fn run_err(context: &'static str, e: worker::Error) -> PortError {
    worker::console_error!("d1 {}: {}", context, e);
    PortError::Unavailable
}

/// Classify a D1 INSERT failure by SQLite's extended result code, which
/// D1 embeds verbatim in the error message as `(extended:
/// SQLITE_CONSTRAINT_<CLASS>)` — more specific than matching the bare
/// word `constraint`, which every constraint class (UNIQUE, FOREIGN KEY,
/// CHECK, NOT NULL) contains, and which is RFC 160's defect: all four
/// collapsed into `Conflict`.
///
/// **Only UNIQUE and FOREIGN KEY are classified.** CHECK and NOT NULL are
/// not reachable by any production caller today — every `CHECK`-
/// constrained column in this schema is written from a Rust enum through
/// a `_str()` helper, never a raw caller-controlled string, and every
/// `NOT NULL` column backing an INSERT here is bound from a non-`Option`
/// field. Classifying branches nothing can produce would put untestable
/// code in the exact helper whose untested assumption caused this RFC
/// (RFC 160 §4.5/§1.1 — provoking those two classes at all required a
/// temporary, sentinel-gated bind substitution in production code,
/// restored afterward, specifically because no real caller can reach
/// them). Anything else — including a genuine CHECK/NOT NULL failure, if
/// a future change ever makes one reachable — falls through to
/// [`run_err`], today's path, unchanged.
///
/// `FOREIGN KEY` maps to [`PortError::NotFound`]: an INSERT addresses no
/// existing row, so the only possible subject is something it
/// *referenced* — "the record does not exist" (`NotFound`'s own doc) is
/// already true of that. D1's message names neither the column nor the
/// referenced table, so a variant meant to carry "which reference was
/// missing" has no payload to carry; reusing `NotFound` costs nothing
/// a new variant would have bought.
#[inline]
pub(crate) fn classify_insert_err(context: &'static str, e: worker::Error) -> PortError {
    let msg = format!("{e}").to_ascii_lowercase();
    if msg.contains("sqlite_constraint_foreignkey") {
        PortError::NotFound
    } else if msg.contains("sqlite_constraint_unique") {
        PortError::Conflict
    } else {
        run_err(context, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 160 §0's own recorded strings, verbatim — `worker::Error::
    // RustError` is a plain Rust variant (not an FFI binding), so this
    // runs on the host like any other pure-function test.

    const UNIQUE_MSG: &str =
        "D1: D1Error { cause: JsValue(Error: UNIQUE constraint failed: tenants.slug: SQLITE_CONSTRAINT (extended: SQLITE_CONSTRAINT_UNIQUE)) }";
    const FOREIGN_KEY_MSG: &str =
        "D1: D1Error { cause: JsValue(Error: FOREIGN KEY constraint failed: SQLITE_CONSTRAINT (extended: SQLITE_CONSTRAINT_FOREIGNKEY)) }";

    fn err(s: &str) -> worker::Error { worker::Error::RustError(s.to_owned()) }

    #[test]
    fn unique_classifies_as_conflict() {
        assert!(matches!(classify_insert_err("test", err(UNIQUE_MSG)), PortError::Conflict));
    }

    #[test]
    fn foreign_key_classifies_as_not_found() {
        assert!(matches!(classify_insert_err("test", err(FOREIGN_KEY_MSG)), PortError::NotFound));
    }

    // RFC 160 §4.5: CHECK and NOT NULL are not reachable by any
    // production caller today, and this helper does not special-case
    // them — they, and any other unrecognized message, fall through to
    // `run_err`'s `Unavailable`, not silently become a `Conflict` the
    // way the pre-RFC-160 `contains("constraint")` test would have.
    //
    // **Flagging, not silently substituting**: that fallthrough has no
    // host test here. `run_err` calls `worker::console_error!`, which
    // panics ("function not implemented on non-wasm32 targets") the
    // moment it runs outside wasm32 — the same limitation that applies
    // to every other `worker::Env`-touching call in this workspace.
    // Confirmed directly: adding that assertion aborts the test binary
    // (SIGABRT), not a normal test failure.
}
