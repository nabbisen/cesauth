//! Service layer.
//!
//! The service layer is where domain rules (from `oidc`, `webauthn`,
//! `jwt`, `magic_link`) and persistence ports (`ports`) are composed
//! into the actual multi-step flows cesauth provides.
//!
//! **Why this layer is in `core`.** The flows themselves - "redeem
//! this code for a token", "rotate this refresh token" - are
//! Cloudflare-agnostic. They read from a ClientRepository and a
//! RefreshTokenFamilyStore, but they do not care which adapter is on
//! the other side of those traits. Keeping the flows here lets us
//! unit-test them with `adapter-test` before wiring to Cloudflare.
//!
//! Each service function takes its dependencies by generic reference
//! rather than by `dyn Trait`, so the call graph is statically
//! resolved and there's no allocation overhead on the hot path.

pub mod client_auth;
pub mod introspect;
pub mod revoke;
pub mod token;

#[allow(async_fn_in_trait)]
const _: () = ();
