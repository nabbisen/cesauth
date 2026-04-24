//! WebAuthn route handlers.
//!
//! The four endpoints here are thin HTTP glue around
//! `cesauth_core::webauthn::{registration, authentication}`:
//!
//! * `POST /webauthn/register/start`    mints a challenge, parks it.
//! * `POST /webauthn/register/finish`   verifies attestation, persists
//!                                      the new authenticator row, and
//!                                      issues a session.
//! * `POST /webauthn/authenticate/start`  mints an assertion challenge.
//! * `POST /webauthn/authenticate/finish` verifies the assertion, bumps
//!                                        `sign_count`, issues a session,
//!                                        and (if an `/authorize` flow
//!                                        was in progress) mints an
//!                                        authorization code.
//!
//! "Issue a session and maybe mint a code" is the shared tail of every
//! auth path. It lives in `post_auth::complete_auth` so magic-link
//! verify, passkey auth, and passkey registration all end up in exactly
//! the same browser state on success.
//!
//! One submodule per ceremony: `register` groups start+finish for
//! enrollment, `authenticate` groups start+finish for assertion. The
//! single helper `rp_from_config` is shared by all four handlers and
//! lives here.

use cesauth_core::webauthn::RelyingParty;

use crate::config::Config;

mod authenticate;
mod register;

pub use authenticate::{authenticate_finish, authenticate_start};
pub use register::{register_finish, register_start};

fn rp_from_config(cfg: &Config) -> RelyingParty {
    RelyingParty {
        id:     cfg.rp_id.clone(),
        name:   cfg.rp_name.clone(),
        origin: cfg.rp_origin.clone(),
    }
}
