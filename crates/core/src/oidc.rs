//! OIDC protocol logic.
//!
//! The split:
//!
//! * [`discovery`]    - serializes the `.well-known` document from config.
//! * [`pkce`]         - PKCE verifier/challenge validation (RFC 7636).
//! * [`authorization`] - the `/authorize` request shape and validation.
//! * [`token`]        - the `/token` request/response shapes.
//!
//! Nothing here touches storage. The caller is expected to hand us the
//! already-resolved `OidcClient`, the already-extracted PKCE verifier,
//! and so on. This lets us stay storage-agnostic and unit-testable.

pub mod authorization;
pub mod discovery;
pub mod introspect;
pub mod pkce;
pub mod token;
