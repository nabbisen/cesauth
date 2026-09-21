//! **RFC 117** — the authorization-code exchange as a typestate pipeline.
//!
//! The only way to obtain the data a token is minted from is to walk this chain,
//! each step consuming the previous one:
//!
//! ```text
//! AuthenticatedClient::authenticate      (the client proved itself; RFC 137)
//! ConsumedCode::take(.., &client)        (only with that proof: the code is consumed)
//!   .bind_client(&client)                (it was issued to that client)
//!   .bind_redirect(uri)                  (the redirect URI matches; RFC 6749 §4.1.3)
//!   .verify_pkce(verifier)               (PKCE verifies; RFC 7636)
//!   .into_mint_input()                   (-> MintInput: the mint's only input)
//! ```
//!
//! Every field is private and every transition takes `self`, so there is no way
//! to reach a later state, or the code's contents, except by passing the checks
//! before it. A future refactor that mints before verifying does not compile: the
//! data it would mint from does not exist yet. To audit the exchange's invariants
//! it is enough to read this file.
//!
//! **What the types prove, and what they do not.** They prove the *order* of the
//! checks (authenticate, then take, then client, redirect and PKCE) and that none
//! can be skipped. `take` holds the proof but does not compare it: `bind_client`
//! does, after the take, so a wrong-client attempt still consumes the code
//! (RFC 137 T1). They do not prove `authenticate` was
//! handed the client's true stored view (a caller can still fabricate a
//! `ClientAuthView`), nor that expiry holds: that is the store's (RFC 140).
//! `take` passes `now_unix` and treats `None` as an unknown code; no expiry
//! comparison exists here.
//!
//! Every transition returns the `CoreError` the procedural code returned, because
//! existing tests pin the wire. Only the **code-exchange** mint is governed:
//! `rotate_refresh` also signs access tokens and is RFC 118's.
//!
//! # Compile-time guarantees
//!
//! The names resolve from outside the crate (this is the control: without it the
//! `compile_fail` blocks below could pass for the wrong reason):
//!
//! ```
//! use cesauth_core::service::token::exchange_pipeline::{ConsumedCode, MintInput, VerifiedExchange};
//! fn _names_resolve(_: Option<ConsumedCode>, _: Option<VerifiedExchange>, _: Option<MintInput>) {}
//! ```
//!
//! `take` demands the proof of authentication, so consuming a code before
//! authenticating does not compile (RFC 137 §13.1). Given it, the call compiles:
//!
//! ```
//! use cesauth_core::ports::store::AuthChallengeStore;
//! use cesauth_core::service::token::exchange_pipeline::{AuthenticatedClient, ConsumedCode};
//! use cesauth_core::types::ChallengeHandle;
//! fn _take_with_proof<S: AuthChallengeStore>(s: &S, h: &ChallengeHandle, c: &AuthenticatedClient) {
//!     let _ = ConsumedCode::take(s, h, 0, c);
//! }
//! ```
//!
//! Without it, the same call does not (E0061):
//!
//! ```compile_fail
//! use cesauth_core::ports::store::AuthChallengeStore;
//! use cesauth_core::service::token::exchange_pipeline::ConsumedCode;
//! use cesauth_core::types::ChallengeHandle;
//! fn _take_without_proof<S: AuthChallengeStore>(s: &S, h: &ChallengeHandle) {
//!     let _ = ConsumedCode::take(s, h, 0);
//! }
//! ```
//!
//! A `MintInput` cannot be constructed outside this module (private fields, E0451):
//!
//! ```compile_fail
//! use cesauth_core::service::token::exchange_pipeline::MintInput;
//! use cesauth_core::types::Scopes;
//! let _ = MintInput {
//!     client_id: String::new(), user_id: String::new(),
//!     scopes: Scopes::default(), nonce: None, auth_time: 0,
//! };
//! ```
//!
//! Neither can a `VerifiedExchange`, the mint license (E0451):
//!
//! ```compile_fail
//! use cesauth_core::service::token::exchange_pipeline::VerifiedExchange;
//! let _ = VerifiedExchange { inner: todo!() };
//! ```
//!
//! A step cannot be skipped: `into_mint_input` exists only on a
//! `VerifiedExchange` (E0599):
//!
//! ```compile_fail
//! use cesauth_core::service::token::exchange_pipeline::ConsumedCode;
//! fn skip(c: ConsumedCode) { let _ = c.into_mint_input(); }
//! ```
//!
//! Nor can the states be duplicated: a `VerifiedExchange` is move-only, so one
//! code cannot be minted twice (E0382):
//!
//! ```compile_fail
//! use cesauth_core::service::token::exchange_pipeline::VerifiedExchange;
//! fn twice(v: VerifiedExchange) { let _a = v.into_mint_input(); let _b = v.into_mint_input(); }
//! ```

use crate::error::{CoreError, CoreResult};
use crate::oidc::pkce::{self, ChallengeMethod};
use crate::ports::repo::ClientAuthView;
use crate::ports::store::{AuthChallengeStore, Challenge};
use crate::service::client_auth::authenticate_token_client;
use crate::types::{ChallengeHandle, Scopes};

/// Proof that a client authenticated: its only constructor runs
/// [`authenticate_token_client`]. `bind_client` takes this, not a bare id, so the
/// comparison cannot be satisfied by handing the code its own `client_id` back.
pub struct AuthenticatedClient {
    client_id: String,
}

impl AuthenticatedClient {
    pub fn authenticate(view: &ClientAuthView, presented_secret: Option<&str>) -> CoreResult<Self> {
        authenticate_token_client(view, presented_secret)?;
        Ok(Self { client_id: view.client_id.clone() })
    }
}

/// An authorization code the store has atomically consumed.
pub struct ConsumedCode {
    client_id:             String,
    user_id:               String,
    scopes:                Scopes,
    redirect_uri:          String,
    code_challenge:        String,
    code_challenge_method: String,
    nonce:                 Option<String>,
    auth_time:             i64,
}

/// A consumed code issued to the authenticated client.
pub struct ClientBoundCode { inner: ConsumedCode }

/// A client-bound code redeemed with the redirect URI it was issued for.
pub struct RedirectBoundCode { inner: ClientBoundCode }

/// The mint license: consumed, client-bound, redirect-bound, PKCE-verified.
pub struct VerifiedExchange { inner: RedirectBoundCode }

/// What tokens are minted from. Constructed only by
/// [`VerifiedExchange::into_mint_input`]; fields private, read through accessors.
pub struct MintInput {
    client_id: String,
    user_id:   String,
    scopes:    Scopes,
    nonce:     Option<String>,
    auth_time: i64,
}

impl ConsumedCode {
    /// The only constructor. `None` from the store (absent, used, or expired —
    /// the store's rule, RFC 140) is `invalid_grant`, as is a handle that holds
    /// something other than an authorization code.
    ///
    /// `_authenticated` is proof that authentication ran first, so a failed
    /// authentication cannot consume a code (RFC 137 §13.1). It is carried, not
    /// compared: `bind_client` compares, after this, so a wrong-client attempt
    /// still consumes the code.
    pub async fn take<S: AuthChallengeStore + ?Sized>(
        store:          &S,
        handle:         &ChallengeHandle,
        now_unix:       i64,
        _authenticated: &AuthenticatedClient,
    ) -> CoreResult<Self> {
        let challenge = store
            .take(handle, now_unix)
            .await
            .map_err(|_| CoreError::Internal)?
            .ok_or(CoreError::InvalidGrant("code is unknown or already used"))?;
        match challenge {
            Challenge::AuthCode {
                client_id, user_id, scopes, code_challenge, code_challenge_method,
                redirect_uri, nonce, auth_time, ..
            } => Ok(Self {
                client_id, user_id, scopes, redirect_uri,
                code_challenge, code_challenge_method, nonce, auth_time,
            }),
            _ => Err(CoreError::InvalidGrant("handle is not a code")),
        }
    }

    /// RFC 6749 §4.1.3 / RFC 137 T1: the code must be redeemed by the client it
    /// was issued to. Runs after `take`, so a wrong-client attempt has already
    /// consumed the code; the wire error is the same `invalid_grant` as an
    /// unknown code, and the distinct message reaches logs only.
    pub fn bind_client(self, client: &AuthenticatedClient) -> CoreResult<ClientBoundCode> {
        if self.client_id != client.client_id {
            return Err(CoreError::InvalidGrant("code was issued to a different client"));
        }
        Ok(ClientBoundCode { inner: self })
    }
}

impl ClientBoundCode {
    /// RFC 6749 §4.1.3: the redirect URI at `/token` must equal the one bound to
    /// the code at `/authorize`.
    pub fn bind_redirect(self, presented: &str) -> CoreResult<RedirectBoundCode> {
        if self.inner.redirect_uri != presented {
            return Err(CoreError::InvalidGrant("redirect_uri mismatch"));
        }
        Ok(RedirectBoundCode { inner: self })
    }
}

impl RedirectBoundCode {
    /// RFC 7636: delegates to `oidc::pkce`. An unsupported stored method is
    /// `invalid_request`; a wrong or malformed verifier is `PkceMismatch`.
    pub fn verify_pkce(self, verifier: &str) -> CoreResult<VerifiedExchange> {
        let code = &self.inner.inner;
        let method = ChallengeMethod::parse(&code.code_challenge_method)?;
        pkce::verify(verifier, &code.code_challenge, method)?;
        Ok(VerifiedExchange { inner: self })
    }
}

impl VerifiedExchange {
    /// The only way to obtain a [`MintInput`].
    pub fn into_mint_input(self) -> MintInput {
        let c = self.inner.inner.inner;
        MintInput {
            client_id: c.client_id,
            user_id:   c.user_id,
            scopes:    c.scopes,
            nonce:     c.nonce,
            auth_time: c.auth_time,
        }
    }
}

impl MintInput {
    pub fn client_id(&self) -> &str { &self.client_id }
    pub fn user_id(&self)   -> &str { &self.user_id }
    pub fn scopes(&self)    -> &Scopes { &self.scopes }
    pub fn nonce(&self)     -> Option<&str> { self.nonce.as_deref() }
    pub fn auth_time(&self) -> i64 { self.auth_time }
}

// `missing_debug_implementations` is on, and a derived `Debug` would print the
// user id, scopes and PKCE challenge into any log line that formats a state.
// These say nothing about their contents (cf. `Secret`, `RecoveryCode`).
macro_rules! redacted_debug {
    ($($t:ident),+) => {$(
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($t), " { .. }"))
            }
        }
    )+};
}
redacted_debug!(AuthenticatedClient, ConsumedCode, ClientBoundCode, RedirectBoundCode, VerifiedExchange, MintInput);

#[cfg(test)]
mod tests;
