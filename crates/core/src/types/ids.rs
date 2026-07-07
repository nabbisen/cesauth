//! **RFC 116** — Security-critical identifier newtypes.
//!
//! Every identifier that participates in an authentication or
//! authorization decision gets its own type, so that transposing two
//! arguments (`rotate(family_id, presented_jti, new_jti, …)`,
//! `check_permission(user_id, permission, …)`) is a *compile error*
//! instead of a latent bug.
//!
//! ## Construction rules
//!
//! * [`mint()`](TenantId::mint) — `pub(crate)`. Only cesauth mints
//!   identifiers; minted ids are UUIDv4 strings, matching every
//!   pre-RFC 116 row in D1 and every DO key.
//! * [`parse()`](TenantId::parse) — the **single** entry point for
//!   attacker-controlled input (route params, cookie bodies, token
//!   claims, form fields). Validation is shape-only and deliberately
//!   permissive: cesauth has legacy non-UUID identifiers in
//!   production shape (`tenant-default`, operator-registered client
//!   ids), so the rule is "non-empty, bounded length, ASCII-graphic"
//!   rather than strict UUID. Existence checks remain the
//!   repositories' job.
//! * [`from_storage()`](TenantId::from_storage) — `pub(crate)`
//!   trusted re-hydration for values read back from D1 / DO storage,
//!   which cesauth itself wrote. Skips validation (storage rows may
//!   predate any future tightening of `parse`); adapters use this at
//!   the read boundary.
//!
//! ## What is deliberately NOT here
//!
//! * No `Deref<Target = str>` and no `From<String>` — implicit
//!   stringification is exactly the bug class this module removes.
//! * `Permission` is **not** an id; it is sealed separately with
//!   catalog semantics (RFC 120).
//! * Non-security identifiers (orgs, groups, plans, …) keep
//!   [`crate::types::Id`] until a follow-up RFC decides otherwise.
//!
//! Serialization is `#[serde(transparent)]`: wire formats, D1 rows,
//! DO payloads, cookies, and JWTs are byte-identical to pre-RFC 116.

use core::fmt;

use serde::{Deserialize, Serialize};

/// Maximum accepted length for any externally supplied identifier.
/// Generous (UUIDs are 36; handles are 43) but bounded so hostile
/// input cannot smuggle megabytes into storage keys or log lines.
pub const MAX_ID_LEN: usize = 128;

/// Why a presented identifier was rejected at the boundary.
///
/// The variants are intentionally coarse: boundary rejection messages
/// must not become an oracle for internal id formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdParseError {
    /// Empty string.
    Empty,
    /// Longer than [`MAX_ID_LEN`].
    TooLong,
    /// Contains a byte outside ASCII-graphic (controls, whitespace,
    /// non-ASCII). Identifiers are machine tokens, never prose.
    InvalidCharacter,
}

impl fmt::Display for IdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "identifier is empty"),
            Self::TooLong => write!(f, "identifier exceeds {MAX_ID_LEN} bytes"),
            Self::InvalidCharacter => write!(f, "identifier contains an invalid character"),
        }
    }
}

impl std::error::Error for IdParseError {}

/// Shared shape check. ASCII-graphic = `0x21..=0x7E` — printable,
/// no whitespace, no controls, no multi-byte surprises.
fn validate_shape(s: &str) -> Result<(), IdParseError> {
    if s.is_empty() {
        return Err(IdParseError::Empty);
    }
    if s.len() > MAX_ID_LEN {
        return Err(IdParseError::TooLong);
    }
    if !s.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(IdParseError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! define_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Fallible boundary constructor for attacker-controlled
            /// input. Validates *shape*, not existence.
            pub fn parse(s: impl Into<String>) -> Result<Self, IdParseError> {
                let s = s.into();
                validate_shape(&s)?;
                Ok(Self(s))
            }

            /// Mint a fresh identifier (UUIDv4).
            ///
            /// **Caller contract:** use only to create a new identifier.
            /// To re-hydrate an existing stored value, use [`Self::from_storage`].
            #[allow(dead_code)] // adopted incrementally across RFC 116 phases
            pub fn mint() -> Self {
                Self(uuid::Uuid::new_v4().to_string())
            }

            /// Trusted re-hydration of a value cesauth itself wrote to
            /// D1 / DO storage. Bypasses validation — storage is inside
            /// the trust boundary and may hold legacy shapes.
            ///
            /// **Caller contract:** use only for values that cesauth wrote
            /// (D1 rows, DO payloads, signed cookies, JWT claims).
            /// For attacker-supplied input, use [`Self::parse`] instead.
            #[allow(dead_code)]
            pub fn from_storage(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            /// Borrow the inner string (SQL binding, DO keys, JWT
            /// claims, log-safe echo — identifiers are not secret).
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume into the inner string at a storage boundary.
            #[allow(dead_code)]
            pub(crate) fn into_string(self) -> String {
                self.0
            }
        }

        // Identifiers are not secret: full echo, but tagged with the
        // type name so logs show which kind of id this is.
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

define_id! {
    /// Top-level isolation boundary (spec §3.1). Accepts the legacy
    /// slug `tenant-default` as well as minted UUIDs.
    TenantId
}

define_id! {
    /// A principal — human, service account, anonymous, operator, or
    /// federated (spec §5). The `sub` of issued tokens.
    UserId
}

define_id! {
    /// OIDC client registration id. May be operator-chosen.
    ClientId
}

define_id! {
    /// An active-session id (the `ActiveSession` DO key and the
    /// session-cookie body field).
    SessionId
}

define_id! {
    /// Refresh-token family id (the `RefreshTokenFamily` DO key,
    /// ADR-011).
    FamilyId
}

define_id! {
    /// A refresh-token `jti` claim — the per-rotation token identity
    /// inside a family.
    Jti
}

define_id! {
    /// Opaque handle naming a [`crate::ports::Challenge`] in the
    /// AuthChallenge DO. The browser only ever carries the handle,
    /// never challenge contents.
    ChallengeHandle
}

define_id! {
    /// A role id referenced by `role_assignments` (RFC 086 lattice).
    RoleId
}

impl TenantId {
    /// The legacy default tenant (`tenant-default`), pre-0.5.0 rows'
    /// home. See [`crate::tenancy::DEFAULT_TENANT_ID`].
    pub fn default_tenant() -> Self {
        Self(crate::tenancy::DEFAULT_TENANT_ID.to_owned())
    }
}

#[cfg(test)]
mod tests;
