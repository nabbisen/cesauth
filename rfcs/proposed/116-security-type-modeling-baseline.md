# RFC 116 — Security-critical type modeling baseline

**Status.** Proposed
**Tier.** P0 · Category A (strategy §6: must implement now)
**Size.** Large (mechanical, wide)
**Tracks.** Security-Critical Assurance Strategy §5.6, §8 (RFC theme 1);
audit report `docs/src/expert/security-assurance-audit-v0.80.2.md` G1, G3.
**Touches.** `crates/core/src/types.rs` (new `types/ids.rs`,
`types/secret.rs`), `core::ports::{repo, store}`, `core::authz`,
`core::service::*`, call sites in `crates/backend` and adapters.

## 1. Summary

Introduce newtypes with private constructors for every security-sensitive
identifier and for secret material, replacing the current
`pub type Id = String` alias at the security core's boundaries. Identifier
newtypes: `TenantId`, `UserId`, `ClientId`, `SessionId`, `FamilyId`,
`Jti`, `ChallengeHandle`, `RoleId`. Secret newtypes: `RawSecret`,
`HashedSecret`, `RedactedSecret`.

## 2. Motivation

Today three adjacent `&str` parameters in
`RefreshTokenFamilyStore::rotate(family_id, presented_jti, new_jti, …)`
and the `(user_id, permission)` pair in `authz::check_permission` are
freely transposable; the compiler accepts any ordering. Secrets travel
as `String` and ride along in `#[derive(Debug)]` types (`Challenge`,
token-exchange inputs), so one careless `{:?}` in a log line away from
leakage. Newtypes make the mix-up class unrepresentable and make secret
display a compile-visible decision.

## 3. Background

`crates/core/src/types.rs` deliberately chose `pub type Id = String`
("the alias lets us swap representations later"). This RFC is that swap,
limited to the security core. Hashing at rest (Magic Link OTP SHA-256,
client-secret SHA-256, TOTP AES-GCM) is already correct; the gap is
purely type-level confusability and debug-format leakage.

## 4. Target code areas

- `crates/core/src/types/ids.rs` (new) — identifier newtypes.
- `crates/core/src/types/secret.rs` (new) — secret newtypes.
- `crates/core/src/ports/repo.rs`, `ports/store.rs` — trait signatures.
- `crates/core/src/authz/service.rs` — `check_permission` signature.
- `crates/core/src/service/{token, client_auth, revoke, introspect, sessions}.rs`.
- Adapters and `crates/backend` route glue (boundary conversions).

## 5. Security properties / invariants

1. A `TenantId` cannot be passed where a `UserId` is expected (and so on
   for every pair) — enforced by the compiler.
2. A `RawSecret` cannot be persisted: repository/store traits accept
   only `HashedSecret` where a stored credential is written.
3. `Debug`/`Display` of `RawSecret` and `HashedSecret` print a fixed
   redaction marker, never the contents. (`HashedSecret` is not
   *confidential* but redacting it keeps logs free of oracle material.)
4. `RawSecret` zeroizes its buffer on drop.
5. Identifier newtypes are format-validated at construction (UUIDv4
   shape for D1-minted ids; opaque-handle shape for DO handles), so an
   attacker-supplied string enters the core only through a fallible
   smart constructor.

## 6. Non-goals

- No change to wire formats, D1 schema, DO storage encoding, or cookie
  contents. Newtypes serialize transparently (`#[serde(transparent)]`).
- No newtype for *every* string in the codebase — display names,
  slugs, locales, etc. stay `String`.
- No typestate in this RFC (that is RFC 117/118).
- `Id` alias remains for non-security entities (orgs, groups, plans)
  until a follow-up decides otherwise.

## 7. Proposed design

### 7.1 Identifier newtypes

```rust
// crates/core/src/types/ids.rs
macro_rules! define_id {
    ($(#[$doc:meta])* $name:ident, $expected:literal) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Fallible boundary constructor. Validates shape, not existence.
            pub fn parse(s: impl Into<String>) -> Result<Self, IdParseError> { … }
            /// Infallible constructor for values minted by cesauth itself.
            pub(crate) fn mint() -> Self { Self(uuid_v4_string()) }
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl fmt::Debug for $name {           // ids are not secret; full echo
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }
    };
}
define_id!(TenantId, "uuid-or-slug");
define_id!(UserId, "uuid");
define_id!(ClientId, "uuid-or-registered");
define_id!(SessionId, "uuid");
define_id!(FamilyId, "uuid");
define_id!(Jti, "uuid");
define_id!(ChallengeHandle, "base64url-32");
define_id!(RoleId, "uuid-or-catalog");
```

Construction rules: `mint()` is `pub(crate)` — only the core mints ids.
`parse()` is the single entry for attacker-controlled input (route
extractors, cookie bodies, token claims). Validation is shape-only
(length/alphabet), deliberately cheap; existence checks remain the
repositories' job.

### 7.2 Secret newtypes

```rust
// crates/core/src/types/secret.rs
pub struct RawSecret(zeroize::Zeroizing<String>);   // no Clone, no Serialize
pub struct HashedSecret(String);                     // sha256 hex/b64, comparable
pub struct RedactedSecret;                           // display-only placeholder

impl RawSecret {
    pub fn new(s: String) -> Self;                  // takes ownership; caller's copy gone
    pub fn expose(&self) -> &str;                   // the one intentional read point
    pub fn sha256(&self) -> HashedSecret;
}
impl HashedSecret {
    pub fn from_storage(hex: String) -> Self;
    pub fn ct_eq(&self, other: &HashedSecret) -> bool {  // constant time
        crate::util::constant_time_eq_bytes(self.0.as_bytes(), other.0.as_bytes())
    }
}
impl fmt::Debug for RawSecret   { /* "RawSecret(REDACTED)" */ }
impl fmt::Debug for HashedSecret{ /* "HashedSecret(REDACTED)" */ }
```

`RawSecret` intentionally implements neither `Clone` nor
`Serialize`; moving it is the only way to pass it on, which makes
secret flow auditable by grep for `.expose()`.

`ClientRepository::client_secret_hash` returns
`PortResult<Option<HashedSecret>>`; `service::client_auth` compares via
`ct_eq`, eliminating the ad-hoc byte juggling. `Challenge::MagicLink`'s
`code_hash` becomes `HashedSecret`. `PartialEq` is deliberately **not**
derived for `HashedSecret` so the only equality is constant-time.

### 7.3 Boundary conversion pattern

Routes/extractors in `crates/backend` parse raw strings into newtypes at
the edge and pass newtypes inward; the core never sees raw `&str`
identifiers. Adapters unwrap with `as_str()` when binding SQL params or
DO keys. This formalises the DTO→domain conversion the strategy's §9
implementation guidance asks for.

### 7.4 Dependency addition

`zeroize = "1"` (workspace dependency; tiny, no transitive risk). Record
in `DEPENDENCIES.md`.

## 8. Data model impact

None. Serialized forms are `#[serde(transparent)]` strings; D1 schema,
DO payloads, cookies, JWTs unchanged byte-for-byte.

## 9. API impact

None on the wire. Internally every port-trait signature touching a
security identifier or secret changes type; this is a compile-time
breaking change for the workspace, resolved within the same release.

## 10. Testing strategy

- Unit tests per newtype: parse accepts/rejects (property-tested with
  `proptest` string strategies), `Debug` redaction asserted by
  `format!("{:?}", …)` string match, zeroize drop behaviour.
- A compile-fail test (`trybuild` dev-dependency, or a documented
  doc-test with `compile_fail`) demonstrating that swapping `TenantId`
  / `UserId` arguments does not compile.
- Existing 931-test suite must pass unchanged after mechanical
  migration (behaviour-preserving refactor).

## 11. Migration strategy

Phased, by module, each phase compiling green:
1. Land `types/ids.rs` + `types/secret.rs` with tests (additive).
2. Convert `ports/store.rs` traits + adapter-test + adapter-cloudflare.
3. Convert `ports/repo.rs` + adapters.
4. Convert `authz`, `service::*`, then backend route glue.
Bulk edits via Python scripts (project precedent: sed is unreliable on
multi-line signatures).

## 12. Rollout plan

Single minor release. No operator action; no env-var change. CHANGELOG
entry under "Internal hardening". Ships with RFC 116 moved to `done/`.

## 13. Risks and mitigations

- **Churn volume** → mechanical, phase-gated by `cargo check`;
  conformance suite in adapter-test catches semantic drift.
- **WASM size regression** → newtypes are zero-cost wrappers; verify
  against `BUNDLE_SIZE_BUDGET.md` in the backend build.
- **Over-zealous validation breaking legacy ids** (pre-0.5.0 rows in
  the default tenant) → `parse` accepts the documented legacy shapes;
  migration-chain tests extended with a legacy-id fixture.

## 14. Acceptance criteria

1. No `&str`/`String` identifier or secret parameter remains in
   `core::ports`, `core::authz::check_permission`, or
   `core::service::{token, client_auth, revoke, introspect, sessions}`.
2. `format!("{:?}")` of any type containing secret material contains
   `REDACTED` and not the material (test-asserted).
3. `grep -rn "\.expose()" crates/` yields only reviewed sites listed in
   the RFC's closing note.
4. Full host-side suite green; wasm32 `cargo check` green.

## 15. Open questions

- Should `Permission` move here or stay in RFC 120? **Decision:** stays
  in RFC 120 — it is an authorization-core concern with catalog
  semantics, not a plain identifier.
- `ChallengeHandle` vs distinct handle types per challenge kind?
  Deferred; the `Challenge` enum variant already disambiguates kind.
