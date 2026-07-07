# Security-Critical Assurance Audit — v0.80.2

**Status.** Complete. This audit fulfils deliverable §10.1 of the
*Security-Critical Assurance Strategy* architect instruction and is the
basis for RFCs 116–124 (`rfcs/proposed/`).

**Scope.** The authentication and authorization core of cesauth at
v0.80.2: authorization-code lifecycle, refresh-token lifecycle, session
lifecycle, tenant boundary, authorization decision core, secret/token
material handling, audit events, and the web API boundary.

**Method.** Source inspection of `crates/core`, `crates/adapter-test`,
`crates/adapter-cloudflare`, `migrations/`, and `fuzz/`; full host-side
test-suite run (931 tests: 767 core, 133 adapter-test conformance,
31 migration-chain); cross-check against the requirements spec v2
(v0.78.13), the external design v2, and existing RFCs 001–113.

---

## 1. Current security-critical modules

| Area | Module(s) | Storage authority |
|---|---|---|
| Authorization code / parked AR / WebAuthn ceremony / Magic Link OTP / TOTP gate | `core::ports::store::{Challenge, AuthChallengeStore}`, `core::service::token`, `core::oidc::{authorization, pkce}` | AuthChallenge DO (single-threaded; atomic `take`) |
| Refresh token families | `core::ports::store::{FamilyInit, FamilyState, RotateOutcome, RefreshTokenFamilyStore}`, `core::service::token::rotate_refresh` | RefreshTokenFamily DO |
| Sessions | `core::ports::store::{SessionState, SessionStatus, ActiveSessionStore}`, `core::session`, `core::session_index` | ActiveSession DO + D1 session index |
| Tenant boundary | `core::tenancy`, composite FKs in `migrations/0013+`, `core::ports::repo::*Repository` | D1 |
| Authorization decisions | `core::authz::{service::check_permission, types::{Permission, Scope, ScopeRef, RoleAssignment}, scope_covers}` | D1 `role_assignments` |
| Secrets / token material | `core::service::client_auth`, `core::jwt`, `core::totp`, `core::magic_link` | D1 (hashes), wrangler secrets |
| Audit | `core::audit` (hash chain, ADR-010 / RFC 008), chain-verify cron | D1 `audit_events` |
| Web API boundary | `crates/backend` routes, CSRF/CSP/cookie machinery (RFC 006, 011) | — |

## 2. What is already strong (do not re-solve)

1. **Atomic one-time consumption.** `AuthChallengeStore` documents and
   the DO adapter enforces: no `put` overwrite, atomic `take`, expiry =
   absence. The conformance suite in `adapter-test` pins this.
2. **Reuse-hardened rotation (ADR-011).** `RotateOutcome::ReusedAndRevoked
   { reused_jti, was_retired }` with a retired-jti forensic ring;
   family-wide revocation on reuse is atomic inside the DO.
3. **Single authorization entry point.** `authz::check_permission` with
   the `scope_covers` lattice (14 dedicated tests); routes do not
   compute their own permission logic.
4. **Constant-time comparisons.** `util::constant_time_eq_bytes` /
   `_u32` used in PKCE verify, TOTP verify, client-secret verify, and
   preview signing.
5. **Tenant lineage at the schema level.** Composite FKs
   `(tenant_id, X) REFERENCES …(tenant_id, id)`, inline `UNIQUE`
   discipline (v0.78.8/10/11), pinned by 31 migration-chain tests.
6. **Audit hash chain.** SHA-256 row linking with daily cron
   verification and retention re-sealing.
7. **Existing property tests and fuzzing.** `proptest` on redirect-URI
   validation and JWT claims (RFC 003); `cargo-fuzz` target
   `jwt_parse` (RFC 005).

The RFC set therefore concentrates on *type-level* gaps and *generated*
(state-machine / fuzz) testing gaps, not on redesigning storage
semantics that are already correct.

## 3. Identified gaps

### G1 — No domain newtypes anywhere (highest leverage)

`crates/core/src/types.rs` defines `pub type Id = String;`. Every
security-sensitive identifier — tenant, user/subject, client, session,
refresh-token family, jti, challenge handle — is a bare `&str`/`String`.
Consequences observable in current signatures:

```rust
// core/src/authz/service.rs — user_id and permission are adjacent &str
pub async fn check_permission<RA, RR>(…, user_id: &str, permission: &str, …)

// core/src/ports/store.rs — three adjacent &str, all swappable
async fn rotate(&self, family_id: &str, presented_jti: &str, new_jti: &str, …)
```

A transposition at any call site compiles. **Risk: high. → RFC 116.**

### G2 — Repository APIs accept un-scoped lookups

`UserRepository::find_by_id(&self, id: &str)` and
`find_by_email(&self, email: &str)` take no tenant context, although the
spec (§3, §7.1) makes email uniqueness *per-tenant* and the tenant the
topmost partition. Tenant filtering is currently a convention at call
sites, not a property of the port type. **Risk: high. → RFC 119.**

### G3 — No secret-material types

`client_secret: Option<String>` travels as a plain `String`;
`Challenge` (which carries `code_hash`) derives `Debug`; there is no
`RawSecret` / `HashedSecret` / `RedactedSecret` distinction, no
redacting `Debug`, no zeroize-on-drop. Hashing-at-rest is correct, but
nothing in the type system prevents a future log line from printing raw
material. **Risk: medium-high. → RFC 116 (types) + RFC 123 (audit
redaction property).**

### G4 — Validation ordering is by convention in token exchange

`service::token::exchange_code` performs take → bind checks → PKCE
verify → mint in the right order, but nothing structural prevents a
refactor from minting before `pkce::verify`. The order is pinned only
by example-based tests. **Risk: medium. → RFC 117 (typestate pipeline).**

### G5 — `Permission(pub String)` is openly constructible

The public tuple field plus `From<&str>` means any string becomes a
`Permission`; `check_permission` itself takes `permission: &str`.
Catalog membership is not enforced at the type boundary.
**Risk: medium. → RFC 120.**

### G6 — No state-machine property tests for lifecycles

Refresh-family rotation, session start/touch/revoke/expire, and
challenge put/peek/take are tested with hand-written sequences only.
Interleaved operation sequences (e.g. rotate ∥ revoke ∥ reuse) are not
generated. **Risk: medium. → RFC 118, RFC 121.**

### G7 — Fuzz surface is one target

Only `jwt_parse` is fuzzed. Redirect-URI validation, `/token` body
parsing, Magic Link OTP/handle parsing, JWKS parsing, and
`Accept-Language` negotiation are unfuzzed hostile-input boundaries.
**Risk: medium. → RFC 122.**

### G8 — Audit completeness is by convention

Every mutating route is supposed to emit an audit event; nothing
mechanically verifies the route↔EventKind mapping or that no raw secret
reaches an event payload. **Risk: medium. → RFC 123.**

### G9 — RFC hygiene note (non-security)

RFC numbers 114 and 115 are consumed by CHANGELOG-documented work
(workspace restructure; Leptos migration) but have no files under
`rfcs/`. Numbers stay consumed (policy: never reuse); back-filling the
two files is recommended housekeeping, tracked outside this RFC set.

## 4. Risk ranking and category decision (strategy §6)

| # | Target | Gap | Category | RFC |
|---|---|---|---|---|
| 1 | Domain identifier & secret newtypes | G1, G3 | **A — must implement now** | 116 |
| 2 | Authorization-code exchange pipeline | G4 | **A** | 117 |
| 3 | Refresh-family state-machine tests | G6 | **A** | 118 |
| 4 | Tenant-scoped repository APIs | G2 | **B — implement soon** (cross-cutting refactor; sequenced after 116) | 119 |
| 5 | Authorization core sealing + property tests | G5 | **A** (tests) / **B** (sealing) | 120 |
| 6 | Session/challenge state-machine harness | G6 | **B** | 121 |
| 7 | Fuzz expansion | G7 | **B** | 122 |
| 8 | Audit completeness enforcement | G8 | **B** | 123 |
| 9 | Kani / TLA+ pilot | — | **C — pilot only, time-boxed** | 124 |
| — | Verus broadly; Flux as default; typestate for UI; policy engine | — | **D — defer / do not adopt** | (recorded here; no RFC) |

## 5. Recommended sequencing

```
116 ──► 117 ──► 118 ──► 119 ──► 120 ──► 121 ──► 122 ──► 123 ──► 124
types   code    refresh tenant  authz   state-  fuzz    audit   pilot
        flow    family  scope   core    machine
```

116 first because every later RFC consumes its newtypes. 117/118 next:
highest-value lifecycle invariants with smallest blast radius. 119 is
the widest mechanical refactor and benefits from the newtypes being
settled. 124 is strictly optional and must not block anything.

Each RFC is independently shippable; a full `cargo test` pass on
`cesauth-core`, `cesauth-adapter-test`, and `cesauth-migrate-test` is
the gate between steps, per existing project discipline.
