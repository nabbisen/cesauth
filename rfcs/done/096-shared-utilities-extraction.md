# RFC 096 — Shared utilities extraction

**Status**: Implemented | **Tier**: Refactoring | **Size**: Medium | **Target**: v0.66.0

## Problem

The codebase has accumulated multiple independent implementations of identical
pure functions across crates and modules. Each was added in isolation as new
features came in (RFC 080's ISO-8601 formatter, RFC 090's variant, RFC 074's
preview signature check). The duplicates have drifted slightly in style and
test coverage, increasing maintenance cost and the surface for subtle bugs.

## Concrete duplications found

### 1. `constant_time_eq` — **5 independent implementations**

| Location | Signature | Notes |
|---|---|---|
| `core/src/oidc/pkce.rs:67` | `fn constant_time_eq(a: &[u8], b: &[u8]) -> bool` | private |
| `core/src/admin/preview.rs:271` | `fn constant_time_eq(a: &[u8], b: &[u8]) -> bool` | private |
| `adapter-cloudflare/src/admin/principal_resolver.rs:55` | `fn constant_time_eq(a: &[u8], b: &[u8]) -> bool` | private |
| `worker/src/csrf.rs:86` | `pub fn constant_time_eq(a: &str, b: &str) -> bool` | string variant |
| `core/src/totp.rs:357` | `fn constant_time_eq_u32(a: u32, b: u32) -> bool` | u32 variant |

All four byte/string variants implement the identical xor-accumulate algorithm.

### 2. ISO-8601 formatter — **3 independent implementations**

| Location | Function | Algorithm |
|---|---|---|
| `core/src/admin/service.rs:470` | `format_unix_as_iso8601` + `days_to_ymd` | Gregorian cycles, year ≥ 2000 |
| `worker/src/cron_status.rs:70` | `fmt_unix` + `days_to_ymd` | Identical algorithm, slightly different names |
| `ui/src/admin/audit_chain.rs:155` | `format_unix` | Different approach (`time` crate) |

The `admin/service.rs` and `cron_status.rs` versions are byte-for-byte identical
in algorithm. `audit_chain.rs` uses the `time` crate.

### 3. Test fixtures — **3 independent `test_signer` builders**

| Location | Returns |
|---|---|
| `core/src/jwt/signer.rs:381` | `(JwtSigner, [u8; 32])` |
| `core/src/oidc/id_token.rs:342` | `(JwtSigner, VerifyingKey)` |
| `core/src/service/token/tests.rs:52` | `JwtSigner` |

Each constructs the same PKCS#8 Ed25519 PEM from a fixed seed.

### 4. Inline stub adapters

| Location | Stubs |
|---|---|
| `core/src/authz/tests.rs:21-50` | `StubRoles`, `StubAssignments` (`RefCell` based) |
| `core/src/authz/service.rs:330-360` | `StubAssignments`, `StubRoles` (`Mutex` based) |

Same purpose, different internal mutex choice.

## Proposed solution

Create `crates/core/src/util/` module hierarchy:

```
crates/core/src/util/
├── mod.rs              # re-exports
├── constant_time.rs    # constant_time_eq_bytes, _str, _u32
├── time_iso8601.rs     # format_unix_as_iso8601, days_to_ymd
└── test_helpers.rs     # #[cfg(test)] — test_signer, etc.
```

For worker-specific helpers, add `crates/worker/src/util.rs` re-exporting
core's `time_iso8601` so `cron_status.rs` doesn't reimplement it.

For test stubs that need to be shared between modules within `core`,
collect them in `crates/core/src/authz/test_stubs.rs` gated on `#[cfg(test)]`.

## Acceptance

- Each duplicate fn has exactly one implementation.
- Call sites switch to the shared version (compile error if not).
- Tests still pass.
- No new pub API surface (utilities are `pub(crate)`).

## Out of scope

- Refactoring the `time` crate use in `audit_chain.rs` — it's a separate
  decision whether to standardize on `time` crate or hand-rolled formatters.
