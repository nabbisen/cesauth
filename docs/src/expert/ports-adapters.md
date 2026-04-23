# Ports & adapters pattern

cesauth follows the hexagonal architecture pattern: the domain
(`core`) defines operations as traits, and adapters (one in-memory,
one Cloudflare) implement them. This chapter is the canonical
reference for how and why.

## `core` defines the ports

`core` declares trait-based persistence ports in `src/ports/`. Each
port is named after a domain operation, not a storage technology:

- `AuthChallengeStore` — `put`, `peek`, `take`, `bump_magic_link_attempts`
- `RefreshTokenFamilyStore` — `init`, `rotate`, `revoke`, `peek`
- `ActiveSessionStore` — `start`, `touch`, `status`, `revoke`
- `RateLimitStore` — `hit`, `reset`
- `UserRepository`, `ClientRepository`, `AuthenticatorRepository`,
  `GrantRepository`, `SigningKeyRepository`
- `AuditSink`, `CacheStore`

There is no generic "KV-ish trait" or "database-ish trait". Each
trait names what callers actually need. Per the project brief:

> storage は広く抽象化しすぎないこと。汎用ストレージフレームワークを
> 持ち込まないこと。必要な抽象は、read / write / transact / lock /
> serialize / revoke / consume / rotate に限ること。

This is a deliberate trade-off: slightly more code at each adapter
site, in exchange for the D1 vs DO semantic divide being **visible
in the type system**.

## The service layer composes ports

`core/src/service/token.rs` composes ports into multi-step flows the
product exposes — `exchange_code`, `rotate_refresh`. These functions
take their dependencies by generic reference to traits, not by `dyn
Trait`:

```rust
pub async fn exchange_code<C, AC, RF, G, S>(
    clients:  &C,
    codes:    &AC,
    families: &RF,
    grants:   &G,
    signer:   &S,
    /* ... */
) -> Result<TokenResponse, CoreError>
where
    C:  ClientRepository,
    AC: AuthChallengeStore,
    RF: RefreshTokenFamilyStore,
    G:  GrantRepository,
    S:  JwtSigner,
{ /* ... */ }
```

The call graph is statically resolved and the adapter swap happens at
compile time.

## `adapter-test` pins the domain spec

Before touching Cloudflare, the in-memory adapters pin the spec on
the host:

- **Auth codes are single-consumption** → `take` returns `None` the
  second time.
- **Refresh-token reuse burns the family** → `rotate` with a retired
  jti returns `ReusedAndRevoked`; subsequent calls on the same family
  see `AlreadyRevoked`.
- **Rate-limit window rolls** → hits past `window_secs` start a fresh
  count.
- **Email uniqueness is case-insensitive** → `create` with mixed case
  of an existing email returns `Conflict`.

These properties are encoded in `cargo test`. A test failing here
means the domain spec is wrong. A test passing here but failing in
`wrangler dev` means the Cloudflare adapter is wrong. That
separation was the whole point.

## `adapter-cloudflare` owns every Cloudflare dependency

Every `use worker::…` lives in this crate. The four Durable Object
classes (`AuthChallenge`, `RefreshTokenFamily`, `ActiveSession`,
`RateLimit`) and the adapter implementations of each port live here.

The DO state types — `Challenge`, `FamilyState`, `SessionState` —
are **not** defined here; they live in `core::ports::store` so the
in-memory adapter and the production adapter share the exact same
shape. If the two adapters ever serialize a field differently, a
single core-level type change catches both at once.

## Encoding a pitfall: the `d1_int` helper

`wasm_bindgen::JsValue::from(i64)` produces a JavaScript **BigInt**.
D1's `bind()` only accepts `string | number | boolean | ArrayBuffer
| null` — a BigInt fails at bind time with an opaque error. The
worker-rs `D1Type::Integer(i)` internally does `JsValue::from_f64(i
as f64)` to dodge this; our adapter keeps a local helper:

```rust
#[inline]
fn d1_int(v: i64) -> JsValue {
    JsValue::from_f64(v as f64)
}
```

Every `i64.into()` inside `.bind(&[...])` uses `d1_int(...)` instead.
The module preamble documents this; if you add a new INSERT/UPDATE,
reach for the helper.

A companion `run_err` helper logs the D1 error before collapsing
into `PortError::Unavailable` — the enum has no payload, so without
that log the HTTP layer just says "storage error" with no
breadcrumbs:

```rust
#[inline]
fn run_err(context: &'static str, e: worker::Error) -> PortError {
    worker::console_error!("d1 {}: {}", context, e);
    PortError::Unavailable
}
```

## Error model

Ports return `PortResult<T>` where `PortError` is a small enum:

- `NotFound`
- `Conflict`
- `PreconditionFailed(&'static str)`
- `Unavailable`
- `Serialization`

The service layer translates these to `CoreError` variants that map
to OIDC error responses in the HTTP layer. A port never returns an
HTTP status code — that would leak the transport into the domain.
