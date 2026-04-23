# Architecture overview

This chapter captures *why* cesauth is structured the way it is. If
you want a tour of what each crate does, jump to [Crate
layout](./crate-layout.md). For storage-specific rationale, see
[Storage responsibilities](./storage.md).

## Layering

```
                    ┌──────────────────────────────┐
  HTTP requests →   │        crates/worker         │   cdylib (WASM)
                    │  routes + bindings + glue    │
                    └──────────────┬───────────────┘
                                   │
                ┌──────────────────┴──────────────────┐
                │                                     │
         ┌──────▼───────┐                   ┌─────────▼──────────┐
         │ cesauth-core │                   │  cesauth-adapter-  │
         │              │                   │      cloudflare    │
         │  • domain    │  implements ports │  (Durable Objects, │
         │  • services  │ ◄─────────────────│    D1, KV, R2)     │
         │  • ports     │                   │                    │
         └──────▲───────┘                   └────────────────────┘
                │
                │ implements ports
                │
         ┌──────┴──────────────┐
         │ cesauth-adapter-test│   in-memory, host-side tests
         └─────────────────────┘
```

## The constraint that drove the split

The project brief had one unusual constraint: *Cloudflare-native, but
`core` must be Cloudflare-independent*. That rules out the obvious
approach of shoving service logic directly into `worker` route
handlers. Instead `core` defines domain operations as trait-based
ports, and adapters — one Cloudflare, one in-memory — implement them.
The service layer composes ports to express multi-step flows.

A full-width expansion of this reasoning lives in [Ports &
adapters](./ports-adapters.md). The short version: the D1
(eventual-consistency-friendly CRUD) vs DO (per-key serialized state
machines) semantic divide must be **visible** in the type system. A
single `KeyValueStore` trait would smuggle the weaker guarantee across
the boundary.

## `worker` is thin by design

No business logic lives in a route handler. A route does four things:

1. Parse the request (query string, form body, headers).
2. Build adapters by borrowing `&Env`.
3. Call a `core::service::*` function.
4. Map `Result<_, CoreError>` to HTTP via `error::oauth_error_response`.

If a route handler is tempted to write a non-trivial `if`, that
condition belongs in `core`. The rule keeps the HTTP layer boring
and the domain layer testable on a plain host toolchain.

## Build targets

- **Host target (default members).** `core`, `adapter-test`, `ui`
  build and test on a plain host Rust toolchain. This is the
  iteration loop:

  ```sh
  cargo check
  cargo test
  ```

  These three crates deliberately avoid any `use worker::*` so that
  iteration does not require a WASM toolchain.

- **Cloudflare target.** `adapter-cloudflare` and `worker` target
  `wasm32-unknown-unknown`. The full workspace shares `edition =
  "2024"` and `rust-version = "1.85"`.

- **`worker-build` and virtual manifests.** The workspace root is a
  virtual manifest (`[workspace]` only, no `[package]`).
  `worker-build` rejects virtual manifests with `missing field
  'package'`, so `wrangler.toml`'s build command points it at the
  cdylib crate explicitly:

  ```toml
  main = "crates/worker/build/worker/shim.mjs"

  [build]
  command = "cargo install -q worker-build && worker-build --release crates/worker"
  ```

  Output lands at `crates/worker/build/worker/`. `build/` is in
  `.gitignore` unanchored, so the nested path is covered.

## Testing strategy

**Host (fast, deterministic):**
- `core` unit tests: pure functions (PKCE vector, OTP round-trip,
  scope restriction, HTML escape).
- `adapter-test` integration tests: port contracts against the
  in-memory impls — single-consumption, reuse-burns-family, window
  rolls, case-insensitive email uniqueness.

**Cloudflare (slow, for wiring verification):**
- `wrangler dev` smoke tests against real DO + D1 bindings, asserting
  adapter impls match the in-memory contract under Cloudflare's
  actual consistency model.

Every domain-level property is encoded as a host test. The wrangler
tests only validate the bridge. That separation is what makes a
five-minute host iteration loop possible even though the production
surface runs on WASM.
