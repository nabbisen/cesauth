# Crate layout

cesauth is a five-crate Cargo workspace. Each crate has a single
responsibility and a clear build target.

```
cesauth/
├── crates/
│   ├── core/              # pure-Rust domain: OIDC, WebAuthn, JWT,
│   │                      # Magic Link, ports (trait definitions)
│   ├── adapter-test/      # in-memory port impls, for host tests
│   ├── adapter-cloudflare/# DO classes + Cloudflare port impls
│   │                      # (D1, DO-RPC, KV, R2)
│   ├── ui/                # accessible HTML templates
│   └── worker/            # cdylib entrypoint: #[event(fetch)],
│                          # router, secrets, audit plumbing
├── migrations/            # D1 schema
├── wrangler.toml
└── Cargo.toml             # virtual workspace manifest
```

| Crate                        | Responsibility                                                    | Build target        |
|------------------------------|-------------------------------------------------------------------|---------------------|
| `cesauth-core`               | OIDC / WebAuthn / JWT / Magic Link domain rules + port traits     | pure Rust, host     |
| `cesauth-adapter-cloudflare` | DO classes + Cloudflare-specific port impls (D1, DO-RPC, KV, R2)  | `wasm32-unknown`    |
| `cesauth-adapter-test`       | In-memory port impls for host-side integration tests              | pure Rust, host     |
| `cesauth-ui`                 | Accessible HTML templates                                         | pure Rust, host     |
| `cesauth-worker`             | `#[event(fetch)]` entrypoint, router, secrets, audit plumbing     | `cdylib` (WASM)     |

## Why five crates and not three

The rough split could have been: pure domain, Cloudflare adapter,
Workers entrypoint. Two things justified the extra boundaries:

- **`adapter-test` is a first-class crate, not a test module.** It
  isolates the in-memory implementations so the contract tests that
  pin the domain spec can be linked from any context — host unit
  tests, future integration tests, documentation examples. Keeping
  them as a crate stops `adapter-cloudflare` from accidentally
  depending on them, which would pull host-only deps into the WASM
  build.

- **`ui` is a first-class crate because templates have design
  constraints.** Accessibility (`aria-live`, semantic headings,
  keyboard focus order), CSP, and CSRF-token rendering are in scope;
  JavaScript interactivity is not. Isolating them means a future
  designer can iterate without touching `worker`.

## Module layout: no `mod.rs`

cesauth uses the Rust 2018+ adjacent-file form consistently. A module
`foo` with submodules lives as:

```
src/
├── foo.rs         ← declares `pub mod bar;` etc.
└── foo/
    ├── bar.rs
    └── baz.rs
```

**Not:**

```
src/
└── foo/
    ├── mod.rs     ← don't do this
    ├── bar.rs
    └── baz.rs
```

Rationale: when opening a module entrypoint, editors and search
tools show `foo.rs` near its siblings rather than burying it as one
of many `mod.rs`. The two forms are otherwise equivalent.

## `core` has no Cloudflare dependency

```
[dependencies]
# core/Cargo.toml — no worker, no wasm-bindgen, no cloudflare-*
serde, serde_json, async-trait, thiserror, base64, ed25519-dalek,
p256, hmac, sha2, jsonwebtoken, url, time, uuid, ...
```

That is not a happy accident. Any `use worker::*` in core would break
host iteration; any `tokio::*` would break the WASM build. The grep
test `rg --files-with-matches 'use worker' crates/core/` should
always come back empty. If it does not, a port boundary has been
skipped.
