# Dependency Upgrade Status

Last audited: 2026-05-21 (v0.80.2)

This document tracks intentionally held dependencies and the conditions
needed to upgrade them.  Run `cargo update --dry-run --verbose` to
regenerate the "Unchanged" list.

---

## Applied in v0.80.1 — v0.80.2

| Crate | Before | After | Notes |
|---|---|---|---|
| `either` | 1.15.0 | 1.16.0 | Minor; patch applied |
| `num-conv` | 0.2.1 | 0.2.2 | Patch applied |
| `pin-project` + internal | 1.1.12 | 1.1.13 | Patch applied |
| `worker` + macros + sys | 0.8.1 | 0.8.3 | Minor; Workers runtime fixes |
| `zerofrom` | 0.1.7 | 0.1.8 | Patch applied |
| `leptos` | =0.8.2 | =0.8.19 | See §Leptos below |
| `leptos_router` | =0.8.2 | =0.8.13 | Separate cadence; highest stable |

---

## Held dependencies

### Leptos (partially resolved)

**Current:** `leptos =0.8.19`, `leptos_router =0.8.13`

The original hold (RFC 115 §2) was due to a reported
`getrandom 0.3` / `uuid 1.18` issue on Workers wasm32 builds in
Leptos 0.8.6+.  The workspace already carries `getrandom 0.4.2` via
`uuid = { features = ["js"] }` in `cesauth-core`, which makes the
`wasm_js` feature available globally (Cargo features are additive).

**Host-side** `cargo check` passes with `leptos =0.8.19`.  The
wasm32/Trunk build still needs end-to-end verification (`trunk build`
against `wasm32-unknown-unknown`).  Until that is done, treat the
pin as unverified for production.

**To upgrade further:** `leptos 0.9.x` is the next major series;
wait for stable release.  No action needed at present.

---

### RustCrypto suite — **BLOCKED** by `ed25519-dalek 2.x`

| Crate | Current | Latest | Blocker |
|---|---|---|---|
| `sha2` | 0.10.9 | 0.11.0 | `ed25519-dalek 2.x` requires `sha2 ^0.10` |
| `sha1` | 0.10.6 | 0.11.0 | Same |
| `hmac` | 0.12.1 | 0.13.0 | Same |
| `crypto-common` | 0.1.6 | 0.1.7 | Same |
| `pkcs8` | 0.10.2 | 0.11.0 | `ed25519-dalek 2.x` requires `pkcs8 ^0.10` |
| `rand_core` | 0.6.4 | 0.10.1 | `ed25519-dalek 2.x` requires `rand_core ^0.6` |

`ed25519-dalek` is the JWT signing library for cesauth's Ed25519 keys.
Version `2.2.0` (current) hard-pins the entire RustCrypto 0.10/0.12
suite.  Version `3.0.0` (pre-release as of 2026-05-21; `3.0.0-pre.7`)
is expected to use the newer crypto series.

**Action:** When `ed25519-dalek 3.0.0` stable ships, upgrade the
entire suite in one batch:

```
ed25519-dalek  2.x → 3.x
sha2           0.10 → 0.11
sha1           0.10 → 0.11
hmac           0.12 → 0.13
crypto-common  0.1  → 0.2
pkcs8          0.10 → 0.11
rand_core      0.6  → 0.10
```

Check the `ed25519-dalek` release notes for API changes in the JWT
signing path (`crates/core/src/oidc/jwt.rs`).

---

### `rusqlite` — major version jump

**Current:** 0.32.1  **Latest:** 0.39.0  (7 major versions behind)

`rusqlite` is used only by `cesauth-migrate-test` (the migration chain
integration test runner).  It is not in the production Workers binary.

**Upgrade path:**
1. Check `rusqlite` 0.39 changelog for API changes.
2. Update `crates/migrate-test/Cargo.toml`.
3. Verify all 31 migration chain tests pass.
4. Ship as an isolated patch.

Low risk because `rusqlite` is test-only, but the gap is large enough
to warrant a dedicated upgrade commit.

---

### `gloo-net` 0.6 → 0.7

**Current:** 0.6.0  **Latest:** 0.7.0

`gloo-net` is the browser HTTP client used by Leptos components
(`crates/frontend/src/pages/`).  Upgrade together with the next Leptos
version bump to avoid mixing gloo-net and leptos minor versions.

---

## How to re-audit

```sh
cargo update --dry-run --verbose 2>&1 | grep -E "Unchanged|Updating"
```

This shows both what would change (Updating) and what is held back
(Unchanged) and why.
