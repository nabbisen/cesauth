# RFC 110a — Rate limit summary surface (deferred)

**Status**: Proposed (deferred — KV-heavy data source, env-blocked verification needed)  
**Tier**: P2  
**Size**: Medium  
**Target**: v0.75.0+ (contingent on rustup/wasm32 environment availability)  
**Phase**: Safety controls panel gap-fill (RFC 110 follow-up)  
**Refs**: PDF v0.50.1 page 9 "Operations UX: Safety controls" / RFC 110 / `crates/worker/src/auth_brute_force.rs` (KV-backed rate limit bucket source) / `crates/worker/src/token_endpoint.rs` (token-endpoint rate limit)

## Problem

The PDF v0.50.1 page 9 "Safety controls" panel lists "Rate limit
status" as the first of four operator-facing indicators. RFC 110's
v0.72.0 audit recorded this as a gap; v0.74.0 ships 110b/c/d/e but
**defers 110a** because the data source (KV bucket reads from
multiple rate-limit pools) needs wasm32-only Workers KV API and the
current development sandbox cannot compile-verify it.

## Why deferred

cesauth has at least two rate-limit pools today:

- **Auth brute force** (`auth_brute_force.rs`) — per-account login
  attempt throttle, KV-backed sliding window.
- **Token endpoint** (`token_endpoint.rs`) — per-client `/token`
  request throttle.

A meaningful summary needs:

1. Enumerate active KV keys under each pool's prefix (Workers KV
   `list({ prefix })` operation, wasm32-only).
2. Aggregate by "currently throttling" vs "tripped".
3. Surface as
   `SafetyControlsReport::rate_limit_status: Option<RateLimitStatus>`.

The `RateLimitStatus` struct is **already defined** in
`crates/core/src/admin/types.rs` and wired into `SafetyControlsReport`
as `Option<RateLimitStatus>`. The UI renderer in
`crates/ui/src/admin/safety.rs` already handles both cases:

- `Some(status)` → renders "N throttled bucket(s), M tripped client(s)"
- `None` → renders "— (RFC 110a deferred)"

So shipping 110a is a single PR: implement the worker-side KV
enumeration helper, wire it into `safety.rs` handler, populate the
field. The host-side scaffold is in place.

## Design

### Service helper

```rust
// New: crates/core/src/admin/service/safety_controls.rs (or sibling)
pub async fn compute_rate_limit_status<K: KvBucketSource>(
    kv: &K,
) -> PortResult<RateLimitStatus>;
```

Where `KvBucketSource` is a new port:

```rust
// crates/core/src/admin/ports.rs
pub trait KvBucketSource {
    /// Enumerate buckets currently in a "throttled" or "tripped" state
    /// across all rate-limit pools (auth brute force + token endpoint).
    async fn count_active(&self) -> PortResult<(u32, u32)>;  // (throttled, tripped)
}
```

### Cloudflare adapter

Implements `KvBucketSource` by calling Workers KV `list({ prefix })`
across the two known pool prefixes
(`brute_force:` and `token_rl:`).

### Worker handler

```rust
let rate_limit_kv = CloudflareKvBucketSource::new(&ctx.env);
let rate_limit   = compute_rate_limit_status(&rate_limit_kv).await.ok();
let controls = SafetyControlsReport {
    rate_limit_status: rate_limit,  // Some(status) instead of None
    ..compute_safety_controls(/* … */).await?
};
```

## Acceptance

- [ ] `cargo-1.91 build --workspace --target wasm32-unknown-unknown --release` succeeds
- [ ] `safety_page_does_not_yet_show_rate_limit_status` pin is flipped
      to a positive assertion (replaces the "RFC 110a deferred" check
      with a positive count assertion)
- [ ] Adapter-test stub `InMemoryKvBucketSource` for host-side
      service unit tests
- [ ] No production warnings

## Open questions

- **Q1**: Are there other rate-limit pools beyond `brute_force` and
  `token_rl`? Quick audit of `crates/worker/src/` needed before
  implementation to ensure the summary is comprehensive.
- **Q2**: Should the indicator surface per-pool counts (auth vs
  token), or just the aggregate? Aggregate keeps the panel scannable;
  per-pool can land in a follow-up "drill in" affordance.
