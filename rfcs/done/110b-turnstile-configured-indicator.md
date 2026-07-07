# RFC 110b — Turnstile configured indicator

**Status**: Implemented (v0.74.0)  
**Tier**: P2  
**Size**: Small  
**Target**: v0.74.0  
**Phase**: Safety controls panel gap-fill (RFC 110 follow-up)  
**Refs**: PDF v0.50.1 page 9 "Operations UX: Safety controls" / RFC 110 / `crates/worker/src/turnstile.rs::TurnstileConfig::is_configured`

## Problem

The PDF v0.50.1 page 9 "Safety controls" panel lists "Turnstile
configured" as one of four operator-facing indicators. RFC 110's
v0.72.0 audit recorded this as a gap; v0.74.0 ships the indicator.

## Design

Boolean indicator only — never the secret bytes. The worker handler
checks `env.var("TURNSTILE_SECRET_KEY")` and forwards a `bool` through
`SafetyControlsReport::turnstile_configured`. The UI renders an OK or
MISSING badge.

### Data flow

```
worker handler
  └─ env.var("TURNSTILE_SECRET_KEY").is_ok() → bool
       └─ SafetyControlsReport::turnstile_configured
              └─ ui::admin::safety_page → <span class="badge ok|critical">
```

### Secret-leakage invariant

The forward-looking pin
`crates/ui/src/admin/tests.rs::rfc_110::safety_page_never_exposes_secret_material`
(introduced in v0.72.0) asserts neither the secret bytes nor the env-var
name itself ever appear in rendered HTML. v0.74.0 extends the pin to
also check `TURNSTILE_SECRET_KEY` as a string sentinel — even the env-var
name is privileged information that doesn't need to surface.

## Implementation

- Added field `turnstile_configured: bool` to `SafetyControlsReport`
  (`crates/core/src/admin/types.rs`).
- Worker handler `crates/worker/src/routes/admin/console/safety.rs`
  populates it via the `env.var` check.
- UI renderer `crates/ui/src/admin/safety.rs::render_safety_controls`
  emits the `configured` / `MISSING` badge.

## Acceptance

- [x] `cargo-1.91 test --workspace --lib` green
- [x] `safety_page_shows_turnstile_indicator_when_configured` passes
- [x] `safety_page_shows_turnstile_missing_when_not_configured` passes
- [x] `safety_page_never_exposes_secret_material` still passes (env-var
      name not leaked)
- [x] No production warnings

## Migration / compatibility

- Backward-compatible: `safety_page` gains an `Option<&SafetyControlsReport>`
  parameter; callers passing `None` get the v0.73.0 behaviour (page
  shows only the Data Safety Dashboard, no Safety controls section).
- Worker handler verification is wasm32-blocked in the v0.74.0
  release sandbox; the env-var lookup is a 3-line straight-pipe and
  will be checked by CI once an environment with rustup/wasm32 is
  available.

## Open questions

None.
