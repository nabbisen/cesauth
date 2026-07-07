# RFC 110d — TOTP key status indicator

**Status**: Implemented (v0.74.0)  
**Tier**: P2  
**Size**: Small  
**Target**: v0.74.0  
**Phase**: Safety controls panel gap-fill (RFC 110 follow-up)  
**Refs**: PDF v0.50.1 page 9 "Operations UX: Safety controls" / RFC 110 / `TOTP_SECRET_KEY` env var (cesauth deployment guide)

## Problem

The PDF v0.50.1 page 9 "Safety controls" panel lists "TOTP key status"
as one of four operator-facing indicators. RFC 110's v0.72.0 audit
recorded this as a gap; v0.74.0 ships the indicator.

## Design

Same shape as RFC 110b (Turnstile indicator) — boolean only, never the
secret material:

```
worker handler
  └─ env.var("TOTP_SECRET_KEY").is_ok() → bool
       └─ SafetyControlsReport::totp_key_configured
              └─ ui::admin::safety_page → <span class="badge ok|critical">
```

### Secret-leakage invariant

Identical to RFC 110b. The same pin
(`safety_page_never_exposes_secret_material`) guards both env-var
names. A regression in either gap-fill flips the pin.

## Implementation

- Added field `totp_key_configured: bool` to `SafetyControlsReport`.
- Worker handler populates via the env-var check (env-blocked
  verification, mechanical change).
- UI renderer emits the badge.

## Acceptance

- [x] `cargo-1.91 test --workspace --lib` green
- [x] `safety_page_shows_totp_key_indicator` passes
- [x] `safety_page_never_exposes_secret_material` passes (env-var name
      not leaked)
- [x] No production warnings

## Migration / compatibility

Same as RFC 110b.

## Open questions

None.
