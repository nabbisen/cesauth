# RFC 110c — Refresh-token reuse alerts summary

**Status**: Implemented (v0.74.0)  
**Tier**: P2  
**Size**: Small  
**Target**: v0.74.0  
**Phase**: Safety controls panel gap-fill (RFC 110 follow-up)  
**Refs**: PDF v0.50.1 page 9 "Operations UX: Safety controls" / RFC 110 / RFC 9700 §4.14.2 / `crates/worker/src/audit.rs::EventKind::RefreshTokenReuseDetected`

## Problem

The PDF v0.50.1 page 9 "Safety controls" panel lists "Refresh reuse
alerts" as one of four operator-facing indicators. RFC 110's v0.72.0
audit recorded that the `RefreshTokenReuseDetected` audit event is
emitted on detection (RFC 9700 §4.14.2 telemetry) but not summarised
anywhere in the admin console — operators had to query the audit log
directly. v0.74.0 ships the summary.

## Design

A bounded count of recent reuse events. The window is 24h —
operator-attention-grabbing if non-zero (refresh reuse means either a
session got stolen or replayed), short enough to be SQL-cheap.

### Data flow

```
audit_events (D1)
  └─ kind = "refresh_token_reuse_detected"
       └─ AuditEventRepository::search(kind, since=now-86400, limit=1000)
              └─ count_refresh_reuse_since(repo, now-86400) → u64
                     └─ SafetyControlsReport::refresh_reuse_count_24h
                            └─ ui::admin::safety_page → "0 (clean)" or "N in 24h"
```

The service helper `count_refresh_reuse_since` is in
`crates/core/src/admin/service/safety_controls.rs`. The 1000-row soft
cap is documented as "if you ever exceed this, the alert itself is the
signal" — at that scale the operator needs to be on the runbook, not
counting rows.

### Rendering

- `count == 0`: `<span class="badge ok">0 (clean)</span>`
- `count >= 1`: `<span class="badge critical">N in 24h</span>`

There's no middle ground — any reuse detection is operator-attention.

## Implementation

- Added field `refresh_reuse_count_24h: u64` to `SafetyControlsReport`.
- Added `count_refresh_reuse_since(repo, since_unix)` service helper
  (`crates/core/src/admin/service/safety_controls.rs`).
- Added `compute_safety_controls(...)` service helper that composes all
  four indicators into a single `SafetyControlsReport`.
- Worker handler `crates/worker/src/routes/admin/console/safety.rs`
  invokes the service helper with `now_unix`.
- UI renderer `crates/ui/src/admin/safety.rs::render_safety_controls`
  emits the badge.
- 4 host-buildable service tests in `safety_controls.rs::tests`:
  filter-by-kind, lower-bound-inclusive, no-events-zero, window-boundary.

## Acceptance

- [x] `cargo-1.91 test --workspace --lib` green
- [x] `count_refresh_reuse_filters_to_kind_and_window` passes
- [x] `count_refresh_reuse_respects_lower_bound_strictly` passes
- [x] `compute_safety_controls_uses_24h_window` passes
- [x] `safety_page_shows_refresh_reuse_zero_as_clean` passes
- [x] `safety_page_shows_refresh_reuse_count_as_critical` passes
- [x] No production warnings

## Migration / compatibility

- Backward-compatible: same as RFC 110b.
- Service-level helper is fully host-testable (8 tests across kind
  filter, window boundary, zero-result, integration with
  `compute_safety_controls`).
- Cloudflare D1 adapter (`CloudflareAuditEventRepository`) already
  supports `AuditSearch::since` (RFC 109, v0.71.0); no adapter change
  needed.

## Open questions

None.
