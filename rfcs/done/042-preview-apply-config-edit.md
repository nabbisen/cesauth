# RFC 042 — Preview-and-apply adoption: config_edit (LOG_LEVEL)

**Status**: Implemented  
**Priority**: P2 (RFC 018 infrastructure has zero adopters)  
**Size**: Small (~60 LOC worker handler change)  
**Depends on**: RFC 018

## Problem

RFC 018 shipped `mint_preview_token`, `verify_preview_token`, `ImpactStatement`,
`preview_body()` — all unused. Dead code in an audited codebase is a signal
problem for reviewers and accumulates maintenance debt.

## Decision

Adopt preview-and-apply for the `LOG_LEVEL` config change in the admin console:

1. `POST /admin/console/config/log_level/preview`:
   - Read current LOG_LEVEL from KV config
   - Compute `log_level_impact(before, after)`
   - Mint preview token
   - Render `preview_body()` in `admin_frame()`

2. `POST /admin/console/config/log_level/apply`:
   - Verify preview token (TTL, CSRF, HMAC)
   - Emit `OperationPreviewed` + `OperationApplied` audit events
   - Write new LOG_LEVEL to KV
   - Redirect with flash

This gives RFC 018 its first live adoption, validates the UX, and documents
the pattern for all future destructive admin operations.
