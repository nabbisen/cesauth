# RFC 039 — Docs drift cleanup + drift-scan hardening

**Status**: Implemented  
**Priority**: P1 (misleading operator docs → operational accident)  
**Size**: Small (~20 lines changed + drift-scan patterns)  
**Depends on**: RFC 030

## Problem

Docs still contain references that contradict the current implementation:
- "audit から code を拾う" — OTP is no longer in audit (fixed in prior work)
- `dev-delivery code=...` references as if still in use
- R2 storage references that were removed
- drift-scan deny list does not catch these patterns

## Decision

1. Search and remove/update stale references in `docs/` and code comments
2. Add deny patterns to `scripts/drift-scan.sh`:
   `dev-delivery`, `code=`, `audit.*code`, `MagicLinkPayload.*Debug`
3. Add `MagicLinkPayload` `#[derive(Debug)]` guard — ensure `code` field is
   never present in Debug output (replace with `[REDACTED]`)
