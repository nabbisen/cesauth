# RFC 038 — nodejs_compat removal

**Status**: Implemented  
**Priority**: P2 (ADR-016 follow-through)  
**Size**: Trivial (1 line)  
**Depends on**: RFC 029 (measurement complete)

## Problem

RFC 029 measured 0 diff when removing `nodejs_compat` from `wrangler.toml`.
ADR-016 notes it as a "v0.54.x deletion candidate". It remains, adding
unexplained surface to the deployment config.

## Decision

Remove `compatibility_flags = ["nodejs_compat"]` from `wrangler.toml`.
Add a comment explaining the removal references ADR-016 / RFC 038.
Update `docs/src/expert/nodejs-compat-investigation.md` Results table.
