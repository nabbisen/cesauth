# RFC 051 — Add tenant_id to credential tables (data review P2)

**Status**: Implemented  
**Priority**: P2 (data structure review item)  
**Size**: Medium

authenticators, totp_authenticators, totp_recovery_codes, consent, grants — none carry tenant_id directly. This makes tenant-scoped export/import require multi-hop joins and prevents direct tenant boundary validation at the schema layer.

Migration 0020: add tenant_id column to authenticators (and optionally others). Backfill via users JOIN. Add index.
