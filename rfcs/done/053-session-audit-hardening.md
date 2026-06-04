# RFC 053 — Session audit and cleanup hardening

**Status**: Implemented  
**Priority**: P2  
**Size**: Small

- Add session_index_audit tests for the `audit` and `repair` cron passes
- Ensure audit_events.request_id is written for session operations
- Add missing audit EventKind: `SessionCreated`, `SessionExpired`, `MfaVerified`
