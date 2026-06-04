# RFC 036 — Audit request_id end-to-end wiring

**Status**: Implemented  
**Priority**: P2 (RFC 015 partial implementation)  
**Size**: Medium (~60 LOC)  
**Depends on**: RFC 015 (request_id type exists)

## Problem

RFC 015 added `RequestId`, `LogConfig.request_id`, and the `audit_events.request_id`
column. However `NewAuditEvent`, `AuditEventRow`, `worker::audit::Event`, and the
D1 INSERT query do not carry `request_id`. The column is always NULL.

## Decision

1. Add `request_id: Option<String>` to `NewAuditEvent` and `AuditEventRow`
2. Update D1 INSERT in `adapter-cloudflare/src/ports/audit.rs` to include the column
3. Thread `request_id` from the per-request `LogConfig` through to each audit event
   emission site in the worker handlers
4. `RequestId::local()` for cron-path audit events (NULL semantics: no inbound request)
