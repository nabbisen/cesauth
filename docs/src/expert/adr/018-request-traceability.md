# ADR-018: Request correlation ID and deliberate absence of a file-writing logger

**Status**: Accepted  
**RFC**: RFC 015  
**Date**: 2026-05-xx  

## Context

The v0.50.1 external review asked whether cesauth's server logging is
adequate for incident response and whether a file-writing logger is needed.

Two related questions:

1. Can a single client request be traced end-to-end through logs and audit?
2. Should cesauth persist log lines to a file (KV, R2, or D1)?

## Decision

### Q1: Correlation ID

**Decision**: Use `cf-ray` as the per-request correlation identifier.

Every log line and audit row emitted during request handling carries a
`request_id` field sourced from the `cf-ray` Cloudflare edge header.  In
local development and cron paths where no `cf-ray` exists, a `local-<uuid>`
fallback is generated.

**Rationale**:

- `cf-ray` is already in Cloudflare's Logpush pipeline and the dashboard; no
  new infrastructure needed.
- The header appears in response headers so clients can capture it on failure
  and report it to operators.
- Not a secret: `cf-ray` is already observable client-side; logging it
  reveals nothing new.

**Consequences**:

- `LogConfig` gains a `request_id: Option<String>` field.
- Every log `Record` includes `request_id` when non-null (skip-if-none keeps
  cron lines compact).
- `audit_events` gains a nullable `request_id TEXT` column (migration 0015).
- Operators can correlate: `request_id` in an audit row → grep logs for the
  same request_id → full context.

### Q2: No file-writing logger

**Decision**: cesauth does NOT and SHOULD NOT write log lines to any
persistent storage (KV, R2, D1, or otherwise).

**Rationale**:

**Platform incompatibility**: Cloudflare Workers has no filesystem.
Persisting logs requires writes to KV, R2, or D1.

**Security posture conflict**: Per-request log persistence would:
- Create a second high-volume write path contending with the audit chain
  append (already discussed in RFC 014).
- Expand the exfiltration surface: log lines at `Debug`/`Trace` include
  internal diagnostics that should be ephemeral.
- Undermine the sensitivity gating already implemented (`LOG_EMIT_SENSITIVE`
  default `0`): persisted sensitive logs would expose data that the gating
  was designed to contain to the operator terminal.

**Existing infrastructure is sufficient**: `console_log!`/`wrangler tail`
captures logs for live debugging; Logpush to R2/S3/Datadog provides
operator-configured persistence with their own retention and access-control
policies.  Building a second log-persistence path inside cesauth duplicates
operator infrastructure concerns that belong outside the authentication
service.

**Audit is the persistence layer**: Security-relevant events are already
recorded in the hash-chained `audit_events` table (ADR-010).  That table is
the permanent record.  Operational logs are transient by design.

**Consequences**:

- Operators who need persistent log history configure Logpush in the
  Cloudflare dashboard.
- cesauth's deployment documentation explicitly states this design decision
  so contributors don't propose file-logger PRs.
- `wrangler tail` is the recommended tool for real-time log access.

## Alternatives considered

### A. KV-backed log buffer

Write recent log lines to a KV key with TTL.  Rejected:
- Adds ~1 KV write per request per log line.
- KV writes are eventually consistent; a failing worker may lose its last
  log lines.
- Adds a new storage dependency to every request, increasing error surface.

### B. Logpush inside the worker (intercepting `console.*`)

Workers cannot intercept `console.*` output before Cloudflare's runtime
captures it.  Rejected as architecturally impossible.

### C. Structured log sink port (like `AuditEventRepository`)

A `LogSink` trait with KV and in-memory adapters.  Rejected for the same
security and complexity reasons as A.  The audit chain already provides
a structured, tamper-evident record for security events.

## Implementation note

The `request_id` field is nullable in `audit_events` (migration 0015):

- `NULL` means "emitted outside a request context" (cron, background).
- A non-null value is the `cf-ray` (production) or `local-<uuid>` (dev).

This is **not** a chain-format change.  The hash chain
(`previous_hash` → `chain_hash`) is unaffected by the new column.
