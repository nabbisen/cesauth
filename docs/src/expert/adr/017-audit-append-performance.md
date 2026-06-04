# ADR-017: Audit append performance — Path A (accept + measure)

**Status**: Accepted  
**RFC**: RFC 014  
**Date**: 2026-05-xx  

## Context

cesauth's audit log is hash-chained (ADR-010).  Every `audit_events` append
requires a read-tail → compute-hash → INSERT sequence.  Under high-rate
audit events (e.g. `/introspect` at 600 req/min per client) concurrent
appends can collide on the `seq` UNIQUE constraint, requiring retries.

The current implementation retries up to `APPEND_RETRY_BUDGET = 3` times.

## Decision

**Path A: accept the current design, add latency telemetry.**

For v0.50.x–v0.53.x, accept the retry-based approach and instrument it:

- Log a `console_warn!` when append latency exceeds 100ms or retries > 0.
- Document the approximate ceiling (~100 events/second sustained).
- Defer redesign to RFC 014 follow-up when telemetry shows the ceiling is hit.

**Path B (Durable-Object-serialized append)** is the preferred future path
when Path A telemetry triggers.  ADR-017 will be updated when Path B is
implemented.

## Rationale

- No known deployment has hit the ceiling as of v0.52.x.
- v0.43.0's introspection rate limit (default 600/min) caps the worst case.
- v0.48.0's audit retention keeps table size bounded.
- The instrumentation provides the signal to trigger Path B at the right time.

## Audit-append ceiling (approximate)

| Mode | Sustained rate | Notes |
|---|---|---|
| No concurrency | ~300 events/s | D1 serialized single-writer |
| Low concurrency (2-4 workers) | ~100 events/s | Retry overhead starts |
| High concurrency (10+ workers) | ~30 events/s | Retry storms degrade p95 |

These are order-of-magnitude estimates; actual numbers depend on D1 edge
latency and table size.  The telemetry warning (`latency_ms > 100`) triggers
well before the ceiling is reached.

## Path B design (deferred)

If telemetry confirms contention, the follow-up RFC will implement:

1. A `AuditChainDO` Durable Object that serializes all appends.
2. The DO maintains the current tail hash in memory; appends are sequential
   within the DO.
3. The hash chain (ADR-010) remains intact — chain walks still read from D1;
   only the write path changes.
4. Migration: drain the old D1-direct path over one release window, then
   switch.

The `chain_hash` invariant (ADR-010) is the constraint that prevents naive
solutions (queue-based async appends could reorder events).

## Consequences

- `CloudflareAuditEventRepository::append` emits a `console_warn` on slow
  or retried appends.
- `docs/src/deployment/day-2-runbook.md` gains a detection/mitigation entry.
- Operators with high-introspection deployments should watch for the warning.
