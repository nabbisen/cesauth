# RFC 014: Audit append performance — D1 contention under high-rate events

**Status**: Ready
**ROADMAP**: External codebase review v0.50.1 — P2 audit-append D1 contention
**ADR**: This RFC produces ADR-017 if a redesign (Path B) is chosen; Path A documents the trade-off and accepts current design with telemetry instrumentation
**Severity**: **P2 — performance / scalability; ship after operational telemetry confirms it's a real problem**
**Estimated scope**: Path A (acceptance + telemetry) is small; Path B (DO-serialized append) is medium-large with hash-chain integrity preservation
**Source**: External Rust+Cloudflare codebase review attached to v0.50.1 conversation, citing `crates/adapter-cloudflare/src/ports/audit.rs` read-tail-then-INSERT-with-retry pattern.

## Background

cesauth's audit log is hash-chained (ADR-010).
Every audit write requires:

1. Read the current tail row (for `chain_hash` of
   the predecessor).
2. Compute the new row's `chain_hash` from
   predecessor + payload.
3. INSERT the new row.

If two writes race, both read the same tail, both
compute the same `chain_hash`, both attempt to
INSERT — and one will conflict on `seq` uniqueness.
The current implementation retries up to
`APPEND_RETRY_BUDGET` times.

```rust
// crates/adapter-cloudflare/src/ports/audit.rs
for _attempt in 0..APPEND_RETRY_BUDGET {
    let tail = db.prepare(
        "SELECT ... FROM audit_events ORDER BY seq DESC LIMIT 1"
    ).first().await?;
    let (next_seq, prev_hash) = ...;
    let chain_hash = compute_chain_hash(...);
    match insert.run().await {
        Ok(_) => return Ok(...),
        Err(_) => continue,
    }
}
```

D1 is **single-database serialized**. Every audit
write contends on the same database. SELECT(tail)
→ INSERT is inherently a read-then-write; it can't
be batched. Under high event volume, retry storms
worsen tail latency.

### Why this isn't P0

- cesauth has not yet shipped to a deployment
  volume where this fails.
- v0.43.0's per-client introspection rate-limit
  (default 600/min) caps the worst case.
- v0.48.0's retention keeps the table itself
  small.
- The contention is a future scaling issue that
  audit-heavy `/introspect` will hit first.

The reviewer's framing: "high負荷時の安定性大" —
meaningful at high load, not currently a blocker.

### Trade-off survey

| Path | Trade-off |
|---|---|
| **A. Accept current design** | Simple; works at current scale; documents the ceiling |
| **B. Serialize via Durable Object** | Strong consistency preserved; chain still walkable; bottleneck moves to one DO instance per chain |
| **C. Async via Queue** | Decouples request latency from D1 contention; weakens chain (ordering across multiple workers becomes the queue's problem) |
| **D. Per-tenant chains** | Spreads load across chains; complicates retention and verification |

The default for v0.50.x is **Path A with
operational telemetry** so cesauth can measure
when Path B becomes necessary.

## Requirements

1. cesauth MUST measure audit-append latency in
   production via operational logging.
2. The measurement MUST surface tail-latency p95 /
   p99 and retry rate, exposed via the existing
   `log::emit` channel for Logpush forwarding.
3. cesauth MUST document the audit-append
   ceiling — approximate maximum sustained write
   rate before contention degrades user-perceived
   latency.
4. If a redesign is chosen, chain integrity
   (ADR-010) MUST remain unbroken.

## Design — Path A (accept + measure)

For v0.50.x, accept the current design and add
observability. Defer redesign to a future RFC
when telemetry shows the ceiling is hit.

### Step 1 — Append-latency telemetry

Instrument
`CloudflareAuditEventRepository::append`:

```rust
async fn append(&self, ev: &NewAuditEvent<'_>) -> PortResult<AuditEventRow> {
    let start = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let mut retries = 0u32;

    for _attempt in 0..APPEND_RETRY_BUDGET {
        // ... existing logic ...
        match insert.run().await {
            Ok(_) => {
                let duration_ms = ((OffsetDateTime::now_utc().unix_timestamp_nanos() - start) / 1_000_000) as u64;
                if duration_ms > 100 || retries > 0 {
                    worker::console_warn!(
                        "audit_append latency_ms={duration_ms} retries={retries} kind={:?}",
                        ev.kind,
                    );
                }
                return Ok(...);
            }
            Err(_) => {
                retries += 1;
                continue;
            }
        }
    }
    Err(...)
}
```

100ms threshold triggers surfacing. Healthy
appends complete in 10-30ms; past 100ms indicates
contention.

The warning carries `kind`, `latency_ms`, and
`retries` — never payload contents (RFC 008
invariant).

### Step 2 — Operator runbook entry

`docs/src/deployment/day-2-runbook.md`:

```markdown
## Operation: detecting audit-append contention

### Symptom

Logpush queries surface `audit_append latency_ms=...
retries=...` warnings at increasing rate.

### Diagnosis

| Pattern | Likely cause |
|---|---|
| `latency_ms > 100, retries = 0` | D1 transient slowness, not contention |
| `retries > 0` consistently | Concurrent appends racing |
| `latency_ms > 1000` repeatedly | Hitting D1 serialization ceiling |

### Mitigation

Short-term:
- Reduce `INTROSPECTION_RATE_LIMIT_THRESHOLD` (ADR-014)
- Reduce `AUDIT_RETENTION_DAYS` to shrink table

Medium-term:
- Migrate to Path B audit-append redesign
  (RFC 014 follow-up + ADR-017)
```

### Step 3 — Append ceiling documentation

`docs/src/deployment/operational-envelope.md`
(coordinates with RFC 013):

```markdown
## Audit-append ceiling

cesauth's audit log is hash-chained (ADR-010).
Appends are serialized through D1's single-
database write path. Approximate ceiling:

- **Sustained**: ~100 audit events per second
- **Burst**: ~500 events per second (retry budget
  absorbs spikes up to ~5 seconds)

Beyond this, appends start to queue and tail
latency grows.

### Per-event-kind contribution

Dominant kind in production is `TokenIntrospected`
(one per `/introspect` call). At 100 events/sec,
that's 6000 introspections/min total — aligning
with per-client rate-limit default (600/min × 10
clients).

Operators with higher `/introspect` rates should
increase rate-limit window or reduce threshold to
stay within the audit-append ceiling.
```

## Design — Path B (DO-serialized append, deferred)

If telemetry shows the ceiling has been hit,
move audit-append into a Durable Object owning
the chain head:

```
Worker request → AuditChainHead DO → D1 INSERT
                 (single instance,
                  holds chain_hash in memory)
```

The DO's single-threaded execution removes the
read-tail race. The chain is still in D1 (still
queryable, still verifiable by
`audit_chain_cron`). Append latency drops to "one
D1 INSERT" — no SELECT round-trip.

**Cost**: an additional DO instance. Bottleneck
moves from D1 to the DO instance. A single DO
sustains ~1000 RPS on Cloudflare's documented
performance envelope — 10× headroom over Path A.

**Failure modes**:
- DO cold-start adds ~50ms latency to first
  append after idle. Mitigate via existing
  keep-alive pattern.
- DO eviction loses no data (chain head re-reads
  tail from D1 on restart). In-memory hash cache
  rebuilds; first-append-after-eviction is
  slower.
- Cross-region writes traverse network to the
  DO's region. Acceptable since audit is
  non-blocking (handlers `.ok()` audit failures).

**Hash-chain preservation**: DO reads D1 tail on
start, maintains running `chain_hash` in memory.
Appends update memory + D1 atomically per
DO request. v0.48.0 retention pruning still
works — retention prunes `audit_events`; the DO's
in-memory hash is unaffected.

**Migration**: rolling-deploy swap of
`AuditEventRepository` impl from `D1AppendRepo`
to `DoAppendRepo`. No schema change. No wire
change.

**Why Path B over C/D**:
- Path C (async via Queue) weakens the hash chain
  — order depends on consumer scheduling, weaker
  than DO's strict serialization.
- Path D (per-tenant chains) complicates
  retention (each chain has its own anchor) and
  verification. Useful only for many-tenant
  high-volume deployments — not cesauth's primary
  shape.

## Test plan — Path A

1. **`audit_append_emits_high_latency_warning`**
   — pin warning emission when latency > 100ms.
   Stub time source.
2. **`audit_append_emits_retry_warning`** — pin
   when `retries > 0`.
3. **`audit_append_does_not_warn_on_fast_path`**
   — pin: <100ms, 0 retries → no warning.
4. **Telemetry validation** — load test (separate
   effort, not CI) confirms warnings surface.

## Test plan — Path B (deferred)

5. **`do_audit_append_serializes_concurrent_writes`**
   — pin no-race property.
6. **`do_audit_append_chain_walkable_across_evictions`**
   — pin chain integrity across DO cold-starts.
7. **Migration test** — D1AppendRepo → DoAppendRepo
   migration preserves sequence + hash chain
   continuity.
8. **`audit_chain_cron::verify_chain` succeeds
   post-migration** — pin verifier still walks
   correctly.

## Security considerations

**Path A**:

- Telemetry MUST NOT log audit payload (RFC 008
  invariant) — only `kind`, `latency_ms`,
  `retries`. Confirm in test plan.
- High-latency warnings give operators a
  side-channel about traffic shape. Acceptable —
  operators are trusted.

**Path B (deferred)**:

- DO single-instance is a single-point-of-failure
  for audit. If DO unavailable, appends fail. The
  audit module's `.ok()` discard pattern
  preserves request flow — no security regression
  vs current D1 path.
- DO compromise gives an attacker ability to
  insert audit rows with chosen `chain_hash`.
  ADR-010 hash-chain integrity detects this on
  next `audit_chain_cron::verify_chain` — same
  detection surface as compromised D1 access.

## Open questions

**Telemetry threshold to trigger Path B?**
Tentative: sustained 30-day p95 audit-append
latency > 100ms, OR retry rate > 5%. Operationally
measurable via Logpush queries.

**ADR-017 to write?** Yes, when Path B is chosen.
ADR-017 documents the DO-serialized append
decision, chain-integrity preservation argument,
migration mechanics.

**Does Path B's DO need replication for HA?** No.
Cloudflare manages DO instances; failover is
automatic. Audit-append availability tracks DO
platform availability — same as every other DO
in cesauth.

## Implementation order — Path A

1. **PR 1** — Telemetry instrumentation. ~30 LOC
   + 3 tests.
2. **PR 2** — Operator runbook + envelope chapter
   updates (coordinate with RFC 013). ~150 LOC of
   prose.
3. **PR 3** — CHANGELOG + release.

## Implementation order — Path B (deferred)

When telemetry triggers:

1. **ADR-017 draft**.
2. **PR 1** — `AuditChainHead` DO class.
3. **PR 2** — `DoAppendRepo` adapter.
4. **PR 3** — Migration: switch repo binding,
   verify chain post-cutover.
5. **PR 4** — ADR-017 graduates to Accepted.

## Notes for the implementer

- Path A is "do nothing yet, measure". The work
  is observability + ops doc, not redesign.
  Cheap to ship.
- Path B is real work but well-bounded — single
  new DO class, single new repo adapter,
  mechanical migration. Don't pre-build it; wait
  for telemetry.
- The "ceiling" estimate (100/s sustained,
  500/s burst) is from the reviewer's static
  analysis, not measurement. First telemetry run
  revises the estimate. Document as
  "approximate" until measured.
- Coordinate with RFC 013 (operational envelope)
  on the per-request budget table — audit-append
  cost per request is a row in that table.
