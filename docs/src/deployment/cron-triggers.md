# Cron Triggers

cesauth uses Cloudflare Workers Cron Triggers for scheduled tasks
that run independently of incoming HTTP requests. As of v0.18.0,
one trigger is registered: the **anonymous-trial retention
sweep** (ADR-004 §Q3). Future scheduled tasks will land in the
same `[triggers]` block; the dispatcher in
`crates/worker/src/lib.rs` branches on `event.cron()` to
multiplex.

## What ships

```toml
# wrangler.toml
[triggers]
crons = ["0 4 * * *"]
```

This block registers one cron expression with Cloudflare. On the
schedule, Cloudflare invokes the worker's `#[event(scheduled)]`
handler. cesauth's handler dispatches to `sweep::run`, which lists
unpromoted anonymous user rows past the 7-day retention window,
emits `EventKind::AnonymousExpired` audit per row, then deletes.

## Why 04:00 UTC

Late enough that the previous day's promotion-flow stragglers
have settled (the 24h token TTL guarantees no live promotion is
in flight against a row that's about to expire). Early enough
that operators in any timezone see the result before their
workday — a sweep that surfaces a problem at 04:00 UTC is
visible to APAC ops by morning standup, EU ops by mid-morning,
US ops by start of day.

The schedule is global. Cron Triggers do not run in a
specific region; Cloudflare's runtime selects the location for
each invocation. cesauth's sweep is region-agnostic — it
operates against D1 which is regional but accessed transparently.

## How to add a new trigger

1. Append the cron expression to the `crons` array.
2. Add a branch in the dispatcher
   (`crates/worker/src/lib.rs::scheduled`) that matches the new
   `event.cron()` value.
3. Implement the handler — usually a new module under
   `crates/worker/src/`.
4. Document it here, in CHANGELOG, and in the operator runbook.

The `event.cron()` returns the literal string from the array
(e.g. `"0 4 * * *"`), so the dispatcher's branches are exact
string matches. Keep them ordered from most-frequent to
least-frequent so common-path matching is fast.

```rust
#[event(scheduled)]
pub async fn scheduled(
    event: ScheduledEvent,
    env:   Env,
    _ctx:  ScheduleContext,
) {
    match event.cron().as_str() {
        "0 4 * * *"     => { sweep::run(&env).await.ok(); }
        "*/15 * * * *"  => { /* future: 15-min metric emit */ }
        other => {
            console_warn!("unknown cron schedule: {other}");
        }
    }
}
```

The `console_warn!` on unknown values is intentional. The most
likely cause is `wrangler.toml` and the dispatcher disagreeing
about a cron string — visible in `wrangler tail` rather than
silently dropped.

## Verifying a trigger fired

Cloudflare's dashboard surfaces invocation history under
**Workers & Pages → cesauth → Settings → Triggers**. Each
scheduled invocation appears with its start time, duration, and
outcome (succeeded / failed).

`wrangler tail --format=pretty` streams scheduled invocations
live. cesauth's sweep emits one summary `Info` line per run:

```
{
  "ts": 1714287000,
  "level": "info",
  "category": "storage",
  "msg": "anonymous sweep complete: 12/12 rows deleted"
}
```

The fraction is *deleted / surveyed*. A discrepancy (`X/Y` where
`X < Y`) means at least one row's delete failed and was logged
at `Warn` — search `wrangler tail` for `"anonymous sweep delete
user_id="` to find the per-row diagnostics.

## Manual invocation for smoke-testing

`wrangler` does not expose a "run scheduled now" button, but two
paths exist:

### Local dev environment

```sh
wrangler dev --test-scheduled
```

In another terminal:

```sh
curl http://localhost:8787/cdn-cgi/handler/scheduled
```

This invokes the scheduled handler against the local Miniflare
runtime. The cron string passed to `event.cron()` is empty in
this mode, so cesauth's dispatcher will hit the `_` arm and
warn. To test a specific branch, temporarily change the match
guard or add a `force_run` env var.

### Production manual fire (use sparingly)

There is no first-class "run now" button. To smoke-test in
production:

1. Edit `wrangler.toml` to fire imminently:
   ```toml
   [triggers]
   crons = ["*/5 * * * *"]   # every 5 minutes
   ```
2. `wrangler deploy`.
3. Wait for the next 5-minute boundary.
4. Verify via `wrangler tail` and the dashboard.
5. **Revert** the schedule and `wrangler deploy` again.

This is best done against staging first. Against a loaded
production deployment, the sweep is best-effort, not
transactional — a partial run leaves the operator with the same
diagnostic state as a normal sweep, but every additional fire
costs CPU and emits audit rows.

## Limits

- **One Workers Paid invocation per fire** — counts toward your
  daily request quota. cesauth's sweep is a few D1 round-trips
  per row plus one R2 write per row; for the expected
  steady-state volume (anonymous trials per day in tens to low
  hundreds) this is negligible.
- **Cron Triggers are best-effort** — Cloudflare aims to fire
  at the scheduled time but may be delayed by several minutes
  under load. Do not design schedules whose correctness depends
  on tight timing.
- **No backfill** — if your worker is offline at the scheduled
  time, the trigger is skipped, not queued. cesauth's sweep is
  idempotent across runs; one missed day means one extra day
  of anonymous-row residence, which the next sweep cleans.

## When NOT to use a Cron Trigger

- **Per-tenant scheduled tasks.** Cron Triggers are per-worker,
  not per-tenant. Use Durable Object alarms for tenant-scoped
  scheduling.
- **Sub-minute granularity.** Cron's smallest interval is one
  minute. For finer scheduling, see DO alarms.
- **Bulk batch processing of large datasets.** Workers have a
  CPU-time limit per invocation. If your task can't reasonably
  finish in the limit, decompose it into smaller chunks each
  triggered by a separate cron entry, or move it off-Worker
  entirely.

## Future scheduled tasks

The ROADMAP `Later` section lists candidates that may earn cron
slots:

- **Operational metric emission** — periodic flush of
  in-memory counters to a metrics endpoint.
- **Refresh-token-family compaction** — pruning expired
  refresh-token-family rows at coarser granularity than the
  per-request cleanup.
- **Audit-log lifecycle** — moving R2 audit objects to
  cold storage on a schedule, if R2's built-in lifecycle rules
  prove insufficient.

None are scheduled. When one ships, the schedule and the
dispatcher branch land together in the same release, and this
chapter is updated.

## See also

- [Pre-flight checklist § F](./preflight.md#f---cron-triggers)
- [Day-2 operations runbook](./runbook.md) — the operator-facing
  view of "did the sweep run, did it sweep what it should".
- [`crates/worker/src/sweep.rs`] — the sweep implementation.
- [Tenancy chapter — Operator runbook](../expert/tenancy.md) —
  the `tenancy.md` runbook section covers diagnostic queries
  for anomalous sweep behavior.
