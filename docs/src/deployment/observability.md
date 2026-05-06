# Observability

cesauth ships three observability surfaces: **structured logs**
(via `wrangler tail` and Cloudflare's log push), **the audit
trail** (per-event records in R2), and **Cloudflare's built-in
metrics** (request rates, error rates, latency from the
dashboard). This chapter is about getting useful signal from
each.

cesauth does NOT ship Prometheus exporters, OpenTelemetry
instrumentation, or other custom metrics infrastructure as of
v0.5.x. The Workers runtime makes those non-trivial; if you
need them, see "Operational metric emission" in the ROADMAP.

## Structured logs

The log channel in `crates/worker/src/log.rs` emits JSON lines
(`console.log` from a Worker is captured by `wrangler tail` and
Logpush). Each line carries:

| Field | Meaning |
|---|---|
| `ts` | Unix seconds. |
| `level` | `trace` / `debug` / `info` / `warn` / `error`. |
| `category` | One of: `Auth`, `Session`, `Crypto`, `Storage`, `RateLimit`, `Csrf`, `Router`, `Config`, `Audit`. |
| `msg` | Human-readable description. |
| `subject` | Optional user/session ID for correlation. |

The `LOG_LEVEL` `[var]` filters out lines below the threshold:
`info` (default) drops `debug` and `trace`. The
`LOG_EMIT_SENSITIVE` flag gates the `Auth`, `Session`, and
`Crypto` categories — these may carry user IDs or credential
IDs, so they're suppressed by default in production.

### Tailing live

```sh
wrangler tail --env production --format=pretty
```

Filter by category in your shell:

```sh
wrangler tail --env production --format=json \
  | jq 'select(.category == "Storage")'
```

Filter by subject for incident response:

```sh
wrangler tail --env production --format=json \
  | jq 'select(.subject == "u-7K9F2L")'
```

`wrangler tail` is real-time only — it streams from the moment
you connect. For historical logs, use Logpush.

### Logpush — historical retention

Cloudflare Logpush ships Worker logs to S3 / GCS / Datadog /
Splunk / etc. on a continuous basis. Configure it from the
Cloudflare dashboard: **Workers & Pages → cesauth → Settings
→ Observability → Logpush**.

Without Logpush, logs are retained for ~24 hours in
Cloudflare's tail buffer. With Logpush, they're retained
wherever you ship them.

For incident response, **Logpush is non-optional in
production** — a 3am incident can't wait until business hours
to ask Cloudflare support for log access.

### Useful queries

In your downstream log destination, the queries that earn
their keep are:

**Auth failures spiking:**
```
level=warn AND category=Auth AND msg=*token_invalid* | count by minute
```

**Rate-limit escalations (Turnstile triggered):**
```
category=RateLimit AND msg=*escalate*
```

**One specific user's session activity:**
```
category=Session AND subject="u-7K9F2L"
```

**Sweep ran (or didn't) yesterday:**
```
category=Storage AND msg=*"anonymous sweep"*
  AND ts > yesterday_04_00 AND ts < yesterday_04_30
```

**Storage errors (D1/R2 failures):**
```
level=error AND category=Storage
```

A production deployment should have alerts on the last query —
storage errors are rare and almost always indicate an upstream
problem (D1 brownout, account-level issue) that needs
investigation.

## The audit trail

The audit trail is a separate observability surface from the
log channel. Logs are operational ("did the request succeed");
audit events are security-relevant ("who did what to whom").

Each audit event is one R2 object with:

| Field | Meaning |
|---|---|
| `kind` | `EventKind` variant — see `crates/worker/src/audit.rs`. |
| `subject` | The user/principal the event is about. |
| `client_id` | The OAuth client involved, if any. |
| `ip` | Source IP (sometimes masked — see ADR-004 §Q5 for the anonymous-sweep case). |
| `reason` | Free-form code with `via=...,...` markers. |
| `ts` | Unix seconds. |

### Querying the audit trail

R2 doesn't have SQL. Query patterns:

1. **Through the admin console** — the
   `/admin/console/audit` page lists recent events with
   filters by kind and subject. Read-only; no SQL flexibility.
2. **Direct R2 list + filter** — list objects, fetch
   matching ones, parse JSON. Slow at scale.
3. **Logpush of audit events** — cesauth doesn't push audit
   events to an external destination today, but the audit
   writer is a single function (`crates/worker/src/audit.rs`)
   easily extended to fan out to a SIEM.

For day-to-day incident response, the admin console works. For
historical compliance queries (months of data, complex
filters), pushing audit events to a SIEM is the answer.

### Useful audit queries

**Who promoted recently?**
```
kind=anonymous_promoted
  AND ts > unixepoch() - 7 * 86400
```

**Failed magic-link verification spike:**
```
kind=magic_link_failed
  AND ts > unixepoch() - 3600
```

**A specific user's activity:**
```
subject="u-7K9F2L"
```

**Admin token use (always worth review):**
```
kind=admin_*
```

The Day-2 operations runbook has more application-specific
queries.

## Cloudflare-native metrics

The Cloudflare dashboard has request-level metrics out of the
box. **Workers & Pages → cesauth → Analytics**:

- **Requests per second**, broken out by status code.
- **CPU time per request** (P50, P99). Workers have a CPU
  ceiling per invocation; trending toward it predicts upcoming
  503s.
- **Subrequests per request** — each D1 query, R2 fetch, KV
  read counts. cesauth's `/authorize` cold path is the
  highest-subrequest endpoint; sustained growth suggests a
  cache miss pattern worth investigating.
- **Errors** by status code. The 4xx breakdown is signal
  about client bugs; the 5xx breakdown is signal about cesauth.

The dashboard retains ~30 days of metrics. For longer
retention, use the Workers Analytics Engine API to push to
your own observability stack.

### Custom Domain analytics

If cesauth is on a Custom Domain, the per-domain analytics
under **Websites → auth.example.com → Analytics** show
edge-perspective request data: cache hit rates, geographic
distribution, threat scores. cesauth doesn't cache much, so
the cache-rate panel is uninformative; the geographic
distribution is occasionally useful for spotting attacks.

## What to alert on

A small alerting set that catches the most-painful failure
modes:

1. **5xx error rate > 1%** for 5+ minutes. Either cesauth has
   an unhandled error path or a storage backend is degraded.
2. **`category=Storage AND level=error`** appearing at all.
   Storage errors are not a normal-traffic event.
3. **CPU time P99 > 80% of the limit** (50ms on Bundled, 30s
   on Unbound — verify your account tier). Predicts upcoming
   timeouts.
4. **Cron Trigger failed to fire** (no `"anonymous sweep"`
   log in the 24h after expected fire time). The sweep
   silently not running is the worst-case observability
   failure.
5. **Audit event volume zero** for an extended period. Either
   no traffic (which you'd notice via the request-rate metric)
   or the audit writer is silently broken.

Cloudflare's built-in alerting (**Notifications** in the
dashboard) covers (1) and (3). (2), (4), (5) need your
downstream observability stack.

## What NOT to obsess over

- **Per-request latency**, except at high P99. cesauth is
  doing work the user has to wait for — a 200ms `/authorize`
  is normal and not worth optimizing without a specific
  user-visible problem.
- **D1 query count.** Workers run on a per-request CPU budget,
  not a per-DB-query budget. As long as CPU time is fine,
  query count is fine.
- **R2 object count.** R2's pricing is per-object-month; the
  audit log grows inexorably and that's the design. Lifecycle
  rules manage cost.

## See also

- [Operational logging](../expert/logging.md) — the developer-
  facing view of `crates/worker/src/log.rs`: categories, levels,
  and what each is for.
- [Day-2 operations runbook](./runbook.md) — what to actually
  do when an alert fires.
- [Disaster recovery](./disaster-recovery.md) — when the
  observability surfaces themselves are the problem.
