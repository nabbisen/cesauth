# Observability

cesauth ships three observability surfaces: **structured logs**
(via `wrangler tail` and Cloudflare's log push), **the audit
trail** (a hash-chained D1 table, `audit_events`), and
**Cloudflare's built-in metrics** (request rates, error rates,
latency from the dashboard). This chapter is about getting
useful signal from each.

cesauth does NOT ship Prometheus exporters, OpenTelemetry
instrumentation, or other custom metrics infrastructure as of
v0.5.x. The Workers runtime makes those non-trivial; if you
need them, see "Operational metric emission" in the ROADMAP.

## Structured logs

The log channel in `crates/backend/src/log.rs` emits JSON lines
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

**Storage errors (Durable Object / D1 / KV / R2 failures):**
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

Since **v0.32.0** (ADR-010), audit events are rows in the D1
`audit_events` table, each linked to the previous row by a
SHA-256 hash chain. The full mechanism — chain semantics,
verification, tamper investigation — is documented in
[Audit log hash chain](../expert/audit-log-hash-chain.md); this
section covers only what an operator needs during an incident.

`audit_events` (migration `0008_audit_chain.sql`):

| Field | Meaning |
|---|---|
| `seq` | Monotonic sequence; the chain follows `seq` order. |
| `id` | Public event ID (UUID v4), for log correlation. |
| `ts` | Unix seconds, captured at write time. |
| `kind` | `EventKind` variant, snake-cased — see `crates/backend/src/audit.rs`. |
| `subject` | The user/principal the event is about, if any. |
| `client_id` | The OAuth client involved, if any. |
| `ip` | **Always NULL as the code stands.** The column exists and the writer supports it (`audit.rs:432`, `with_ip`), but that builder method has no callers, and `write_owned` — the helper every call site uses — hardcodes `ip: None` (`audit.rs:500`). Not masked here either; masking, where it happens, is a `reason`-string convention (see below). |
| `user_agent` | **Always NULL as the code stands**, for the same reason as `ip`: `with_user_agent` (`audit.rs:433`) has no callers. |
| `reason` | Free-form code with `via=...,...` markers — e.g. the anonymous-create path (`EventKind::AnonymousCreated`), `via=anonymous-begin,ip=<masked>` (ADR-004 §Q5), masks the IP *inside this string*, not the `ip` column above. |
| `payload` | Canonical JSON event body; the bytes the hash chain covers. |
| `payload_hash`, `previous_hash`, `chain_hash` | Hash-chain fields — see the linked chapter for what each covers. |
| `created_at` | Wall-clock at row insert. |

Do not plan IP or user-agent correlation on this table as it stands: those
two columns are reserved but unwritten. The only IP that reaches the trail
today is the masked value inside the `reason` string of the anonymous-create
event.

Indexed by `idx_audit_events_ts` (time-range queries),
`idx_audit_events_kind_ts` (kind+time), and a partial
`idx_audit_events_subject` (subject lookups) — these are what
make the console's filters, and the `wrangler d1 execute` query
below, fast rather than a full table scan.

### Querying the audit trail

Four routes surface the table:

1. **`/admin/console/audit`** — the admin console's audit
   browser. Filters, per `crates/backend/src/routes/admin/console/audit.rs`:
   `kind` (**substring** match — legacy field), `subject` (**substring**
   match; `actor` is an alias), `event` (**exact** match on kind — the
   RFC 109 dropdown), `from`/`to` (RFC 3339 UTC bounds, inclusive),
   `limit`. `kind`/`subject` being substring rather than exact matters
   during an incident — "subject contains" is a materially broader query
   than "subject is." **An invalid `from`/`to` value is dropped
   silently, not rejected** — the page still renders, unfiltered by that
   bound, with no error shown.
2. **`/admin/console/audit/export`** (`POST`) — exports filtered
   rows as CSV or JSONL for offline analysis. **The export
   itself writes an audit event** — exporting the log is itself
   a logged action, though that write is **best-effort**: if it
   fails, the export still succeeds, unlogged. Exports are also
   **capped at `AUDIT_EXPORT_MAX_ROWS`, default 10,000 rows** — a
   compliance export spanning months of data can silently
   truncate at that limit.
3. **`/admin/console/audit/chain`** (status) and
   **`/admin/console/audit/chain/verify`** (`POST`, on-demand
   full re-verify) — chain integrity. A daily cron
   (`audit_chain_cron`) verifies incrementally; a reported gap
   or tamper alarm means investigate the affected range before
   trusting it. Full detail, including what to do when an alarm
   fires: [Audit log hash chain](../expert/audit-log-hash-chain.md).
4. **`wrangler d1 execute`** against `audit_events` directly,
   for anything the console's fixed filters can't express —
   arbitrary `WHERE` clauses, joins against other tables,
   ad-hoc aggregation:

   ```sh
   wrangler d1 execute cesauth-prod --remote \
     --command "SELECT seq, ts, kind, subject FROM audit_events
                WHERE kind = 'admin_user_created'
                  AND ts > strftime('%s', 'now', '-7 days')
                ORDER BY seq DESC"
   ```

(Local dev also exposes `/__dev/audit`; it does not exist in
production.)

For day-to-day incident response, the admin console covers most
needs. For historical or compliance queries spanning months of
data or requiring joins the console can't express, `wrangler d1
execute` against `audit_events` is the current answer — cesauth
does not push audit events to an external destination (SIEM)
today.

### Useful audit queries

In the two syntaxes that actually exist — `wrangler d1 execute` SQL, and
the console's filter fields (§Querying the audit trail above):

**Who promoted recently?**
```sh
wrangler d1 execute cesauth-prod --remote \
  --command "SELECT seq, ts, subject FROM audit_events
             WHERE kind = 'anonymous_promoted'
               AND ts > strftime('%s', 'now', '-7 days')
             ORDER BY seq DESC"
```
Console: `event=anonymous_promoted` (exact-match field) with `from` set
to a timestamp 7 days back.

**Failed magic-link verification spike:**
```sh
wrangler d1 execute cesauth-prod --remote \
  --command "SELECT seq, ts, subject FROM audit_events
             WHERE kind = 'magic_link_failed'
               AND ts > strftime('%s', 'now', '-1 hours')
             ORDER BY seq DESC"
```
Console: `event=magic_link_failed` with `from` set to an hour back.

**A specific user's activity:**
```sh
wrangler d1 execute cesauth-prod --remote \
  --command "SELECT seq, ts, kind, reason FROM audit_events
             WHERE subject = 'u-7K9F2L'
             ORDER BY seq DESC"
```
Console: `subject=u-7K9F2L` — remember this field is a **substring**
match, so it can also return other subjects whose id happens to contain
that string.

**Admin token use (always worth review):**
```sh
wrangler d1 execute cesauth-prod --remote \
  --command "SELECT seq, ts, kind, subject FROM audit_events
             WHERE kind LIKE 'admin\_%' ESCAPE '\'
             ORDER BY seq DESC"
```
There is no `admin_*` kind glob in the codebase — the `LIKE` above matches
all ten `admin_`-prefixed kinds: `admin_bucket_safety_changed`,
`admin_bucket_safety_verified`, `admin_client_created`,
`admin_console_viewed`, `admin_login_failed`, `admin_session_revoked`,
`admin_threshold_updated`, `admin_token_created`, `admin_token_disabled`,
`admin_user_created`. For the question in this heading, start with
`admin_token_created` and `admin_token_disabled`. Console equivalent:
`kind=admin_` — the substring match (§Querying the audit trail) does the
same thing without needing a glob.

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
- **R2 object count.** cesauth's Worker makes **no R2 API calls at
  all**. `wrangler.toml` declares an `ASSETS` R2 bucket binding, but
  nothing in `crates/backend` or `crates/adapter-cloudflare` reads or
  writes it — it's vestigial. (The Leptos frontend bundle is served by
  **Workers Static Assets**, a different Cloudflare product configured
  under `wrangler.toml`'s `[assets]` section; that's not R2 either.)
  The audit log is **not** R2 — it's D1 rows — and its growth is
  bounded by the daily `audit_retention_cron` job
  (`AUDIT_RETENTION_DAYS` / `AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS`
  operator env vars, defaults 365 / 30 days), not by an R2 lifecycle
  rule.

## See also

- [Operational logging](../expert/logging.md) — the developer-
  facing view of `crates/backend/src/log.rs`: categories, levels,
  and what each is for.
- [Day-2 operations runbook](./runbook.md) — what to actually
  do when an alert fires.
- [Disaster recovery](./disaster-recovery.md) — when the
  observability surfaces themselves are the problem.
