# RFC 015: Request traceability — correlation ID + lifecycle log + audit cross-link

**Status**: Ready
**ROADMAP**: External review follow-up — operator question on logging completeness and traceability
**ADR**: This RFC produces ADR-018 documenting (a) the correlation-ID design, (b) the deliberate absence of a file-writing logger
**Severity**: **P2 — operability gap; not security-blocking but materially impedes incident response**
**Estimated scope**: Small/medium — ~120 LOC across `log.rs`, `audit.rs`, `lib.rs` middleware + 1 schema migration (additive nullable column) + ~15 tests

## Background

The v0.50.1 conversation surfaced a question worth
explicit answer: is server logging adequate, can a
client request be traced end-to-end, and does
cesauth need a file-writing logger?

Reading the existing implementation
(`crates/worker/src/log.rs`, ~212 lines):

**What exists and works well**:
- Categorized (`Http`, `Auth`, `Session`,
  `RateLimit`, `Storage`, `Crypto`, `Config`,
  `Dev`).
- Level-gated (`Trace < Debug < Info < Warn <
  Error`).
- Sensitivity-gated (categories
  `is_sensitive() == true` are dropped unless
  `LOG_EMIT_SENSITIVE=1`).
- One JSON object per line via
  `console_{log,warn,error}!`. Cloudflare's
  runtime captures and surfaces in the Logs tab,
  `wrangler tail`, and Logpush.
- Tiny wire shape — `ts`, `level`, `category`,
  `msg`, optional `subject`. No allocation per
  field.

**What's missing** (the operator's question):

1. **No correlation between log lines from the
   same request.** A `/token` exchange emits
   ~5 log lines across the handler; a `/authorize`
   emits ~8. There is no shared identifier letting
   an operator group them. When a user reports
   "my login failed at 14:03 UTC", the
   investigator gets ~50 lines from that minute
   and cannot tie them to one request.

2. **No correlation between log lines and audit
   events.** A failed `/token` may emit
   `RefreshTokenReuseDetected` audit; the operator
   reading the audit row cannot find the
   surrounding `log` lines for the same request.

3. **No HTTP request lifecycle log.** Some routes
   emit a manual `Category::Http` line at start;
   most don't. There is no consistent "request
   started / request ended (status, duration)"
   middleware. p95 latency or "is /token slow
   right now" cannot be answered from logs alone.

4. **No file-writing logger** — and this is a
   **deliberate property**, not a gap. Cloudflare
   Workers has no filesystem; introducing one via
   KV/R2/D1 writes per log line would (a)
   contradict the security posture (every log line
   is now persisted, increasing exfiltration
   surface), (b) add storage contention to the
   audit-append already noted in RFC 014, (c) lose
   the level / sensitivity gating advantages of
   the current pattern. The operator's question
   correctly anticipates this — "セキュリティ重視のため
   不要なログは出力したりファイルに残したりすることは不要".
   This RFC closes the question with explicit
   documentation rather than implementation.

The fix is **minimal additive correlation**
(items 1-3) plus **explicit non-feature
documentation** (item 4), without proliferating
log lines. The total wire surface grows by
exactly one field per log line and one column
per audit row.

## Requirements

1. Every log line emitted during request handling
   MUST carry a `request_id` field unique to that
   request.
2. The request_id MUST be derivable from a header
   the operator can also see in their CF /
   Logpush stream — i.e., usable for
   client-side-to-server-side correlation when
   the client surfaces the same id on its own
   error page.
3. Every audit row written during request
   handling MUST optionally record the
   request_id, allowing audit-to-log
   cross-reference.
4. There MUST be exactly one HTTP request
   lifecycle log per request (`http` category,
   `Info` level), emitted as middleware — not
   per-handler — covering method, path, status,
   duration, request_id.
5. Cesauth MUST NOT add per-request log volume
   beyond what already exists. The lifecycle log
   replaces ad-hoc `Category::Http` lines from
   handlers; per-handler diagnostics stay
   unchanged at their current level/category.
6. Cesauth MUST NOT introduce a file-writing
   logger. The decision is recorded as an ADR
   and surfaced in operator documentation so
   future contributors don't propose one.

## Design

### Correlation-ID source

Cloudflare's edge attaches a `cf-ray` header to
every inbound request — a globally-unique
identifier (e.g., `8b3c4d5e6f7a8b9c-NRT`)
already visible in Cloudflare's dashboard, in
Logpush exports, and observable client-side via
the response header.

**Decision**: use `cf-ray` as the request_id
source.

Reasoning:
- **Free**. No allocation, no CSPRNG draw, no
  schema work for the id itself.
- **Already in operator's pipeline**. Logpush
  records it; the Cloudflare dashboard shows it.
  Operators already know how to grep their
  logs for a `cf-ray`.
- **Cross-environment correlation**. A client
  that captures `cf-ray` from a failure response
  can hand it to the operator; the operator pulls
  the matching server-side log lines.
- **Not secret**. `cf-ray` is in the response
  headers cesauth already returns; including it
  in our own logs reveals nothing new.

**Fallback for non-CF environments**: in
`WRANGLER_LOCAL=1` (dev, no real `cf-ray`), or if
the header is absent for any reason, generate
a UUIDv4 server-side. Marked `local-` prefix to
distinguish in logs.

### `RequestId` newtype

In `crates/worker/src/request_id.rs` (new file):

```rust
//! Per-request correlation identifier.
//!
//! Sourced from `cf-ray` in production; UUIDv4 in
//! local dev. Threaded through every log emission
//! and audit write produced during request
//! handling. Not a security boundary — `cf-ray`
//! is already in the response and observable
//! client-side.

use uuid::Uuid;
use worker::{Headers, Request};

/// Per-request correlation key. Cheap to clone
/// (small string).
#[derive(Debug, Clone)]
pub struct RequestId(String);

impl RequestId {
    /// Extract from `cf-ray` if present;
    /// otherwise generate a `local-<uuid>`.
    pub fn from_request(req: &Request) -> Self {
        let from_header = req.headers()
            .get("cf-ray").ok().flatten()
            .filter(|v| !v.is_empty() && v.len() <= 64);
        match from_header {
            Some(v) => Self(v),
            None    => Self(format!("local-{}", Uuid::new_v4())),
        }
    }

    pub fn as_str(&self) -> &str { &self.0 }
}
```

The `≤ 64` length filter is defensive — `cf-ray`
in observed practice is ~20 chars; a malicious
client can't override the inbound CF-supplied
header (the runtime overwrites it), but a bug
elsewhere shouldn't allow an unbounded value
into log records.

### Threading through `LogConfig`

`crates/worker/src/log.rs` `LogConfig` gains an
optional `request_id`:

```rust
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub min_level:      Level,
    pub emit_sensitive: bool,
    /// Per-request correlation. `None` for cron /
    /// background paths where there is no inbound
    /// request.
    pub request_id:     Option<String>,
}
```

`LogConfig::from_env(env)` continues to set
`request_id: None`. A new
`LogConfig::for_request(env, &request_id)`
constructs the per-request flavor.

The `Record` wire shape gains:

```rust
#[derive(Serialize)]
struct Record<'a> {
    ts:         i64,
    level:      Level,
    category:   &'static str,
    msg:        &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject:    Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,   // ← new
}
```

`emit` reads `cfg.request_id` and writes it into
the record. Per-line cost: ~30 bytes for the
extra JSON field when present. Acceptable.

For cron-pass and background log lines, no
request_id — field absent (skip-if-none keeps the
record short).

### Per-request `LogConfig` construction

The worker-level `fetch` handler currently
constructs `Config::from_env` near the entry of
each route. Each route handler that wants to log
calls `Config::from_env(&ctx.env)` and reads
`config.log`.

After this RFC: the `fetch` middleware extracts
`RequestId::from_request(&req)` once at the top,
threads it into a per-request log config, and
makes it available to handlers.

The plumbing decision is: how do handlers access
the per-request config without changing every
signature?

**Options considered**:

- **(A)** Add a parameter to every route handler.
  ~50 sites, all touched. Heavy diff.
- **(B)** Stash the request_id in
  `RouteContext`'s data slot. Workers' router
  exposes a typed data field per request.
  Localized.
- **(C)** Use a thread-local. Doesn't fit Workers
  (no threads, but executors can interleave).
  Reject.

**Decision**: (B). The router's `RouteContext`
can carry a per-request value. Existing code
already uses `ctx.env`; add `ctx.data` (or
equivalent depending on workers-rs surface) to
carry the request_id. Handlers that already
construct `Config::from_env(&ctx.env)` change to
`Config::from_env_with_request(&ctx.env, ctx)`,
which pulls the id off the context and stamps
the LogConfig.

If the router's `data` slot is unavailable in
the current workers-rs API surface, a
thread-of-execution-local pattern via tokio's
`TaskLocal` or a small `RefCell` in a per-task
state object is acceptable. The implementer's
call.

### HTTP lifecycle log middleware

`fetch` wraps the existing `router.run(...)`
call:

```rust
pub async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let request_id  = RequestId::from_request(&req);
    let log_cfg     = LogConfig::for_request(&env, request_id.as_str());
    let method      = req.method().to_string();
    let path        = req.path();   // pre-routing
    let started_at  = OffsetDateTime::now_utc().unix_timestamp_nanos();

    // ... thread request_id into ctx (option B above) ...

    let response = router_with_ctx(request_id.clone()).run(req, env.clone()).await;

    let status     = response.as_ref().map(|r| r.status_code()).unwrap_or(0);
    let duration_ms = ((OffsetDateTime::now_utc().unix_timestamp_nanos() - started_at) / 1_000_000) as u64;

    log::emit(&log_cfg, Level::Info, Category::Http,
        &format!("{method} {path} -> {status} {duration_ms}ms"),
        None,
    );

    response.map(|r| security_headers::apply(r, &env))
}
```

Three observations:

- **One log per request, not two.** No "request
  started" line — that doubles the log volume
  with no incremental value over the "request
  ended" line that carries duration.
- **Path is pre-routing.** The exact path the
  client sent. Includes the leading slash. Does
  NOT include query string (privacy: query
  strings can carry tokens, scopes, redirect_uri
  values that are operator-visible but
  user-typeable).
- **Status 0 on handler error.** If the handler
  panics (rare; Workers panic = 500 from the
  runtime), `response` is `Err` and we log
  `status=0`. Real status comes from the runtime
  layer above us, which we don't see.

### Removing ad-hoc `Category::Http` emissions

A handful of routes
(`oidc/authorize.rs:60`,
`oidc/token.rs:39`, etc.) currently emit a
`Category::Http` line at the start of the
handler. With the middleware lifecycle log, these
become redundant. **Remove them**.

This **reduces log volume** while improving
correlation. The middleware line carries `method
+ path + status + duration` (more info than the
old per-handler "starting" lines). Net log
output per request: same or fewer lines.

### Audit cross-link — `audit_events.request_id`

Schema change: `audit_events` gains a nullable
`request_id TEXT` column.

**Migration `0011_audit_request_id.sql`**:

```sql
ALTER TABLE audit_events ADD COLUMN request_id TEXT;
-- Nullable. Populated for events written during
-- a request handler; NULL for cron / background
-- events.
-- Pre-v0.50.x rows have request_id = NULL.
```

**SCHEMA_VERSION 10 → 11.** First schema bump
since v0.50.0. The column is nullable, the
migration is a single ALTER, and there is no
index — query patterns are still seq-ordered or
subject-filtered.

`NewAuditEvent`:

```rust
pub struct NewAuditEvent<'a> {
    pub id:           &'a str,
    pub ts:           i64,
    pub kind:         &'a str,
    pub subject:      Option<&'a str>,
    pub client_id:    Option<&'a str>,
    pub ip:           Option<&'a str>,
    pub user_agent:   Option<&'a str>,
    pub reason:       Option<&'a str>,
    pub request_id:   Option<&'a str>,    // ← new
    pub payload:      &'a str,
    pub payload_hash: &'a str,
    pub created_at:   i64,
}
```

`audit::write_owned` and friends gain an
`Option<&str>` argument for request_id. Every
call site in `crates/worker/src/routes/**` is
updated to pass it. The wiring follows the same
ctx-data thread as the log config.

**Hash chain implication**. The chain hash is
computed over `(prev_hash, payload_hash, seq, ts,
kind)` per ADR-010 — `request_id` is NOT part of
the chained set. Adding it to the row does NOT
break existing chain verification. Pin via test:

```rust
#[test]
fn chain_hash_excludes_request_id() {
    // construct two NewAuditEvents identical
    // except for request_id; assert their
    // computed chain hashes are equal.
}
```

This deliberately scopes `request_id` as
**operationally meaningful, cryptographically
incidental**. An operator who tampers with
`request_id` doesn't break the chain — the chain
still detects the tampering they actually care
about (kind, subject, payload).

### What stays out of scope

- **Distributed tracing (W3C Trace Context,
  OpenTelemetry).** Cesauth is a single Workers
  edge; there is no upstream/downstream graph
  to propagate trace context across. If a future
  cesauth deployment fronts a multi-service
  architecture, revisit. Today, `cf-ray` plus
  request_id is the right granularity.

- **Per-request span tree.** A single request
  emits a flat list of `request_id`-tagged log
  lines. No parent/child span structure. Adding
  spans would require either (a) async-context
  propagation that Workers' executor doesn't
  natively support, or (b) explicit span
  arguments to every helper. Cost too high vs
  flat-list value.

- **Sampling.** Today every record passes the
  level + sensitivity gates and is emitted; no
  rate-based sampling. If volume becomes a
  problem (RFC 014's audit-append concern is
  the equivalent for the audit table), consider
  sampling on Logpush filters operator-side
  rather than in cesauth.

- **Trace-id in client-facing error responses.**
  An operator wanting "show users the request_id
  on error pages so they can quote it in support
  tickets" is a UI/UX choice. Out of v0.50.x
  scope. The mechanism (request_id is available
  in `ctx`) makes future addition trivial.

### Explicit non-feature: file-writing logger

The operator's question explicitly raised this.
The answer is: **cesauth deliberately does not
write log files**, for four reasons:

1. **No filesystem.** Cloudflare Workers has no
   POSIX filesystem. A "file" logger would mean
   per-line writes to KV / R2 / D1 — each is a
   subrequest and a billable operation, and the
   D1 path serializes through the same database
   audit-append uses (RFC 014).
2. **Security posture.** The current
   sensitivity-gated transient log stream
   (`console_{log,warn,error}!`) is consumed by
   Cloudflare's runtime and forwarded to
   operator-controlled destinations (Logpush →
   SIEM). Persisting locally creates an
   additional retention surface that's outside
   the operator's existing audit/log governance.
3. **Operational redundancy.** Operators
   already have Cloudflare Logs (transient) and
   `audit_events` (durable, hash-chained). A
   third destination duplicates one of those
   two without adding capability.
4. **The "no unnecessary logs" discipline**
   asked by the operator question itself. A
   file-writing logger would tend to retain more
   not less.

**Decision document this in ADR-018** alongside
the request-correlation design. The ADR makes
the absence load-bearing — a future contributor
proposing a file logger reads the ADR first and
sees the four reasons. Discussion happens
against the recorded decision rather than as
greenfield design.

## Test plan

### `request_id.rs`

1. **`from_request_uses_cf_ray_when_present`**
   — pin extraction.
2. **`from_request_falls_back_to_local_uuid`**
   — pin fallback shape (`local-` prefix).
3. **`from_request_rejects_oversized_cf_ray`**
   — pin the ≤ 64 char defense.
4. **`from_request_rejects_empty_cf_ray`**
   — pin: empty string falls to local-uuid.

### `log.rs`

5. **`record_includes_request_id_when_set`** —
   pin wire shape.
6. **`record_omits_request_id_when_none`** —
   skip-if-none pin.
7. **`request_id_does_not_bypass_level_gate`** —
   pin: setting request_id doesn't promote a
   filtered record.
8. **`request_id_does_not_bypass_sensitivity_gate`**
   — same for sensitive categories.

### Worker middleware

9. **`http_lifecycle_log_emitted_once_per_request`**
   — pin: exactly one Http-category line per
   request.
10. **`http_lifecycle_log_carries_method_path_status_duration`**
    — wire-shape pin.
11. **`http_lifecycle_log_path_excludes_query_string`**
    — privacy pin.
12. **`http_lifecycle_log_request_id_matches_handler_log_lines`**
    — correlation pin.

### Audit

13. **`audit_row_persists_request_id`** — round-
    trip via the in-memory adapter.
14. **`chain_hash_excludes_request_id`** — pin
    that audit chain integrity is unaffected.
15. **`audit_search_does_not_index_by_request_id`**
    — current admin search is by kind/subject
    only; pin that adding the column doesn't
    accidentally introduce a new search axis
    (would need its own indexing decision).

## Security considerations

**`cf-ray` as a public token**. `cf-ray` is in
the response headers cesauth already returns. An
attacker can trivially grab it from a network
trace. **It is not a secret**. Including it in
log lines and audit rows reveals nothing.

**Correlation as a side-channel**. An audit row
with a `request_id` that matches the operator's
log line for "POST /token, status 401, duration
4ms" tells an audit-reader more than today's row
does. Specifically: an audit-reader can now know
"this audit event came from a fast-failing
request" — useful for incident triage, but also
revealing of timing characteristics. This is a
weak side-channel (timing already reveals more
on the response side); the trade is acceptable
for the operability gain.

**Hash chain robustness**. `request_id` is
**not** in the chained tuple. An attacker
modifying `request_id` post-hoc doesn't break
the chain — but also doesn't benefit, because
the chain was never the integrity source for
that field. The integrity property of audit
remains: `(kind, subject, payload)` and the
sequence are tamper-evident. Adding a non-chained
column is consistent with v0.50.0's `audience`
column (also nullable, also non-chained).

**Operator visibility of request flow**.
Tightened correlation lets an operator
reconstruct any user's session in detail. This
is **expected** — that's what the audit log is
for. The change here is making correlation
practical at the per-request scale rather than
the per-second scale. Operators are trusted by
the cesauth threat model.

**Non-feature: file logger**. Documented above.
Adding one would worsen the security posture by
adding a persistence surface. Pin the absence
in ADR-018.

## Open questions

**Should the lifecycle log line elevate to
`Warn` when status >= 500?** Yes — small
change, makes operator alerting easier (filter
on `level: warn` for HTTP errors). Add to PR 3.

**Should `request_id` be searchable in the
admin audit console?** Out of v0.50.x scope.
The column is nullable and unindexed; adding a
search-by-request-id field to `AuditSearch`
would need an index decision (sparse index or
full-table scan? operator query patterns?).
Defer until operator demand surfaces.

**Should `audit::write_*` accept request_id
positionally or via a builder?** Positional —
cesauth's audit API is currently positional and
this RFC keeps the convention. If the parameter
list grows past ~10 positional args (currently
~9), revisit; for one new arg, keep simple.

**Should cron passes get a synthetic
request_id?** The cron handler in `lib.rs:60-105`
runs five passes daily. Each pass currently
emits log lines without correlation. **Yes**,
each pass should mint a `cron-<pass-name>-<unix>`
synthetic id (e.g., `cron-sweep-1715203200`)
and pass it to its `LogConfig`. Audit rows the
pass writes carry the same id. Operators
investigating "why did the audit retention
prune so much last Tuesday" get a correlation
key. Add as PR 4 in implementation order.

## Implementation order

1. **PR 1** — `request_id.rs` newtype +
   `LogConfig.request_id` field + `Record`
   wire shape addition. ~80 LOC + 8 tests
   (items 1-8). No behavior change for routes
   yet — handlers that don't pass through the
   new constructor get `request_id: None` on
   their log lines.
2. **PR 2** — Schema migration
   `0011_audit_request_id.sql` + `NewAuditEvent`
   field + adapter writes. ~40 LOC + 3 tests
   (items 13-15). SCHEMA_VERSION 10 → 11.
   Audit calls still pass `request_id: None`
   since the worker glue isn't wired yet.
3. **PR 3** — Worker middleware: lifecycle log,
   ctx threading, removal of ad-hoc
   Category::Http emissions, route handler
   updates to pass request_id through to log
   and audit. ~150 LOC + 4 tests (items 9-12).
4. **PR 4** — Cron-pass synthetic request_id.
   ~30 LOC + 2 tests.
5. **PR 5** — ADR-018: request correlation
   design + non-feature documentation of
   file-writing-logger absence. New chapter
   `docs/src/deployment/observability.md`
   (or extend if it exists) with the operator's
   how-to: "find all log lines for a single
   user request".
6. **PR 6** — CHANGELOG + release.

## Notes for the implementer

- Keep the wire-shape addition (`request_id`
  field on `Record`) surgical. JSON schema
  consumers (Logpush → SIEM) will see the new
  field on every line; upstream tooling that
  treats unknown fields strictly will need a
  one-line adjustment. Document in CHANGELOG
  under "Wire format" as additive only.
- The `≤ 64` length filter on `cf-ray` is
  defensive. Don't relax it without a concrete
  reason. Cloudflare's actual `cf-ray` values
  are far shorter; an inbound oversized value
  is a defect or an attack, either way reject.
- **Don't start with PR 3 (the middleware).**
  The pure-data PRs 1+2 land first; PR 3 wires
  them up. This way each PR is independently
  reviewable and the test suite stays green
  after each.
- The request_id propagation pattern (ctx.data
  or equivalent) is the largest design choice
  in this RFC. If workers-rs's API doesn't
  expose a clean per-request data slot, the
  next-best is wrapping every handler in a
  small closure that captures `request_id`.
  The closure pattern is workable but verbose;
  prefer the data-slot if the API allows.
- Coordinate with RFC 008's static-grep test
  on the `Record` wire shape: the new
  `request_id` field is fine (not a denylist
  match), but if a future contributor names a
  new field "code_id" or similar, the grep
  catches it. Cross-reference in the test
  comments.
- The ADR-018 file-logger non-feature
  documentation is the **most reusable**
  artifact of this RFC. Future "why don't we
  write logs to a file" questions get
  redirected to the ADR. Make sure the four
  reasons (no FS, security posture, redundancy,
  no-unnecessary-logs discipline) are in the
  ADR text verbatim.
