# Admin console

The **Cost &amp; Data Safety Admin Console** is an operator-facing
surface that ships with cesauth starting in v0.3.0. It is NOT a part
of the authentication flow — end users never see it. It exists so a
human operator can answer four questions without leaving the browser
tab:

1. **Is the deployment drifting cost-wise?** D1 rows growing fast? R2
   filling up? KV counter-entries piling without eviction?
2. **Are the R2 buckets configured the way I *think* they are?** Or
   has a `wrangler r2 bucket cors put` somewhere in the team made
   `AUDIT` publicly listable by accident?
3. **What just happened?** Searchable view of the audit log with
   filters for `kind` and `subject`.
4. **Anything yelling right now?** A consolidated alert page that
   folds cost and safety alerts together.

The design follows
`cesauth-拡張開発指示書-CostDataSafetyAdminConsole.md` — a brief, plain
Japanese spec that asks for *visibility over decoration*, explicit
dangerous operations, and strict separation from the authentication
core.

---

## The six pages

| URL                           | Purpose                                                            | Minimum role |
|-------------------------------|--------------------------------------------------------------------|--------------|
| `GET  /admin/console`         | Overview — alert counts, recent events, last verified buckets      | ReadOnly     |
| `GET  /admin/console/cost`    | Per-service metrics + trend                                        | ReadOnly     |
| `GET  /admin/console/safety`  | Attested bucket-safety rows + re-verify button                     | ReadOnly     |
| `GET  /admin/console/audit`   | Audit log search (prefix / kind / subject filters)                 | ReadOnly     |
| `GET  /admin/console/config`  | Attested settings + thresholds (the review surface)                | ReadOnly     |
| `GET  /admin/console/alerts`  | Consolidated alert center                                          | ReadOnly     |

All six pages are **`Accept`-aware**: browsers get HTML, scripts that
send `Accept: application/json` get the underlying JSON. Every view
emits an `AdminConsoleViewed` audit event with the page name in
`reason`, matching the spec's "監視失敗自体も監査対象" expectation.

## The three write endpoints

| URL                                          | Audit kind                   | Minimum role |
|----------------------------------------------|------------------------------|--------------|
| `POST /admin/console/safety/:bucket/verify`  | `AdminBucketSafetyVerified`  | Security     |
| `POST /admin/console/config/:bucket/preview` | *(read — no event)*          | Operations   |
| `POST /admin/console/config/:bucket/apply`   | `AdminBucketSafetyChanged`   | Operations   |
| `POST /admin/console/thresholds/:name`       | `AdminThresholdUpdated`      | Operations   |

The `preview`/`apply` split is the spec's §7 "two-step confirmation".
`apply` requires `{"confirm": true, ...}` in the body; the HTML
confirmation screen that wraps this as a form is deferred to 0.3.1.

The `verify` endpoint deserves its own note: it does NOT change the
attested booleans. It just stamps `last_verified_at` /
`last_verified_by`. The spec calls this out because re-attestation
has to be cheap enough that operators actually do it on a regular
cadence; nothing changes, only "I checked" is recorded.

---

## Role model

Four roles, declared in `core::admin::types::Role`:

| Role       | What it may do                                                                          |
|------------|-----------------------------------------------------------------------------------------|
| `ReadOnly` | View every console page. Nothing else.                                                  |
| `Security` | Read + **re-verify** bucket safety attestations + revoke an active session.             |
| `Operations` | Security + **edit** bucket safety attestations + edit thresholds + create users.      |
| `Super`    | Operations + manage admin tokens themselves (CRUD over `admin_tokens`).                 |

The matrix is codified as a pure synchronous function
`core::admin::policy::role_allows(role, action)`, with unit-test
coverage of every cell in `crates/core/src/admin/tests.rs`. Adding a
role or an action means editing that matrix and its tests — nowhere
else.

### Per §14: this is provisional

The spec flags the role model as provisional pre-tenant-boundaries.
When a Keycloak-realm-shaped multi-tenancy story lands, the role enum
will be revisited alongside it. Until then, the four-role model is
intentionally narrow — enough to gate dangerous operations off from
read-only eyes, not enough to express per-bucket or per-client ACLs.

---

## Admin authentication

### The bootstrap path

A fresh deployment has `admin_tokens` empty and exactly one way in:
the `ADMIN_API_KEY` secret. Presenting that secret as the bearer
resolves to a synthetic Super principal with id `super-bootstrap` (no
D1 row, `touch_last_used` is a no-op). This preserves the pre-0.3
admin API access pattern verbatim.

```bash
# Bootstrap access, fresh install
curl -H "Authorization: Bearer $ADMIN_API_KEY" \
     https://cesauth.example/admin/console
```

### Minting scoped tokens

Every other principal is a row in `admin_tokens`, storing
`token_hash` = SHA-256(plaintext) as 64-char lower hex. Plaintext is
never stored; you mint it, hand it to the operator, then forget it.

```bash
# 1. Generate 32 random bytes, base64url-encode. This is the plaintext
#    bearer the operator will use.
TOKEN=$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '=')
echo "plaintext: $TOKEN"   # give THIS to the operator, once

# 2. Compute its SHA-256 (the hash is what goes into D1).
HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)

# 3. Insert the row. Role is one of: read_only, security, operations, super.
wrangler d1 execute cesauth --remote --command "
  INSERT INTO admin_tokens (id, token_hash, role, name, created_at)
  VALUES (
    lower(hex(randomblob(16))),  -- a random UUID-ish id
    '$HASH',
    'operations',
    'alice@example',
    strftime('%s','now')
  );
"
```

### Disabling a token

```bash
wrangler d1 execute cesauth --remote --command "
  UPDATE admin_tokens
  SET disabled_at = strftime('%s','now')
  WHERE name = 'alice@example';
"
```

Disabled rows stay in the table for audit continuity; the resolver
treats them as unknown (401 with reason `disabled_token`).

### Failed-auth audit trail

Every `AdminPrincipalResolver::resolve` failure emits an
`AdminLoginFailed` event with a reason slug:

| Reason slug        | Meaning                                    |
|--------------------|--------------------------------------------|
| `missing_bearer`   | No `Authorization: Bearer …` header        |
| `unknown_token`    | Bearer did not match `ADMIN_API_KEY` or any non-disabled hash |
| `disabled_token`   | Bearer hash matches a row with `disabled_at IS NOT NULL` |
| `insufficient_role`| Principal resolved, but role was too low for the requested action |

Grep the audit log for `admin_login_failed` to see bearer-guessing
activity.

---

## Metrics-source fidelity caveats

**This is the most important section for an operator to read.** The
admin console surfaces metrics with varying degrees of *truth*. The
policy layer attaches a `note` to each service's trend when it's
informational rather than authoritative.

| Service          | What we surface                                  | Fidelity           | Note                                   |
|------------------|--------------------------------------------------|--------------------|----------------------------------------|
| D1               | `COUNT(*)` per tracked table                     | **Authoritative**  | Direct queries on owned tables         |
| R2               | `object_count` + `bytes` via paginated `list()`  | **Authoritative**  | Capped at 10 pages × 1000 objects      |
| KV               | Count of keys under the `counter:` prefix        | Proxy              | True KV ops/sec requires CF analytics  |
| Workers          | Sum of self-maintained per-day counters, 7-day   | **Proxy**          | CF dashboard is authoritative          |
| Turnstile        | Sum of self-maintained per-day counters, 7-day   | **Proxy**          | CF dashboard is authoritative          |
| Durable Objects  | *(empty)*                                        | Not available      | Workers cannot enumerate DO instances  |

### Why the Worker/Turnstile counters read as zero in 0.3.0

`CloudflareUsageMetricsSource::sum_kv_counter_last_7d` reads
`counter:workers:requests:YYYY-MM-DD` and
`counter:turnstile:{verified,rejected}:YYYY-MM-DD`. Those keys are
**read** in 0.3.0 but are **not yet written** — the hot-path
increments are tracked as a 0.3.1 follow-up (priority 8 in the spec
landed; this is a separate concern). A brand-new deployment legitimately
shows zero here until the instrumentation ships.

### Why Durable Objects is blank

The Workers runtime exposes no API to enumerate active DO instances
or their per-instance call counts. When Cloudflare ships such an API,
we wire it in. Until then, the trend's note points operators at the
Cloudflare dashboard.

---

## Data-safety attestation model

R2 bucket configuration — `public`/`cors`/`bucket_lock`/`lifecycle`/
`event_notifications` — lives on Cloudflare's side and is reachable
only via the control-plane API with an account-scoped API token.
cesauth runs inside the Workers runtime; that token is NOT available
to it. There are two ways a monitoring tool can handle this gap:

1. **Fetch the CF API from the Worker using a stored token.** This
   lets the tool show "current live state". The cost is that the
   Worker then holds an account-scoped admin token, which is a
   monumentally larger security blast radius than an auth server
   should have.

2. **Attestation.** The operator checks the real state out-of-band
   (wrangler, CF dashboard, their IaC), enters it into a D1 row, and
   clicks "re-verify" periodically. The console surfaces "what you
   last confirmed" and alerts when the confirmation gets stale.

cesauth takes path (2). The relevant D1 table is
`bucket_safety_state`; each row has the five attested flags plus
`last_verified_at`/`last_verified_by`/`notes`. The Safety Dashboard
is where a Security+ principal clicks "re-verify"; the Configuration
Review page is where an Operations+ principal edits the flags
themselves.

### Why `public=true` is always Critical

The `evaluate_bucket_safety` policy raises a **Critical** alert for
any bucket whose attestation is `public=true`, even the `ASSETS`
bucket (which might legitimately be public). The rationale is that
accidental public R2 is the highest-impact data incident this
deployment can produce on its own; we prefer to raise, let the
operator dismiss, and remember rather than silently pass.

---

## Change-op protocol (§7 two-step confirmation)

The JSON flow today:

```bash
# 1. Preview the proposed change. No write occurs.
curl -X POST \
     -H "Authorization: Bearer $ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "public": false,
       "cors_configured": true,
       "bucket_lock": true,
       "lifecycle_configured": true,
       "event_notifications": false,
       "notes": "confirmed wrangler r2 bucket lock get"
     }' \
     https://cesauth.example/admin/console/config/AUDIT/preview

# -> { "ok": true, "diff": { "bucket": "AUDIT",
#      "current": { ... },
#      "proposed": { ... },
#      "changed_fields": ["bucket_lock", "lifecycle_configured"] } }

# 2. Inspect the diff. If it matches intent, re-POST with confirm:true
#    to /apply. The body is otherwise identical.
curl -X POST \
     -H "Authorization: Bearer $ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "public": false,
       "cors_configured": true,
       "bucket_lock": true,
       "lifecycle_configured": true,
       "event_notifications": false,
       "notes": "confirmed wrangler r2 bucket lock get",
       "confirm": true
     }' \
     https://cesauth.example/admin/console/config/AUDIT/apply

# -> { "ok": true, "before": { ... }, "after": { ... } }
```

The `apply` handler audits the attempt *before* performing the write,
then audits the outcome. If the write fails, the attempt event
remains. This matches the spec's §11 "監視失敗自体も監査対象": the act
of trying to make a change is itself audit-worthy, independent of
whether the change succeeded.

### Threshold updates

```bash
curl -X POST \
     -H "Authorization: Bearer $ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"value": 200000}' \
     https://cesauth.example/admin/console/thresholds/cost.d1.row_count.warn
```

Well-known threshold names live in
`core::admin::types::threshold_names`:

- `cost.d1.row_count.warn` — D1 table row count warn threshold
- `cost.r2.object_count.warn` — R2 object count warn
- `cost.r2.bytes.warn` — R2 bytes warn
- `safety.bucket.verification_staleness_days` — bucket attestation
  staleness (default 30 days; `evaluate_bucket_safety` uses strict
  `>` so exactly-at-boundary counts as still fresh)
- `audit.write_failure_ratio.warn` — audit write-fail permille warn
  (the engine doesn't compute this automatically in 0.3.0; the row
  exists for future use)

The D1 column is `TEXT` so operators may insert bespoke threshold
names for their own tooling without a schema change.

---

## Response shape & CSP

Every `/admin/console/*` response carries:

```
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'self'; script-src 'none';
                         style-src 'self' 'unsafe-inline';
                         img-src 'self' data:;
                         form-action 'self';
                         frame-ancestors 'none';
                         base-uri 'none'
```

The admin pages are pure server-rendered HTML with **zero
JavaScript**. That is not a limitation; it is the security posture.
`script-src 'none'` is a tight lock, not a performative one. The
admin UI is deliberately text-heavy tables and semantic forms — the
spec's §9 "装飾より可視性を優先" (visibility over decoration) is
taken literally.

401 responses additionally carry `WWW-Authenticate: Bearer
realm="cesauth-admin"` so browser clients get a credential prompt.
403 (role too low) does not — the caller authenticated, they're just
not allowed to do *this*.

---

## What's deferred to 0.3.1

- **HTML edit forms with two-step confirmation UI.** The preview/apply
  pair today is JSON-scripted. The UI wrapper is priority 8 in the
  spec.
- **Admin-token management UI.** The D1 table, port
  (`AdminTokenRepository`), and in-memory adapter exist; the routes
  and UI templates are priority 7.
- **Workers-request and Turnstile-verify hot-path counters.** The
  admin console already reads these KV keys; 0.3.1 starts incrementing
  them.
- **Durable Objects enumeration.** Blocked on Cloudflare shipping a
  runtime API.

---

## Further reading

- `cesauth-拡張開発指示書-CostDataSafetyAdminConsole.md` — the original
  Japanese spec. Authoritative for what this subsystem is trying to
  do.
- `crates/core/src/admin/` — the pure-Rust domain layer. Start with
  `types.rs` (data shapes), then `policy.rs` (rules), then
  `service.rs` (orchestration).
- `crates/adapter-cloudflare/src/admin/` — the Cloudflare-backed port
  implementations. The metrics adapter
  (`admin/metrics.rs`) is the most interesting one if you want to
  understand what cesauth can and cannot read from inside a Worker.
- `crates/worker/src/routes/admin/` — the HTTP handlers. `auth.rs`
  is the middleware everything flows through; each `console/*.rs` is
  one page.
- `crates/ui/src/admin/` — the HTML templates. No JS, strict CSP,
  plain `format!` — no templating engine dependency.
