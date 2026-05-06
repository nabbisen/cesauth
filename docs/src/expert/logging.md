# Operational logging

Distinct from the **audit log** (R2-backed, authoritative,
append-only) is the **operational log** (stdout, lossy, for live
diagnostics). This chapter covers the latter.

## What goes where

| Concern                                        | Audit | Log |
|------------------------------------------------|-------|-----|
| "Who authenticated when?"                      | ✅    |     |
| "Which refresh tokens were reused?"            | ✅    |     |
| "What was the p95 latency of /token last hour?"|       | ✅  |
| "Why did this `/magic-link/verify` 500?"       | partial (AuthFailed) | ✅ (structured cause) |
| "Did the user's account exist at request time?"| ✅    |     |
| "What's the rate-limit bucket utilization?"    |       | ✅  |

Audit answers authoritative questions after the fact. Logs answer
operational questions in real time. Losing a log line is tolerable;
losing an audit record is not.

## Categories

Every log line carries a `Category`:

| Category     | Sensitive? | Example payload                                   |
|--------------|------------|---------------------------------------------------|
| `Http`       | no         | `/token grant_type=authorization_code`            |
| `Auth`       | **yes**    | `exchange_code failed: PreconditionFailed("invalid_grant")` |
| `Session`    | **yes**    | `session started sid=…`                           |
| `RateLimit`  | no         | `bucket=magic_link_request escalate`              |
| `Storage`    | no         | `d1 users.create: UNIQUE constraint failed`       |
| `Crypto`     | **yes**    | `JwtSigner::from_pem failed: …`                   |
| `Config`     | no         | `load_signing_key failed: secret not set`         |
| `Dev`        | no         | `/__dev/stage-auth-code handle=…`                 |

Sensitive categories can legitimately carry user IDs, credential
IDs, or cryptographic error details. They are dropped by default
because leaking them to a log aggregator is a subtle privacy
problem. Enable with `LOG_EMIT_SENSITIVE="1"` in `.dev.vars` (or
via `wrangler secret put` in production), and treat enabling as an
explicit, time-boxed ops action.

## Levels

`LOG_LEVEL` in `wrangler.toml` `[vars]` picks the floor:

```
trace < debug < info < warn < error
```

Default `info`. Lines below are dropped in the emit function before
any serialization cost.

## Wire format

JSON Lines, one object per record:

```json
{"ts": 1715712445, "level": "info", "category": "http", "msg": "/token grant_type=authorization_code", "subject": "demo-cli"}
```

`wrangler tail --format=pretty` renders this with category and
level columns. Cloudflare's log viewer treats these as structured
fields. The `subject` field is optional; it is typically the
`client_id` for outbound auth lines, `sub` for session lines, or a
bucket name for rate-limit lines.

## Call site

```rust
use crate::log::{self, Category, Level};

log::emit(&cfg.log, Level::Info, Category::Http,
          &format!("/authorize client_id={}", ar.client_id),
          Some(&ar.client_id));

log::emit(&cfg.log, Level::Warn, Category::Session,
          "csrf mismatch on /magic-link/request",
          None);
```

The first argument is a `LogConfig`, which `Config::from_env` reads
from `LOG_LEVEL` and `LOG_EMIT_SENSITIVE`.

## What logs are NOT for

- **Not audit.** If an operator later needs to answer "was this
  refresh token revoked at the moment this request arrived?", that
  answer must come from the `audit_events` D1 table (v0.32.0+,
  ADR-010), not from logs which may be gone.
- **Not user-visible.** Errors returned to clients go through
  `error::oauth_error_response`. Logs are for the operator.
- **Not for PII under normal operation.** Sensitive categories
  exist precisely because the boundary is porous; the default is to
  drop them.

## Debugging a 500

`/token`'s 500 paths all emit a structured log:

```
{"lvl":"error","cat":"config","msg":"load_signing_key failed: ..."}
{"lvl":"error","cat":"crypto","msg":"JwtSigner::from_pem failed: ..."}
{"lvl":"warn", "cat":"auth",  "msg":"exchange_code failed: <CoreError>"}
```

This is the primary tool for triaging the beginner tutorial's
common failures — see [Troubleshooting](../beginner/troubleshooting.md).

Turn `LOG_LEVEL="debug"` and `LOG_EMIT_SENSITIVE="1"` on together
for full visibility during triage, then turn them back off. Debug
lines include user and credential IDs.
