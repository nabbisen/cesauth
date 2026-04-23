# Inspecting state

Three classes of state matter during local debugging:

1. **D1 rows** — users, OIDC clients, grants. Relational, persistent.
2. **Audit log** — what cesauth did and why. R2-backed, append-only.
3. **Operational logs** — live `wrangler tail` output. Not persisted.

Each has its own inspection path.

## D1 rows

```sh
# All tables. `.tables` is a sqlite3 interactive-shell meta-command
# and is NOT understood by `wrangler d1 execute`, which takes only
# real SQL. Query sqlite_master instead.
wrangler d1 execute cesauth --local \
  --command "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"

# User rows
wrangler d1 execute cesauth --local \
  --command 'SELECT id,email,status FROM users;'

# Grants (refresh-token families that have ever been issued)
wrangler d1 execute cesauth --local \
  --command 'SELECT * FROM grants;'
```

Common dot-command equivalents you might reach for in the sqlite3
shell:

| Interactive      | Working SQL                                                  |
|------------------|--------------------------------------------------------------|
| `.tables`        | `SELECT name FROM sqlite_master WHERE type='table';`         |
| `.indexes`       | `SELECT name FROM sqlite_master WHERE type='index';`         |
| `.schema users`  | `SELECT sql FROM sqlite_master WHERE name='users';`          |
| `.schema`        | `SELECT sql FROM sqlite_master;`                             |

## Audit log

cesauth writes every security-relevant event to the `AUDIT` R2 bucket
under `audit/YYYY/MM/DD/<uuid>.ndjson`. There is no `wrangler r2
object list` subcommand in Wrangler v3 or v4 — only `get`, `put`, and
`delete`. Instead, cesauth exposes a dev-only listing endpoint:

```sh
# Latest 20 events with bodies
curl -s 'http://localhost:8787/__dev/audit?body=1&limit=20' | \
  jq '.keys[] | {key, body}'

# Filter by event kind
curl -s 'http://localhost:8787/__dev/audit?body=1' | \
  jq '[.keys[].body | select(.kind=="token_issued")]'

# Narrow to a specific day
curl -s 'http://localhost:8787/__dev/audit?prefix=audit/2026/04/23/' | \
  jq .
```

Query parameters:

| Param    | Default                       | Meaning                                |
|----------|-------------------------------|----------------------------------------|
| `prefix` | today (`audit/YYYY/MM/DD/`)   | R2 key prefix                          |
| `limit`  | `20`, clamped to `100`        | Max objects                            |
| `body=1` | off                           | Fetch each object's body as parsed JSON|

The endpoint returns `404` unless `WRANGLER_LOCAL="1"` is set in
`.dev.vars`. Deployments MUST NOT set it.

## Operational logs

Operational logs are different from the audit log: they describe
**how** cesauth is running (latency, rate-limit escalations, storage
hiccups), not what it authorized. Logs are structured JSON Lines
that show up in `wrangler tail`:

```sh
wrangler tail --format=pretty
```

Knobs live in `.dev.vars`:

```
LOG_LEVEL="debug"            # default: info
LOG_EMIT_SENSITIVE="1"       # default: 0
```

`LOG_LEVEL` accepts `trace`, `debug`, `info`, `warn`, `error`.
`LOG_EMIT_SENSITIVE` gates the `Auth`, `Session`, and `Crypto`
categories, which may carry user ids or credential ids. They are
dropped by default because leaking them to a log aggregator is a
subtle privacy problem; turn them on only for local triage.

Restart `wrangler dev` after changing either value — `.dev.vars` is
read once at boot.

See [Operational logging](../expert/logging.md) for the category
taxonomy and routing rules.
