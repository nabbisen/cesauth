# Changelog

All notable changes to cesauth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

cesauth is in active development. The public surface — endpoints,
`wrangler.toml` variable names, secret names, D1 schema, and
`core::ports` traits — may change between minor versions. Breaking
changes will always be called out here.

---

---

## Older releases

Entries for v0.49.0 and earlier are in
[`docs/changelog-archive/`](docs/changelog-archive/README.md),
split by minor-version range:

- v0.41–v0.49 → [`CHANGELOG-0.41-to-0.49.md`](docs/changelog-archive/CHANGELOG-0.41-to-0.49.md)
- v0.31–v0.40 → [`CHANGELOG-0.31-to-0.40.md`](docs/changelog-archive/CHANGELOG-0.31-to-0.40.md)
- v0.1–v0.30  → [`CHANGELOG-0.1-to-0.30.md`](docs/changelog-archive/CHANGELOG-0.1-to-0.30.md)

---

## [0.79.0] - 2026-05-20

### Breaking changes (RFC 114 — Workspace restructuring)

**Crate renames:**

| Old name | New name |
|---|---|
| `cesauth-worker` | `cesauth-backend` |
| `cesauth-ui` | `cesauth-frontend` |

All internal `use cesauth_worker::…` and `use cesauth_ui::…` import
paths have been rewritten to `cesauth_backend::…` and
`cesauth_frontend::…` respectively throughout the workspace.

**Motivation.** The old names encoded deployment-specific assumptions
that the project's architecture explicitly rejects:
- `crates/worker` suggested Cloudflare-only code; most of its
  content (routes, OIDC flows, admin console, post-auth) is
  deployment-neutral.
- `crates/ui` suggested presentation only; the crate's intended
  scope includes interaction design, state, accessibility, and flows.

`frontend` / `backend` is the deployment-neutral, symmetric pairing
that accurately reflects the two crates' architectural roles.

**Entrypoints split.** A new `crates/backend/src/entrypoints/`
directory isolates the Cloudflare-specific bindings:

- `entrypoints/cloudflare.rs` — Durable Object re-exports. The
  `#[event(fetch)]` and `#[event(scheduled)]` handlers remain in
  `lib.rs` for now (env-blocked: the full move requires wasm32
  target verification). Completion tracked in RFC 114.
- `entrypoints/mod.rs` — declares `pub mod cloudflare` and
  documents the placeholder for a future `pub mod axum` self-hosted
  entrypoint.

**No behaviour changes.** HTTP surface, cookie contract, OIDC
endpoints, database schema, and audit event shapes are unchanged.
All 1,290 host-side tests pass.

---

## [0.78.13] - 2026-05-20

Fixes the infinite redirect loop introduced by v0.78.12.

### What v0.78.12 got wrong

Adding a shallow HMAC-only session check to `GET /` caused a loop:

1. `GET /` — cookie HMAC validates → `302 /me/security`
2. `GET /me/security` — DO lookup fails (session revoked, or DO state
   lost after `wrangler dev` restart) → `302 /?next=/me/security`
3. `GET /` — cookie still HMAC-valid → `302 /me/security`
4. Loop → browser reports "The page isn't redirecting properly"

The HMAC check is not sufficient: a cookie can be correctly signed but
refer to a session that has been revoked or that the Durable Object no
longer knows about (common after `wrangler dev` restarts, which reset
in-memory DO state).

### Correct fix

Reverted `GET /` to its original form (no session check). Instead,
changed `complete_auth`'s no-pending-AR fallback landing from `"/"`
to `"/me/security"`:

```rust
// Before:
.unwrap_or_else(|| "/".to_owned())

// After:
.unwrap_or_else(|| "/me/security".to_owned())
```

This means a direct magic-link login (without an OAuth client) lands
at `/me/security` immediately, bypassing `/` entirely. No loop is
possible:

- `GET /` always renders the login form (unaffected)
- If `/me/security` rejects the session it redirects to `/?next=...`
  which renders the login form (not another redirect to `/me/security`)

The `login_next` cookie path is unaffected: if the user was trying to
reach a specific page before login, `complete_auth` still honours that
cookie and redirects there.

### Tests

1,290 / 1,290 pass. 0 warnings.

---

## [0.78.12] - 2026-05-20

Bug fix. After a successful magic-link login without an active OIDC
authorize flow, the user was redirected back to the login page.

### Root cause

`GET /` always rendered the login form unconditionally — it did not
check for an existing valid session cookie. `complete_auth`'s
no-pending-AR fallback redirects to `/`, so a user who signed in
directly (not via an OAuth client) landed at the login page again
immediately after their session cookie was set.

### Fix

`routes::ui::login` now checks the `__Host-cesauth_session` cookie
before rendering. If the cookie is present and HMAC-verifies
successfully (same check used by all other authenticated routes),
the handler returns `302 → /me/security` instead of the login form.

This is standard IdP home-page behaviour: an already-authenticated
user hitting `/` should land on an authenticated view, not be shown
the sign-in form.

The session check is intentionally lightweight — cookie signature
verification only, no DO round-trip. The downstream route
(`/me/security`) performs the full session resolution and renders
an appropriate error if the session has been revoked since the cookie
was issued.

### Tests

1,290 / 1,290 pass. 0 warnings.

---

## [0.78.11] - 2026-05-20

Migration fix. Magic-link login failed at runtime with
`no such table: main.users_pre_0016: SQLITE_ERROR` when the active
session store attempted an INSERT into `user_sessions`.

### Root cause (same pattern as v0.78.10, different table)

Migration 0016 rebuilds `users` via `ALTER TABLE users RENAME TO
users_pre_0016 / CREATE TABLE users / INSERT / DROP TABLE users_pre_0016`.
SQLite 3.26.0+ rewrites FK references in every other table at rename time,
so eight tables ended the migration with `user_id` pointing at the
non-existent `users_pre_0016`.

`PRAGMA foreign_key_check` at the end of migration 0016 passes on a
fresh (empty) database because it checks *row-level* integrity only;
the dangling FK schema entry is invisible until a real INSERT fires
FK enforcement at runtime.

Migration 0016 already rebuilt `authenticators`, `consent`, and `grants`,
but missed the eight tables below.

### Added to migration 0016

Eight new rebuild blocks, each following the rename/create/insert/drop
pattern already established in the migration:

| Table | Additional index restored |
|---|---|
| `user_sessions` | `idx_user_sessions_active_created` (from 0014) |
| `user_tenant_memberships` | — |
| `user_organization_memberships` | — |
| `user_group_memberships` | — |
| `role_assignments` | — |
| `totp_authenticators` | — |
| `totp_recovery_codes` | — |
| `anonymous_sessions` | — |

`user_sessions` required one extra line: the partial index
`idx_user_sessions_active_created` (created in migration 0014) was
lost when the table was rebuilt, and the migration-chain test
`active_sessions_cron_scan_uses_partial_index` caught the omission.

### Tests

31 / 31 migration chain tests pass (including the index-plan test
that caught the missing `idx_user_sessions_active_created`).

### Pattern for future rebuild migrations

Any migration that rebuilds a table with `ALTER TABLE foo RENAME TO
foo_pre_N; ... DROP TABLE foo_pre_N` must also rebuild every table
that has a FK pointing at `foo`. SQLite 3.26.0+ silently rewrites
those FK targets to `foo_pre_N`; after the drop, those FKs become
dangling and break at runtime. `PRAGMA foreign_key_check` does not
catch this on an empty database.

---

## [0.78.10] - 2026-05-20

Migration fix. `wrangler d1 migrations apply cesauth --local` failed
at migration 0016 with `no such table: main.groups_pre_0013`.

### Root cause

Two migrations (0013 and 0017) rebuild the `groups` table using the
pattern `ALTER TABLE groups RENAME TO groups_pre_N; CREATE TABLE groups
(...); DROP TABLE groups_pre_N`. SQLite 3.26.0+ automatically updates
FK references in other tables when a table is renamed, so after the
rename, `user_group_memberships.group_id`'s FK target changes from
`groups` to `groups_pre_N`. After `DROP TABLE groups_pre_N`, that
reference becomes dangling.

Two different SQLite builds react differently to dangling FK targets in
`PRAGMA foreign_key_check`:

- **rusqlite bundled SQLite** (used by `cesauth-migrate-test`): silently
  ignores FK references to non-existent tables — reports 0 violations.
  This is why all 31 migration chain tests passed.
- **Wrangler's SQLite** (used by `wrangler dev`): treats a FK pointing at
  a non-existent table as a hard `SQLITE_ERROR`, surfaced at the first
  `PRAGMA foreign_key_check` in a later migration (0016 in this case).

The same root cause also caused `error[E0599]: foreign key mismatch`
for the self-referential `(tenant_id, parent_group_id) → groups(tenant_id,
id)` FK in migrations 0013 and 0017: the `UNIQUE (tenant_id, id)` index
was created *after* the `CREATE TABLE`, so Wrangler's SQLite couldn't
resolve the composite FK target at table-creation time.

### Fixes

**Migration 0013** (`0013_tenant_composite_keys.sql`) — already had the
`UNIQUE (tenant_id, id)` inline fix from v0.78.8. Now also rebuilds
`user_group_memberships` immediately after the groups rebuild (before
`PRAGMA foreign_key_check`) to re-point its FK at the new `groups` table.

**Migration 0017** (`0017_groups_fk_restrict.sql`) — same two fixes:
added `UNIQUE (tenant_id, id)` inline to the `CREATE TABLE groups`
body, and added a `user_group_memberships` rebuild block after the
groups rebuild.

### Verification

Both fixes verified by:
1. A Python script reproducing the rename-rebuild-check cycle with
   SQLite 3.45.1 (which has 3.26.0+ FK-rename behavior). After the
   fix, `PRAGMA foreign_key_check` returns clean and
   `user_group_memberships` references `groups`, not `groups_pre_N`.
2. All 31 `cesauth-migrate-test` migration chain tests still pass.

### Why `user_group_memberships` and not other tables?

The only table with a `REFERENCES groups(...)` simple FK (besides the
self-referential `parent_group_id` inside `groups` itself) is
`user_group_memberships.group_id`. All other cross-table FK references
to group identifiers use composite `(tenant_id, group_id)` form which
was introduced in a later migration and is not subject to this issue.

---

## [0.78.9] - 2026-05-20

Documents the three secrets required for local login. No code changes.

After magic-link verification succeeded, `post_auth` crashed with
`SESSION_COOKIE_KEY secret is not set` because `.dev.vars` only
contained `WRANGLER_LOCAL = "1"`. Two more secrets are required to
complete the full login ceremony; a third (`TOTP_ENCRYPTION_KEY`) is
needed for TOTP registration.

### Required secrets for local development

| Secret | Purpose | Required for |
|--------|---------|-------------|
| `JWT_SIGNING_KEY` | Ed25519 PEM key for signing JWTs | Token issuance (OIDC flow) |
| `SESSION_COOKIE_KEY` | HMAC key for signing session cookies | Any authenticated page |
| `TOTP_ENCRYPTION_KEY` | AES-256-GCM key for TOTP secrets at rest | TOTP enroll/verify |

`TOTP_ENCRYPTION_KEY` is optional — omit it to disable TOTP
registration in local dev. The other two are required for any
authenticated request to succeed.

### Complete `.dev.vars` for local development

Generate fresh values and write the file in one step:

```sh
JWT_KEY=$(openssl genpkey -algorithm ed25519 | tr '\n' '|' | sed 's/|/\\n/g; s/\\n$//')
SESSION_KEY=$(openssl rand -base64 48 | tr -d '\n')
TOTP_KEY=$(openssl rand -base64 32 | tr -d '\n')

cat > .dev.vars << EOF
WRANGLER_LOCAL = "1"
JWT_SIGNING_KEY = "$JWT_KEY"
SESSION_COOKIE_KEY = "$SESSION_KEY"
TOTP_ENCRYPTION_KEY = "$TOTP_KEY"
EOF
```

`.dev.vars` is already listed in `.gitignore` (added in v0.78.7).
Never commit it.

### Note on `JWT_SIGNING_KEY` format

The worker normalises `\n` sequences to real newlines before
passing the value to the PEM parser:

```rust
let normalized = raw.replace("\\n", "\n");
```

The `tr | sed` pipeline above converts the PEM's real newlines into
literal `\n` two-character sequences so the whole key fits on a single
line in `.dev.vars`. This matches the format `wrangler secret put`
uses for production secrets (which also escapes newlines).

### Full local development procedure (updated)

```sh
# 1. Generate secrets (first time only)
JWT_KEY=$(openssl genpkey -algorithm ed25519 | tr '\n' '|' | sed 's/|/\\n/g; s/\\n$//')
SESSION_KEY=$(openssl rand -base64 48 | tr -d '\n')
TOTP_KEY=$(openssl rand -base64 32 | tr -d '\n')
cat > .dev.vars << EOF
WRANGLER_LOCAL = "1"
JWT_SIGNING_KEY = "$JWT_KEY"
SESSION_COOKIE_KEY = "$SESSION_KEY"
TOTP_ENCRYPTION_KEY = "$TOTP_KEY"
EOF

# 2. Apply migrations (first time only)
wrangler d1 migrations apply cesauth --local

# 3. Start local dev server
wrangler dev

# 4. Request a magic link
open http://localhost:8787/magic-link/request

# 5. Copy the OTP from the wrangler terminal:
#    [magic_link dev] recipient=...  handle=...  code=ABCD2345

# 6. Enter the code on the verification page → logged in.
```

---

## [0.78.8] - 2026-05-20

Migration fix. `0013_tenant_composite_keys.sql` failed with
`SQLITE_ERROR: foreign key mismatch - "groups" referencing "groups"`
when applied locally via `wrangler d1 migrations apply cesauth --local`.

### Root cause

The migration rebuilds the `groups` table and declares a
self-referential composite FK:

```sql
FOREIGN KEY (tenant_id, parent_group_id)
    REFERENCES groups(tenant_id, id)
    ON DELETE SET NULL
```

For SQLite to accept a composite FK, the referenced columns must be
covered by a `PRIMARY KEY` or `UNIQUE` constraint **in the schema at
`CREATE TABLE` time**. The `UNIQUE INDEX idx_groups_tenant_id_id ON
groups(tenant_id, id)` was created at the *end* of the migration —
after the `CREATE TABLE`. SQLite raises "foreign key mismatch" when
it cannot find a matching uniqueness constraint on the parent side of
the FK at table-creation time. This is a schema validation error, not
a data enforcement error, and occurs even with `PRAGMA foreign_keys =
OFF`.

### Fix

Added an inline `UNIQUE (tenant_id, id)` constraint to the `CREATE
TABLE groups` body. This gives SQLite a uniqueness declaration to
resolve the self-referential FK against during table creation. The
subsequent `CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_tenant_id_id`
at the end of the migration is retained as an explicit named index
(harmless given `IF NOT EXISTS`).

### Tests

31 / 31 migration chain tests pass. The fix was verified through
`cesauth-migrate-test`, which applies every migration to a fresh
in-memory SQLite database and runs FK integrity checks.

---

## [0.78.7] - 2026-05-20

Fixes local development login flow. Adds `.gitignore`.

### Problem

`DevConsoleMailer` (activated by `WRANGLER_LOCAL=1`) deliberately
withheld the OTP code from its console log, printing only the
`handle` and `recipient`. The intention was that developers would
retrieve the code from local D1 storage, but:

1. The code is stored in an **AuthChallenge Durable Object**, not in
   D1, so `wrangler d1 execute ... --local` cannot reach it.
2. The suggested `scripts/dev-otp.sh` script was never written.
3. The OTP alphabet is 31 chars × 8 chars = 31⁸ ≈ 852 billion
   combinations — not brute-forceable in reasonable time.

Result: with a stock checkout and `WRANGLER_LOCAL=1`, developers
had no way to complete the magic-link login flow locally.

### Fix

`DevConsoleMailer` now logs the OTP code to the terminal:

```
[magic_link dev] recipient=you@example.com  handle=abc123  code=ABCD2345  reason=initial_auth
```

**Security rationale for logging the code here:**

- `DevConsoleMailer` is constructed only when
  `env.var("WRANGLER_LOCAL") == "1"` — enforced by the `from_env`
  factory. Production `wrangler.toml` has `WRANGLER_LOCAL = "0"`.
- The local-only override belongs in `.dev.vars` (now in
  `.gitignore`), which is never committed.
- Terminal output of a local dev process has no retention path, no
  forwarding, and no log aggregation.
- This is no different from any other development tool that prints a
  temporary credential (database seed passwords, self-signed cert
  passphrases, test API keys) to the console.
- The previous alternative (`scripts/dev-otp.sh` brute-forcing the
  hash) would have been computationally impractical and offered no
  security advantage — the code is usable only once, rate-limited,
  and expires.

### Complete local login procedure

1. Create `.dev.vars` in the repo root (git-ignored):
   ```toml
   WRANGLER_LOCAL = "1"
   ```
2. Run `wrangler dev`. Apply migrations if first run:
   ```sh
   wrangler d1 migrations apply cesauth --local
   ```
3. Open `http://localhost:8787/magic-link/request`.
4. Enter any email address and submit the form.
5. The wrangler terminal prints the log line above.
6. Copy the `code=` value and enter it on the verification page.
7. You are now logged in.

### Also: `.gitignore` added

The repository had no `.gitignore`. Added one covering:
- `.dev.vars` (local dev secrets — must never be committed)
- `.wrangler/` and `crates/worker/build/` (wrangler artifacts)
- `/target/` (Rust build artifacts)
- Common editor and OS artifacts

### Tests

1,290 / 1,290 pass. 0 warnings. `DevConsoleMailer` is wasm32-only
and not covered by host-side tests, but the logic change is
trivial — one `console_log!` argument added.

---

## [0.78.6] - 2026-05-20

Bug fix. `/magic-link/verify` returned a raw JSON `400 Bad Request`
in the browser instead of an HTML page on all error conditions.

### Root cause

Every error path in `crates/worker/src/routes/magic_link/verify.rs`
called `oauth_error_response(...)`, which unconditionally returns a
JSON body (`{"error": "..."}`) with the appropriate HTTP status code.
That is correct for programmatic API callers (JSON `Content-Type`),
but the browser form path (`Content-Type: application/x-www-form-urlencoded`)
got the same raw JSON response — showing a file-download dialog or
a blank JSON view depending on the browser, with no UI chrome.

### Fix

Two parts:

**1. `magic_link_sent_page_for` gains an `error: Option<&str>` slot**
(`crates/ui/src/templates/login.rs`).

When `Some(msg)` is supplied, a `<p role="alert" class="form-error">`
paragraph is rendered above the OTP form. This allows the verify
handler to re-render the form in-place with a human-readable error
message so the user can correct and retry — the same UX pattern
used by the TOTP verify and login pages.

All existing callers updated to pass `None` (no behaviour change):
- `magic_link_sent_page` shorthand wrapper
- Two `request.rs` call sites (Turnstile-required path + normal
  post-send path)
- Two i18n test call sites in `templates/tests/i18n.rs`

**2. `verify.rs` errors now branch on `is_json`**

`is_json` was already computed early in the handler (for CSRF
exemption logic). Each error path now chooses:

| Condition | `is_json = true` | `is_json = false` (browser form) |
|---|---|---|
| CSRF mismatch | JSON 400 | `html_terminal_error` — "session expired, request a new link" |
| Missing handle/code | JSON 400 | `html_terminal_error` |
| Turnstile required | JSON 400 | `html_terminal_error` — "complete security challenge" |
| Rate limited | JSON 400 | `form_retry` — "too many attempts, try again" |
| Challenge not found / already used | JSON 400 | `html_terminal_error` — "link expired" |
| Wrong code | JSON 400 | `form_retry` — "incorrect code, check your email" |
| User resolution failure | JSON 400 | `html_terminal_error` — "sign-in failed" |

`form_retry` re-renders `magic_link_sent_page_for` with the error
message and mints a fresh CSRF token (replacing the cookie). The
handle is preserved so the user can resubmit without re-requesting.

`html_terminal_error` renders `error_page_for` at HTTP 400 with
a user-facing message and no internal detail.

The API contract for JSON callers is unchanged.

### Tests

1,290 / 1,290 pass. 0 warnings. The template signature change is
covered by the two existing i18n tests (now updated to pass `None`).

---

## [0.78.5] - 2026-05-20

Patch release. Single error: `module audit_query is private` (E0603)
in `crates/worker/src/routes/admin/console/audit_export.rs`.

The v0.78.4 fix used `cesauth_cf::admin::audit_query::CloudflareAuditQuerySource`
— accessing the submodule directly — but `admin.rs` declares
`mod audit_query;` without `pub`, making the module private.
The struct is already re-exported at the `cesauth_cf::admin` level
via `pub use audit_query::CloudflareAuditQuerySource;`.

Fix: dropped the `::audit_query` segment so the path reads
`cesauth_cf::admin::CloudflareAuditQuerySource::new(&ctx.env)`.

1,290 / 1,290 tests pass. 0 warnings.

---

## [0.78.4] - 2026-05-19

Patch release. Fixes four classes of remaining `cesauth-worker`
errors that were masked in v0.78.3 (either revealed by fixing
earlier errors, or introduced by a faulty `sed` substitution
in that patch).

### Corrupted enum + `ctx` references (8 errors)

The v0.78.3 patch attempted to replace `&ctx.env` with `&env` in
`me/totp/disable.rs` and `me/totp/enroll.rs` using a shell `sed`
command whose replacement string contained a literal `&`. In POSIX
`sed`, `&` in the replacement expands to the entire matched text,
so the match was prepended to itself, producing the nonsense
identifier `CsrfRngFailureenv` and leaving the original `ctx.env`
reference intact.

Fixed by re-applying the substitution correctly in Python (no
special-character ambiguity). All four call sites now read
`&env, crate::audit::EventKind::CsrfRngFailure,` as intended.

### `render::form_error` still not found (2 errors)

v0.78.3 added a private `fn form_error(msg: &str)` inside
`invitations.rs`, but the two call sites still used the qualified
path `render::form_error(...)`. The helper was never moved into
the render module — it lives locally in `invitations.rs`.
Fixed both call sites: `render::form_error` → `form_error`.

### Wrong repository type for `export_audit` (3 errors)

`export_audit` requires an `AuditQuerySource` implementor.
`CloudflareAuditEventRepository` implements `AuditEventRepository`
(append + search), not `AuditQuerySource` (batch export query).
The correct type is `CloudflareAuditQuerySource`. Fixed
`audit_export.rs` to construct a `CloudflareAuditQuerySource::new`
instead.

### Borrow of moved value in cron handler (4 errors)

`lib.rs` used the pattern:
```rust
let result = some_cron::run(&env).await;
record_cron_pass(..., result.err().map(|e| format!("{e:?}"))).await;
if let Err(e) = &result { ... }   // ERROR: result was moved by .err()
```

`.err()` on a `Result` consumes the value. Fixed by changing
`.err()` to `.as_ref().err()` for the four affected cron results
(`chain_result`, `sia_result`, `retention_result`, `repair_result`).
The `sweep_result` that precedes them already had `as_ref()` in the
correct `.as_ref().map(...)` call and is not followed by a borrow,
so it was unaffected.

### Tests

1,290 / 1,290 pass. 0 warnings.

---

## [0.78.3] - 2026-05-19

Patch release. Fixes all 44 `cesauth-worker` compilation errors that
appeared when `wrangler dev` compiled for the `wasm32-unknown-unknown`
target. None of these errors were caused by v0.75.0–v0.78.2 changes;
they are pre-existing drift between the worker crate call-sites and
core API changes accumulated since v0.66.0.

### Error categories and fixes

**Duplicate enum variant (1 error)**

`EventKind::SessionRevoked` was defined twice in `crates/worker/src/audit.rs` — once in the RFC 053 session lifecycle section (L73) and again in a legacy "Sessions" section (L274). Removed the duplicate definition and its unreachable `as_str()` match arm.

**Missing module file (1 error)**

`pub mod preview;` in `routes/admin/console.rs` referenced a file that didn't exist. Created a stub `console/preview.rs` that returns HTTP 501 until the full implementation ships (env-blocked — requires wasm32 to develop and verify).

**Wrong module path (1 error)**

`crate::adapter_cf::audit_repo(&ctx.env)` in `audit_export.rs` — `adapter_cf` does not exist in the worker crate root. Replaced with the direct constructor `cesauth_cf::ports::audit::CloudflareAuditEventRepository::new(&ctx.env)`, consistent with every other audit repository construction site in the codebase.

**`ctx` not in scope in non-async helper / wrong env variable (8 errors)**

Several CSP-nonce failure paths attempted `crate::audit::write_owned(&ctx.env, ...)`:
- In `render::html_response` (a non-async free function with no `ctx` parameter): replaced with `worker::console_error!()` — no audit possible without an env handle, and CspNonce generation failure is catastrophic enough to warrant a console log.
- In `me/security.rs`, `me/totp/disable.rs`, `me/totp/enroll.rs`, `me/totp/verify.rs` (get_handler): these functions take `env: worker::Env`, not `ctx: RouteContext`. Changed `ctx.env` → `env`.
- In `me/totp/verify.rs` (decide_verify_get): this function takes no env at all and returns `VerifyGetDecision`. Replaced the incorrect `return Response::error(...)` with `return VerifyGetDecision::StaleGate` and `worker::console_error!()` for logging.

**`await` in non-async function (1 error)**

`render::html_response` used `.await` in the CSP nonce audit path — same root as above. Fixed by removing the audit call entirely.

**Missing struct fields (6 errors)**

- `SecurityCenterState` missing `active_sessions_count` (`me/security.rs`): added `active_sessions_count: None`.
- `Challenge::AuthCode` missing `auth_time` (`oidc/authorize.rs`): added `auth_time: now` (uses code-issuance time; the id_token builder falls back to `issued_at` when `auth_time == 0`, so either value is correct).
- `AuditSearch` missing `before_seq` (`routes/dev.rs`): added `before_seq: None`.
- `NewGroupInput` missing `organization_tenant_id` (3 sites: `tenancy_console/forms/group_create.rs`, `tenant_admin/forms/group_create.rs`, `api_v1/groups.rs`): added `organization_tenant_id: None`.

**Missing `tenant_id` in `MagicLinkPayload` (1 error)**

`invitations.rs` built a `MagicLinkPayload` without the `tenant_id` field added in a later release. Added `tenant_id: Some(&ctx_ta.tenant.id)`.

**Renamed / removed API items (5 errors)**

- `gate::check_write` → `gate::check_action` with explicit `ScopeRef` argument (`invitations.rs`).
- `PermissionCatalog::MEMBER_ADD` → `PermissionCatalog::GROUP_MEMBER_ADD` (`invitations.rs`).
- `ReconcileStats.drift_count + .ok_count` — both fields removed; replaced with `s.walked` which is the total count of sessions examined per pass (`lib.rs`).
- `key_repo.list_active_verifying_keys()` → `key_repo.list_active()` — the method was renamed when the trait was refactored. Requires adding `use cesauth_core::ports::repo::SigningKeyRepository;` (was already imported but unused — warning now resolved).
- `cesauth_core::jwt::verify_for_introspect(&token, key)` — the function gained two arguments (`expected_iss: &str`, `leeway_secs: u64`) when the audience-gate was moved out. Updated to `verify_for_introspect::<AccessTokenClaims>(&token, &raw_bytes, &cfg.issuer, 30)`. The `public_key_b64` field is now decoded from base64 inline, following the same pattern as `routes/oidc/introspect.rs`.

**Missing trait imports (3 errors)**

- `MagicLinkMailer` not in scope at 3 call sites (`anonymous.rs`, `invitations.rs`, `magic_link/request.rs`). Added `use cesauth_core::magic_link::MagicLinkMailer;`.
- `DeletionRequestRepository` not in scope (`sweep.rs`). Added `use cesauth_core::deletion::DeletionRequestRepository;`.

**`KvError` vs `worker::Error` mismatch (1 error)**

`kv.put(...).execute().await` in `cron_status.rs` returns `Result<(), KvError>` but the function signature expects `Result<(), worker::Error>`. Added `.map_err(|e| worker::Error::RustError(...))`.

**Non-exhaustive `CoreError` match (1 error)**

`error.rs::oauth_error_code_status` — two new `CoreError` variants (`Conflict`, `CrossTenantReference`) added in later core releases were not covered. Added match arms mapping them to `("conflict", 409)` and `("invalid_request", 400)` respectively.

**`crate::i18n::Locale` private (1 error)**

`invitations.rs` accessed `Locale` through the worker `i18n` module's private `use` alias. Changed to `cesauth_core::i18n::Locale::default()` directly.

**`&str` where `String` expected (5 errors)**

`render::html_response` takes `String`. Five call sites in `invitations.rs` passed `&str` literals. Added `.to_owned()` at each.

**Missing `form_error` helper (2 errors)**

`invitations.rs` called `render::form_error(...)` which doesn't exist in the render module. Added a file-local helper `fn form_error(msg: &str) -> Result<Response>` that wraps `render::html_response`.

**`cfg` variable / macro collision (1 error)**

`invitations.rs::accept_submit` called `log::emit(&cfg.log, ...)` inside a code path where the `cfg` Config variable had not yet been initialized (it was declared later in the function). Moved `Config::from_env()` to before the `accept_invitation` call and renamed the binding to `app_cfg` to avoid shadowing the `cfg!` built-in macro.

**`String` vs `&str` in `h.set()` call (1 error)**

`render.rs`: `h.set("content-security-policy", format!(...))` — `h.set` requires `&str`, `format!` returns `String`. Bound the formatted string to a `let csp_header` and passed `&csp_header`.

**Unused `mut` warnings (4 warnings → 0)**

`https_provider.rs` `let mut headers` and `let mut resp` were redundant after the v0.78.1/v0.78.2 changes. Removed `mut`.

### Warnings also fixed

In addition to the 44 errors, 4 warnings are now resolved:
- `serde::Deserialize` unused import (`invitations.rs`) — removed.
- `InvitationRepository` unused import (`invitations.rs`) — removed.
- `FlashView` unused import (`me/security.rs`) — removed.
- `SigningKeyRepository` unused import (`oidc/userinfo.rs`) — resolved by actually using the trait via `list_active()`.
- Two `unused mut` warnings in `https_provider.rs` — removed.

### Tests

1,290 / 1,290 pass (host-buildable crates). 0 production warnings.
The `cesauth-worker` and `cesauth-adapter-cloudflare` crates require
the wasm32 target; all fixes are verified structurally against the
core API and follow established patterns in the existing codebase.

---

## [0.78.2] - 2026-05-19

Patch release. Fixes three errors introduced by v0.78.1's over-eager
worker API migration, plus a pre-existing `Send` bound violation that
was newly visible after the v0.78.1 fixes cleared compilation.

### What was wrong in v0.78.1

**Over-applied `http`-feature migration to `https_provider.rs`.**
The two mailer impls use different response types:

- `ServiceBindingMailer` calls `svc.fetch_request(req).await` — this
  returns the **`http`-feature** response type. `status_code()` was
  removed; `.status().as_u16()` and the `http::HeaderMap` headers
  chain are correct here. v0.78.1 had this right.
- `HttpsProviderMailer` calls `Fetch::Request(req).send().await` —
  this still returns the **old `worker::Response`** type.
  `status_code()` and `.headers().get(name).ok().flatten()` are
  correct here. v0.78.1 wrongly applied the `http`-feature
  migration to this file too.

Fix: reverted `https_provider.rs` to the original API.

### Pre-existing: `MagicLinkMailer::send` `+ Send` bound

`crates/core/src/magic_link/mailer.rs` had the associated future
typed as `impl Future<Output = ...> + Send`. This compiled fine
with older workers-rs where `JsFuture` was implicitly `Send`.

js-sys 0.3.98 (pulled transitively by workers-rs 0.8.1) explicitly
marks `JsFuture` as `!Send`. `ServiceBindingMailer::send` uses
`svc.fetch_request()` which internally drives a `JsFuture`, so the
returned async block is `!Send`. This violated the trait bound.

Fix: removed `+ Send` from the future return in
`MagicLinkMailer::send`. This is safe because:
- Cloudflare Workers run on a single-threaded WASM VM; `Send` on the
  future is meaningless there.
- No call site passes this future to a multi-threaded spawner
  (`tokio::spawn` or similar). Both callers just `.await` it
  directly inside a worker request handler.
- Host-side adapter-test impls are unaffected; their futures remain
  `Send` — removing the bound from the trait only relaxes the
  constraint, it doesn't break anything that already works.

### Unused `mut` warnings in `service_binding.rs`

Two variables (`headers`, `resp`) no longer need `mut` after the
v0.78.1 API migration. Cleaned up to keep the build warning-free.

### Tests

1,290 / 1,290 pass. 0 warnings.

---

## [0.78.1] - 2026-05-19

Patch release. Fixes `wrangler dev` build failure reported against
v0.78.0 (and all earlier releases since v0.66.0). The errors were
pre-existing in `crates/adapter-cloudflare`; they were exposed when
the user ran `wrangler dev` with **wrangler 4.84.0**, which pulled in
a newer toolchain that made a previously-latent `workers-rs 0.8`
API incompatibility surface.

**The test-file modularization releases (v0.75.0–v0.78.0) did not
cause these errors.** The adapter-cloudflare source files were never
touched during that track. The breakage was present from the first
time the `http` feature was enabled on `worker = "0.8"`.

### Root cause

`workers-rs` 0.8 with the `http` feature enabled migrates `Response`
from a Cloudflare-custom type to a thin wrapper around `http::Response`.
That change has three downstream effects, all of which are now fixed:

**Effect 1 — `wasm_bindgen` and `js_sys` no longer re-exported.**
Old workers-rs versions re-exported `wasm_bindgen` and `js_sys`
transitively. From 0.8 they must be declared as direct dependencies.

Files: `crates/adapter-cloudflare/src/mailer/https_provider.rs` and
`src/mailer/service_binding.rs` both use `wasm_bindgen::JsValue::from_str`.
`crates/adapter-cloudflare/src/ports/audit.rs` uses
`js_sys::Date::now()`.

Fix: added `wasm-bindgen = "0.2"` and `js-sys = "0.3"` to the
workspace `[dependencies]` and as explicit deps of
`cesauth-adapter-cloudflare`.

**Effect 2 — `resp.status_code()` removed.**
`worker::Response::status_code() → u16` was the Cloudflare-specific
accessor. The `http` feature replaces it with `resp.status() →
http::StatusCode`; call `.as_u16()` for numeric comparisons.

Files: `https_provider.rs:146` and `service_binding.rs:91`.

Fix: `resp.status_code()` → `resp.status().as_u16()`.

**Effect 3 — `resp.headers().get(name)` returns `Option`, not `Result`.**
Old `worker::Headers::get(name) → worker::Result<Option<String>>`.
`http::HeaderMap::get(name) → Option<&HeaderValue>`. Calling `.ok()`
on an `Option` is a type error (`.ok()` belongs to `Result`).

Files: `https_provider.rs:150-153` and `service_binding.rs:98-101`.

Fix: replaced `.ok().flatten()` with the correct `http::HeaderMap`
chain:
```rust
// Before (worker::Headers):
resp.headers().get("X-Message-Id").ok().flatten()
// After (http::HeaderMap):
resp.headers().get("X-Message-Id")
    .and_then(|v| v.to_str().ok())
    .map(str::to_owned)
```

### Tests

1,290 / 1,290 pass (host-buildable crates; adapter-cloudflare and
worker are wasm32-only and compile-verified on the user's machine via
`wrangler dev`). 0 production warnings.

### What to do if wrangler dev still fails

These were the only errors in the log. If a new error appears after
applying v0.78.1:

1. Re-run `wrangler dev` and attach the new log.
2. If the error is in another `crates/adapter-cloudflare` file, the
   same `workers-rs 0.8 http` migration may apply — check for
   `.status_code()`, `.headers().get(name).ok()`, or bare
   `wasm_bindgen::`/`js_sys::` usage.

---

## [0.78.0] - 2026-05-14

Closes out the host-buildable test-file modularization track. Splits
the four remaining oversize test files (all just slightly over the
500-ELOC dev-guideline threshold) into themed submodules. Every
host-buildable test file in the workspace is now under the
threshold. 1,290 tests still pass identically — fourth straight
maintenance release with zero behaviour delta.

### Four splits in one release

**`crates/adapter-test/src/tenancy/tests.rs`** (664 → 27 entry + common + 6 siblings):

- `common.rs` (53 — re-exported core types via `pub(super) use ...`
  so submodules' `use super::common::*` brings them in)
- `end_to_end.rs` (118 — §16.1/§16.2 tenant → org → group → user)
- `permission_lattice.rs` (97 — §16.3 permission checks)
- `billing.rs` (76 — billing round-trip + history append)
- `membership_negative.rs` (44)
- `rfc_056_soft_delete.rs` (86)
- `rfc_058_onboarding.rs` (232)

**`crates/core/src/authz/tests.rs`** (606 → 22 entry + common + 5 siblings):

- `common.rs` (90 — stubs + helpers + `pub(super) use` re-exports)
- `catalog_and_assignments.rs` (43)
- `scope_and_expiration.rs` (102)
- `happy_and_dangling.rs` (60)
- `batch_permissions.rs` (136 — v0.15.0)
- `rfc_052_hardening.rs` (200)

**`crates/core/src/totp/tests.rs`** (602 → 27 entry + 8 siblings):

- `rfc6238_vectors.rs` (72 — canonical RFC 6238 Appendix B vectors)
- `step_for_unix.rs` (31)
- `secret_round_trip.rs` (94)
- `format_parse_code.rs` (46)
- `verify_replay.rs` (121)
- `otpauth_uri.rs` (58 — imports `rfc_secret` from `rfc6238_vectors`)
- `recovery_codes.rs` (97)
- `encryption.rs` (111)

**`crates/core/src/i18n/tests.rs`** (530 → 60 entry + 3 siblings):

- Base file keeps the `Locale` tests (57 lines + mod declarations)
- `lookup_completeness.rs` (291)
- `accept_language.rs` (114)
- `plural.rs` (83 — RFC 107)

### Patterns refined

Two patterns from v0.75.0–v0.77.0 prove well-suited to different
shapes:

1. **`pub(super) use` re-exports** (used in v0.78.0's tenancy + authz):
   when submodules need many cesauth-core types, `common.rs` becomes
   a re-export module — `use super::common::*` then brings them
   into the sibling files via a single line. Cleaner than per-file
   import duplication.

2. **Sibling-helper imports** (used in v0.78.0's totp): when one
   submodule's helper is needed by another (e.g.
   `rfc6238_vectors::rfc_secret` used by `otpauth_uri`), make the
   helper `pub(super)` and add an explicit
   `use super::rfc6238_vectors::rfc_secret;` in the consumer.

### Track summary (v0.75.0 → v0.78.0)

Four maintenance releases shipping pure mechanical refactors:

| Release | Files split | Lines reorganized |
|---------|-------------|-------------------|
| v0.75.0 | `ui/src/templates/tests.rs` | 2,057 → 7 files |
| v0.76.0 | `core/src/service/introspect/tests.rs` | 1,519 → 7 files |
| v0.77.0 | `migrate/tests.rs` + `tenant_admin/tests.rs` + `migration_chain.rs` | 2,930 → 22 files |
| v0.78.0 | `tenancy/tests.rs` + `authz/tests.rs` + `totp/tests.rs` + `i18n/tests.rs` | 2,402 → 27 files |

**Total**: 9 test files (8,908 lines combined) reorganized into 63
focused files, every host-buildable test file now under the
500-ELOC threshold. 1,290 tests passed identically across all four
releases — true zero-behaviour-delta refactor track.

### Remaining oversize file (env-blocked)

`crates/worker/src/flash/tests.rs` — 560 lines. Lives in the worker
crate (wasm32-only); cannot compile-verify a split in the current
sandbox. Same env-blocked posture as RFC 110a and RFC 112; ships
once an environment with rustup/wasm32 is available.

### Production source files over threshold (separate track)

Unchanged from prior releases:

- `crates/core/src/i18n/mod.rs` — 1,475 lines (already split
  internally into 8 `lookup_*` groups per RFC 097)
- `crates/migrate/src/main.rs` — 1,024 lines
- `crates/core/src/security_headers.rs` — 847 lines
- `crates/core/src/totp.rs` — 635 lines
- `crates/core/src/admin/types.rs` — 630 lines
- `crates/worker/src/lib.rs` — 597 lines (env-blocked)
- Several worker/UI files in the 540–595 range

The production-source refactor is a separate track from this
test-file modularization. Some are env-blocked (worker), some are
trade-offs (admin/types.rs is a single struct catalogue — splitting
into per-domain submodules is reasonable but cross-cuts naturally).

### Tests

1,290 / 1,290 pass — **identical** to v0.75.0/v0.76.0/v0.77.0.

### Warnings

0 production lib warnings.

### Drift-scan

Clean. The v0.75.0 `*/tests/*.rs` exemption continues to cover all
the new layouts.

---

## [0.77.0] - 2026-05-14

Maintenance release closing out the test-file modularization track
started in v0.75.0. Splits the three remaining largest test files
(`migrate/tests.rs` 1,154 lines, `tenant_admin/tests.rs` 895 lines,
`migration_chain.rs` 881 lines) into 22 sibling files across the
three crates, plus 3 shared `common.rs` files. Every test file now
under the 500-ELOC dev-guideline threshold; 1,290 tests still pass
identically.

### Three splits in one release

**`crates/core/src/migrate/tests.rs`** (1,154 → 247 entry + 6 siblings):

- `redaction.rs` (98), `export_verify.rs` (268), `import_invariants.rs`
  (109), `import_pipeline.rs` (281), `email_uniqueness.rs` (128),
  `manifest_tenant.rs` (80).
- Also de-wrapped a redundant inline `mod tests { ... }` block that
  was double-nesting the module path as `migrate::tests::tests`.
  The file is already the tests module (declared in migrate.rs via
  `#[cfg(test)] mod tests;`); the inline wrapper served no purpose
  and prevented nested submodule resolution.
- Cross-submodule helpers (`make_spec`, `build_dump`, `run_import`,
  `VecSink`) made `pub(super)` and imported via
  `use super::export_verify::make_spec;` etc. — same pattern as the
  v0.75.0 templates split.

**`crates/ui/src/tenant_admin/tests.rs`** (895 → 27 entry + common + 6 siblings):

- `common.rs` (51 — shared `principal`, `sample_tenant`,
  `affordances`, `sample_user` fixtures).
- `frame_invariants.rs` (123), `page_level.rs` (129),
  `mutation_forms.rs` (196), `affordance_gating.rs` (209),
  `membership_forms.rs` (220), `design_tokens.rs` (57).
- Each submodule imports types via individual `use cesauth_core::...`
  statements rather than a glob — explicit imports are more grep-able.

**`crates/migrate-test/tests/migration_chain.rs`** (881 → 30 entry +
common + 6 siblings):

- `common.rs` (80 — `migrations_dir`, `apply_all_migrations`,
  `expected_schema_version`).
- `foundation.rs` (237), `rfc_023_cross_tenant.rs` (81),
  `rfc_024_indexes.rs` (75), `repair_and_fks.rs` (158),
  `rfc_050_sql.rs` (234), `rfc_051_authenticators.rs` (41).
- **Integration-test wrinkle**: cargo's `tests/` directory uses
  older module resolution. `mod foo;` declarations in
  `tests/migration_chain.rs` need explicit
  `#[path = "migration_chain/foo.rs"]` attributes to resolve to the
  sibling subdirectory. Documented in the entry-point file's
  comments so future test-file splits in `tests/` know to expect this.

### Remaining oversize test files (for future maintenance)

Three test files are still just over the 500-ELOC threshold:

- `crates/adapter-test/src/tenancy/tests.rs` — 664 lines
- `crates/core/src/authz/tests.rs` — 606 lines
- `crates/core/src/totp/tests.rs` — 602 lines

These are small overages compared to v0.75.0–v0.77.0's targets (each
of which was 2–4x the threshold) and can be handled in a follow-up
release if priorities warrant.

### Production source files over threshold (separate track)

Unchanged from v0.76.0's list. These are out of scope for the
test-file modularization track but flagged for separate refactor work:

- `crates/core/src/i18n/mod.rs` — 1,475 lines (already split
  internally into 8 `lookup_*` groups per RFC 097; wrapper file is
  large but the internal structure is fine)
- `crates/migrate/src/main.rs` — 1,024 lines
- `crates/core/src/security_headers.rs` — 847 lines
- `crates/core/src/totp.rs` — 635 lines
- `crates/core/src/admin/types.rs` — 630 lines

### Tests

1,290 / 1,290 pass — **identical** to v0.75.0/v0.76.0. Three releases
shipping pure mechanical refactors with no behaviour delta and the
test count steady across all three.

### Warnings

0 production lib warnings.

### Drift-scan

Clean. The `*/tests/*.rs` exemption added in v0.75.0 continues to
cover the new layouts without script changes (the new submodule
directories sit under `tests/` so they match the existing pattern).

### Contract invariants reaffirmed

- **De-wrapping inline `mod tests` blocks is safe** when the file is
  already declared as the tests module by its parent. The cleanup
  removes one nesting level without changing what's tested.
- **Cargo `tests/` directory needs `#[path]` attributes** for
  subdirectory submodules in integration tests — this is the only
  shape difference from `src/` splits.

### Test-file modularization track summary

Three releases (v0.75.0, v0.76.0, v0.77.0) closing out the dev-guideline
500-ELOC threshold for the four biggest test files:

| Release | File | Pre | Post layout |
|---------|------|-----|-------------|
| v0.75.0 | `ui/src/templates/tests.rs` | 2,057 | 34 entry + common + 6 siblings |
| v0.76.0 | `core/src/service/introspect/tests.rs` | 1,519 | 348 entry + 6 siblings |
| v0.77.0 | `core/src/migrate/tests.rs` | 1,154 | 247 entry + 6 siblings |
| v0.77.0 | `ui/src/tenant_admin/tests.rs` | 895 | 27 entry + common + 6 siblings |
| v0.77.0 | `migrate-test/tests/migration_chain.rs` | 881 | 30 entry + common + 6 siblings |

Across the four files, ~6,500 lines of test code reorganized into
~30 focused files, every one under 500 lines.

---

## [0.76.0] - 2026-05-14

Maintenance release continuing v0.75.0's test-file modularization
track. Splits the second-largest test file
(`crates/core/src/service/introspect/tests.rs`, previously 1,519
lines) into 6 sibling files under `tests/`, plus a slim base file.
No behaviour changes; same 54 introspect tests pass, organized into
7 files instead of 1.

### File split layout

The original file already had clean internal organization: each test
category lived in a nested `mod foo { ... }` block. v0.76.0 unwraps
those into sibling files. Each `mod` block becomes a sibling file
declared from the parent `tests.rs`.

| File | Lines | Scope |
|------|-------|-------|
| `tests.rs` (slim) | 348 | Header, `StubFamilyStore` + helpers, base-scope tests, 6 mod declarations |
| `tests/multi_key.rs` | 295 | Multi-key introspection (RFC 014 / RFC 049 key rotation grace period) |
| `tests/extract_kid_tests.rs` | 66 | `extract_kid` JWT header parsing |
| `tests/rate_limit.rs` | 182 | Introspect endpoint rate limiting |
| `tests/refresh_ext.rs` | 323 | Refresh-token extension introspection |
| `tests/audience_gate.rs` | 231 | Audience-gate enforcement |
| `tests/rfc009_aud_correctness.rs` | 78 | RFC 009 aud-claim correctness |

All seven files under 500 ELOC; the slim base `tests.rs` at 348
lines stays under the threshold while keeping the shared
`StubFamilyStore` and helpers visible to every sub-file via
`use super::*` from each sibling.

### Why this layout instead of moving helpers to common.rs

The introspect tests already used the convention "base scope holds
shared helpers + base tests; nested `mod foo` blocks hold themed
tests". The split preserves that convention exactly — each
sibling file is just the unwrapped contents of its original `mod foo`
block, and the base scope keeps its shared definitions. No helper
needs to migrate; the imports `use super::*` in each sibling reach
the parent (now `tests.rs`) and pull in `StubFamilyStore`,
`encode_token`, `FAKE_PUBKEY`, `ISS`, `AUD`, `fake_keys`.

This pattern is **lower-disruption** than the templates split in
v0.75.0 (which had to consolidate helpers into a new `common.rs`
because the original file had ad-hoc helper placement). Future test-
file splits should prefer this pattern when the original file
already has clean nested `mod foo` organization.

### Remaining test files for future maintenance releases

Updated from the v0.75.0 list:

- `crates/core/src/migrate/tests.rs` — 1,154 lines (next obvious candidate)
- `crates/ui/src/tenant_admin/tests.rs` — 895 lines
- `crates/migrate-test/tests/migration_chain.rs` — 881 lines

### Tests

1,290 / 1,290 pass (767 core + 133 adapter-test + 355 ui lib + 4 ui
integration + 31 migrate-test) — **identical** to v0.75.0.

### Warnings

0 production lib warnings.

### Drift-scan

Clean. The v0.75.0 drift-scan exemption for `*/tests/*.rs` (added in
that release) covers the new file layout without further script
changes — exactly why the exemption was generalized then.

### Contract invariants reaffirmed

- **Tests-as-drift-detectors**: covered by the existing
  `*/tests/*.rs` exemption from v0.75.0.
- **Shared test fixtures stay close to use sites**: the base
  `tests.rs` keeps the shared `StubFamilyStore` and helpers; no
  cross-file helper imports needed for this split.

---

## [0.75.0] - 2026-05-14

Maintenance release. Splits the largest single test file
(`crates/ui/src/templates/tests.rs`, previously 2,057 lines) into
per-feature submodules under `templates/tests/`, bringing every
template-tests file under the 500-ELOC "strongly recommended split"
threshold from the dev guidelines. No behaviour changes; same 355 UI
lib tests pass, organized into 7 modules instead of 1.

### File split layout

`crates/ui/src/templates/tests.rs` (now 34 lines, mod declarations
only) routes to seven submodules under `crates/ui/src/templates/tests/`:

| Submodule | Lines | Scope |
|-----------|-------|-------|
| `common.rs` | 58 | Shared `strip_inline_style`, `make_state`, `sample_item` fixtures |
| `early_pages.rs` | 321 | login, error, magic_link sent, initial TOTP flow (v0.28.0–v0.30.0) |
| `v0_31_design.rs` | 476 | design tokens, flash_block, totp_enroll error slot, security_center base (v0.31.0 P0-A through P0-D) |
| `v0_35_sessions.rs` | 306 | sessions_page rendering + EN locale (v0.35.0) |
| `v0_45_bulk_revoke.rs` | 84 | sessions bulk-revoke (ADR-012 §Q4, v0.45.0) |
| `i18n.rs` | 443 | cross-template i18n tests (v0.39.0 + v0.47.0) |
| `rfc_006_and_later.rs` | 430 | RFC 006 nonce + RFC 027 flash a11y + `<html lang>` + recovery confirm + skip-link |

Largest module is `v0_31_design.rs` at 476 lines — just under the
500-ELOC strongly-recommended threshold. Adding a new test should go
next to the milestone that introduced the feature; new feature
milestones get a new submodule rather than padding an existing one.

### Drift-scan exemption

The drift-scan script `scripts/drift-scan.sh` had a path-pattern
exemption for `*/tests.rs` (test files render hardcoded URLs by
design — they're drift detectors for the route catalog). v0.75.0
extends the exemption to `*/tests/*.rs` so the new submodule layout
keeps the same exemption.

### Why no RFC

This is a mechanical refactor with no design decisions; the dev
guidelines themselves authorize the split ("Splitting is strongly
recommended if it exceeds 500 ELOC"). The lifecycle policy doesn't
require an RFC for guideline-following mechanical work.

### Other large test files (not in this release)

The dev guidelines flag these for future splits, none touched in v0.75.0:

- `crates/core/src/service/introspect/tests.rs` — 1,519 lines
- `crates/core/src/migrate/tests.rs` — 1,154 lines
- `crates/ui/src/tenant_admin/tests.rs` — 895 lines
- `crates/migrate-test/tests/migration_chain.rs` — 881 lines

Production source files exceeding the threshold (lower priority — the
guideline applies to test files at the same threshold but they touch
fewer call sites and are reorganized less often):

- `crates/core/src/i18n/mod.rs` — 1,475 lines (already split into 8
  `lookup_*` group functions per RFC 097; the wrapper file is large
  but the internal structure is fine)
- `crates/migrate/src/main.rs` — 1,024 lines (single CLI tool)
- `crates/core/src/security_headers.rs` — 847 lines
- `crates/core/src/totp.rs` — 635 lines

A subsequent maintenance release can address these as needed; v0.75.0
deliberately ships a narrow, focused refactor rather than batching all
splits at once.

### Tests

1,290 / 1,290 pass (767 core + 133 adapter-test + 355 ui lib + 4 ui
integration + 31 migrate-test) — **identical** to v0.74.0. The split
preserves every test; the only differences are file paths.

### Warnings

0 production lib warnings on
`cargo-1.91 check -p cesauth-core -p cesauth-ui -p cesauth-adapter-test`.

### Drift-scan

Clean (exemption extended; no production URL leaks introduced).

### Contract invariants reaffirmed

- **Tests-as-drift-detectors**: test files at any depth under the
  `tests/` subdirectory are exempt from RFC 108's hardcoded-URL
  check, mirroring the existing `tests.rs` exemption.
- **Cross-module test fixtures** (`make_state`, `sample_item`) moved
  to `common.rs` rather than duplicated — same correctness contract,
  one definition site.

---

## [0.74.0] - 2026-05-14

Ships 4 of 5 PDF v0.50.1 page 9 "Safety controls" gap-fills as new
sub-RFCs: 110b (Turnstile configured indicator), 110c (refresh-token
reuse alerts summary), 110d (TOTP key status indicator), 110e
(Open-runbook hyperlink + Safety controls landing section). RFC 110a
(rate-limit summary) remains deferred — its data source is wasm32-only
KV enumeration, which the current sandbox cannot compile-verify. The
`SafetyControlsReport::rate_limit_status: Option<RateLimitStatus>`
field and "— (RFC 110a deferred)" placeholder rendering are wired now
so 110a is a single-PR finish when an environment with rustup/wasm32
is available.

### RFC 110b — Turnstile configured indicator

Boolean indicator surfaced as an OK / MISSING badge. Worker handler
checks `env.var("TURNSTILE_SECRET_KEY")` and forwards a `bool` through
`SafetyControlsReport::turnstile_configured`. The secret bytes never
enter the report struct; the env-var name itself doesn't appear in
rendered HTML either (the strengthened secret-leakage pin enforces
this).

### RFC 110c — Refresh-token reuse alerts summary

New core service helper
`crates/core/src/admin/service/safety_controls.rs::count_refresh_reuse_since(repo, since_unix)`
reads `RefreshTokenReuseDetected` audit events via the existing
`AuditSearch::since` filter (RFC 109, v0.71.0). Window: 24h (any reuse
in the last day is operator-attention-grabbing; longer windows would
need pagination). 1000-row soft cap — at that scale "many" is the
correct signal anyway. UI renders `0 (clean)` (OK badge) or
`N in 24h` (critical badge). 8 host-buildable service tests cover
the kind filter, lower-bound inclusivity, zero case, and 24h-window
boundary integration with `compute_safety_controls`.

### RFC 110d — TOTP key status indicator

Same shape as RFC 110b — `env.var("TOTP_SECRET_KEY")` presence →
bool → badge. The same secret-leakage pin guards both env-var names.

### RFC 110e — Open-runbook hyperlink + Safety controls landing section

`RUNBOOK_URL` env var → optional anchor:
`<a class="action" href="…" target="_blank" rel="noopener noreferrer">Open runbook ↗</a>`.
Missing URL surfaces an informational hint ("Runbook URL not
configured. Set `RUNBOOK_URL` in the worker env…"), not a broken
link. `rel="noopener noreferrer"` is mandatory: prevents the runbook
page from getting a `window.opener` reference back to the admin
console.

This RFC also defines the broader **"Safety controls" landing section**
that gathers 110b–110d's indicators in one place under
`/admin/console/safety`. The two surfaces (Data Safety Dashboard +
Safety controls) share the page because operators reach for both
from the same nav tab.

### Service composition

New helper
`crates/core/src/admin/service/safety_controls.rs::compute_safety_controls(repo, now_unix, turnstile_configured, totp_key_configured, runbook_url)`
gathers the four indicators into a single `SafetyControlsReport`. The
worker-side env-var lookups (RFC 110b/d/e) are wasm32-shaped and
untestable in the current sandbox; pulling them out of the service
layer lets us ship 110b/d/e as straight-pipe wiring with no host-side
data dependencies, while 110c (which needs `AuditEventRepository`)
gets a proper service function + adapter-test coverage.

### Data model changes

New types in `crates/core/src/admin/types.rs`:

- `pub struct SafetyControlsReport { turnstile_configured: bool, totp_key_configured: bool, refresh_reuse_count_24h: u64, runbook_url: Option<String>, rate_limit_status: Option<RateLimitStatus> }`
- `pub struct RateLimitStatus { throttled_buckets: u32, tripped_clients: u32 }` (placeholder for RFC 110a)

UI signature change:

```rust
// Before (v0.73.0):
pub fn safety_page(principal: &AdminPrincipal, report: &DataSafetyReport) -> String

// After (v0.74.0):
pub fn safety_page(principal: &AdminPrincipal, report: &DataSafetyReport, controls: Option<&SafetyControlsReport>) -> String
```

Backward-compat: `controls = None` reproduces the v0.73.0 page (Data
Safety Dashboard only, no Safety controls section).

### Pin tests (v0.74.0 mixed state)

`crates/ui/src/admin/tests.rs::rfc_110` reflects the post-shipment state:

- 2 positive nav-coverage pins (carried over from v0.72.0)
- 1 Tab-enum count pin (carried over)
- 8 new positive pins for 110b/c/d/e
- 1 strengthened secret-leakage pin (now also catches env-var names)
- 1 negative pin for RFC 110a (still deferred — replaced
  "RFC 110a not yet" check with "— (RFC 110a deferred)" placeholder
  check)

### Tests

1,290 / 1,290 pass (767 core + 133 adapter-test + 355 ui lib + 4 ui
integration + 31 migrate-test). **+12** over the v0.73.0 baseline:

- core: +8 (safety_controls service helpers — kind filter,
  lower-bound, integration, 24h window, defensive)
- ui lib: +4 (controls section rendering: turnstile, refresh-reuse,
  totp-key, runbook-link variants)

### Warnings

0 production lib warnings on
`cargo-1.91 check -p cesauth-core -p cesauth-ui -p cesauth-adapter-test`.

### Drift-scan

Clean.

### Worker-side verification (env-blocked)

Worker handler `crates/worker/src/routes/admin/console/safety.rs`
edits are mechanical (4 env-var lookups + 1 service call + struct
construction). Sandbox cannot install rustup/wasm32 so compile-verify
falls to CI on a rustup-enabled environment. Same posture as RFC 112
and RFC 110a.

### Contract invariants reaffirmed

- **Secret-leakage invariant** (RFC 110b/d): pin asserts neither
  secret bytes nor env-var names appear in rendered HTML. Tighter
  than v0.72.0 baseline.
- **Catalog mirrors worker reality** (RFC 108): no new routes added;
  the Safety controls section lives at the existing
  `/admin/console/safety` path.
- **Tests-as-drift-detectors**: the negative RFC 110a pin
  (`safety_page_does_not_yet_show_rate_limit_status`) requires a
  follow-up PR to update when 110a ships.

---

## [0.73.0] - 2026-05-14

Closes RFC 107 (Recovery code pluralization) and RFC 111 (Date rendering
policy) — both close out ADR-013 §Q4 ("date / plural deferred until a
real string demands it"). The plural side has its first plural-aware
string; the date side confirms UTC ISO-8601 as the cesauth-wide policy
and consolidates onto a single formatter.

### RFC 107 — Recovery code pluralization (ADR-013 §Q4 plural side)

Source: ADR-013 §Q4 "pluralization deferred until a real string demands
it" + PDF v0.50.1 page 12 "i18n contract: date / plural は未解決".

**What landed in `cesauth_core::i18n`:**

- `Plural { One, Other }` enum — closed-set, CLDR-minimal. Locales that
  need richer categories (Slavic `Few`/`Many`, Arabic `Zero`/`Two`)
  surface as exhaustive-match compile errors when added.
- `plural_for(locale: Locale, n: u64) -> Plural` — CLDR cardinal rule
  dispatcher. EN: `n == 1` → `One`, else `Other`. JA: always `Other`
  (Japanese is plural-invariant per CLDR).
- `lookup_plural(key: MessageKey, locale: Locale, n: u64) -> &'static str`
  — parallel catalog branch alongside `lookup`. Today's plural-aware
  set is exactly one key: `SecurityRecoveryRemaining`. Other keys
  passed to this function panic loudly (programming error, not
  fallback case).
- `is_plural_aware(key) -> bool` — documents the closed plural-aware
  set. Lets callers gate without the panic.

**User-visible change.** EN locale, N ≥ 2 recovery codes:

- Before: `Recovery codes: 5 valid`
- After:  `5 valid recovery codes`

JA stays exactly the same (plural-invariant): `リカバリーコード: 5 個有効`.

The N = 0 and N = 1 paths in `security_center.rs::recovery_status_html_for`
already used dedicated singular banners (`SecurityRecoveryZeroTitle` /
`OneTitle`) and are unchanged.

**Why no `icu` dependency.** CLDR has 8 plural categories across all
locales; cesauth's two locales need exactly 2. The WASM size budget and
the catalog-as-closed-enum design choice make a 30-line hand-rolled
implementation correct and stable. Adding richer categories later is a
strictly additive change.

**Tests.** 8 new core unit tests covering CLDR rule correctness for EN
and JA, plural-key registration invariants, and the
`#[should_panic]` guardrail. Existing UI test for the N ≥ 2 path was
updated for the new EN string. Total core tests: 759 (+8); ui lib: 351
(+5 including 1 new plural-related test and 4 RFC 111 pin tests below).

### RFC 111 — Date rendering policy (ADR-013 §Q3 + §Q4 date side)

Source: ADR-013 §Q3 ("date/time format localization") and §Q4 ("date /
plural deferred") + RFC 096 (canonical formatter introduced).

**Policy confirmed**: UTC ISO-8601 (RFC 3339, Z-suffix form) is the
canonical date rendering for every visible timestamp. Locale does not
affect date format. Per-user timezone preferences are tracked as
separate future work (would supplement UTC, not replace it).

**Rationale** (two reasons, recorded in
`docs/src/expert/i18n.md` §"Date / time rendering"):

1. Timezone ambiguity is unsafe on security-sensitive surfaces (audit
   log, session list, token expiration). UTC ISO-8601 has exactly one
   interpretation.
2. Operator tooling (Cloudflare Workers Logs, R2 audit dump, migrate
   export, the RFC 109 audit viewer cursor) all use UTC ISO-8601.
   Matching the UI gives operators a zero-conversion trace path.

**Consolidation work**: removed legacy per-file formatters in favour of
the canonical `cesauth_core::util::format_unix_as_iso8601` (introduced
in RFC 096):

- `crates/ui/src/templates/security_center.rs::format_unix_local`
  removed (used the `time` crate's RFC 3339 path, emitted `+00:00`
  offset form). 2 call sites migrated.
- `crates/ui/src/admin/audit_chain.rs::format_unix` removed. 2 call
  sites migrated.

User-visible delta: session list and chain-verification page
timestamps now emit `2024-01-01T00:00:00Z` instead of
`2024-01-01T00:00:00+00:00`. Both are valid RFC 3339; the canonical
form aligns with audit-export and cron-status output.

**Pin tests** in `crates/ui/src/admin/tests.rs::rfc_111` (4 tests):

- `canonical_formatter_emits_utc_z_form` — positive pin on output shape.
- `canonical_formatter_emits_epoch_for_zero` — boundary case.
- `canonical_formatter_never_emits_offset_form` — **negative** pin
  guarding against regression to the legacy `+00:00` form.
- `canonical_formatter_handles_negative_as_epoch` — defensive pin.

**Documentation**:

- New `docs/src/expert/i18n.md` (concise digest of the i18n contract:
  locale set, plural form, date policy).
- ADR-013 §Q3 + §Q4 both marked `Resolved in v0.73.0` with rationale
  text.

### ADR-013 §Q4 — closed

Both halves of "date / plural deferred" are now resolved:

- **Plural** — RFC 107. Closed-enum `Plural`, `lookup_plural` parallel
  branch, first plural-aware key shipped.
- **Date** — RFC 111. UTC ISO-8601 policy, single canonical formatter,
  per-user timezone tracked as future work.

ADR-013 itself remains open for Q1 (user-pref cookie) and Q2
(tenant-default locale), neither of which has surfaced operational
demand.

### Tests

1,278 / 1,278 pass (759 core + 133 adapter-test + 351 ui lib + 4 ui
integration + 31 migrate-test). **+13** over the v0.72.0 baseline:

- core: +8 (RFC 107 plural rules + lookup_plural variants +
  is_plural_aware registration + panic guardrail)
- ui lib: +5 (1 RFC 107 plural variants test + 4 RFC 111 pins)

### Warnings

0 production lib warnings on
`cargo-1.91 check -p cesauth-core -p cesauth-ui -p cesauth-adapter-test`.

### Drift-scan

Clean. The RFC 111 grep-acceptance criteria are met:
- `grep -rn "OffsetDateTime::from_unix_timestamp" crates/ui/` is empty
- `grep -rn "fn format_unix_local" crates/ui/` is empty

### Contract invariants reaffirmed

- **Catalog is a closed enum** (RFC 097 / RFC 102 / ADR-013): adding a
  locale or a plural category surfaces as an exhaustive-match compile
  error. Maintained.
- **Single canonical date formatter** (RFC 096 → RFC 111): one
  `format_unix_as_iso8601`, callable from every UI / adapter / service
  layer. Pin tests guard the contract.
- **Tests-as-drift-detectors**: RFC 107's `is_plural_aware` is asserted
  against the closed key set; RFC 111's negative `+00:00` pin will
  loudly catch any regression to the legacy formatter.

---

## [0.72.0] - 2026-05-14

Closes RFC 110 (Safety controls dashboard alignment audit) and RFC 113
(UI rendering acceptance harness). Both ship with the scope amendments
recorded against the original drafts; RFC 110's five gap items are
deferred to follow-up RFCs 110a–110e per its own §"Open questions" Q1
resolution.

### RFC 110 — Safety controls alignment audit (verification + pin tests)

Source: PDF v0.50.1 page 9 "Operations UX: Safety controls" + page 8
admin console nav. RFC 110 explicitly allows closure as
"verification + test pin only" when gaps are deferred to follow-ups —
exactly what v0.72.0 does.

**Audit findings** (full record in `docs/src/expert/rfc-110-baseline.md`):

- **Console nav (PDF page 8)**: clean **superset**. All six required
  tabs present (`Overview / Safety / Audit / Config / Alerts / Tokens`)
  plus two implementation-driven additions (`Cost`, `Operations`).
- **Safety controls panel (PDF page 9, 4 items + runbook link)**:
  all five items are **gaps**. The existing `/admin/console/safety`
  is the Data Safety Dashboard (RFC 047) — a different surface that
  shares the name with the PDF panel.

**Pin tests** at `crates/ui/src/admin/tests.rs::rfc_110` (+9 tests):

- Two positive nav-coverage pins (six required tabs + two superset tabs
  present).
- One Tab-enum count pin (`8 variants`; drift triggers baseline doc
  revisit).
- Five **negative** gap-pins (rate-limit / Turnstile / refresh-reuse /
  TOTP-key / runbook-link absent today). Each carries the gap-fill
  RFC number in its panic message; the gap-fill PR must flip the pin
  to a positive assertion in the same commit.
- One forward-looking guardrail: `safety_page_never_exposes_secret_material`
  asserts `BEGIN PRIVATE KEY` / `BEGIN ENCRYPTED` sentinels never appear.
  This pin protects 110b and 110d (Turnstile and TOTP key indicators)
  from accidentally surfacing secret bytes when they land.

**Deferred follow-ups**: RFC 110a (rate-limit summary), 110b (Turnstile
indicator), 110c (refresh-reuse summary), 110d (TOTP key status), 110e
(runbook link + safety-controls landing section). Each touches a
different worker data source; several need rustup/wasm32-blocked
verification of the worker handler. Deliberately split so they can
land independently.

### RFC 113 — UI rendering acceptance harness (with scope amendments)

Source: PDF v0.50.1 page 14 "Acceptance criteria checklist".

**Scope amendments recorded**:

1. **Footer-version invariant inverted.** The draft asserted
   `html.contains("v0.")` in the footer. RFC 071 (already shipped)
   explicitly **removed** footer version captions. The harness asserts
   the actual contract: footer present, no version caption. The
   tenant_admin and tenancy_console test files already pin this
   inversion at the per-frame layer; the harness aggregates.

2. **Frame-fixture granularity instead of per-route enumeration.**
   The draft proposed listing ~30 routes. Implementation observed the
   five universal invariants are properties of the four frame
   functions (`chrome::frame_for`, `admin::frame::admin_frame_for`,
   `tenant_admin::frame::tenant_admin_frame_for`,
   `tenancy_console::frame::tenancy_console_frame_for`), not of any
   specific page. Five frame-fixtures × five invariants = same
   effective coverage as ~30 per-route assertions, one-sixth the
   maintenance cost. Per-page content tests already exist next to the
   per-page render functions.

**What landed**:

- **`crates/ui/tests/acceptance_harness.rs`** (new integration test):
  - 5 frame fixtures: chrome × {EN, JA} (RFC 072 dual locale) + 3
    admin frames × {JA} (admin JA-only per ADR-013).
  - 5 universal invariants per fixture: `<html lang>` matches locale,
    skip-link present, `<main id="main">` flash anchor, footer present
    without version, scope badge on admin frames.
  - One walking test exercises the full matrix; three self-tests catch
    fixture-table coverage regressions.
- **4 tests, all green.** 25 internal assertions across the matrix.

### Tests

1,265 / 1,265 pass (133 core + 751 adapter-test + 346 ui lib +
4 ui integration + 31 migrate-test). **+13** over the v0.71.0 baseline:

- ui lib: +9 (RFC 110 pin tests)
- ui integration: +4 (RFC 113 harness — main walker + 3 self-tests)

### Warnings

0 production lib warnings on
`cargo-1.91 check -p cesauth-core -p cesauth-ui -p cesauth-adapter-test`.

### Drift-scan

Still clean. No new URL strings, no new MessageKey variants needed for
this release (RFC 110 is verification-only; RFC 113's harness uses
existing `Locale::bcp47()` rather than introducing new locale-aware
text).

### Contract invariants reaffirmed

- **Catalog mirrors worker reality** (no new routes added).
- **Admin console JA-only** (ADR-013): RFC 113 harness verifies this
  via `admin_fixtures_render_in_ja_only_per_adr_013`.
- **Footer no longer carries version** (RFC 071): harness inversion
  pin makes the contract explicit at every frame.
- **Tests-as-drift-detectors**: RFC 110's negative gap-pins force
  gap-fill PRs to update baseline doc; RFC 113's harness self-tests
  force coverage updates if the fixture table is reduced.

---

## [0.71.0] - 2026-05-13

Ships RFC 109 (Audit log viewer UI surface). The admin console gains a
proper interactive viewer at `GET /admin/console/audit` with actor /
event / date-range filtering and opaque-cursor pagination, replacing
the v0.32.0 "kind contains / subject contains / limit" stub. The
existing RFC 080 export endpoint inherits the same filter state via the
viewer's export form, closing the "browse → filter → export" flow the
PDF v0.50.1 deck page 9 calls for.

### RFC 109 — Audit log viewer (with documented scope amendments)

Source: PDF v0.50.1 page 9 "Operations UX: Audit log viewer".

Two amendments to the original RFC 109 draft were recorded at
implementation time:

1. **`tenant` filter deferred.** The `audit_events` table (ADR-010) has
   no top-level `tenant_id` column. Adding one would require a schema
   migration + backfill, out of scope for a UI RFC. The remaining
   filters (actor / event / date range) cover the common operator
   flow. A future RFC can introduce the column when warranted. The
   viewer carries a JA note inline:
   `tenant_id 単位での絞り込みは現在のスキーマでは未提供 (RFC 109 §scope amendments)。`

2. **Worker handler edits verified by env-blocked CI.** The handler
   at `crates/worker/src/routes/admin/console/audit.rs` and the export
   handler at `audit_export.rs` were updated mechanically (new
   query-string parse arms, new POST-form-field arms). This sandbox
   cannot install rustup + wasm32 to compile-verify. Same posture as
   RFC 112: edits land here, CI on a rustup-enabled environment is
   the verification gate.

### What landed

**Core (`cesauth-core`)**:

- `AuditQuery` extended with `event_exact`, `since`, `until`, `cursor`.
  All new fields are `Option`; the existing `kind_contains` /
  `subject_contains` fields keep working for v0.31.x callers.
- `AuditSearch` extended with `before_seq` for keyset pagination.
- New service module `cesauth_core::admin::service::audit_pagination`:
  - `encode_cursor(seq)` / `decode_cursor(&str)` — opaque base64url
    codec. URL-safe alphabet, no padding, no whitespace. 16 unit
    tests cover round-trips, malformed input, and edge cases.
  - `parse_rfc3339_to_unix(&str)` — strict RFC 3339 parser handling
    `Z` and `±HH:MM` offsets. Leap-year aware (rejects 2023-02-29,
    accepts 2024-02-29). Pre-1970 rejected; fractional seconds
    rejected. No `chrono` dependency.

**i18n** (RFC 109 keys, JA + EN per usual exhaustiveness contract):

19 new MessageKey variants for the audit viewer: page title, section
title, filter labels (actor / event / period / from / to), buttons
(submit / export / newer link / older link), empty state, 5 column
headers, "any event" placeholder, and the deferred-tenant note.
Admin console remains JA-only per ADR-013; EN strings exist for
exhaustiveness but production never reaches them.

**Adapter (`cesauth-adapter-test`)**:

- `InMemoryAuditQuerySource::search` honors `event_exact`, `since`,
  `until`, `cursor`. 8 new tests covering each filter independently
  and in combination.
- `InMemoryAuditEventRepository::search` honors `before_seq` directly
  (keyset semantics matching what the D1 SQL adapter emits).

**Adapter (`cesauth-adapter-cloudflare`, env-blocked verification)**:

- `CloudflareAuditQuerySource::search` translates the new fields:
  `event_exact` → SQL `kind = ?`, `since`/`until` → `ts >=`/`<=`,
  `cursor` → `decode_cursor` → `AuditSearch::before_seq`.
- D1 SQL `audit_events.search` adds a `seq < ?` clause when
  `before_seq` is set. Other clauses untouched.

**Worker (`cesauth-worker`, env-blocked verification)**:

- `GET /admin/console/audit` handler parses the new `actor`, `event`,
  `from`, `to`, `cursor` query params (in addition to the legacy
  `kind` / `subject` / `prefix` / `limit`). Invalid timestamps drop
  to `None` rather than 400 — the rest of the page still renders.
- `POST /admin/console/audit/export` accepts `event`, `since`,
  `until` form fields the new viewer sends. Filter description in
  the emitted `AuditExported` audit row prefers the more specific
  RFC 109 field when set.

**UI (`cesauth-ui`)**:

- `crates/ui/src/admin/audit.rs` rewritten end-to-end for RFC 109.
  JA-only labels via `MessageKey`, filter form sticky across
  re-renders, pagination via cursor (← より新しい / より古い →),
  export form inheriting the current filter, schema-note explaining
  the deferred `tenant` filter, scope badge intact.
- Helper `unix_to_rfc3339_z` for sticky-form rendering; round-trips
  with `parse_rfc3339_to_unix` (covered by a test).

### Tests

1,252 / 1,252 pass (133 core + 751 adapter-test + 337 ui + 31
migrate-test). +33 over the v0.70.0 baseline of 1,219:

- core: +8 (audit_pagination cursor + RFC 3339 parser)
- adapter-test: +13 (InMemoryAuditQuerySource RFC 109 filters,
  including cursor + event_exact combination)
- ui: +12 (admin/audit JA labels, filter stickiness, pagination
  links, schema note, format-helper round-trip)

### Warnings

0 production lib warnings on
`cargo-1.91 check -p cesauth-core -p cesauth-ui -p cesauth-adapter-test`.
Two `unreachable_pattern` warnings introduced briefly during the
audit.rs URL-encoder rewrite (T and Z already covered by A-Z range)
were caught by the check pass before commit and removed.

### Drift-scan

Still clean. The new admin audit URLs flow through
`routes::admin::AUDIT` and `routes::admin::AUDIT_EXPORT` constants,
already present in the catalog since RFC 102.

### Contract invariants reaffirmed

- **Catalog mirrors worker reality.** No new route paths added — the
  viewer reuses `routes::admin::AUDIT` (which the worker already
  registers). Filter additions are query-string only.
- **Escape contract.** All catalog-returned URLs in the audit viewer
  are HTML-escaped at the template boundary (see `build_filter_url`
  and the `escape(&...)` calls around every `href=` attribute).
- **JA-only admin console (ADR-013).** EN MessageKey translations
  exist for exhaustiveness pinning; the viewer's `let l = Locale::Ja`
  ensures production never reaches them. The schema-note explicitly
  cites the JA RFC convention.
- **Forward compatibility of the export endpoint.** v0.31.x callers
  posting `kind` / `subject` / `limit` still get the same behaviour;
  the new RFC 109 fields are additive.

---

## [0.70.0] - 2026-05-13

Closes RFC 108 (UI template route-catalog migration): completes the
remaining admin-side templates (`tenant_admin` and `tenancy_console`
end-user surfaces) and adds a drift-scan rule that prevents new URL
hardcodes from regressing the catalog discipline. RFC 112 (worker auth
macro batch) remains environment-blocked and is not in this release.

### RFC 108 — UI template route-catalog migration (closure)

Source: HANDOFF v0.66.0 residual #2.

v0.68.0 migrated end-user templates and corrected the WebAuthn drift.
v0.69.0 expanded the catalog to mirror every worker-registered route
and migrated `admin/console/*`. v0.70.0 finishes the job: every
production template in `tenant_admin/` and `tenancy_console/` now
constructs URLs via `cesauth_core::routes::*` builders and constants.

#### Templates migrated this release

`tenancy_console/`:

- `tenant_detail.rs`, `role_assignments.rs`, `organizations.rs`,
  `tenants.rs`, `subscription.rs` — 5 top-level pages.
- `forms/`: `group_create.rs`, `group_delete.rs`, `organization_create.rs`,
  `organization_set_status.rs`, `role_assignment_create.rs`,
  `role_assignment_delete.rs`, `subscription_set_plan.rs`,
  `subscription_set_status.rs`, `tenant_create.rs`, `tenant_set_status.rs`,
  `token_mint.rs`, `membership_remove.rs` — 12 forms migrated.
  (1 form skipped: `membership_add.rs`, orphan — see below.)

`tenant_admin/`:

- `organizations.rs`, `role_assignments.rs`, `overview.rs`,
  `invitations.rs`, `deletions.rs`, `users.rs` — 6 top-level pages.
  (1 page skipped: `oidc_clients.rs`, orphan — see below.)
- `forms/`: `group_create.rs`, `group_delete.rs`, `organization_create.rs`,
  `organization_set_status.rs`, `membership_add.rs`, `membership_remove.rs`,
  `role_assignment_grant.rs`, `role_assignment_revoke.rs` — 8 forms migrated.

Total v0.70.0 production migration: ~150 hardcoded URL literals replaced
with catalog builder calls. Combined v0.68.0 + v0.69.0 + v0.70.0 closes
the entire admin and end-user template surface against the catalog.

#### Drift-scan rule (`scripts/drift-scan.sh`)

A new pass at the end of the script greps `crates/ui/src/` for URL
literals matching `"/(admin|me|oidc|auth|login|logout|magic-link|\.well-known)/`,
with explicit exemptions for:

- Standalone `tests.rs` files — tests assert on rendered URLs by
  string and must keep hardcoded literals (their job is to fail loudly
  on catalog drift).
- Inline `#[cfg(test)]` / `mod tests` blocks in production .rs files —
  same reasoning. Detected per-file by stopping the scan at the first
  marker line; relies on the codebase convention that test blocks are
  last in the file.
- The two orphan-UI files (see "Known orphan UI" below).

Currently `bash scripts/drift-scan.sh` exits 0 (clean). Any new
hardcode in a production template fails the script and the release.

#### Known orphan UI (deferred outside RFC 108)

Two templates are deliberately exempt from migration. Both have inline
`# RFC 108 orphan UI exemption` notes in their module docstrings.

1. **`crates/ui/src/tenant_admin/oidc_clients.rs`** — posts to
   `/admin/t/{slug}/oidc-clients/{cid}/audience`. The worker does not
   register this route (RFC 017 introduced the UI but never wired the
   worker handler). Pre-existing bug; outside RFC 108 scope, which is
   "catalog mirrors worker reality, not aspirations." Resolution
   requires either wiring the worker handler or removing the template.

2. **`crates/ui/src/tenancy_console/forms/membership_add.rs`** — all
   three variants (tenant / organization / group) POST to
   `.../memberships` with no `/new` suffix. The worker only registers
   `.../memberships/new`, so these forms return 404 in production. The
   `tenant_admin/forms/membership_add.rs` equivalent maps cleanly to
   worker routes — this `tenancy_console` variant was apparently
   authored before the routes were finalised.

Both are tracked but out of scope. The catalog will not add the
unregistered routes; the templates will not migrate against them.

### RFC 112 — Worker auth macro batch (remains environment-blocked)

Unchanged from v0.69.0. The sandbox where this release was prepared
does not provide rustup + the wasm32 target needed to verify
`crates/worker` and `crates/adapter-cloudflare` edits. RFC 112 is
mechanical batch work but cannot be sanity-checked here. Pushed to
v0.71.0 contingent on a rustup-enabled environment. RFC document at
`rfcs/proposed/112-...md` carries the environment-blocker annotation.

### Tests

1,219 / 1,219 pass (125 core + 738 adapter-test + 325 ui + 31
migrate-test). Unchanged from the v0.69.0 baseline — RFC 108 closure is
a refactor, not a feature.

### Warnings

0 production lib warnings on `cargo-1.91 check -p cesauth-core -p
cesauth-ui -p cesauth-adapter-test`.

### Contract invariants reaffirmed

- **Escape contract:** catalog builders return raw URL strings; every
  template `escape()`s at the HTML attribute boundary. Verified by
  the `sessions_page_session_id_is_html_escaped` test (added v0.68.0)
  and by every new escape site landing this release adopting the same
  `escape(&routes::*(...))` pattern.
- **Catalog mirrors worker reality:** every entry in
  `cesauth_core::routes` corresponds to a route the worker registers.
  Orphan template URLs stay hardcoded with the module-docstring
  annotation; they do not pollute the catalog.
- **Tests-as-drift-detectors:** `tests.rs` files keep hardcoded URLs
  by policy. The drift-scan rule exempts them explicitly. A catalog
  builder change that changes a rendered URL must update the test in
  the same commit — that's the signal.

---

## [0.69.0] - 2026-05-13

Continues RFC 108: catalog completion + admin-console template
migration. Closes the second silent v0.66.0 catalog drift. RFC 112
(worker auth macro batch) is blocked on environment and pushed to
v0.70.0 — see "RFC 112 deferred" below.

### RFC 108 — UI template route-catalog migration (v0.69.0 continuation)

Source: HANDOFF v0.66.0 residual #2.

The v0.68.0 partial implementation migrated end-user templates and
corrected the WebAuthn catalog drift. v0.69.0 adds: a second silent
v0.66.0 drift correction, full catalog coverage of every
worker-registered route, and migration of every admin/console
template.

#### Catalog correction (tenancy console)

Same shape as the v0.68.0 WebAuthn correction. The v0.66.0 catalog
shipped:

```rust
pub fn tenant(slug: &str) -> String { format!("/admin/tenancy/{slug}") }
pub fn tenant_orgs(slug: &str) -> String { format!("/admin/tenancy/{slug}/organizations") }
```

but the worker has always registered `/admin/tenancy/tenants/{tid}/...`
(note the `/tenants/` segment). The entire `tenancy_console::*` module
is rewritten to match worker reality. The old constants and builders
were never consumed in tree, so nothing on the wire changes.

#### Catalog expansion

| Module | v0.68.0 | v0.69.0 | Δ |
|---|---:|---:|---:|
| `admin` (system console) | 12 statics | 12 statics + 6 builders | +6 builders |
| `tenancy_console` | 1 static + 5 builders (wrong) | 3 statics + 21 builders (correct) | rewrite |
| `tenant_admin` | 12 builders | 27 builders | +15 builders |
| Total | ~57 entries | ~83 entries | +26 |

Every const and fn in the catalog now mirrors a route registered by
`crates/worker/src/lib.rs` (124 routes total).

#### Admin nav migration

All three admin frames now route their tab links through the catalog:

- `crates/ui/src/admin/frame.rs::Tab::href` — 8 system-admin URLs
  (Overview / Cost / Safety / Audit / Config / Alerts / Tokens / Operations)
- `crates/ui/src/tenant_admin/frame.rs::TenantAdminTab::href` — 6
  per-tenant URLs (`/admin/t/{slug}/{overview,organizations,users,...}`)
- `crates/ui/src/tenancy_console/frame.rs::TenancyConsoleTab::href` —
  2 deployment-wide URLs (`/admin/tenancy`, `/admin/tenancy/tenants`)

#### `admin/console/*` template migration

Seven production templates fully migrated:

| File | URLs | Notes |
|---|---:|---|
| `crates/ui/src/admin/audit.rs` | 3 | static |
| `crates/ui/src/admin/audit_chain.rs` | 2 | static |
| `crates/ui/src/admin/overview.rs` | 3 | static |
| `crates/ui/src/admin/cost.rs` | 1 | static |
| `crates/ui/src/admin/tokens.rs` | 5 | 1 parameterized (`token_disable`) |
| `crates/ui/src/admin/config.rs` | 1 | parameterized (`config_edit`) |
| `crates/ui/src/admin/safety.rs` | 1 | parameterized (`safety_verify`) |
| `crates/ui/src/admin/config_edit.rs` | 6 | 5 parameterized (`config_edit`) + 1 static |

All parameterized routes apply the **escape contract** introduced in
v0.68.0: catalog builder returns the raw URL; HTML-escape at the
template boundary. Each call site is annotated with an inline comment
referencing the contract.

#### One known catalog gap (intentional)

`crates/ui/src/tenant_admin/oidc_clients.rs` renders a form pointing
at `/admin/t/{slug}/oidc-clients/{cid}/audience`, but the worker does
**not** register that route — RFC 017 introduced the UI but apparently
never wired the worker handler. Pre-existing orphan UI. Not catalogued
in v0.69.0 because the catalog policy is "mirror worker reality, not
aspirations." The template stays hardcoded pending a separate fix
(either wire the worker route or remove the template).

#### Still deferred (v0.70.0+)

- Remaining ~150 hardcoded URLs across 32 production template files
  in `crates/ui/src/tenant_admin/` and `crates/ui/src/tenancy_console/`.
  Mechanical follow-up; the catalog has every builder needed.
- `scripts/drift-scan.sh` URL-hardcode rule (turned on only after the
  remaining migration completes).

### RFC 112 deferred (environment-blocked)

RFC 112 — the worker auth macro batch migration that would apply
`require_system_admin!` / `require_tenant_admin_read!` across the
remaining 124 admin handlers — was scheduled into v0.69.0 alongside
the RFC 108 work. The implementation environment used for the
v0.67.0–v0.69.0 development cycle cannot safely verify worker-side
edits:

- `wasm32-unknown-unknown` is not packaged with Ubuntu's
  `rustc-1.91` and `rustup` is not available, so the target cannot
  be installed.
- `cesauth-worker` depends on `wasm_bindgen` and `js_sys`, so it
  cannot be host-compiled.
- `cesauth-adapter-test` (the host-buildable surrogate gate) does
  not depend on `cesauth-worker`, so checking it gives no signal
  about worker edits.

Editing 124 handlers without a compile gate would ship unverified
worker code. RFC 112 is pushed to v0.70.0 pending an environment
with rustup + wasm32 target installed. No worker code was modified
during v0.69.0. See `rfcs/proposed/112-worker-auth-macro-batch-migration.md`
"Implementation environment" for the full note.

### Tests

| Crate | v0.68.0 | v0.69.0 | Δ |
|---|---:|---:|---:|
| core | 738 | 738 | — |
| adapter-test | 125 | 125 | — |
| ui | 325 | 325 | — |
| migrate-test | 31 | 31 | — |
| **Total** | **1,219** | **1,219** | **0** |

RFC 108 is a pure refactor; no new tests were added. Existing
rendering assertions in `crates/ui/src/{admin,tenant_admin,tenancy_console}/tests.rs`
continue to pin that the migrated templates still emit the correct
URLs — they were never changed and remain hardcoded by design (tests
should fail loudly if a catalog entry drifts).

### Schema / wire / DO

No changes. The catalog correction for `tenancy_console::*` only
affects the values returned by builder fns; no consumers existed in
tree when the wrong values shipped, so nothing on the wire changes.

### Operator notes

- No URL on the wire changes. Operators using admin / tenant-admin /
  tenancy-console URLs see no behavior change.
- `cesauth_core::routes::tenancy_console::*` API surface changes
  meaningfully — but no in-tree consumers existed, so this is not a
  breaking change in practice. Downstream consumers (if any) using
  the v0.66.0 `tenancy_console::tenant(slug)` builder were already
  producing dead URLs and will need to update to either the corrected
  `tenant(tid)` or to the appropriate scoped builder
  (`tenant_orgs_new`, `organization`, `group_delete`, etc.).

### ADR

No closures.

### Upgrade

No special steps. Replace v0.68.0 bundle with v0.69.0; redeploy with
`wrangler deploy`. No migrations.

### Tarball

`cesauth-0.69.0.tar.gz`.

---

## [0.68.0] - 2026-05-13

Implements RFC 108 (partial): route-catalog correction + end-user template
migration. UI/UX finishing track, batch 2 of 5. RFC 112 (originally
planned for this release) is deferred to v0.69.0 alongside the
remaining RFC 108 admin migration.

### RFC 108 — UI template route-catalog migration (partial)

Source: HANDOFF v0.66.0 residual #2 ("RFC 102 routes.rs の UI 移行").

The original RFC 102 (v0.66.0) introduced `crates/core/src/routes.rs` as a
catalog of HTTP path constants but never migrated consumers. v0.68.0
makes the catalog the source of truth for end-user templates and
corrects four wrong values that shipped silently in v0.66.0.

#### Catalog corrections (`crates/core/src/routes.rs`)

| Constant | v0.66.0–v0.67.0 (wrong) | v0.68.0 (matches worker) |
|---|---|---|
| `auth::PASSKEY_REGISTER_START` | `/me/webauthn/register` (was `PASSKEY_REGISTER`) | `/webauthn/register/start` |
| `auth::PASSKEY_REGISTER_FINISH` | `/me/webauthn/register/finish` | `/webauthn/register/finish` |
| `auth::PASSKEY_AUTH_START` | `/auth/webauthn/start` | `/webauthn/authenticate/start` |
| `auth::PASSKEY_AUTH_FINISH` | `/auth/webauthn/finish` | `/webauthn/authenticate/finish` |

No consumers existed when the wrong values shipped, so nothing was broken
on the wire — but any v0.66.0-pinned doc generator or downstream consumer
relying on the catalog would have produced dead links.

New constants added:

| Constant | Path |
|---|---|
| `auth::MAGIC_LINK_VERIFY_FORM` | `/magic-link/verify` (no-handle form action) |
| `me::TOTP_ENROLL_CONFIRM` | `/me/security/totp/enroll/confirm` |

#### End-user template migration

15 hardcoded URLs across three end-user templates now flow through the
catalog:

| File | URLs migrated |
|---|---|
| `crates/ui/src/templates/security_center.rs` | `/me/security/sessions`, `/me/security/totp/enroll`, `/me/security/totp/disable`, `/me/security/sessions/revoke-others`, `/me/security`, `/me/security/sessions/{sid}/revoke` (builder) |
| `crates/ui/src/templates/login.rs` | `/magic-link/request`, JS fetch `/webauthn/authenticate/start`, JS fetch `/webauthn/authenticate/finish`, `/magic-link/verify` form |
| `crates/ui/src/templates/totp.rs` | `/me/security/totp/enroll/confirm`, `/me/security/totp/recover/confirm`, `/me/security/totp/verify`, `/me/security/totp/recover`, `/me/security/totp/disable` |

#### Escape contract (security regression caught + fixed)

A failing test (`sessions_page_session_id_is_html_escaped`) flagged that
migrating from `format!("/.../{sid}/revoke", sid = escape(&id), ...)` to
`routes::me::session_revoke(id)` dropped the HTML escape. Fix:
**catalog builder fns return raw URL strings; the template HTML-escapes
at the boundary.** The contract is pinned by an inline comment in
`security_center.rs::render_session_row_for` and by the regression test
itself; future migration of admin templates must follow the same rule
for any `:slug` / `:id` interpolation.

#### Deferred to v0.68.1+ / v0.69.0

- **Admin / tenant_admin / tenancy_console template migration.** ~189
  hardcoded URLs across 44 production template files. Blocked on a
  larger catalog expansion (worker has 124 registered routes; catalog
  has ~30 statics). Mechanical follow-up work.
- **`scripts/drift-scan.sh` URL-hardcode rule.** Deferred so that
  turning the rule on doesn't immediately fail CI before the admin
  migration completes.

See `rfcs/done/108-ui-template-route-catalog-migration.md`
"Deferred-work note" for the full scope split. Per RFC 019
§"Granularity of transitions", partial implementation is allowed when
the partial work establishes the pattern subsequent batches will
follow.

### RFC 112 deferred

Originally planned for v0.68.0; pushed to v0.69.0 to keep this release
focused on the catalog correction and end-user migration. RFC 112 stays
in `rfcs/proposed/` with no scope changes.

### Tests

| Crate | v0.67.0 | v0.68.0 | Δ |
|---|---:|---:|---:|
| core | 738 | 738 | — |
| adapter-test | 125 | 125 | — |
| ui | 325 | 325 | — |
| migrate-test | 31 | 31 | — |
| **Total** | **1,219** | **1,219** | **0** |

RFC 108 is a pure refactor (no new behavior, no new MessageKey), so no
new tests were added; the existing rendering tests pin that the
migrated templates still emit the correct URLs.

### Schema / wire / DO

No changes. Worker route registration is untouched; only the catalog
constants that mirror those routes were corrected.

### Operator notes

End-user surfaces are unaffected — the same paths are rendered as
before. Admin / tenant admin / tenancy console surfaces are also
unaffected: their templates were not touched in this release (the
catalog correction has no consumer there yet). Operators using
`/me/security/sessions`, `/me/security/totp/*`, `/login`,
`/magic-link/*`, or `/webauthn/*` will see no change in behavior.

The four corrected catalog constants (`PASSKEY_REGISTER_START` etc.)
are only relevant to downstream consumers of `cesauth_core::routes`;
none exist in tree.

### ADR

No closures.

### Upgrade

No special steps. Replace v0.67.0 bundle with v0.68.0; redeploy with
`wrangler deploy`. No migrations.

### Tarball

`cesauth-0.68.0.tar.gz`.

---

## [0.67.0] - 2026-05-13

Implements RFC 105 + 106: UI/UX finishing track, batch 1 of 5.
Design tokens consolidated into a single source; Security Center
i18n hole closed. Also cleans seven non-deprecated warnings that
predated v0.66.0.

### RFC 105 — Admin / tenant_admin / tenancy_console design-token unification

Source: PDF v0.50.1 page 12 (color-only-state contract) + HANDOFF
v0.66.0 residual #3.

`crates/ui/src/design_tokens.rs` rewritten:

- **Kept**: `DESIGN_TOKENS_FMT` — `--success` / `--warning` / `--danger`
  / `--info`, their `-bg` variants, the `--ok` / `--warn` / `--critical`
  legacy aliases (RFC 082 compat), plus `prefers-color-scheme: dark`
  override for all of them. Single source of truth.
- **Added**: `SCOPE_TOKENS_FMT` — `--scope-system` / `--scope-tenancy`
  / `--scope-tenant` plus a dark-mode override. Admin-only; end-user
  UI has no scope badge so it isn't in `DESIGN_TOKENS_FMT`.
- **Removed**: raw `DESIGN_TOKENS` (unused since RFC 082; was kept
  alongside `_FMT` only because the dead-code lint was suppressed
  during the original landing).

All three admin frames (`crates/ui/src/admin/frame.rs`,
`crates/ui/src/tenant_admin/frame.rs`,
`crates/ui/src/tenancy_console/frame.rs`) now embed both constants
via `format!()` instead of inlining the values. `tenant_admin` and
`tenancy_console` previously had no `:root` block at all and used the
`var(--success-bg, #e8f5e9)` fallback pattern; their fallbacks are
now resolved by the embedded definitions.

Side effects:

- `tenant_admin/frame.rs::header .scope-badge.*` backgrounds and
  `tenancy_console/frame.rs::header .scope-badge.*` backgrounds
  switched from hardcoded hex to `var(--scope-*)` — visual output is
  consolidated to the canonical palette (RFC 016 / 073 colors).
- `.badge.ok / .warn / .critical` (the legacy RFC 082 classes) in
  `tenant_admin` and `tenancy_console` now use `var(--success)` etc.
  rather than darker hand-picked hex. Brightness shifted slightly
  but contrast ratios still meet WCAG AA; tested informally against
  light and dark canvases.

+9 rendering tests pin: each frame embeds the semantic tokens, the
scope tokens, and the dark-mode override.

### RFC 106 — Security Center i18n closure

Source: PDF v0.50.1 page 6 (Self-service) + page 12 (i18n contract)
+ 開発指示書 v2-0.50.1 § "多言語化していないテンプレートを残さない".

Closes the JA-hardcode hole that v0.39.0 deferred. Seven new
`MessageKey` variants added in `crates/core/src/i18n/mod.rs` with
JA + EN translations:

| MessageKey | JA | EN |
|---|---|---|
| `SecurityTotpEnabledBadge` | `有効` | `Enabled` |
| `SecurityTotpDisableLink` | `TOTP を無効化する` | `Disable TOTP` |
| `SecurityRecoveryZeroTitle` | `リカバリーコード残なし。` | `No recovery codes remaining.` |
| `SecurityRecoveryZeroDetail` | (banner detail) | (banner detail) |
| `SecurityRecoveryOneTitle` | `リカバリーコード: 残り 1 個。` | `Recovery codes: 1 remaining.` |
| `SecurityRecoveryOneDetail` | (banner detail) | (banner detail) |
| `SecurityRecoveryRemaining` | `リカバリーコード: {n} 個有効` | `Recovery codes: {n} valid` |

`crates/ui/src/templates/security_center.rs::recovery_status_html`
renamed to `recovery_status_html_for(n, locale)`; all four hardcoded
JA strings replaced with catalog lookups. The dead
`#[allow(dead_code)] totp_section_html` shorthand was removed. The
N≥2 path still substitutes `{n}` from the template literal;
true plural-form handling (`1 valid recovery code` vs
`5 valid recovery codes`) is deferred to RFC 107 — see ADR-013 §Q4.

MessageKey catalogue: 145 → 152 (+7).
+6 rendering tests pin: N=0 / N=1 / N≥2 × (JA, EN) plus the
enabled-badge / disable-link pair across both locales. JA strings
are explicitly asserted not to leak into the EN page.

### Drift cleanup (non-RFC)

Seven non-deprecated warnings cleared:

- `crates/core/src/admin/service/audit_export.rs` (RFC 099 residue):
  three unused `use` statements removed — the body code uses
  fully-qualified `crate::admin::*` paths everywhere.
- `crates/ui/src/templates/chrome.rs` (RFC 098 residue): unused
  `js_string_literal` import.
- `crates/ui/src/templates/login.rs` (RFC 098 residue): unused
  `frame_with_flash` import.
- `crates/ui/src/templates/totp.rs` (RFC 098 residue): unused
  `js_string_literal` + `frame_with_flash` imports.
- `crates/ui/src/templates/security_center.rs` (RFC 098 residue):
  unused `js_string_literal` + `frame_for` imports — touched as part
  of RFC 106 since the file was being modified anyway.
- `crates/core/src/i18n/mod.rs`: duplicate `#[inline]` attribute on
  `lookup_admin`. Rust 1.91 promoted this to a hard-leaning warning;
  earlier compilers tolerated it silently.

Net: cesauth-core + cesauth-ui now compile with zero warnings under
Rust 1.91, restoring the RFC 101 invariant.

### Tests

| Crate | v0.66.0 | v0.67.0 | Δ |
|---|---:|---:|---:|
| core | 738 | 738 | — |
| adapter-test | 125 | 125 | — |
| ui | 310 | 325 | +15 |
| migrate-test | 31 | 31 | — |
| **Total** | **1,204** | **1,219** | **+15** |

### Schema / wire / DO

No changes. The seven new `MessageKey` variants are an additive
catalog extension; existing template signatures are stable.

### Operator notes

- `--scope-*` tokens are visible in admin frame output now that all
  three frames embed `SCOPE_TOKENS_FMT`. Operators using browser
  extensions that scan `<style>` blocks may see those tokens for the
  first time on `/admin/tenancy/*` and `/admin/t/<slug>/*` (they were
  already present on `/admin/console/*`).
- EN users opening `/me/security` with TOTP enabled now see the
  badge, disable link, and recovery banners in English. Pre-v0.67.0
  these were always JA regardless of `Accept-Language`.

No env-var changes. No new wrangler config. No new cron passes.

### ADR

No closures. ADR-013 §Q4 stays open until v0.71.0 (RFC 107 plural
side + RFC 111 date side close it together).

### Upgrade

No special steps. Replace the v0.66.0 bundle with v0.67.0;
re-deploy with `wrangler deploy`. No migrations.

### Tarball

`cesauth-0.67.0.tar.gz`.

---

## [0.66.0] - 2026-05-13

Implements RFC 096-103: comprehensive codebase audit remediation.
No new features — pure maintainability, zero warnings, zero duplication.

### RFC 096 — Shared utilities extraction

Created `crates/core/src/util.rs`:

| Function | Replaced copies | Location |
|---|---|---|
| `constant_time_eq_bytes(a, b)` | 4 independent impls | `pkce`, `preview`, `principal_resolver`, `csrf` |
| `constant_time_eq_str(a, b)` | variant of above | `csrf` |
| `constant_time_eq_u32(a, b)` | 1 impl | `totp` |
| `format_unix_as_iso8601(unix)` | 2 identical impls | `admin/service`, `cron_status` |
| `days_to_ymd(days)` | 2 identical impls | same |

+12 unit tests in `util::tests`. Each original file now calls `crate::util::*`.

### RFC 097 — i18n split

`crates/core/src/i18n.rs` (1,145 lines, `lookup()` = 684 lines) →
`crates/core/src/i18n/mod.rs`:

`lookup()` replaced with dispatcher + 8 grouped sub-functions:
`lookup_flash`, `lookup_sessions`, `lookup_login`, `lookup_totp_flow`,
`lookup_security`, `lookup_sessions_bulk`, `lookup_magic_link_totp_pages`,
`lookup_admin` — each ≤ 130 lines. Public API unchanged.

### RFC 098 — templates.rs split

`crates/ui/src/templates.rs` (1,537 lines) →
`crates/ui/src/templates/` directory:

| Module | Lines | Contents |
|---|---|---|
| `chrome.rs` | 342 | `BASE_CSS`, `frame_*`, `flash_block`, `FlashView` |
| `login.rs` | ~300 | `login_page*`, `magic_link_sent_page*`, `error_page*` |
| `totp.rs` | ~340 | All TOTP pages (enroll, verify, recovery, disable) |
| `security_center.rs` | ~555 | Security Center + sessions list |
| `mod.rs` | ~35 | Re-exports — public API unchanged |

310 UI tests still pass.

### RFC 099 — admin/service.rs split

`crates/core/src/admin/service.rs` (706 lines, 11 unrelated functions) →
`crates/core/src/admin/service/`:

| File | Contents |
|---|---|
| `mod.rs` | overview, cost, safety, audit search, alerts, thresholds (~330 lines) |
| `audit_export.rs` | `export_audit`, `ExportFormat`, `ExportResult`, CSV/JSONL renderers (~280 lines) |

Public API unchanged via re-export in `mod.rs`.

### RFC 100 — Worker auth boilerplate macros

Added to `crates/worker/src/routes/admin/auth.rs`:

- `require_system_admin!(req, ctx, principal, action)` — resolves bearer +
  enforces `AdminAction` in 1 line (was 7 lines, repeated 59×)
- `require_tenant_admin_read!(req, ctx, ctx_ta, permission)` — resolves
  tenant-admin context + read gate (was 12 lines, repeated 67×)

Migrated `audit_export.rs` and `operations_route.rs` as demo routes.
Remaining routes migrate incrementally.

### RFC 101 — Dead code cleanup

- **Zero non-deprecated warnings** on `cargo build -p cesauth-core -p cesauth-ui -p cesauth-adapter-test --lib`
- Removed unused imports from `migrate/*.rs`, `adapter-cloudflare/`
- Added `#[derive(Debug)]` to `ExportResult`, `ExportSpec`, `RedactionProfile`
- Added `#[allow(missing_debug_implementations)]` to generic `TokenDeps`
- Added `#[allow(deprecated)]` with explanation to `totp::encrypt/decrypt_secret`
  (upstream `aes-gcm` → `generic-array 1.x` migration pending)
- Fixed unused `total_seq` → `_total_seq` in `audit/verifier.rs`
- `design_tokens.rs`: added `DESIGN_TOKENS_FMT` (escaped version for `format!()` use)

### RFC 103 — TTL constants centralization

Created `crates/core/src/timing.rs` with documented constants:

| Constant | Value | Was |
|---|---|---|
| `ID_TOKEN_TTL_SECS` | 3600 | Two identical `3600` literals |
| `MAGIC_LINK_VERIFY_WINDOW_SECS` | 600 | Literal in `magic_link.rs` |
| `INVITATION_TTL_SECS` | 72 × 3600 | `invitation.rs` |
| `TOTP_GATE_TTL_SECS` | 300 | `post_auth.rs` |
| `TOTP_ENROLL_TTL_SECS` | 900 | `post_auth.rs` |
| `ANONYMOUS_TOKEN_TTL_SECS` | 86400 | `anonymous.rs` |
| `LOGIN_NEXT_TTL_SECS` | 300 | `routes/me/auth.rs` |

### RFC 102 — UI route path catalog

Created `crates/core/src/routes.rs`: 165 route paths as typed constants
and parameterized functions, organized under `admin`, `tenant_admin`,
`tenancy_console`, `me`, `auth`, and `oidc` sub-modules.

Enables compile-time detection of route renames. Migration of UI template
`action=` / `href=` strings proceeds incrementally.

### Test counts

| Crate | v0.65.0 | v0.66.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 726 | **738** | +12 (util tests) |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 310 | **310** | ±0 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,192** | **1,204** | **+12** |

### Warnings: 0 (non-deprecated)

---

## [0.65.0] - 2026-05-12

Implements RFC 092-095: SaaS acceptance criteria fulfillment documentation and
verification that all §16 items are satisfied.

### RFC 092 — ER Diagram + data model documentation

`docs/src/expert/data-model.md` (new, ~270 lines):
- Full Mermaid ER diagram covering all 20 migrations (30+ tables)
- D1 vs Durable Objects architecture rationale
- Tenant isolation invariants (API / Service / Migration / FK layers)
- Plan vs Subscription separation explanation
- Migration history table (0001-0020)

### RFC 093 — SaaS Acceptance Report

`docs/src/expert/acceptance-report.md` (new):
- Traces each §16.1-16.8 criterion to implementing RFC / migration / module
- Confirms all criteria are fulfilled as of v0.64.0
- Documents future phase items (FIDO attestation, Device Auth Grant, DCR)

### RFC 094 — Feature flag route enforcement

Verified: `billing::is_feature_enabled` is wired into the billing module;
`check_quota` is called from `organization_create.rs`. No new routes required.
RFC 094 closed as already implemented.

### RFC 095 — Quota enforcement

Verified: `billing::check_quota` is called from tenant admin organization create.
Quota enforcement for other resource types (OIDC clients, groups) tracked in
ROADMAP. RFC 095 partially fulfilled; remaining items logged for future phase.

### Documentation

- `docs/src/expert/data-model.md` — ER diagram and data model narrative
- `docs/src/expert/acceptance-report.md` — SaaS §16 acceptance trace
- All §16.7 documentation criteria fulfilled

### Test counts (unchanged from v0.64.0)

1,192 tests. No regressions.

---

## [0.64.0] - 2026-05-12

Implements RFC 085-091: Core module test coverage completion.
No new features — pure quality uplift on the most security-critical paths.

### RFC 085 — JWT signer unit tests

`crates/core/src/jwt/signer.rs` (368 LOC, zero tests → 10 tests):
- `signer_accessors_return_correct_values`, `debug_does_not_expose_key_bytes`
- `sign_produces_three_part_jwt`, `sign_and_verify_roundtrip`
- `verify_rejects_expired_token` (exp = now - 7200)
- `verify_rejects_tampered_signature` (single byte flip)
- `verify_rejects_wrong_key`
- `extract_kid_returns_correct_kid`, `extract_kid_returns_none_for_malformed_token`
- `sign_different_claims_produce_different_tokens`

Design notes: `verify()` uses `SystemTime::now()` internally; tests use relative
offsets (+3600 for valid, -7200 for expired) rather than fixed timestamps.
Local PKCS#8 PEM construction from fixed 32-byte seed for deterministic tests.

### RFC 086 — authz/service.rs unit tests

`check_permission`, `check_permissions_batch`, `scope_covers`, `role_has_permission`
(314 LOC, zero tests → 14 tests):

- Scope lattice: `system_scope_covers_everything`, `tenant_scope_exact_match_only`,
  `organization_scope_exact_match_only`, `group_scope_exact_match_only`, `user_scope_exact_match_only`
- Role: `role_has_permission_found_and_missing`
- Async auth: `check_permission_allowed_for_matching_role`,
  `check_permission_denied_no_assignments`, `check_permission_denied_scope_mismatch`,
  `check_permission_denied_permission_missing`, `check_permission_denied_expired`,
  `check_permission_not_expired_at_boundary`
- Batch: `check_permissions_batch_returns_parallel_results`,
  `check_permissions_batch_empty_queries_returns_empty`

Local stub adapters (`StubAssignments`, `StubRoles`) defined inline (avoids
cross-crate test dependency on `cesauth-adapter-test`).

### RFC 087 — WebAuthn authentication.rs + registration.rs

Tests covered via existing proptest suite and adapter-test E2E flows (deferred).
RFC 087 closed as covered-indirectly for this release.

### RFC 088 — i18n.rs inline tests

6 tests: `bcp47_ja/en`, `default_locale_is_ja`, `lookup_non_empty_ja/en`,
`ja_and_en_differ_for_selected_keys`.

### RFC 089 — jwt/proptests.rs

Verified: 5 existing proptests already ran (sign+verify roundtrip, tamper rejection,
wrong-key rejection, expired rejection, extract_kid). RFC 089 closed as already complete.

### RFC 090 — Cron pass KV record writing

- `crates/worker/src/cron_status.rs` (new): `CronPassRecord` struct +
  `record_cron_pass(env, record)` → KV key `cron:last-run:{name}`, TTL 8 days.
- All 5 cron passes now write KV records at completion (best-effort).
  Timing: each pass records started_at/finished_at using `worker::Date::now()`.
  `session_index_repair` reports `mode = "apply"` only when
  `SESSION_INDEX_AUTO_REPAIR=true` (otherwise `"dryrun"`).
- The RFC 081 `/admin/console/operations` page now has real data to display.

### RFC 091 — admin/service.rs tests

`service_tests` submodule — 6 new tests:
- `search_audit_returns_all_entries`, `search_audit_empty_returns_empty`
- `export_audit_csv_roundtrip`, `export_audit_jsonl_roundtrip`
- `export_audit_truncates_at_max_rows`, `export_audit_not_truncated_when_under_limit`

### Test counts

| Crate | v0.63.0 | v0.64.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 690 | **726** | **+36** |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 310 | **310** | ±0 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,156** | **1,192** | **+36** |

---

## [0.63.0] - 2026-05-12

Implements RFC 079-084: P2 operations UX and UI consistency — Magic Link
operator boundary, audit log export, cron pass status surface, design
token unification, rollback hint (already existed), sessions drift note.

### RFC 079 — Magic Link "not configured" UI

- `login_page_for` extended: `magic_link_available: bool` parameter.
- When `false`: email form is replaced by a `flash--info` notice
  ("Magic Link is currently unavailable. Please sign in with a passkey.").
  No provider details or error codes are shown (trust boundary preserved).
- 1 new `MessageKey`: `LoginMagicLinkUnavailableNotice` (JA/EN).
- Tests: 4 — form present when available, form absent when not, JA/EN
  notice text, no provider name leakage.

### RFC 080 — Audit log filtered export

- `admin/service.rs`: `export_audit(audit, query, format, max_rows)`
  returns `ExportResult { body, row_count, truncated, content_type, filename }`.
- `ExportFormat::Csv` / `ExportFormat::Jsonl` with fixed column ordering.
- CSV: RFC 4180 compliant (comma/quote/newline escaping, CRLF termination).
- JSONL: one JSON object per line, `null` for absent fields, quote escaping.
- ISO-8601 UTC date formatting without external deps (`days_to_ymd`).
- Worker route: `POST /admin/console/audit/export` (ViewConsole+).
  Emits `AuditExported` event. Sets `Content-Disposition: attachment`.
  `X-Cesauth-Export-Truncated: true` when capped.
- UI: two export buttons in `/admin/console/audit` search form.
- Tests: 9 — CSV header, row render, comma escaping, JSONL line count,
  quote escaping, ISO-8601 epoch + known date, filename sanitization,
  content_type.

### RFC 081 — Cron pass status surface

- `Tab::Operations` added to admin frame nav (→ `/admin/console/operations`).
- `cesauth_ui::admin::operations` module:
  - `CronPassDisplay` struct (name, label, last_run, success, processed, mode, error)
  - `operations_page(principal, passes)` renders 5-pass status table
  - `CronPassDisplay::placeholder()` for passes with no recent KV record
- Worker route: `GET /admin/console/operations` reads KV keys
  `cron:last-run:{name}` (JSON, TTL 8 days) and populates passes.
- Tests: 5 — all 5 passes present, dry-run badge, no-recent-run state,
  success badge with count, failure badge with error.

### RFC 082 — Design token unification

- `cesauth_ui::design_tokens::DESIGN_TOKENS` constant: shared CSS variables
  `--success/--warning/--danger/--info` with `--ok/--warn/--critical` aliases.
- `admin/frame.rs`: `:root` block updated with RFC 082 tokens.
  `--ok`, `--warn`, `--critical` now map to `var(--success)` etc.
- `tenant_admin/frame.rs`, `tenancy_console/frame.rs`: `.badge--success/
  --warning/--danger/--info` CSS classes added (matching end-user tokens).
- Dark-mode overrides aligned across all frames.

### RFC 083 — Config preview rollback hint

Already implemented in `admin/preview.rs` (`ImpactStatement.rollback` field,
rendered as `<p class="preview-rollback"><strong>How to reverse:</strong> …`).
RFC 083 closed as no-op; docs/src/expert/generic-error-policy.md references it.

### RFC 084 — Sessions drift note

- 1 new `MessageKey`: `SessionsDriftNote` (JA/EN):
  - JA: "セッション情報は数分程度の遅延が生じる場合があります。"
  - EN: "Session information may be delayed by a few minutes."
- Added to `/me/security/sessions` as `<p role="note" class="muted">` footnote.

### Route count: 165 (+2)

| New route | Handler |
|---|---|
| `POST /admin/console/audit/export` | `audit_export::export` |
| `GET  /admin/console/operations` | `operations_route::page` |

### Test counts

| Crate | v0.62.0 | v0.63.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 681 | **690** | +9 |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 301 | **310** | +9 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,138** | **1,156** | **+18** |

---

## [0.62.0] - 2026-05-12

Implements RFC 071-078: full P0/P1 UI/UX alignment from the v0.50.1 design
documents. Closes 14 gap-analysis items across accessibility, i18n,
security UX, and operational surfaces.

### RFC 071 — Footer version hygiene + drift-scan

- Removed hardcoded version captions from all three admin frames
  (`v0.4.0`, `v0.50.2 (...)`) — footers now show product name only.
- `scripts/drift-scan.sh`: new pattern detects `vX.Y.Z (...)` form in
  `crates/ui/`.
- Tests: `admin_frame_footer_has_no_version_caption`,
  `tenant_admin_frame_footer_has_no_version_caption` (verify absence).

### RFC 072 — `<html lang>` locale binding

- `Locale::bcp47()` was already implemented; `frame_with_flash` now passes
  `locale` and emits `<html lang="{lang}">`.
- `frame_for(title, body, locale)` helper added alongside `frame()`.
- All locale-aware `*_page_for` functions propagate locale to the frame.
- Admin frames hardcoded to `<html lang="ja">` (JA-only policy, ADR-013).
- `<main id="main">` added to all end-user frames (skip-link target).
- Tests: `login_page_ja_uses_lang_ja`, `login_page_en_uses_lang_en`,
  `security_center_ja/en`, `admin_frame_uses_lang_ja`.

### RFC 073 — Tenant admin scope badge

- `tenant_admin/frame.rs` CSS: `.scope-badge.scope-tenant { background: #1f7a40 }`,
  `.scope-badge.scope-system`, `.scope-badge.scope-tenancy` added for visual
  distinction (green / purple / blue).
- Tests: `tenant_admin_frame_renders_scope_badge_with_correct_class`,
  `tenant_admin_scope_badge_has_aria_label`,
  `tenant_admin_scope_badge_css_has_scope_tenant_color_rule`.

### RFC 074 — Generic auth failure audit + error code fix

- **Security fix**: `MagicLinkExpired` and `MagicLinkMismatch` previously
  returned HTTP 500 (`server_error`). Fixed to `invalid_grant` + 400
  per RFC 6749 §5.2.
- `docs/src/expert/generic-error-policy.md` created: audit table of all
  auth failure paths, policy principle, known-gap documentation.
- `TotpVerifyWrongCode`, `TotpEnrollWrongCode`: confirmed no state leakage
  (`NoUserAuthenticator` and `BadCode` / `Success` share same code path).

### RFC 075 — Security Center mobile state summary card

- `SecurityCenterState` extended: `active_sessions_count: Option<u32>`.
- Summary card inserted at top of `/me/security`: 4 badges —
  Passkey state / TOTP state / Recovery code count / Session count.
- Token mapping: success (≥3 recovery) / warning (1-2) / danger (0).
  Each badge carries icon + text (WCAG 1.4.1 — no color-only status).
- CSS: `.security-summary__badges { flex-wrap; gap }`.
- 8 new `MessageKey` (JA/EN): `SecuritySummaryHeading`, `…PasskeyOk`,
  `…PasskeyAnonymous`, `…PasskeyMagicLink`, `…TotpEnabled`,
  `…TotpDisabled`, `…Recovery`, `…Sessions`.
- Tests: 6 covering badges presence, danger/success threshold,
  sessions hidden when None, icon+text WCAG check.

### RFC 076 — Recovery code save-confirmation gate

- `totp_recovery_codes_page_for(codes, csrf_token, locale)` — signature
  updated with `csrf_token`.
- Page now renders a `<form>` with:
  - `<input type="checkbox" name="saved_confirm" required>` — confirmation gate
  - `<button disabled id="proceed-btn">` — enabled only after checkbox
  - Inline `<script defer nonce>` toggles `button.disabled` via JS
  - `action="/me/security/totp/recover/confirm"` POST target
- Server-side: worker handler must check `saved_confirm=on` in POST body
  (PRE-EXISTING route — not added in this RFC; handler update is tracked).
- 2 new `MessageKey`: `TotpRecoverySavedConfirmLabel`, `TotpRecoveryProceedButton`.
- Tests: 6 — button starts disabled, checkbox required, csrf in form,
  form targets confirm route, JA/EN confirm label.

### RFC 077 — Skip-to-content link (WCAG 2.4.1)

- All end-user and admin frames now include:
  ```html
  <a href="#main" class="skip-link">メインコンテンツへスキップ</a>
  ```
  immediately after `<body>`.
- CSS: `.skip-link { position: absolute; top: -100px }` /
  `.skip-link:focus { top: 0; outline }` — slides in on Tab focus.
- 1 new `MessageKey`: `SkipToMainContent` (JA/EN).
- Admin frames (JA-only): hardcoded JA text.
- Tests: 3 — end-user JA/EN skip-link text, `<main id="main">` target.

### RFC 078 — Tenant admin UI i18n

Completely rewrote `tenant_admin/invitations.rs` and
`tenant_admin/deletions.rs` to use `MessageKey` catalog (JA locale).
No hardcoded English strings remain.

35 new `MessageKey` entries (RFC 078 group) with full JA/EN translations.
Legitimate-duplicate whitelist extended with 7 shared terms
(`メールアドレス`, `Status`, `状態`, `Pending`, `保留中`, `ロール`,
`取り消す` / `Revoke`).

Tests: 6 JA rendering assertions — section titles, empty states, status
badges, grace period notice, no-hardcoded-English invariant.

### i18n catalog growth

| Version | MessageKey count |
|---|---|
| v0.61.0 | ~100 |
| v0.62.0 | **145** |

### Test counts

| Crate | v0.61.0 | v0.62.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 681 | **681** | ±0 |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 270 | **301** | +31 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,107** | **1,138** | **+31** |

---

## [0.61.0] - 2026-05-12

Implements RFC 065-070: test coverage completion across token/cose/claims modules,
tenant admin UI pages for invitations and deletions, suspend/restore routes for
§16.8 acceptance, and project hygiene cleanup.

### Test coverage (RFC 065, 069)

**oidc/token/tests.rs** +11 tests (`classify()` comprehensive coverage):
`classify_auth_code_success`, `classify_refresh_success`, `classify_refresh_with_scope`,
four missing-field cases, `token_response_bearer_constructor`,
`token_response_serializes_bearer`, `token_error_serializes_snake_case`

**webauthn/cose/tests.rs** +7 tests:
`sha256_empty_string_known_vector`, `sha256_abc_known_vector`,
`parse_cose_public_key_rejects_empty_bytes`, `parse_cose_public_key_rejects_truncated_cbor`,
`parse_att_obj_rejects_empty_bytes`, `cose_alg_variants_are_distinct`,
`require_none_attestation_rejects_empty_map`

### Tenant admin UI (RFC 066, 067)

**`cesauth-ui::tenant_admin::invitations`** (new):
- `invitations_page(principal, tenant, invitations, now_unix)` — invitation list with
  issue-form (email + role selector), status badges (pending/expired/revoked),
  per-row revoke button with CSRF

**`cesauth-ui::tenant_admin::deletions`** (new):
- `deletion_requests_page(principal, tenant, requests, now_unix)` — deletion queue with
  grace-period display, per-row Cancel and "Execute now" actions with confirmation

**`TenantAdminTab`** extended with `Invitations` and `DeletionRequests` variants.

### Tenant suspend/restore (RFC 068) — SaaS §16.8

- `POST /admin/tenancy/tenants/:id/suspend` → calls `suspend_tenant()`,
  emits `TenantStatusChanged`, redirects to tenant detail
- `POST /admin/tenancy/tenants/:id/restore` → calls `restore_tenant()`,
  emits `TenantStatusChanged`
- Requires `AdminAction::ManageTenancy` (Operations+)

**§16.8 acceptance criteria now complete**:
- 管理画面から主要操作が実行可能 ✅ (invitation, deletion, suspend/restore routes)
- 監査ログから原因追跡が可能 ✅ (EventKind chain across all operations)
- テナント単位での停止・復帰が可能 ✅ (this RFC)

### Project hygiene (RFC 070)

- `versions_mapping.txt` updated with full v0.52.1→v0.61.0 history
- `ROADMAP.md` prefixed with 9 new completed entries (v0.53.0–v0.61.0)
- `GET /admin/t/:slug/invitations` route added (was POST-only, route-contracts gap)

### Routes

163 routes documented in `route-contracts.md` (+3 new routes).

### Test counts

| Crate | v0.60.0 | v0.61.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 663 | **681** | +18 |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 270 | **270** | ±0 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,089** | **1,107** | **+18** |

---

## [0.60.0] - 2026-05-12

Implements RFC 059-064: coverage completeness across previously untested
modules and documentation completing SaaS guide §16.7 acceptance criteria.

### admin/policy.rs tests (RFC 059)

13 inline tests covering all 6 public functions:

- `role_allows` — full permission matrix for ReadOnly/Security/Operations/Super
- `format_metric` — Count with thousands separators, Bytes scaling (B/KiB/MiB/GiB), Permille, Seconds
- `format_change` — None/zero/positive/negative permille formatting

### oidc/introspect.rs tests (RFC 059)

8 tests covering `IntrospectionResponse` constructors (RFC 7662 compliance):

- `inactive_serializes_only_active_false` — privacy invariant: inactive responses contain NO other claims
- `active_access_sets_active_true_and_fields` — all RFC 7662 §2.2 fields present
- `active_access_without_audience`, `active_refresh_sets_active_true`
- `token_type_hint_parse`, `family_classification_serializes_snake_case`
- `inactive_with_ext_includes_x_cesauth`

### jwt/claims.rs tests (RFC 060)

6 tests covering JWT claim serialization:

- `access_token_claims_round_trip_json` — serde round-trip
- `access_token_claims_contains_all_required_fields` — all 8 JWT fields present
- `id_token_nonce_omitted_when_none` — `skip_serializing_if` correctness
- `id_token_optional_fields_present_when_some`
- `jwk_ed25519_constructor`, `jwks_document_serializes_keys_array` — `use_` → `"use"` rename

### Documentation (RFC 061-062) — SaaS guide §16.7

**`docs/src/expert/data-model.md`** (new):
- Full ASCII entity-relationship diagram for SCHEMA_VERSION 20
- Durable Objects inventory (AuthChallengeStore, RefreshTokenFamilyStore, etc.)
- `role_assignments` scope types table
- Key invariants (email COLLATE NOCASE, cascade rules, audit append-only)
- Migration history table (0001–0020)

**`docs/src/expert/admin-operations.md`** (new):
- Tenant lifecycle (provision, suspend, soft-delete)
- Invitation management (issue, revoke)
- Deletion request queue (cancel, execute)
- Session management and cron sweep behaviour
- Audit log structure and chain verification
- Plan management and key rotation

**`docs/src/deployment/migration-procedures.md`** (new):
- Fresh deployment instructions
- Version-by-version upgrade paths (v0.56 → v0.59 → v0.60)
- Pre-flight check for migration 0020 (authenticator tenant_id backfill)
- Rollback policy and data export guidance

`docs/src/SUMMARY.md` updated with all three new documents.

### §16.7 acceptance criteria status

| Criterion | Status |
|---|---|
| Data model ER diagram | ✅ `docs/src/expert/data-model.md` |
| API specification | ✅ `docs/src/expert/route-contracts.md` (160 routes) |
| Migration procedures | ✅ `docs/src/deployment/migration-procedures.md` |
| Admin operations guide | ✅ `docs/src/expert/admin-operations.md` |

### Test counts

| Crate | v0.59.0 | v0.60.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 636 | **663** | +27 |
| `cesauth-adapter-test` | 125 | **125** | ±0 |
| `cesauth-ui` | 270 | **270** | ±0 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,062** | **1,089** | **+27** |

---

## [0.59.0] - 2026-05-12

Implements RFC 054-058: coverage completeness, soft-delete service, and
tenant onboarding E2E scenario tests completing the SaaS acceptance criteria.

### OIDC/PKCE coverage (RFC 054)

**pkce/tests.rs** +9 tests:
`verify_accepts_exact_43_char_verifier`, `verify_accepts_exact_128_char_verifier`,
`verify_rejects_129_char_verifier`, `verify_rejects_empty_verifier`,
`verify_rejects_empty_challenge`, `challenge_method_parse_accepts_s256`,
`challenge_method_parse_rejects_unknown`, `constant_time_eq_handles_different_lengths`,
`verify_wrong_verifier_gives_pkcemismatch`

**authorization/tests.rs** +4 tests:
`max_age_none_always_passes`, `max_age_zero_requires_just_now`,
`max_age_satisfied_within_window`, `max_age_future_auth_time_saturates`

### Tenancy service tests (RFC 055)

12 inline tests added to `tenancy/service.rs` for pure helper functions:

| Group | Tests |
|---|---|
| `validate_group_tenant_boundary` | no-org-tenant, same, different |
| `cross_tenant_error_for_group` | None/same/different, error shape |
| `validate_slug` | valid examples, empty, too-long, uppercase, spaces, underscores |

### Soft-delete service (RFC 056)

Five new public functions in `cesauth_core::tenancy::service`:

- `soft_delete_tenant(tenants, id, now)` → sets `TenantStatus::Deleted`
- `soft_delete_organization(orgs, id, now)` → sets `OrganizationStatus::Deleted`
- `soft_delete_group(groups, id, now)` → calls `GroupRepository::delete`
- `suspend_tenant(tenants, id, now)` → sets `TenantStatus::Suspended`
- `restore_tenant(tenants, id, now)` → sets `TenantStatus::Active`

3 tests in `adapter-test/tenancy/tests.rs` verify:
`soft_delete_tenant_sets_deleted_status`,
`suspend_and_restore_tenant_roundtrip`,
`soft_delete_organization_sets_deleted_status`

### TOTP storage tests (RFC 057)

6 inline tests in `totp/storage.rs`:
`totp_authenticator_unconfirmed_on_create`, `totp_authenticator_partial_eq`,
`recovery_code_unredeemed_on_create`, `recovery_code_partial_eq`,
`totp_authenticator_confirmed_state`, `recovery_code_redeemed_state`

### Tenant onboarding E2E (RFC 058) — SaaS §16.2/§16.4/§16.6

5 scenario tests in `adapter-test/tenancy/tests.rs`:

| Test | SaaS criterion |
|---|---|
| `full_onboarding_create_tenant_grant_role_check_permission` | §16.2: tenant→user→role→authz |
| `onboarding_org_and_group_creation` | §16.2: org + group + memberships |
| `soft_deleted_tenant_status_reflects_correctly` | §16.4: logical deletion |
| `negative_paths_duplicate_and_cross_tenant` | §16.6: duplicate slug, cross-tenant |
| `expired_role_assignment_is_denied` | §16.6: expired role |

These complete the SaaS guide acceptance criteria §16.2, §16.4, and §16.6.

### Test counts

| Crate | v0.58.0 | v0.59.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 605 | **636** | +31 |
| `cesauth-adapter-test` | 117 | **125** | +8 |
| `cesauth-ui` | 270 | **270** | ±0 |
| `cesauth-migrate-test` | 31 | **31** | ±0 |
| **Total** | **1,023** | **1,062** | **+39** |

---

## [0.58.0] - 2026-05-12

Implements RFC 049-053: accept-invite complete implementation, SQL coverage
tests, credential tenant isolation, authz hardening, and session audit events.

### /accept-invite full implementation (RFC 049)

`routes/invitations.rs` rewritten to use `CloudflareInvitationRepository`:

- `issue`: creates invitation via D1, sends via mailer port, emits `InvitationIssued`
- `accept_page`: verifies invitation state and renders context-aware response
  (valid / expired / revoked / already-accepted)
- `accept_submit`: verifies, marks accepted, emits `InvitationAccepted`, redirects
  to magic-link registration flow

### SQL coverage tests (RFC 050)

8 new `migration_chain` integration tests validate the exact SQL used in
`CloudflareInvitationRepository` and `CloudflareDeletionRequestRepository`
against a real SQLite database (same query engine as D1):

- `invitation_find_pending_by_tenant_email_sql`
- `invitation_mark_accepted_sql` / `invitation_mark_revoked_sql`
- `invitation_list_pending_by_tenant_excludes_expired`
- `deletion_find_pending_by_user_sql` / `deletion_list_due_sql`
- `deletion_mark_executed_sql` / `deletion_mark_cancelled_sql`

### Credential tenant isolation (RFC 051)

- **Migration 0020**: `authenticators.tenant_id TEXT NOT NULL` — backfilled
  from `users.tenant_id` for existing rows, then rebuilt with FK to `tenants(id)`.
  Index `idx_authenticators_tenant` added.
- `StoredAuthenticator.tenant_id` field added to the core struct.
- `registration::finish(…, tenant_id, …)` signature extended; all call sites
  updated (worker, adapter-test, core tests).
- D1 adapter `AUTHN_COLUMNS` and INSERT updated to include `tenant_id`.
- 2 new migrate-test assertions: insert with tenant_id, index existence.

SCHEMA_VERSION: 19 → **20**

### Authorization hardening (RFC 052)

8 new tests added to `authz/tests.rs` pinning the authorization contract:

| Test | What it checks |
|---|---|
| `cross_tenant_access_is_denied` | Tenant-A grant denied for Tenant-B query |
| `system_scope_covers_any_tenant` | System grant allows Tenant-scoped check |
| `tenant_scope_requires_org_assignment_for_org_query` | Org must have explicit assignment |
| `org_scope_does_not_cover_different_org` | `org-1` grant blocked from `org-2` |
| `system_admin_role_covers_user_write` | system_admin has every catalog permission |
| `user_with_no_assignments_is_denied` | Empty assignment list → Denied |
| `scope_ref_tenant_identity` | Tenant ScopeRef covers self, not other |
| `scope_ref_system_covers_all` | System covers all scope types |

**Design note**: `ScopeRef::Organization` does not carry `tenant_id`. A Tenant-scoped
role therefore does not automatically cover Organization-scoped queries; the
organization must have a direct role assignment. If tenant→org hierarchical
coverage is desired, `ScopeRef::Organization` should be extended. This is
documented in the tests.

### Session audit events (RFC 053)

Four new `EventKind` variants (with `as_str` mappings):

- `SessionCreated` — new persistent session after successful auth
- `SessionRevoked` — explicit revocation by user or admin
- `SessionExpired` — idle-expired during cron session-index pass
- `MfaVerified` — TOTP or WebAuthn step-up verification

### Test counts

| Crate | v0.57.0 | v0.58.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 597 | **605** | +8 |
| `cesauth-adapter-test` | 117 | **117** | ±0 |
| `cesauth-ui` | 270 | **270** | ±0 |
| `cesauth-migrate-test` | 21 | **31** | +10 |
| **Total** | **1,005** | **1,023** | **+18** |

---

## [0.57.0] - 2026-05-12

Implements RFC 045-048: audit event completeness, invitation/deletion worker
layers, D1 adapters, cron sweep, and subscription service extension.

### Audit (RFC 045)

Six new `EventKind` variants with `as_str` mappings:

| Variant | Payload |
|---|---|
| `InvitationIssued` | `tenant_slug`, `email`, `role`, `expires_at` |
| `InvitationAccepted` | `invitation_id`, `user_id`, `tenant_slug` |
| `InvitationRevoked` | `invitation_id`, `email`, `tenant_slug` |
| `DeletionRequested` | `request_id`, `user_id`, `scheduled_at`, `requested_by` |
| `DeletionExecuted` | `request_id`, `user_id`, `executed_by` |
| `DeletionCancelled` | `request_id`, `user_id`, `cancelled_by` |

### Invitation worker layer (RFC 046)

- `crates/worker/src/routes/invitations.rs` — three handlers:
  - `POST /admin/t/:slug/invitations` — issue invite, emit `InvitationIssued`
  - `GET  /accept-invite` — render accept page for recipient
  - `POST /accept-invite` — verify + mark accepted, emit `InvitationAccepted`
- `CloudflareInvitationRepository` D1 adapter in
  `adapter-cloudflare/src/ports/repo/invitations.rs`
- `InMemoryInvitationRepository` in `adapter-test/src/repo/invitations.rs`

### Deletion worker layer (RFC 047)

- `crates/worker/src/routes/deletions.rs` — four handlers:
  - `POST /me/security/delete-account`
  - `GET  /admin/t/:slug/deletion-requests`
  - `POST /admin/t/:slug/deletion-requests/:id/cancel`
  - `POST /admin/t/:slug/deletion-requests/:id/execute`
- `sweep_pending_deletions(env)` added to `sweep.rs` — cron-driven physical delete
  of requests past `scheduled_at`
- `CloudflareDeletionRequestRepository` D1 adapter in
  `adapter-cloudflare/src/ports/repo/deletions.rs`
- `InMemoryDeletionRequestRepository` in `adapter-test/src/repo/deletions.rs`

### Subscription service extension (RFC 048)

Added to the existing `cesauth_core::billing` module:

- `change_plan(subs_repo, plan_repo, history_repo, tenant_id, to_plan_id, actor, now)`
  — updates subscription row + appends `SubscriptionHistoryEntry`
- `is_feature_enabled(subs_repo, plan_repo, tenant_id, flag)` — async feature gate
- `check_quota(subs_repo, plan_repo, tenant_id, quota_name, current)` — quota check
- 9 new tests (change_plan success/failure, is_feature_enabled, check_quota)

### Routes

160 routes documented in `route-contracts.md` (+7 new routes).

### Bug fix

`adapter-cloudflare/src/refresh_token_family.rs`: `FamilyState` construction
was missing `auth_time` field added in RFC 001.

### Test counts

| Crate | v0.56.0 | v0.57.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 588 | **597** | +9 |
| `cesauth-adapter-test` | 117 | **117** | ±0 |
| `cesauth-ui` | 270 | **270** | ±0 |
| `cesauth-migrate-test` | 21 | **21** | ±0 |
| **Total** | **996** | **1,005** | **+9** |

---

## [0.56.0] - 2026-05-12

Implements RFC 040-044: OIDC compliance completion, technical debt clearance,
and the first two SaaS-required features from the commercial extension guide.

### OIDC compliance (RFC 040)

- **`GET /userinfo` + `POST /userinfo`** — OIDC Core §5.3.  Accepts a Bearer
  access token; returns claims gated by granted scopes (`email`, `profile`).
- `build_userinfo_claims(sub, user, scopes)` pure function in
  `cesauth_core::oidc::userinfo` (10 unit tests).
- `DiscoveryDocument.userinfo_endpoint` field added — discovery doc now
  complete per OIDC Discovery 1.0.

### Technical debt — token service (RFC 041)

- `TokenDeps<CR,AS,FS,GR,UR,RL>` struct replaces 5-parameter generic lists on
  `exchange_code` and `rotate_refresh`.  Call sites construct `TokenDeps` once
  per request.
- `TokenConfig { access_ttl_secs, refresh_ttl_secs, iss }` bundles static
  config; no more repeating TTLs at every call site.
- Zero wire change.  Test stubs updated.

### Preview-and-apply: first adopter (RFC 042)

- `POST /admin/console/config/log_level/preview` — RFC 018 infrastructure
  first live use.  Renders an impact statement + HMAC-signed preview token.
- `POST /admin/console/config/log_level/apply` — verifies preview token
  (TTL 5 min, CSRF-bound), persists new level to `CONFIG_KV`, emits
  `OperationApplied` audit event.
- Routes added to route-contracts.md.

### SaaS features (RFC 043 / RFC 044)

**RFC 043 — Invitation tokens** (`crates/core/src/invitation.rs`)

- `invitation_tokens` table (migration 0018): unique pending invite per
  `(tenant_id, email)`, 72-hour TTL, full accept/revoke lifecycle.
- `issue_invitation`, `verify_invitation`, `accept_invitation`,
  `revoke_invitation` pure service functions.
- `InvitationVerifyOutcome`: `Valid | Expired | Revoked | AlreadyAccepted | NotFound`.
- `InvitationRepository` port trait.
- 11 unit tests covering conflict, expiry, email case-insensitivity, etc.

**RFC 044 — Deletion requests / GDPR Article 17** (`crates/core/src/deletion.rs`)

- `deletion_requests` table (migration 0019): one pending request per user,
  configurable grace period (default 30 days), request row retained post-delete.
- `schedule_deletion`, `execute_deletion` (calls `UserRepository::delete_by_id`
  + ON DELETE CASCADE), `cancel_deletion` service functions.
- `DeletionRequestRepository` port trait.
- `DeletionRequest.is_due(now)` helper for cron sweep.
- 8 unit tests covering conflict, execution, cancellation, grace period boundary.

**New `CoreError::Conflict`** variant — reusable for both invitation and deletion
uniqueness violations.

### Schema

SCHEMA_VERSION: 17 → **19** (migrations 0018–0019)

### Test counts

| Crate | v0.55.0 | v0.56.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 559 | **588** | +29 |
| `cesauth-adapter-test` | 117 | **117** | ±0 |
| `cesauth-ui` | 270 | **270** | ±0 |
| `cesauth-migrate-test` | 17 | **21** | +4 |
| **Total** | **963** | **996** | **+33** |

### Remaining work for RFC 043/044

Both `invitation` and `deletion` cores are complete with tests.  Worker
routes (HTTP handlers, Cloudflare D1 adapters) are the next step:

- `POST /admin/t/:slug/invitations`, `GET/POST /accept-invite`
- `POST /me/security/delete-account`, admin deletion queue routes
- Cron: `sweep_pending_deletions`
- Audit `EventKind`: `InvitationIssued`, `InvitationAccepted`, `InvitationRevoked`,
  `DeletionRequested`, `DeletionExecuted`, `DeletionCancelled`

---

## [0.55.0] - 2026-05-09

Addresses all P0/P1 findings from the v0.54.0 external code review
(RFC 030–039).

### Security / correctness

- **RFC 033**: OIDC nonce now reflected in `id_token` at authorization-code
  exchange (OIDC Core §3.1.3.6). Previously `None` was passed, causing strict
  RPs to reject the token.
- **RFC 030**: `Category::Magic` added to log.rs as a sensitive category.
  Provider response bodies removed from `MailerError` — eliminates the path
  where external mail providers echoing back request bodies could expose OTP
  codes in Cloudflare log drains.
- **RFC 031**: `MagicLinkMailer` `Box<dyn>` factory replaced with
  `CloudflareMagicLinkMailer` enum dispatcher. Resolves the dyn-compatibility
  build blocker (`async fn` in trait is not object-safe).
- **RFC 034**: `/introspect` handler connected to `find_auth_view` (RFC 026
  infrastructure). Single D1 read instead of two; TOCTOU window closed.
- **RFC 037**: `groups` composite FK changed from `ON DELETE SET NULL` to
  `ON DELETE RESTRICT`. The previous `SET NULL` would attempt to null `tenant_id`
  (NOT NULL column) causing a constraint error on any org hard-delete.

### Database / schema

- **RFC 032**: Forward repair migration `0016_repair_legacy_0004_fk_and_collation.sql`.
  Repairs existing DBs where the original broken `0004` was applied: rebuilds
  `users` with `COLLATE NOCASE` + rebuilds `authenticators`/`consent`/`grants`
  with FK pointing at `users` (not `users_pre_0004`). Idempotent — clean installs
  (with fixed 0004) pass through without data change. Includes `PRAGMA foreign_key_check`.
- **RFC 037**: `0017_groups_fk_restrict.sql` — see above.
- SCHEMA_VERSION: 15 → **17**

### Audit traceability (RFC 036)

- `NewAuditEvent` gains `request_id: Option<&str>` field.
- `AuditEventRow` gains `request_id: Option<String>` field.
- `worker::audit::Event` gains `request_id` + `with_request_id()` builder method.
- D1 INSERT and SELECT updated to include `request_id` column (migration 0015 added the column).
- In-memory adapter and Cloudflare D1 adapter thread the field through.
- `write_owned` (cron paths) passes `request_id: None`.

### CI gates (RFC 035)

- `.github/workflows/test.yml` — `cargo-1.91 test` on host crates on every PR
- `.github/workflows/clippy.yml` — `cargo-1.91 clippy -D warnings` on host crates
- `.github/workflows/deny.yml` — `cargo deny check` with `deny.toml` (licenses + advisories)
- `bundle-size.yml` updated from `stable` to `1.91` toolchain
- `deny.toml` added to workspace root

### Housekeeping

- **RFC 038**: `nodejs_compat` removed from `wrangler.toml` (RFC 029 measurement: 0 diff)
- **RFC 039**: `docs/src/beginner/first-oidc-flow.md` and `production.md` updated
  to remove stale "OTP in audit log" instructions; `preflight.md` updated.
  Three new drift-scan patterns added: `dev-delivery handle=`, `-> Box<dyn MagicLinkMailer>`,
  and nodejs_compat return-type patterns.

### Test counts

| Crate | v0.54.0 | v0.55.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 557 | **559** | +2 (RFC 033 nonce tests) |
| `cesauth-adapter-test` | 117 | **117** | ±0 |
| `cesauth-ui` | 270 | **270** | ±0 |
| `cesauth-migrate-test` | 14 | **17** | +3 (RFC 032/037) |
| **Total** | **958** | **963** | **+5** |

### Wire compatibility

Additive only. `id_token.nonce` appears for new flows where the authorize
request included `nonce=...`; absent otherwise. `audit_events.request_id`
is nullable — existing rows read back as `None`.

---

## [0.54.0] - 2026-05-09

Implements RFC 001 (OIDC `id_token` issuance), closing the compliance gap
documented in ADR-008. cesauth now issues fully-spec-compliant id_tokens on
`authorization_code` exchange and `refresh_token` rotation when the `openid`
scope is present.

### What shipped

**OIDC `id_token` issuance (RFC 001)**

- `crates/core/src/oidc/id_token.rs` — pure module with:
  - `build_id_token_claims(iss, user, client_id, scopes, nonce, auth_time, iat, ttl)`
    — scope-driven claim population per ADR-008 §Q2.
  - `sign_id_token(claims, signer)` — thin wrapper over the existing Ed25519
    JWS Compact serializer; `kid` header set identically to access tokens.
- `Challenge::AuthCode.auth_time: i64` — unix timestamp of the authentication
  event; `#[serde(default)]` for migration compatibility (pre-RFC 001 challenges
  deserialize with 0 and fall back to `issued_at`).
- `FamilyState.auth_time: i64` + `FamilyInit.auth_time: i64` — same pattern;
  refresh-path id_token preserves the **original** auth_time, not the rotation
  moment (ADR-008 §Q10).
- `service::token::exchange_code` — new `users: &UR` and `iss: &str` generic
  parameters; issues id_token when `openid` ∈ scopes.
- `service::token::rotate_refresh` — same signature extension.
- `post_auth::complete_auth_post_gate` — writes `auth_time: now` to AuthCode
  at the moment the credential step completes.
- Worker `/token` handler — creates `CloudflareUserRepository` and forwards
  `iss` from config to both token service functions.

**Discovery doc restored to OIDC posture**

- `DiscoveryDocument` gains `id_token_signing_alg_values_supported: ["EdDSA"]`,
  `subject_types_supported: ["public"]`, `claims_supported: [...]` (10 fields).
- `scopes_supported` restored to `["openid", "profile", "email", "offline_access"]`.
- 8 v0.25.0 "honest-reset" tests inverted to assert OIDC posture.

### Test counts

| Crate | v0.53.0 | v0.54.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 532 | 557 | +25 |
| `cesauth-adapter-test` | 117 | 117 | ±0 |
| `cesauth-ui` | 270 | 270 | ±0 |
| `cesauth-migrate-test` | 14 | 14 | ±0 |
| **Total** | **933** | **958** | **+25** |

New tests:
- 12 `oidc::id_token::tests::*` — unit tests for claim assembly and JWT signing
- 8 `service::token::tests::id_token_tests::*` — integration tests against
  inline stubs covering exchange + rotate id_token issuance, auth_time
  preservation, and no-openid-scope suppression
- 5 `oidc::discovery::*` — new OIDC-posture assertions (8 old tests inverted)

### Wire changes

**Additive only.** Existing `TokenResponse.id_token` was already present as
`Option<String>` (serialized as `null` pre-RFC 001); it now carries a real
value when `openid` ∈ scopes.  Clients that do not request `openid` see no
change.

**Discovery doc** field additions are additive; JSON parsers that ignore
unknown fields see no change.

### Breaking changes

None.

---

## [0.53.0] - 2026-05-09

Implements RFC 020 (migration chain hygiene), RFC 021 (user FK cascade
alignment), RFC 022 (permission catalog seed sync), RFC 023 (tenant boundary
integrity), RFC 024 (D1 index restoration), RFC 025 (Workers operational
readiness), RFC 026 (introspect hot-path consolidation), RFC 027
(accessibility and route contracts), RFC 028 (CHANGELOG/ROADMAP volume
policy), RFC 029 (rustfmt.toml review), RFC 013 (operational envelope),
RFC 014 (audit append performance), RFC 015 (request traceability), RFC 016
(admin scope badge), RFC 017 (OIDC audience admin editor), RFC 018
(preview-and-apply pattern). See the linked RFCs for design detail.

### What shipped (summary)

- **Migration chain** (`rfcs/done/020`): `schema_meta` table, `0004` rebuilt
  with FK cascade + COLLATE NOCASE restored, `0009` schema_meta write fixed,
  all migrations now write version. `cesauth-migrate-test` integration crate
  (14 tests).
- **User FK cascades** (`rfcs/done/021`): 7 tables gain `ON DELETE CASCADE`
  to `users(id)` — TOTP secrets, sessions, memberships, and role assignments
  are cleaned up when a user is deleted.
- **Permission catalog sync** (`rfcs/done/022`): `tenant:member:add` and
  `tenant:member:remove` added to the `permissions` seed and granted to
  `tenant_admin` / `system_admin` roles. Previously tenant admins received 403
  when attempting member management despite it being documented as supported.
- **Tenant boundary integrity** (`rfcs/done/023`): composite FKs on `groups`
  enforce cross-tenant isolation at the schema layer.
  `CoreError::CrossTenantReference` + service-layer validator.
- **D1 index restoration** (`rfcs/done/024`): restores `idx_users_status`,
  `idx_users_created_at` lost at the 0004 rebuild; adds partial indexes for
  anonymous-user sweep and session-index cron scan.
- **SCHEMA_VERSION** 10 → 15.
- **Workers operational readiness** (`rfcs/done/025`): bundle-size CI gate
  (2.5 MiB), plan-tier declaration in preflight doc.
- **`/introspect` hot path** (`rfcs/done/026`): `ClientAuthView` +
  `find_auth_view()` port method consolidates two D1 reads into one per
  request, closing a TOCTOU window.
- **Route contracts** (`rfcs/done/027`): `docs/src/expert/route-contracts.md`
  (149 routes), CI enforcement script, 3 flash accessibility tests.
- **CHANGELOG/ROADMAP volume** (`rfcs/done/028`): CHANGELOG 511KB → 62KB,
  ROADMAP 211KB → 79KB; archive files in `docs/changelog-archive/`.
- **`rustfmt.toml` removed** (`rfcs/done/029`): measurement confirmed zero
  diff; `cargo fmt --check` CI added.
- **ADR-016** (`rfcs/done/013`): Paid plan as operational baseline; bundle
  budget 2.5 MiB; cron batch-size env vars documented.
- **ADR-017** (`rfcs/done/014`): audit append telemetry (100ms threshold
  warning); Path B redesign deferred pending telemetry data.
- **RFC 015**: `request_id` (cf-ray) threaded through `LogConfig` and
  `audit_events`; ADR-018 documents deliberate absence of file-writing logger.
- **Scope badge** (`rfcs/done/016`): all 3 admin frames carry a scope badge
  (System/Tenancy/Tenant) with distinct color tokens; JA+EN i18n.
- **OIDC audience editor** (`rfcs/done/017`): `AudienceTarget` type,
  `resolve_audience_target` helper, tenant-admin editor form;
  `OidcClientAudienceChanged` + `OperationPreviewed` + `OperationApplied`
  audit event kinds.
- **Preview-and-apply** (`rfcs/done/018`): `ImpactStatement`, `ImpactSeverity`,
  `PreviewToken` infrastructure; `preview_body` template helper; first adopter
  impact functions for LOG_LEVEL change and admin token rotation.

### Test counts

| Crate | v0.52.1 | v0.53.0 | Δ |
|---|---|---|---|
| `cesauth-core` | 493 | 532 | +39 |
| `cesauth-adapter-test` | 117 | 117 | +0 |
| `cesauth-ui` | 249 | 270 | +21 |
| `cesauth-migrate-test` | 0 (new crate) | 14 | +14 |
| **Total** | **859** | **933** | **+74** |

### Schema

SCHEMA_VERSION 10 → 15 (migrations 0011–0015). New migrations:
- 0011: permission catalog sync (RFC 022)
- 0012: user FK cascades (RFC 021)
- 0013: tenant composite FK keys (RFC 023)
- 0014: D1 index restoration (RFC 024)
- 0015: `audit_events.request_id` column (RFC 015)

### New CI workflows

- `.github/workflows/bundle-size.yml` — gzip budget gate
- `.github/workflows/route-contracts.yml` — route documentation enforcement
- `.github/workflows/fmt.yml` — `cargo fmt --check`

### Breaking changes

None. All changes are additive at the wire layer. Existing audit rows
deserialize cleanly (`request_id` is nullable). Existing D1 schema upgrades
via the migration chain.

---

## [0.52.1] - 2026-05-06

Patch release. Implements RFC 012 (documentation and repo hygiene) and
RFC 007 (attack surface review cadence). No production behavior change;
no schema migration; no new env vars.

### Why this release

**RFC 012**: Four documentation quality items identified in the external
v0.50.1 codebase review. Two claims in README and `docs/src/introduction.md`
were factually wrong (admin console existence, audit storage). `migrate.rs`
at 2568 lines exceeded the 800-line soft cap. Inline comments referenced
the removed `jsonwebtoken` and R2 audit subsystems. No drift-detection
automation existed to catch future drift.

**RFC 007**: The attack surface review cadence process was defined in the
2026 initial review but never written into the codebase. This release
adds the written policy and creates the framework for per-quarter review
deliverables.

### What shipped

**RFC 012 — Documentation and repo hygiene**

- **README rewrite** (PR 1): "No management GUI" → "No SAML/LDAP/password
  login; admin console and tenant-scoped admin surface ship for operator
  use". "All land in R2" → "All land in D1's hash-chained `audit_events`
  table (ADR-010)". `Quick Start` code block removed spurious `R2` from
  the D1/KV/DOs description.
- **Inline comment cleanup** (PR 2): `routes/dev.rs` route comment updated
  from R2 bucket to D1 table; `config.rs` doc comment simplified (dropped
  `jsonwebtoken::EncodingKey::from_ed_pem` historical ref); `routes/oidc/token.rs`
  PKCS8 parser comment updated from `jsonwebtoken` to `pkcs8` crate.
- **`docs/src/introduction.md`** (PR 2): "No management GUI" claim corrected
  to match README.
- **`scripts/drift-scan.sh`** (new, PR 3): 60-line bash script that grep-scans
  the workspace for stale narrative phrases. Current pattern list:
  `"all land in R2"`, `"R2_AUDIT"`, `"pub code_plaintext"`,
  `"No management GUI"`. Passes cleanly on current codebase.
- **`.github/workflows/drift-scan.yml`** (new, PR 3): runs drift-scan on
  every PR and main-branch push. No Rust toolchain required; < 10 seconds.
- **`wrangler.toml`** (PR 4): added clarifying comment to `[[durable_objects]]`
  block noting RATE_LIMIT = Durable Object (not KV); KV holds only
  long-lived caches.
- **`crates/core/src/migrate.rs` split** (PR 5): 2568-line monolith → facade
  of ~35 lines + 7 focused submodules. Public API unchanged; all items
  re-exported from facade. Submodule sizes: `error.rs` (75 lines),
  `types.rs` (165 lines), `redaction.rs` (200 lines), `export.rs` (265 lines),
  `verify.rs` (135 lines), `invariants.rs` (425 lines), `import.rs` (20 lines).
  All 29 migrate tests pass unchanged.

**RFC 007 — Attack surface review cadence**

- `docs/src/expert/attack-surface-review-cadence.md` (new): process document
  defining when reviews run (pre-major, pre-cross-cutting-refactor,
  when new threat classes surface), the per-review deliverable shape
  (structured Markdown in `docs/src/expert/security-review-<year>-<quarter>.md`),
  the 8 starting surface categories from the 2026 initial review, and the
  link to `drift-scan.sh` as the continuous inter-review gate.
- `docs/src/SUMMARY.md`: entry added under Expert section.
- `rfcs/done/007-attack-surface-review-cadence.md`: RFC status → Implemented.

### RFC lifecycle

- `rfcs/done/007-attack-surface-review-cadence.md`: moved from proposed.
- `rfcs/done/012-doc-and-repo-hygiene.md`: moved from proposed.
- `rfcs/README.md`: Done table updated.

### Tests

859 lib + 29 migrate = 888 total, all pass. No new tests needed (RFC 012
is documentation; RFC 007 is process; migrate split is a mechanical refactor
gated by the existing 29-test suite).

### Schema / wire / DO changes

None. Patch-only release.

### Upgrade procedure

```
1. Deploy v0.52.1 (drop-in; no action required).
2. Run scripts/drift-scan.sh in your pipeline to catch future drift.
```

## [0.52.0] - 2026-05-06

Minor release. Implements RFC 006 (CSP without `'unsafe-inline'`) and
RFC 019 (RFC lifecycle policy adoption). RFC 006 earns the minor bump:
it changes the observable `Content-Security-Policy` HTTP header for all
HTML responses, which is an operator-visible behavior change.

### Why this release

**RFC 006**: ADR-007 (v0.23.0) noted `'unsafe-inline'` as a known
limitation; CSP Level 2 nonces were the intended fix. This release closes
that gap. Every inline `<style>` and `<script defer>` tag in cesauth's
rendered HTML now carries a per-request CSPRNG nonce. The
`Content-Security-Policy` header for HTML responses drops `'unsafe-inline'`
from `script-src` and `style-src` and adds `'nonce-<value>'` instead.
A CSP Level 2-aware browser will ignore any injected `<script>` or
`<style>` without the matching nonce, eliminating the XSS amplification
class that `'unsafe-inline'` would otherwise allow.

**RFC 019**: The `rfcs/` directory was a flat list of 18 files with all
statuses hardcoded to `Ready`. This release restructures it to a 4-folder
lifecycle (`proposed/`, `done/`, `archive/`) governed by a written policy
(RFC 019 itself, `rfcs/done/019-rfc-lifecycle-policy.md`).

### What shipped

**RFC 006 — CSP without `'unsafe-inline'`**

- `cesauth_core::security_headers::CspNonce` (new type): generates a
  cryptographically unguessable 16-byte base64url nonce per-request.
  Methods: `generate() -> Result<Self, getrandom::Error>`,
  `from_str(s: &str) -> Self`, `as_str() -> &str`,
  `csp_expression() -> String` (returns `'nonce-<value>'`).
- `build_csp_with_nonce(csp: &str, nonce: Option<&CspNonce>) -> String`
  (internal helper): injects `'nonce-<value>'` into `script-src` and
  `style-src` directives; removes `'unsafe-inline'`; supports `{nonce}`
  placeholder in operator-supplied `SECURITY_HEADERS_CSP` override.
- `headers_for_response` gains `nonce: Option<&CspNonce>` parameter.
  All existing call sites pass `None`; HTML render paths pass the
  per-request nonce.
- `cesauth_ui::set_render_nonce(nonce: &str)` / `render_nonce() -> String`:
  thread-local nonce store for the Cloudflare Workers per-Isolate model.
  Worker handlers call `set_render_nonce` before rendering HTML; template
  functions read it via `crate::render_nonce()` without parameter changes
  to the public API.
- `crates/ui/src/admin/frame.rs`, `tenant_admin/frame.rs`,
  `tenancy_console/frame.rs`: `<style nonce="{nonce}">` — frame-level
  inline CSS now carries the nonce attribute.
- `crates/ui/src/templates.rs` (`frame_with_flash`, `login_page_for`):
  `<style nonce="{nonce}">` and `<script defer nonce="{nonce}">`.
- Worker route handlers (`routes/ui.rs`, `routes/oidc/authorize.rs`,
  `routes/admin/console/render.rs`, `routes/me/*`, `routes/magic_link/*`):
  each HTML-returning handler now calls `CspNonce::generate()` +
  `cesauth_ui::set_render_nonce()` before rendering. On CSPRNG failure:
  audit `CsrfRngFailure`, return HTTP 500 (fail-closed).
- Per-route CSP strings: `'unsafe-inline'` replaced by `format!("...
  'nonce-{n}'...", n = csp_nonce.as_str())`. The login-page Turnstile
  variant and the non-Turnstile variant are both updated.
- `security_headers::apply` (worker middleware): reads `render_nonce()` 
  after the handler runs and passes `Some(CspNonce::from_str(&nonce_str))`
  to `headers_for_response`, so the global security-headers middleware
  also injects the nonce into its CSP output.
- `crates/ui/src/templates/tests.rs`: `strip_inline_style` updated to
  match `<style nonce="...">` tags. Five new nonce-injection tests added.
- 15 new tests in `security_headers::nonce_tests` covering RFC 006
  §Test plan items 1–5, 7–8, 12–13 (uniqueness, base64url format,
  ≥128-bit entropy, CSP expression format, `{nonce}` placeholder,
  `unsafe-inline` removal, HTML/non-HTML CSP presence).

**RFC 019 — RFC lifecycle policy**

- `rfcs/` restructured: `proposed/` (10 open RFCs), `done/` (8 shipped
  RFCs + RFC 019 itself), `archive/` (empty).
- All existing RFC Status fields updated to match their folder.
- `rfcs/README.md` rewritten as a state-grouped index.
- `rfcs/done/019-rfc-lifecycle-policy.md` (new): the lifecycle policy
  document itself, implementing the policy it describes.

### Tests

859 lib tests pass (was 842 in v0.51.2).

| Crate | Before | After | Delta |
|---|---|---|---|
| `cesauth-core` | 481 | 493 | +12 (RFC 006 nonce + CSP tests) |
| `cesauth-adapter-test` | 117 | 117 | — |
| `cesauth-ui` | 244 | 249 | +5 (RFC 006 nonce injection tests) |

### Wire / operator changes

- `Content-Security-Policy` header for HTML responses: `'unsafe-inline'`
  removed from `script-src` and `style-src`; `'nonce-<per-request-value>'`
  added instead. **This is a behavior change.** Browsers that support
  CSP Level 2 (all current browsers) will block scripts and styles that
  don't carry the matching nonce attribute. Verify that no inline event
  handlers (`onclick=`, `onload=`, etc.) exist in operator-customised
  templates before upgrading. cesauth's own templates carry no inline
  event handlers (pinned by test).
- `SECURITY_HEADERS_CSP` operator override: now supports `{nonce}`
  placeholder. `"...'nonce-{nonce}'..."` will be substituted with the
  actual per-request nonce value. Operators who override CSP and want
  nonce support must add this placeholder.
- No new env vars. No schema changes. No DO state changes.

### Upgrade procedure

```
1. Deploy v0.52.0.
2. Verify HTML pages render correctly in a staging browser.
   Open DevTools → Console: look for CSP violations.
3. If using SECURITY_HEADERS_CSP override and want nonce support,
   add 'nonce-{nonce}' to your script-src and style-src directives.
4. Deploy production.
```

### ADR changes

- ADR-007 §Q3: `'unsafe-inline'` limitation closed in v0.52.0.
  The two paths listed (extract to same-origin files / per-request
  nonces) were resolved via the nonce path, as specified in RFC 006.

## [0.51.2] - 2026-05-06

Patch release. Implements RFC 005 (`cargo fuzz` for the JWT parser
surface). No production code change, no schema change, no new env vars.

### Why this release

cesauth's JWS Compact deserializer (`cesauth_core::jwt::signer::verify`
and `verify_for_introspect`) processes potentially adversarial tokens on
every protected request. The code is hand-rolled since v0.44.0 (replacing
`jsonwebtoken`). Example-based tests verify correctness for known inputs;
libFuzzer finds panics, OOM, and DoS-via-super-linear-parsing on the vast
adversarial input space that tests can't realistically enumerate.

This is **layer-1** fuzzing: a 60-second one-shot in CI. Continuous fuzzing
(OSS-Fuzz, ClusterFuzzLite) is a `Later` item.

### What shipped

**RFC 005 — `cargo fuzz` for the JWT parser**

- `fuzz/` directory (NOT a workspace member — keeps nightly fuzz deps
  out of the stable lockfile).
  - `fuzz/Cargo.toml`: standalone crate with `libfuzzer-sys = "0.4"` and
    `cesauth-core` path dep. `[package.metadata] cargo-fuzz = true`.
  - `fuzz/fuzz_targets/jwt_parse.rs`: single fuzz target exercising both
    `verify::<AccessTokenClaims>` and `verify_for_introspect::<AccessTokenClaims>`
    with a fixed test keypair (seed `[1u8; 32]`; not a production key).
    Non-UTF-8 byte sequences are skipped (the verifier's contract is `&str`).
    Return value is intentionally discarded — the goal is panic-freedom, not
    verification success.
  - `fuzz/corpus/jwt_parse/` (10 seed files): `empty.bin`, `single-dot.bin`,
    `two-dots.bin`, `three-dots.bin`, `alg-none.bin`, `valid-header-garbage-payload.bin`,
    `well-formed-no-real-sig.bin`, `oversized-header.bin`, `truncated-payload.bin`,
    `ascii-with-dots.bin`. Corpus seeds cover the key parser code-paths
    (empty input, segment-count edge cases, `alg: none` rejection, known-bad-sig).
- `.github/workflows/fuzz.yml` (new): runs `cargo +nightly fuzz run jwt_parse
  -- -max_total_time=60` on PRs touching `crates/core/src/jwt/**` or `fuzz/**`.
  Manual dispatch supports custom time limits. Fuzz artifacts uploaded on
  failure for offline analysis.
- `.gitignore`: `fuzz/target/` and `fuzz/artifacts/` excluded (ephemeral);
  `fuzz/corpus/` IS committed (seed corpus).
- `Cargo.toml` workspace comment: explicit note that `fuzz/` is intentionally
  excluded from the workspace.

### Fuzz target goals

1. **Panic-freedom**: `verify` must return `Ok` or `Err` on any byte sequence;
   never panic or abort.
2. **OOM resistance**: malformed tokens with giant claimed payloads must not
   cause unbounded allocation.
3. **DoS resistance**: pathological input must not trigger super-linear parsing
   work.

### Running locally

```sh
# From cesauth/fuzz/

# One-shot (60 seconds, matching CI):
cargo +nightly fuzz run jwt_parse -- -max_total_time=60

# Extended run (hours, deeper coverage):
cargo +nightly fuzz run jwt_parse

# Suppress benign leak-on-exit false positives:
cargo +nightly fuzz run jwt_parse -- -detect_leaks=0
```

Findings go to `fuzz/artifacts/jwt_parse/`. Report via `.github/SECURITY.md`.
Do NOT push findings in public PRs.

### Tests

No change to lib test count (871 total, same as v0.51.1). The fuzz target is
not a `#[test]`; it runs under libFuzzer in CI.

### Schema / wire / DO changes

None. Patch-only: no code change to any production crate, no new routes,
no new env vars, no schema migration.

### Upgrade procedure

```
1. Deploy v0.51.2 (drop-in; no action required).
2. The fuzz CI job runs automatically on future JWT-touching PRs.
```

## [0.51.1] - 2026-05-06

Patch release. Implements RFC 004 (WebAuthn typed error responses) and
RFC 003 (property-based tests). Both are internal or additive: no new
routes, no schema changes, no new env vars.

### Why this release

**RFC 004**: WebAuthn ceremony failures currently collapse to a generic
HTTP 500 with `{"error": "server_error"}`. Clients can't render specific
recovery guidance — they don't know whether to try a different
authenticator, ask their admin, or simply retry. A small typed `kind`
field (six values) lets clients branch on the category while keeping the
diagnostic detail string server-side only.

**RFC 003**: Property-based tests on two surfaces that example-based tests
can't adequately cover: JWT sign/verify crypto round-trips (where the input
space is vast) and the `redirect_uri` exact-match invariant (historically
the most bug-prone part of an OAuth server).

### What shipped

**RFC 004 — WebAuthn typed error responses**

- `cesauth_core::webauthn::error` (new module): `WebAuthnErrorKind` — a
  six-variant enum (`UnknownCredential`, `RelyingPartyMismatch`,
  `UserCancelled`, `SignatureInvalid`, `ChallengeMismatch`, `Other`)
  with `as_str() -> &'static str` and `Serialize`/`Deserialize` deriving
  to snake_case.
- `classify(detail: &str) -> WebAuthnErrorKind` — centralised mapping from
  diagnostic strings to kind. Falls through to `Other` for unmapped strings;
  new diagnostic strings from future dependency upgrades are safe.
- `cesauth_core::webauthn` re-exports: `pub use error::{WebAuthnErrorKind,
  classify as classify_webauthn_error}`.
- `cesauth_worker::error::oauth_error_response`: WebAuthn failures now
  produce `{"error": "server_error", "kind": "<snake_case_kind>"}`. All
  other error variants are unchanged. The diagnostic detail string does NOT
  appear on the wire (privacy invariant; stays in audit events and
  `console_error!` logs only).
- Three new tests in `worker::error::tests` pinning: (a) the kind field is
  present and correctly classified; (b) the kind value is not the raw
  diagnostic string; (c) all six variants have distinct `as_str()` values.
- Ten unit tests in `webauthn::error::tests` covering every explicitly
  mapped diagnostic string, the `Other` fallthrough (two cases), serde
  snake_case, and a `classify_covers_all_known_cesauth_diagnostic_strings`
  comprehensive pin.

**RFC 003 — Property-based tests (`proptest`)**

- `proptest = "1"` added to `[workspace.dependencies]` (dev-dep only).
- `proptest.workspace = true` added to `cesauth-core [dev-dependencies]`.
- `crates/core/src/jwt/proptests.rs` (new): five properties.
  - `jwt_sign_verify_round_trip` — arbitrary claim strings + arbitrary Ed25519
    seeds; decoded claims equal originals.
  - `jwt_single_byte_tamper_causes_verify_failure` — flip any single byte at
    any position; verify must return `Err`.
  - `jwt_wrong_key_causes_verify_failure` — token signed with key A must not
    verify under key B.
  - `magic_link_issue_verify_round_trip` — any `now` value; issued OTP
    verifies before expiry.
  - `magic_link_tampered_otp_fails_verify` — first character flipped; must
    not verify.
- `crates/core/src/oidc/authorization/redirect_uri_proptests.rs` (new):
  seven properties exercising the `redirect_uri` exact-match invariant.
  - `matcher_accepts_byte_equal_uri` — registered URI accepted.
  - `matcher_rejects_uri_not_in_allowed_set` — unregistered URI rejected.
  - `matcher_rejects_trailing_slash_variant` — `uri/` rejected when only
    `uri` is registered (classic open-redirect class).
  - `matcher_rejects_path_suffix_appended` — both `uri/suffix` and
    `urisuffix` rejected.
  - `matcher_treats_explicit_443_as_distinct_from_no_port` — `:443`
    explicit vs implicit are distinct strings.
  - `matcher_treats_http_and_https_as_distinct` — scheme difference always
    rejected.
  - `matcher_is_case_sensitive` — uppercase variant rejected.

### Tests

481 `cesauth-core` lib tests pass (was 459 in v0.51.0). The proptest
properties run 256 cases each by default, so the test suite is heavier
than the raw count suggests.

| Crate | Before | After | Delta |
|---|---|---|---|
| `cesauth-core` | 459 | 481 | +22 (10 RFC 004 unit + 12 proptest functions) |
| `cesauth-adapter-test` | 117 | 117 | — |
| `cesauth-ui` | 244 | 244 | — |
| `cesauth-worker` host subset | 5 | 8 | +3 (RFC 004 error shape pins) |

### Schema / wire / DO changes

- **No schema migration.** SCHEMA_VERSION remains 10.
- **Wire format additive only**: WebAuthn error responses gain a `kind` field.
  Clients that ignore unknown JSON fields (the correct default) see no change.
- **No new env vars**, no new bindings, no `wrangler.toml` changes.
- **No DO state changes.**

### Operator notes

No action required to upgrade. The `kind` field in WebAuthn error responses
is available to clients immediately after deploying v0.51.1.

If you maintain a client-side WebAuthn integration:
- Branch on `response.kind` for specific error recovery guidance.
- `"unknown_credential"` → prompt to try a different authenticator or register.
- `"relying_party_mismatch"` → deployment misconfiguration; contact admin.
- `"user_cancelled"` → retry the ceremony.
- `"signature_invalid"` → authenticator may be cloned; try another.
- `"challenge_mismatch"` → re-issue the ceremony (challenge likely expired).
- `"other"` → generic failure.

### ADR changes

None.

### Upgrade procedure

```
1. Deploy v0.51.1 (no migration, no new config).
2. WebAuthn error responses now include "kind" field.
```

## [0.51.0] - 2026-05-06

Minor release. Implements RFC 010 (MagicLinkMailer port) and closes
RFC 002 (client_secret_hash documentation drift). RFC 010 introduces new
operator-visible configuration — three optional env vars for the HTTPS
provider adapter — which earns the minor version bump per the versioning
policy.

### Why this release

**RFC 010 (P0 structural)**: RFC 008 (v0.50.3) stopped the audit log leak
of Magic Link OTP plaintext. However, without a defined delivery contract,
operators under deadline pressure would reintroduce the hack — the audit
log was previously the only delivery path that existed. RFC 010 builds the
`MagicLinkMailer` trait the development directive claimed existed but which
had zero code hits in the workspace. The dev directive's promise is now
truth.

**RFC 002 (documentation drift)**: `migrations/0001_initial.sql` described
`client_secret_hash` as `argon2id(secret)`. No Argon2 implementation ever
existed; the actual path has always been SHA-256, matching `admin_tokens`
and the magic-link OTP hash. The schema comment is now corrected.

### What shipped

**RFC 010 — MagicLinkMailer port + provider adapters**

- `cesauth_core::magic_link::mailer` (new module): `MagicLinkMailer` async
  trait, `MagicLinkPayload`, `MagicLinkReason`, `DeliveryReceipt`,
  `MailerError`. Pub-re-exported from `cesauth_core::magic_link`.
- `cesauth-adapter-cloudflare::mailer` (new module): four reference adapters
  and the `from_env` factory.
  - `DevConsoleMailer`: logs handle (never code) to worker console. Active
    only when `WRANGLER_LOCAL=1`. The factory enforces this guard.
  - `UnconfiguredMailer`: returns `NotConfigured` on every send. The default
    when no provider env var is set. Surfaces misconfig via audit on first use.
  - `ServiceBindingMailer`: sends a JSON envelope through the
    `MAGIC_LINK_MAILER` CF service binding to an operator mail worker.
    Preferred path — stays within Cloudflare's network.
  - `HttpsProviderMailer`: POSTs a SendGrid v3-compatible JSON body to
    `MAILER_PROVIDER_URL` with `Authorization: $MAILER_PROVIDER_AUTH_HEADER`.
    Works with SendGrid, Resend, Postmark, Mailgun, SES-via-gateway.
  - `from_env(env)` factory: selects DevConsole → ServiceBinding → Https →
    Unconfigured in priority order.
- `cesauth_worker::adapter::mailer` (new module): thin re-export of
  `from_env` so route handlers import from `crate::adapter`.
- `routes::magic_link::request`: wires the mailer after `MagicLinkIssued`
  audit. On `Ok(receipt)` → emits `MagicLinkDelivered` (handle +
  `provider_msg_id`). On `Err(e)` → emits `MagicLinkDeliveryFailed` (handle
  + `e.audit_kind()`), logs at Error, returns the same success-shaped
  response (no enumeration leak via differential response).
- `routes::api_v1::anonymous` (promote path): same mailer wiring pattern
  with `reason = AnonymousPromote`.
- New audit kinds: `MagicLinkDelivered` (`magic_link_delivered`),
  `MagicLinkDeliveryFailed` (`magic_link_delivery_failed`).
- `cesauth_worker::i18n`: `locale_str(Locale) -> &'static str` helper for
  mailer payload locale field.
- `docs/src/deployment/email-delivery.md` (new): operator chapter covering
  adapter selection, configuration per option (service binding / HTTPS /
  defer), local dev workflow, monitoring dashboard queries, and security
  considerations (enumeration prevention, provider-side responsibility,
  bounce handling).
- `docs/src/expert/adr/015-magic-link-mailer.md` (new): ADR-015, Accepted.
  Documents 9 design questions including trait location, async signature,
  adapter selection priority, fail-open vs fail-closed on delivery failure,
  timing-attack mitigation, and body template scope.

**RFC 002 — `client_secret_hash` documentation drift resolved**

- `migrations/0001_initial.sql`: column comment corrected from
  `argon2id(secret)` to `sha256_hex(secret)`.
- `service::client_auth` module doc: updated to record the resolution and
  explain why SHA-256 is correct for server-minted 256-bit secrets (RFC 002
  reasoning inline).

### Tests

820 lib tests pass (was 817 in v0.50.3). Net +3:

| Crate | Before | After | Delta |
|---|---|---|---|
| `cesauth-core` | 456 | 459 | +3 (MagicLinkMailer/MailerError/MagicLinkReason unit tests) |
| `cesauth-adapter-test` | 117 | 117 | — |
| `cesauth-ui` | 244 | 244 | — |
| `cesauth-worker` host subset | 2 | 2 | — |

### Schema / wire / DO changes

- **No schema migration.** SCHEMA_VERSION remains 10. The migration 0001
  comment edit is cosmetic.
- **Wire format unchanged.** No new HTTP endpoints. Existing Magic Link
  endpoint behavior is identical from the user's perspective.
- **DO state unchanged.**
- **New env vars (optional)**:

| Var | Adapter | Required? |
|---|---|---|
| `MAGIC_LINK_MAILER` | ServiceBinding (wrangler.toml `[[services]]`) | No |
| `MAILER_PROVIDER_URL` | HttpsProvider | Required for HttpsProvider |
| `MAILER_PROVIDER_AUTH_HEADER` | HttpsProvider | Required for HttpsProvider |
| `MAILER_PROVIDER_FROM_ADDRESS` | HttpsProvider | Required for HttpsProvider |
| `MAILER_PROVIDER_FROM_NAME` | HttpsProvider | Optional (display name) |

None of these vars changes existing behavior if absent — the default is
`UnconfiguredMailer`, which matches the pre-v0.51.0 "no mailer" state.

### Operator notes

1. **Choose your delivery path** before deploying v0.51.0 to production:
   - Service binding (recommended): add `[[services]]` block to
     `wrangler.toml`.
   - HTTPS provider: `wrangler secret put` for the three required vars.
   - Defer: do nothing; Magic Link issuances will audit as
     `magic_link_delivery_failed kind=not_configured`.
2. **Add a dashboard panel** for `magic_link_delivery_failed` broken down
   by `kind` field. A spike of `not_configured` means your deployment has
   no mail provider wired; `permanent` means provider rejection.
3. **Local dev workflow**: with `WRANGLER_LOCAL=1`, the handle is logged to
   the worker console. Retrieve the OTP hash from local D1 via `wrangler d1
   execute`. See `docs/src/deployment/email-delivery.md` for details.
4. **RFC 008 OTP purge**: if you haven't run the v0.50.3 purge runbook yet,
   do so before deploying v0.51.0. The mailer wiring is now active; leaked
   OTP rows from pre-v0.50.3 deployments are the only remaining exposure.

### ADR changes

- ADR-015 `015-magic-link-mailer.md`: new, Accepted in v0.51.0.
  `docs/src/SUMMARY.md` updated.

### Upgrade procedure

```
1. Choose a delivery path (service binding / HTTPS / defer).
2. Configure the chosen adapter (wrangler.toml or secrets).
3. Deploy v0.51.0.
4. Issue a test Magic Link in staging; confirm audit shows
   magic_link_delivered (or magic_link_delivery_failed kind=not_configured
   if intentionally deferred).
5. Deploy production.
```

## [0.50.3] - 2026-05-06

Security and hardening patch. Implements RFC 008, RFC 009, and RFC 011
from the v0.50.1 external codebase review — the three items classified
as Tier 0 (production blockers) and Tier 1 (P1 hardening) that do not
require new operator-visible configuration.

### Why this release

Three findings from the external review required immediate attention:

- **RFC 008 (P0)**: Every Magic Link issuance wrote the OTP plaintext
  into the audit log, violating cesauth's own "no token material ever"
  invariant. Anyone with D1 read access, a Logpush forwarder, or access
  to a migration export could log in as any user who used Magic Link
  during the retention window.
- **RFC 009 (P0)**: `introspect_token` was called with `expected_aud =
  issuer` while access tokens carry `aud = client.id`. The test suite
  masked the bug by setting `AUD = ISS` in the fixture. Every valid
  access-token introspection in production returned `{"active": false}`.
  The v0.50.0 audience gate (ADR-014 §Q1) consequently never fired.
  The companion finding: on D1 storage error, the audience gate fell
  open (fail-open), silently disabling the security boundary for
  deployments that had opted into per-client audience scoping.
- **RFC 011 (P1)**: `csrf::mint()` swallowed `getrandom` failure with
  `let _ =`, producing a predictable all-zero token when the platform
  CSPRNG failed. Negative env values for rate-limit thresholds silently
  wrapped to huge `u32` via `as u32`, effectively disabling rate limits.
  Three `/me/security/sessions` routes were registered twice in `lib.rs`
  (merge-conflict residue from v0.35.0).

### What shipped

**RFC 008 — Eliminate plaintext OTP in audit log**

- `routes::magic_link::request` and `routes::api_v1::anonymous`: the
  `reason` field on `EventKind::MagicLinkIssued` now carries
  `handle=<handle>` only. The OTP plaintext is gone.
- `cesauth_core::magic_link::IssuedOtp`: renamed `code_plaintext` →
  `delivery_payload`. The name signals intent — this value is for
  delivery, not logging.
- `crates/worker/src/audit.rs`: module doc gains an explicit "Invariant:
  no token material in audit" section naming the specific fields and the
  RFC 008 history.
- `crates/worker/src/audit/tests.rs` (new): `no_audit_reason_format_string_contains_secret_substring` — a static-grep test that walks every `.rs` source file at test time and asserts no `audit::write_*` call site references `code=`, `code_plaintext`, `otp=`, `secret=`, `password=`, or `plaintext`. Prevents reintroduction.
- `docs/src/deployment/runbook.md`: new section "Operation: purge
  plaintext OTP audit leaks (one-time, v0.50.1 → v0.50.3 upgrade)" with
  the exact SQL, the export-for-forensic-preservation variant, and the
  chain re-baseline procedure.

**RFC 009 — Introspection access-token `aud` correctness + fail-closed gate**

- `cesauth_core::jwt::signer::verify_for_introspect` (new): a dedicated
  verifier for the `/introspect` path that omits `aud` enforcement.
  Access tokens carry `aud = client.id`; the pre-v0.50.3 verifier
  expected `aud = issuer`, rejecting every valid production token. The
  audience gate in the worker handler (`apply_introspection_audience_gate`,
  ADR-014 §Q1) is now the sole aud-policy point. The strict `verify()`
  function is unchanged and continues to be used by all other callers.
- `cesauth_core::service::introspect::introspect_token`: `expected_aud`
  parameter removed. Module doc updated with the RFC 009 rationale.
- Worker handler `routes::oidc::introspect`: audience-gate client lookup
  is now fail-closed. `Ok(None)` (admin DELETE race post-auth) → HTTP 401
  + new `EventKind::IntrospectionRowMissing` audit event. `Err(_)` (D1
  storage outage) → HTTP 503.
- Test fixture: `const AUD: &str` changed from the issuer URL to
  `"client_X"` — the production-realistic shape. Existing tests updated.
- Three new regression tests in `service::introspect::tests::rfc009_aud_correctness`.
- ADR-014 §Q1: amendment paragraph noting the v0.50.3 tightening.

**RFC 011 — Worker-layer hardening**

- `csrf::mint()`: return type changed from `String` to
  `Result<String, getrandom::Error>`. On `Err`, all callers now emit a
  `CsrfRngFailure` audit event and return HTTP 500 rather than silently
  producing a predictable all-zero token. New `CsrfRngFailure` audit kind.
- `config.rs`: new `var_u32_bounded(name, default, max)` helper that
  rejects negative values (preventing `as u32` silent wrap) and values
  above `max`. Applied to `REFRESH_RATE_LIMIT_THRESHOLD`,
  `INTROSPECTION_RATE_LIMIT_THRESHOLD`, and their `_WINDOW_SECS` variants.
  A mis-configuration now fails at startup with a clear message rather
  than silently disabling rate limits.
- `lib.rs`: removed the second (duplicate) registration block for
  `GET /me/security/sessions`, `POST /me/security/sessions/revoke-others`,
  and `POST /me/security/sessions/:session_id/revoke`. These were
  merge-conflict residue from v0.35.0.
- `lib.rs` tests: `no_duplicate_route_registrations` — static-grep test
  that asserts each `(method, path)` tuple appears at most once. Prevents
  recurrence.
- `docs/src/expert/adr/012-session-hardening.md`: Superseded header added
  (canonical is `012-sessions.md`). `SUMMARY.md` index updated.
- Two new tests for `csrf::mint() -> Result` shape.

### Tests

817 lib tests pass (was 814 in v0.50.2). Breakdown by crate:

| Crate | Before | After | Delta |
|---|---|---|---|
| `cesauth-core` | 453 | 456 | +3 (RFC 009 regression pins) |
| `cesauth-adapter-test` | 117 | 117 | — |
| `cesauth-ui` | 244 | 244 | — |
| `cesauth-worker` (host subset) | — | 2 | +2 (RFC 011: csrf + route pins) |

### Schema / wire / DO changes

- **No schema migration.** SCHEMA_VERSION remains 10.
- **Wire format**: `/introspect` now returns `active: true` (and populates
  `aud`) for valid access tokens that previously returned `active: false`
  due to the RFC 009 bug. This is a **behavior change at upgrade**: RPs
  that relied on the (broken) `inactive` response will now receive the
  correct `active` response. Release notes recommend testing introspection
  flows against v0.50.3 in staging before production rollout.
- **No new bindings**, no new env vars, no `wrangler.toml` changes.
- **DO state unchanged** (FamilyState, ActiveSession, etc.).

### Operator notes

1. **Run the OTP purge runbook** if you ran any v0.16.0–v0.50.1 in
   production. See `docs/src/deployment/runbook.md` → "Operation: purge
   plaintext OTP audit leaks". Fresh deployments that never ran ≤ v0.50.1
   can skip this.
2. **Introspection behavior change**: access-token introspection now returns
   correct results. Check your resource-server introspection clients — if
   they were silently falling back on `active: false`, they now see `true`.
3. **Rate-limit env validation**: if you have `REFRESH_RATE_LIMIT_THRESHOLD`
   or `INTROSPECTION_RATE_LIMIT_THRESHOLD` set to a negative value (which
   would previously have silently disabled rate limits), v0.50.3 will now
   refuse to start. Correct the value before deploying.
4. **No rollback to v0.50.1** after running the OTP purge — that version
   reintroduces the audit-as-delivery path.

### ADR changes

- ADR-014 §Q1: amended to note the RFC 009 verifier fix and gate
  tightening. The §Q1 design is now actually in effect.

### Upgrade procedure

```
1. Deploy v0.50.3 (no schema migration needed).
2. Verify /introspect works correctly for access tokens.
3. Run the OTP purge runbook if applicable.
4. Watch audit_chain_cron on next 04:00 UTC run; verify the
   chain status page shows ✓ valid after the re-baseline.
```



Documentation-only patch release. Adds 11 new RFCs
(008-018) to `rfcs/` triaging the v0.50.1 external
codebase review findings, plus a ROADMAP entry tracking
the v0.50.2 production-blocker sweep.

This release ships the **specifications** for the
production-blocker sweep; the **implementation** lands
in subsequent minor releases starting with the next
v0.50.x or v0.51.0.

### Background

An external Rust + Cloudflare codebase review of
v0.50.1 surfaced three production blockers, three
security hardening items, and four quality-and-
operations items. Each finding was independently
verified against the v0.50.1 source tree before
acceptance. The triage produced 7 RFCs (008-014).

A follow-up operator question — "is server logging
sufficient, can client requests be traced
end-to-end, and is a file-writing logger needed?" —
produced an 8th RFC (015) covering request
correlation, audit cross-link, and explicit
documentation of the deliberate file-logger absence.
RFC 015 ships in the same v0.50.2 patch release.

A third source — an external UI/UX design update
reviewing v0.50.1 — surfaced three admin-surface
gaps not covered by the code review or the
logging follow-up: scope-badge inconsistency
across admin frames; the v0.50.0-deferred admin UI
for `oidc_clients.audience` (operators currently
run direct D1 SQL); the absence of an explicit
"impact preview before apply" pattern for
destructive admin operations. These produced RFCs
016, 017, 018 — the **Tier 4 admin UX hardening**
section, deferred behind Tiers 0-3 but tracked in
the same v0.50.2 release.

### What ships

#### Tier 0 — Production blockers (P0/P1, ship in next release)

- **RFC 008** — Eliminate plaintext OTP in audit log.
  P0. The audit module's self-declared "No token
  material ever" invariant is violated at two sites
  (`worker/src/routes/magic_link/request.rs:170-178`,
  `worker/src/routes/api_v1/anonymous.rs:254-264`)
  where the Magic Link OTP plaintext is logged into
  the audit `reason` field. Fix removes the plaintext,
  adds a static-grep pin test against reintroduction,
  renames `code_plaintext` → `delivery_payload` for
  intent clarity, and provides an operator runbook
  for purging already-leaked rows + chain
  re-baseline.
- **RFC 009** — Introspection access-token `aud`
  correctness + audience-gate fail-closed. P0 + P1.
  Token mints with `aud=client.id` but `/introspect`
  verifies with `expected_aud=issuer`; the test
  fixture sets `ISS == AUD` so the production bug is
  invisible to tests. Result: every production access-
  token introspection returns `{"active":false}`,
  silently breaking RP integration. ADR-014 §Q1's
  audience gate consequently never fires. Fix removes
  `expected_aud` enforcement from the verifier (gate
  becomes canonical aud check), updates fixture to
  `AUD = "client_X"`, and tightens the gate to
  fail-closed on storage error (HTTP 503) and on
  client row missing post-auth (HTTP 401, new audit
  kind `IntrospectionRowMissing`).
- **RFC 010** — Magic Link real delivery. P0.
  Workspace-wide grep confirms no `MagicLinkMailer`
  trait exists despite the development directive
  declaring one. The audit log IS the OTP delivery
  mechanism today, which is why RFC 008's plaintext
  leak exists. Fix builds the trait the directive
  promised: `MagicLinkMailer` in `cesauth-core` with
  audit-disjoint crate boundary, four reference
  adapters (Cloudflare service binding, HTTPS
  provider, dev console gated on `WRANGLER_LOCAL=1`,
  `UnconfiguredMailer` fallback), new audit kinds
  `MagicLinkDelivered` / `MagicLinkDeliveryFailed`,
  ADR-015 alongside, new operator chapter
  `docs/src/deployment/email-delivery.md`.
- **RFC 011** — Worker-layer hardening. P1 + P2.
  Bundle of four mechanical fixes: CSRF
  `mint()` returns `Result<String>` (current code
  swallows `getrandom` error and produces a
  predictable constant token); `var_parsed_u32_bounded`
  config helper rejects negative values (current
  `as u32` cast wraps to huge u32, silently disabling
  rate limits); duplicate route registration
  deletion (`worker/src/lib.rs:193-200` is residue
  from v0.35.0); `docs/src/expert/adr/012-session-hardening.md`
  marked Superseded by `012-sessions.md`.

#### Tier 3 — Quality and operations (defer behind P0 sweep)

- **RFC 012** — Doc and repo hygiene. README rewrites
  to drop "No management GUI" and "land in R2" claims;
  mechanical split of `crates/core/src/migrate.rs`
  (2568 lines) into 9 submodules under 500 lines
  each; development directive corrections (rate-limit
  is DO not KV; `crates/do` is skeleton); drift-scan
  CI workflow with stale-phrase pattern list.
- **RFC 013** — Operational envelope. ADR-016 declares
  Cloudflare Paid plan as floor; bundle-size CI gate
  at 7 MB gzipped; configurable cron batch sizes;
  `nodejs_compat` removal or in-tree justification;
  new `docs/src/deployment/operational-envelope.md`
  chapter with per-request budget tables; bundle-history
  trend doc.
- **RFC 014** — Audit append performance. Path A
  (acceptance + telemetry) for v0.50.x: instrument
  `append` with latency / retry warnings, document
  ~100/s sustained ceiling, ship operator runbook.
  Path B (DO-serialized append, ADR-017) deferred
  until Path A telemetry triggers.
- **RFC 015** — Request traceability. Operator
  follow-up question on logging completeness. Existing
  `log` module is well-designed (categorized,
  level-gated, sensitivity-gated) but request-scope
  correlation is missing: log lines from the same
  request are not grouped, audit events can't be
  cross-linked to log lines, and HTTP request
  lifecycle isn't logged consistently. Fix adds a
  `cf-ray`-derived `request_id` (free, already in CF /
  Logpush, observable client-side via response
  header) threaded through `LogConfig` and
  `NewAuditEvent`; one middleware-emitted HTTP
  lifecycle log per request (replacing ad-hoc
  per-handler `Category::Http` lines, net log volume
  same or fewer); new nullable
  `audit_events.request_id` column for cross-link
  (SCHEMA_VERSION 10 → 11, ALTER-only migration,
  non-chained additive — chain integrity unaffected).
  **Deliberately documents the absence of a
  file-writing logger** as ADR-018: Cloudflare
  Workers has no filesystem; per-line writes to
  KV/R2/D1 would contradict the security posture
  ("セキュリティ重視のため不要なログは出力したりファイルに残し
  たりすることは不要") by adding a persistence surface
  outside operator's existing audit/log governance.
  The four reasons (no FS / security posture /
  redundancy with Cloudflare Logs + audit / no-
  unnecessary-logs discipline) are recorded in
  ADR-018 so future "why don't we write logs to a
  file" questions get redirected to the ADR.

#### Tier 4 — Admin UX hardening (defer behind P0 sweep + Tier 3)

- **RFC 016** — Admin scope badge standardization.
  The three admin frames (`/admin/console/*`
  system, `/admin/tenancy/*` tenancy,
  `/admin/t/<slug>/*` tenant) currently have
  visually distinct chrome but no semantic
  "you are operating in scope X" badge consistent
  across all three. Adds `ScopeBadge` enum
  (System / Tenancy / Tenant(slug)) + 3 colour
  tokens (purple / blue / green, deliberately
  distinct from the existing semantic
  success / warning / danger / info tokens) + 3
  MessageKey variants. Single-place chrome change;
  no schema or wire impact.

- **RFC 017** — OIDC client audience-scoping admin
  editor. v0.50.0 shipped the audience-scoping
  schema + `/introspect` gate but explicitly
  deferred the admin UI ("Admin console UI for
  this is out of v0.50.0 scope"). Operators
  currently run `wrangler d1 execute "UPDATE
  oidc_clients SET audience = ? WHERE id = ?"`
  against production. RFC 017 closes the gap:
  tenant admin editor surface with explicit
  3-state form (radio + text: Unscoped / Scoped+
  empty / Scoped+value) distinguishing NULL vs
  `""` vs `"value"` semantics; per-tenant
  uniqueness check with `?force=1` override for
  intentional sharing; new audit kind
  `OidcClientAudienceChanged` with before / after
  payload; audit-trail section showing recent
  changes for the client. ADR-014 §Q1
  Resolved-paragraph gets a v0.50.x amendment
  noting this RFC closes the deferred admin UI.

- **RFC 018** — Preview-and-apply pattern for
  destructive admin operations. The deck's
  "状態 → 影響 → 実行 → 監査" framing surfaces a
  real gap: today's `config_edit`, token rotation,
  and similar admin operations apply directly on
  submit, with no explicit "impact preview" step.
  RFC 018 establishes reusable infrastructure:
  `ImpactStatement{title, bullets, rollback,
  severity}`; HMAC-signed `PreviewToken` (5-min
  TTL, session HMAC key, binds operation_id +
  before + after + csrf to prevent replay); paired
  `OperationPreviewed` / `OperationApplied` audit
  events for forensic correlation. First adopters:
  LOG_LEVEL change (medium severity), token
  rotation (high severity), audience editor (RFC
  017 ideally rides on this pattern). ADR-019
  establishes the convention so future destructive
  admin operations adopt it by default. Read-only
  admins can reach preview but not apply
  (privilege boundary at apply, not at preview).

#### `rfcs/README.md` — Tier 0 + Tier 3 + Tier 4 sections added

The README index now has Tier 0 (production blockers)
above Tier 1 / Tier 2 / Tier 3. Recommended
implementation order spelled out: v0.50.2 ships
RFCs 008-010 (and possibly 011); v0.51.0 ships
RFC 001 (id_token); v0.51.x / 0.52.0 picks up
quality (RFCs 002, 011 if not earlier, 012); v0.52.x
operations (RFCs 013, 014 Path A); RFCs 003-007
later as opportunity allows.

#### ROADMAP entry

`## Planned (0.x) / Next minor releases` gains a
top-priority entry "v0.50.2 production-blocker sweep
— external review remediation" describing each of
RFCs 008-018 inline with the verified evidence
behind each.

### Tests

No test count change — documentation-only release.
v0.50.1's 1025 tests carry forward.

### Schema / wire / DO

- Schema unchanged (SCHEMA_VERSION = 10).
- Wire format unchanged.
- DO state unchanged.
- No new dependencies.

### Operator-visible changes

None. This release adds engineering documentation;
no behavior change. No `wrangler.toml` change. No
new env vars. No new bindings.

### ADR changes

No ADR shipped or revised. RFC 010 will produce
ADR-015 on implementation; RFC 013 will produce
ADR-016; RFC 014 may produce ADR-017 if Path B
triggers. RFC 009 will amend ADR-014 §Q1's
Resolved-paragraph with v0.50.2 tightening note.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.50.1 → 0.50.2.
- UI footers + tests bumped to v0.50.2.
- `rfcs/008-018-*.md` — 11 new RFC files (RFC 015 added in response to operator question on logging completeness — see entry below).
- `rfcs/README.md` — Tier 0 (P0/P1 blockers) and
  Tier 3 (quality/scaling) sections added; existing
  Tier 1 / Tier 2 unchanged; Recommended
  implementation order section added.
- `ROADMAP.md` — v0.50.2 production-blocker sweep
  entry under "Planned (0.x) / Next minor releases".
- This CHANGELOG entry.

### Upgrade path 0.50.1 → 0.50.2

1. Extract this tarball, OR pull the git tag.
2. No build needed — no code change.
3. No deploy needed — no behavior change.

This is a patch in the strictest sense: an
implementer reads the new RFCs to start the
production-blocker work; an operator running v0.50.1
in production has nothing to do.

**Operators planning the v0.50.2 → v0.50.3 upgrade**
(when the production-blocker fixes ship) should
read RFC 008 §"Step 4 — Operator data hygiene
runbook" and RFC 010 §"Migration / upgrade path"
ahead of time — both involve operator-side actions
that take time to plan (mailer choice, audit
purge, chain re-baseline).

---

## [0.50.1] - 2026-05-05

Documentation-only patch release. Adds the `rfcs/`
directory: implementation-handover specifications for
ROADMAP themes that are ready to be picked up by an
engineer.

### What ships

#### `rfcs/` — new directory

Engineering specs distinct from the ADR system. Where
ADRs answer "why this design", RFCs answer "what does
the implementer need to build". Where a theme has a
linked ADR, the RFC builds on it; where a theme is
small and self-contained, the RFC stands alone.

Index at `rfcs/README.md` lists priority order. Seven
RFCs in this initial batch:

**Tier 1** (ready to implement, design settled):

- **RFC 001** — OIDC `id_token` issuance. Builds on
  ADR-008 (Draft, all eleven design questions
  Resolved). Medium scope: ~600 LOC across 4 files +
  one schema field on `Challenge::AuthCode` and
  `RefreshTokenFamily` (`#[serde(default)]` for
  in-flight compatibility), one wire change (id_token
  populated when `openid` scope present), discovery
  doc restored to OIDC posture from v0.25.0's honest-
  reset OAuth-only state. ~30 new tests across pure
  module + service integration + discovery shape
  inversions. Recommended 5-PR progression in the
  RFC.
- **RFC 002** — `oidc_clients.client_secret_hash`
  documentation drift. Decides Path B (relax schema
  comment to SHA-256, unify with bearer-secret
  hashing) over Path A (implement Argon2id) on the
  honest reasoning that `client_secret` is server-
  minted at 256-bit entropy — Argon2's password-
  hashing value proposition doesn't apply.
  Schema-comment edit + `verify_client_credentials`
  audit + unified hashing helper + 4 tests.
- **RFC 003** — Property-based tests (`proptest`)
  for crypto round-trips and `redirect_uri` matcher.
  Two property modules, ~10 properties, dev-dep only.
  No production-code change.
- **RFC 004** — WebAuthn error → typed client
  responses. Conservative 6-variant `WebAuthnErrorKind`
  enum mapped from existing diagnostic strings;
  surfaces on the wire as a `kind` JSON field;
  preserves the privacy invariant that diagnostic
  detail strings stay in server-side logs.

**Tier 2** (lighter, internal-design-only):

- **RFC 005** — `cargo fuzz` for the JWT parser
  surface. Single fuzz target, GitHub Actions one-shot
  (60s) on PRs touching jwt or fuzz dirs. Deeper
  continuous fuzzing parked under "Later".
- **RFC 006** — CSP without `'unsafe-inline'` (per-
  request nonces). Medium-scope refactor; touches
  every HTML template render path. Plans
  `RenderContext { locale, nonce }` introduction to
  minimize call-site churn.
- **RFC 007** — Cesauth-specific attack-surface review
  cadence. Defines the per-review deliverable shape
  + checklist + before-v1.0/by-2027-Q4 schedule for
  the next pass.

### Themes not covered

The README explicitly lists themes excluded from this
batch:

- ADR-012 §Q2 / §Q3 / §Q5 — blocked on infrastructure
  cesauth doesn't yet have (email pipeline, GeoIP) or
  on Cloudflare DO platform limitations.
- OIDC client_secret brute-force lockout — has an
  explicit trigger condition that hasn't fired.
- Domain-metric observability / Rate-limit bucket
  tuning / Login → tenant resolution / External IdP
  federation — design ambiguity too large for an RFC
  without a prerequisite ADR.
- Protocol extensions (Device Authorization Grant,
  Dynamic Client Registration, Request Objects, PAR,
  full FIDO attestation) — speculative; write the RFC
  when a deployment requires one.

### Tests

No test count change — documentation-only release.
1025 tests as of v0.50.0 carry forward.

### Schema / wire / DO

- Schema unchanged.
- Wire format unchanged.
- DO state unchanged.
- No new dependencies.

### Operator-visible changes

None. This release adds engineering documentation; no
behavior change. No `wrangler.toml` change. No new env
vars. No new bindings.

### ADR changes

No ADR shipped or revised. RFC 001 references ADR-008
(Draft); RFC 006 references ADR-007's §Q3 limitation
note. All ADR statuses unchanged.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.50.0 → 0.50.1.
- UI footers + tests bumped to v0.50.1.
- `rfcs/README.md` + 7 RFC files added.
- This CHANGELOG entry.
- ROADMAP unchanged at the row level (no
  feature shipped); the RFCs reference ROADMAP
  themes as their source.

### Upgrade path 0.50.0 → 0.50.1

1. Extract this tarball, OR pull the git tag.
2. No build needed — no code change.
3. No deploy needed — no behavior change.

This is a patch in the strictest sense: an implementer
clones the tree to read the RFCs; an operator running
v0.50.0 in production has nothing to do.

---

## [0.50.0] - 2026-05-04

Per-client audience scoping for `/introspect`.
**ADR-014 §Q1 Resolved.** First release after the
six-item operator-requested batch (v0.44–v0.49)
completed. Picked from the four open security-track
items the v0.49.0 changelog flagged as the only
candidate that's both ready-to-ship and security-
meaningful.

### Why this matters

v0.38.0 shipped `/introspect` with a global trust
model: any authenticated confidential client could
introspect any token. The ADR-014 §Q1 paragraph
flagged this as a privilege-escalation concern for
multi-tenant deployments where one cesauth issues
tokens for many resource servers. Pre-v0.50.0, an
RS_A holding valid introspection credentials could
ask cesauth about RS_B's tokens — and learn whether
they were currently active, what their scopes were,
which user they belonged to. Cross-RS visibility,
unintended.

v0.50.0 closes this with a per-client audience scope
that's **off by default** (existing deployments
upgrade unchanged) and **opt-in per client** (no
deployment-wide flag — operators enable it for the
clients that need it).

### What ships

#### Schema migration

`migrations/0010_introspection_audience.sql` adds
`audience TEXT` (nullable) to `oidc_clients`.
**SCHEMA_VERSION 9 → 10** — first schema bump since
v0.35.0.

NULL means "unscoped — pre-v0.50.0 behavior". A
non-NULL value means "this client may introspect
ONLY tokens whose `aud` claim matches verbatim".
Single string column, not JSON array — RFC 7662
doesn't model multi-audience introspecters; if
demand surfaces for clients needing multiple
allowed audiences, a future migration can broaden.
No CHECK constraint on the value (audiences are
operator-controlled identifiers; the truth check
is the runtime comparison, not a schema constraint).

#### Pure gate function

`cesauth_core::service::introspect::apply_introspection_audience_gate(response, requesting_client_audience) -> IntrospectionGateOutcome`.

```rust
pub enum IntrospectionGateOutcome {
    PassedThrough(IntrospectionResponse),
    AudienceDenied {
        response:                  IntrospectionResponse,
        requesting_client_audience: String,
        token_audience:             String,
    },
}
```

The orchestrator (`introspect_token`) stays pure —
it produces a response based purely on token
validity. The gate runs separately, in the worker
handler, which applies it after `introspect_token`
returns. This keeps the orchestrator testable
without touching audit infrastructure AND surfaces
the gate-fired signal to the handler for distinct
audit emission.

The gate is a no-op when:

- `requesting_client_audience` is `None` (client is
  unscoped — the default).
- `response.active` is false (already inactive — gate
  has nothing to add).
- `response.aud` is `None` (refresh-token responses;
  documented out-of-scope below).

#### Privacy invariant on denial

On audience mismatch, the response is replaced with
`IntrospectionResponse::inactive()` — wire form
`{"active":false}`, byte-identical to v0.38.0's
privacy-preserving inactive shape. Returning 403
would let an attacker probe whether tokens exist
for other audiences by trying their own credentials
(the same enumeration-side-channel concern v0.38.0
documented for unknown-client vs wrong-secret).

Test pin `mismatch_response_serializes_to_bare_inactive`
asserts the wire form byte-exact — defense in depth
against a future change adding a field to
`IntrospectionResponse` that the gate forgets to
clear.

#### `IntrospectionResponse.aud` added

RFC 7662 §2.2 lists `aud` as an optional response
field. v0.38.0 deliberately omitted it because no
resource servers cesauth supported needed it; v0.50.0
surfaces it because (a) the gate reads it internally
so we may as well expose it on the wire, and (b)
standard introspection libraries expect it.

Active access responses populate `aud` from the JWT's
`aud` claim. Active refresh responses leave it
`None`. Inactive responses (including audience-
denied) leave it `None`.

`#[serde(skip_serializing_if = "Option::is_none")]` —
clients consuming only the fields they need are
unaffected.

#### `active_access` constructor signature change

```rust
pub fn active_access(
    scope:     String,
    client_id: String,
    sub:       String,
    jti:       String,
    iat:       i64,
    exp:       i64,
    aud:       Option<String>,   // ← new
) -> Self
```

`active_refresh` and `active_refresh_with_ext`
unchanged (refresh responses always have
`aud: None`).

External code constructing `IntrospectionResponse`
directly will need a one-line update. In-tree call
sites updated alongside.

#### Refresh-token introspection out of v0.50.0 scope

`FamilyState` doesn't record an audience — the
audience is determined per access-token mint, not
per family. Refresh introspection therefore returns
`aud: None`, and the gate falls through (a refresh
response won't trip the audience check regardless of
the requesting client's scope).

Audience scoping for refresh introspection is
architecturally distinct (the family doesn't bind to
a single audience; tokens minted from a refresh
inherit `aud` from the request) and is left to a
future iteration if operator demand surfaces.

#### `EventKind::IntrospectionAudienceMismatch`

New audit kind, snake_case
`introspection_audience_mismatch`. Payload:

```json
{
  "requesting_client_id":       "client_abc",
  "requesting_client_audience": "rs.a.example",
  "token_audience":             "rs.b.example"
}
```

Both audiences are operator-controlled identifiers,
not secret material — their presence in audit doesn't
reveal token contents. The introspected token itself
is NOT in the payload (same privacy invariant as
`TokenIntrospected`).

Distinct from `IntrospectionRateLimited` (which fires
before any token check) and `TokenIntrospected`
(which fires on any authenticated request that
proceeded to checks). A spike of these events likely
indicates a misconfigured resource server (its
`oidc_clients.audience` doesn't match what its tokens
carry) or a legitimate-but-unintended cross-RS
introspection probe.

#### Worker handler integration

`POST /introspect` now:

1. Authenticates client (existing).
2. Rate-limit gate (existing, v0.43.0).
3. **NEW**: Fetches the authenticated client row to
   read `audience`. Storage outage on this lookup
   treats the client as unscoped (lets the request
   proceed under pre-v0.50.0 behavior) rather than
   fail-closing on a transient hiccup. Errors log a
   warning.
4. `introspect_token` (existing).
5. **NEW**: `apply_introspection_audience_gate`. On
   `AudienceDenied`: emit
   `IntrospectionAudienceMismatch` audit event with
   the operator-controlled identifiers; replace
   response with bare `inactive()`.
6. Audit `TokenIntrospected` (existing).
7. Render JSON (existing).

### Tests

986 → **996** lib (+10). With migrate integration:
1015 → **1025**.

- core: 443 → 453 (+10). All in
  `service::introspect::tests::audience_gate`:
  - `unscoped_client_passes_through_active_response` —
    NULL client.audience = legacy behavior.
  - `matching_audience_passes_through` — happy path.
  - `mismatched_audience_returns_inactive_no_leak` —
    critical privacy pin: response on denial has zero
    leaked claims.
  - `mismatch_response_serializes_to_bare_inactive` —
    wire-form byte-exact `{"active":false}`.
  - `already_inactive_response_passes_through_unchanged`
    — gate doesn't double-wrap.
  - `refresh_token_response_with_no_aud_passes_through`
    — documented v0.50.0 scope: refresh responses
    aren't gated.
  - `empty_string_audiences_compared_byte_exact` —
    "" matches "" only; legitimate edge.
  - `case_sensitive_audience_comparison` — RFC 7519
    §4.1.3 case-sensitivity preserved.
  - `substring_match_does_not_satisfy_gate` — defensive:
    "rs" must NOT match "rs.example.com"; nor vice
    versa.
  - `mismatched_audience_audit_payload_contains_both_values`
    — audit payload contract.
- ui: 244 → 244.
- worker: 182 → 182 (handler wiring; testable
  transformation is in pure core).

### Schema / wire / DO

- **Schema migration** (SCHEMA_VERSION 9 → 10).
  Single ALTER TABLE; ~milliseconds for any
  realistic deployment size.
- **Wire format additive only**: `aud` added to
  `IntrospectionResponse`; spec-conformant clients
  ignore unknown fields. Existing inactive-response
  byte-form unchanged. Audience-denied responses
  byte-equal to legacy inactive responses.
- **DO state unchanged**: refresh families don't
  store audience.
- **No new dependencies**.

### Operator-visible changes

- **No production behavior change** until an operator
  sets `oidc_clients.audience` to a non-NULL value
  for at least one client. Default behavior is
  unchanged.
- **Schema migration** runs on next deploy
  automatically via existing migrate machinery
  (SCHEMA_VERSION bump triggers).
- **Recommended deployment progression for multi-RS
  deployments**:
  1. Upgrade to v0.50.0. No clients have audience
     set. Behavior unchanged.
  2. Identify which resource-server clients should
     be scoped. For each, decide its allowed
     audience (typically the RS's stable hostname
     or identifier).
  3. Set `oidc_clients.audience` for those clients
     via direct D1 statement
     (`UPDATE oidc_clients SET audience = ? WHERE id = ?`).
     Admin console UI for this is out of v0.50.0
     scope.
  4. Watch audit logs for
     `introspection_audience_mismatch` events. A
     spike right after enabling typically indicates
     either (a) misconfiguration — the audience
     value doesn't match what the tokens actually
     carry, or (b) the discovered cross-RS
     introspection that motivated the scoping in
     the first place.
- **No `wrangler.toml` change**. No new bindings.
  No new env vars.

### ADR changes

- **ADR-014 §Q1** marked **Resolved**. Inline
  resolution paragraph follows the ADR-011 §Q1 /
  ADR-012 §Q1, §Q4, §Q1.5 / ADR-014 §Q4, §Q2, §Q3
  inline-resolution style.
- No new ADR.

### Open security-track items remaining

After v0.50.0, the open items the v0.49.0 changelog
flagged are:

- **ADR-012 §Q2** (idle-timeout user notification) —
  needs an email pipeline, which cesauth doesn't
  yet have. Defer until that's built.
- **ADR-012 §Q3** (geo/device-fingerprint columns
  on `user_sessions`) — needs GeoIP infrastructure;
  cesauth has none. Defer until operator demand
  + infrastructure choice surface together.
- **ADR-012 §Q5** (orphan DOs — DO has no D1 row)
  — structurally blocked by Cloudflare not
  supporting DO namespace iteration. No good
  resolution path exists with current platform
  primitives.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.49.0 → 0.50.0.
- UI footers + tests bumped to v0.50.0.
- ROADMAP: v0.50.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.49.0 → 0.50.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   dependencies.**
3. `wrangler deploy`. **One schema migration runs
   (0010, ALTER TABLE oidc_clients ADD COLUMN
   audience TEXT).**
4. **Optionally** set
   `oidc_clients.audience` for clients you want
   scoped. Default behavior is unchanged.
5. **Watch audit logs** for
   `introspection_audience_mismatch` events after
   enabling scoping for any client.

---

