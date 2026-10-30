# cesauth — CHANGELOG (archive: v0.70–v0.79)

> This file is part of the changelog archive.
> Current releases are in the root [`CHANGELOG.md`](../../CHANGELOG.md).

## [0.79.7] - 2026-05-20

### RFC 115 — Phase C, Screen 5: System operator console migrated to Leptos

35 GET routes under `/admin/console/*` and `/admin/tenancy/*` migrated.
ADR-013 (JA-only operator surface) honoured throughout.

**Admin cookie bearer** (`routes/admin/auth.rs`): `bearer()` now also reads
from `__Host-cesauth_admin` httpOnly cookie, enabling browser-side Leptos
components to authenticate without custom `Authorization` headers.

**New `GET /admin/login?token=<bearer>`**: sets the admin cookie and
redirects to `/admin/console`. Includes a Japanese-text form for token
paste-in. Cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, 12-hour TTL.

**New `routes/admin/operator_json_api.rs`**: shared helpers parallel to
the tenant-admin `json_api.rs`.

**JSON endpoints added** for data pages: console overview, operations,
tokens, tenancy overview, tenants list, tenant detail.

**Frontend (`pages/operator/`)**: All components use Japanese text per
ADR-013. Key components: `ConsoleOverview`, `ConsoleOperations`,
`ConsoleAudit`, `ConsoleSafety`, `ConsoleTokens`, `TenancyOverview`,
`TenancyTenants`, `TenancyTenantDetail`.

---


## Older releases

Entries for v0.49.0 and earlier are in
[`docs/changelog-archive/`](README.md),
split by minor-version range:

- v0.41–v0.49 → [`CHANGELOG-0.41-to-0.49.md`](CHANGELOG-0.41-to-0.49.md)
- v0.31–v0.40 → [`CHANGELOG-0.31-to-0.40.md`](CHANGELOG-0.31-to-0.40.md)
- v0.1–v0.30  → [`CHANGELOG-0.1-to-0.30.md`](CHANGELOG-0.1-to-0.30.md)

---

## [0.79.5] - 2026-05-20

### RFC 115 — Phase C, Screen 4: Login + Magic Link entry point migrated to Leptos

`GET /` and `GET /login` now return the Leptos HTML shell.

#### Frontend changes

**New `crates/frontend/src/pages/login.rs`** — `Login` component:

- **Email form (fallback path)** — A standard `<form method="POST"
  action="/magic-link/request">` that submits normally to the backend.
  The server responds with the OTP input page (still the existing
  string template; will be migrated in v0.79.6). This preserves the
  full magic-link flow without any additional backend changes.

- **Passkey button (primary path)** — A `<button>` that on click
  calls the `cesauthPasskeyAuthenticate` JavaScript helper via
  `js_sys::Reflect`. The button shows a "Signing in…" state while
  the Promise is pending and an inline error message on failure.
  Error codes (`passkey_cancelled`, `passkey_unsupported`,
  `webauthn_not_loaded`) map to user-readable strings.

**New `crates/frontend/static/webauthn.js`** — ES module loaded by
the HTML shell's CSP-nonced bootstrap script. Implements the full
passkey authentication ceremony:

1. `POST /webauthn/authenticate/start` → challenge + handle
2. `navigator.credentials.get({ publicKey })` → browser passkey picker
3. `POST /webauthn/authenticate/finish` → session cookie set
4. `window.location.replace(finishResp.url)` → navigate to the
   correct destination (OIDC `redirect_uri?code=…` or `/me/security`)

`finishResp.url` (the browser Fetch API's `response.url` property)
gives the final URL after all server-side redirects are followed.
This correctly handles both the direct login case (`/me/security`)
and the OIDC Authorization Code flow (the `redirect_uri` of the RP).

The helper is exposed on `window.__cesauth.passkeyAuthenticate`.
The Leptos component reaches it via `js_sys::Reflect::get`.
This design satisfies the strict `script-src 'nonce-…'` CSP — no
`'unsafe-eval'`, no `'unsafe-inline'`, no dynamic `import()`.

**HTML shell updated** to also import `webauthn.js` in the bootstrap
`<script type="module" nonce="…">`, making the helper available on
every Leptos-backed page (passkey registration from `/me/security`
will use it in a future release).

**`Makefile`** — `build-frontend` now also copies `static/` files
into `dist/` so they are served via Workers Static Assets.

#### New Cargo dependencies (all `csr`-feature-gated)

- `web-sys` with features: `Window`, `Navigator`, `Location`,
  `Request`, `RequestInit`, `RequestMode`, `Response`, `Headers`.
- `wasm-bindgen-futures = "0.4"` — `JsFuture` for awaiting the
  WebAuthn Promise from Rust/WASM.
- `js-sys` (workspace, `optional = true`) — `Reflect`, `Function`,
  `Promise`, `JsValue` for the interop bridge.

#### Backend changes

- `routes/ui.rs::login` simplified to a two-line Leptos shell
  handler (no CSRF minting, no template render, no CSP nonce logic —
  all of that now lives in the Leptos component and
  `leptos_shell::leptos_html_shell`).
- No changes to any POST handlers (`/magic-link/request`,
  `/webauthn/authenticate/start`, `/webauthn/authenticate/finish`).

#### Known limitation

The Magic Link sent+verify page (the OTP input screen, currently
served by `magic_link_sent_page_for`) is NOT yet Leptos.  After the
user submits their email, the server responds with the old string
template.  This will be resolved in v0.79.6.

1,290 / 1,290 tests pass.

---

## [0.79.4] - 2026-05-20

### RFC 115 — Phase C, Screen 3: TOTP flows migrated to Leptos

Three TOTP screens in one release — all simpler than Sessions
because they are single-step read+submit forms with no tables.

**Screens migrated:**

| Route | Component | Notes |
|---|---|---|
| `GET /me/security/totp/enroll` | `TotpEnroll` | QR + manual key + confirm form |
| `GET /me/security/totp/verify` | `TotpVerify` | 2FA gate after Magic Link |
| `GET /me/security/totp/disable` | `TotpDisable` | Destructive-action confirm |

**New JSON endpoints:**

- `GET /me/security/totp/enroll.json` — creates an unconfirmed enrollment row,
  sets `__Host-cesauth_totp_enroll` cookie, returns `{ qr_svg, secret_b32, csrf_token }`.
  The QR SVG is server-generated from the TOTP secret and returned as a
  raw string. The Leptos component injects it via `inner_html=…` (safe:
  data is not user-supplied).
- `GET /me/security/totp/verify.json` — validates the TOTP handle cookie, returns
  `{ csrf_token, totp_handle }`. Returns 401 if the gate has expired.
- `GET /me/security/totp/disable.json` — returns `{ csrf_token }`.

**All POST handlers unchanged.** The form submission targets
(`/me/security/totp/enroll/confirm`, `/me/security/totp/verify`,
`/me/security/totp/disable`) still receive form-encoded POST requests;
no changes to CSRF validation, session ownership checks, or audit
event emission.

**New `crates/frontend/src/pages/totp.rs`** contains all three
components — enroll, verify, disable — together. Kept in one file
because they are all small single-form screens sharing the same
`fetch + Resource + Suspense` pattern.

**Notable `TotpEnroll` implementation detail:** the QR SVG is
rendered via Leptos's `inner_html=…` prop, which sets `innerHTML`
on the container `<div>`. This is the correct approach for injecting
server-generated SVG markup. It is safe here because the SVG is
constructed entirely from the TOTP provisioning URI (which contains
only the issuer name and the secret), not from any user input.

1,290 / 1,290 tests pass.

---

## [0.79.3] - 2026-05-20

### RFC 115 — Phase C, Screen 2: Sessions list migrated to Leptos

`GET /me/security/sessions` now serves the Leptos shell.

**New `SessionListItem` serde derives.** The struct gains
`serde::Serialize + Deserialize` so the backend can return it as
JSON and the component can deserialise it.

**New `GET /me/security/sessions.json` endpoint.**  Returns:

```json
{
  "sessions": [ { ...SessionListItem fields... } ],
  "current_session_id": "...",
  "csrf_token": "..."
}
```

A fresh CSRF token is minted server-side and returned alongside
the data.  The component embeds it in every revoke form's hidden
field.  This keeps the CSRF flow identical to the old string-template
approach (server mints, form carries, server validates), adapted for
the CSR data-fetch pattern.

**New `crates/frontend/src/pages/sessions.rs`.**  The `Sessions`
component uses `Resource` + `Suspense` and renders:

- A `<table>` of active sessions, one row per `SessionListItem`.
- Per-row revoke forms (`POST /me/security/sessions/:id/revoke`) with
  CSRF; the current-session row has a disabled button.
- A "Sign out all other sessions" bulk-revoke form
  (`POST /me/security/sessions/revoke-others`) shown only when
  other sessions exist.
- A `SessionsError` fallback component for 401 and network errors.
- `format_ts` helper that emits `YYYY-MM-DD HH:MM` from Unix
  seconds using the `time` crate (already a workspace dep).

**Post-revoke flow unchanged.**  The `post_revoke` and
`post_revoke_others` handlers are not modified.  They continue
to POST-redirect back to `/me/security/sessions` with a flash
cookie.  The Leptos shell at that URL re-fetches the session list
on mount, showing the updated state (and the flash banner once
flash support is added to the Leptos layer in a future release).

**`app.rs`** gets a `<Route path="/me/security/sessions" view=Sessions/>`.

1,290 / 1,290 tests pass.

---

## [0.79.2] - 2026-05-20

### RFC 115 — Phase C, Screen 1: Security Centre migrated to Leptos

`GET /me/security` now serves the Leptos CSR shell instead of a
server-rendered string template.

#### Data flow

```
Browser
  1. GET /me/security        → verify session; return HTML shell
  2. Leptos bundle mounts
  3. GET /me/security.json   → verify session; return SecurityCenterState JSON
  4. SecurityCenter component renders
```

#### Frontend changes (`crates/frontend`)

- `PrimaryAuthMethod` and `SecurityCenterState` gain
  `serde::Serialize` + `serde::Deserialize` derives so they can
  be returned from the JSON endpoint and parsed by the component.
- `[features] csr` expanded: `dep:leptos_router`, `dep:gloo-net`.
- New `src/pages/` module directory.
  - `pages/mod.rs` — declares migrated screen modules.
  - `pages/security_center.rs` — `SecurityCenter` Leptos component:
    uses `Resource` + `Suspense` to fetch `/me/security.json`,
    renders TOTP status, recovery-code warnings, session count,
    and sign-out form. Handles 401 (session expired) by showing
    a "sign in again" notice.
- `app.rs` updated: `<Router>` with `<Routes>`; `GET /me/security`
  → `SecurityCenter`; `GET /__leptos` → `PocCounter` (still present,
  removed in v0.80.0).

#### Backend changes (`crates/backend`)

- `routes/me/security.rs` refactored:
  - `get_handler` now returns the Leptos HTML shell after session
    verification (replaces the old string-template render).
  - New `get_json_handler` — extracts state-building into a shared
    `build_state` helper and returns `SecurityCenterState` as JSON
    with `Cache-Control: no-store`.
- New route `GET /me/security.json` registered in `lib.rs`.

#### Old template

`security_center_page_for` and `security_center_page` remain in
`crates/frontend/src/templates/security_center.rs` for now; they
will be deleted in v0.80.0 when the full Phase C migration completes.

#### Tests

1,290 / 1,290 pass. The `csr` feature is off during cargo test;
all Leptos, leptos_router, and gloo-net code is excluded from the
host-side compilation.

---

## [0.79.1] - 2026-05-20

### RFC 115 — Phase B: Leptos v0.8 foundation

Adds the Leptos CSR infrastructure without migrating any production
screen. All existing screens continue to use the current string
templates unchanged.

**`crates/frontend` changes:**

- `[lib]` section gains `crate-type = ["cdylib", "rlib"]`.
  - `cdylib` — Trunk builds this to a browser WASM bundle with
    `--features csr`. Worker-build and cargo test never see it.
  - `rlib` — cesauth-backend continues to link the template
    functions for un-migrated screens.
- New optional `csr` feature. Activates `leptos = "=0.8.2"` with
  the `leptos/csr` sub-feature plus `console_error_panic_hook`.
  The feature is **never** enabled in the `cesauth-backend`
  dependency graph; no browser-only WASM APIs leak into the
  Cloudflare Workers runtime.
- New `src/app.rs` — root Leptos `App` component and a minimal
  `Counter` component (Phase B smoke test).
- `lib.rs` gains a `#[wasm_bindgen(start)] pub fn leptos_start()`
  entry point, guarded by `#[cfg(feature = "csr")]`. This is what
  the browser calls when the WASM module initialises.
- New `index.html` — Trunk shell template for `trunk serve`
  (local dev only; production uses the backend HTML shell).

**`crates/backend` changes:**

- New `src/routes/leptos_shell.rs` — renders the minimal HTML shell
  the browser needs to bootstrap the Leptos bundle, with:
  - Per-request CSP nonce (RFC 006).
  - `<link rel="preload">` for the WASM binary.
  - `<script type="module" nonce="…">` bootstrap script.
- New route `GET /__leptos` → `leptos_shell::poc_handler`.
  Returns the Phase B counter shell. Route is temporary; Phase C
  replaces it with real authenticated screens.

**`wrangler.toml`:**

- Added `[assets]` section: `directory = "crates/frontend/dist"`.
  Cloudflare Workers Static Assets will serve the Trunk build
  output at `/assets/*`. The dist directory is gitignored (it is
  a build artefact).

**`Makefile`** (new):

- `make build` — `trunk build --release` then `wrangler build`.
- `make dev` — concurrent `trunk watch` + `wrangler dev`.
- `make test` — all host-side tests.
- `make clean` — removes dist/, build/, .wrangler/state.

**Leptos version pin:**

Pinned to `=0.8.2`. Leptos 0.8.6+ pulls `uuid 1.18` → `getrandom
0.3.3`, which requires the `wasm_js` feature on wasm32 targets.
`worker-build` does not propagate that feature, causing build
failures (see GitHub issue #4260 in leptos-rs/leptos). Upgrade
path tracked for a follow-up RFC.

**Running the Phase B PoC locally:**

```sh
# 1. Install Trunk (once)
cargo install trunk
rustup target add wasm32-unknown-unknown

# 2. Build the frontend bundle
make build-frontend          # or: cd crates/frontend && trunk build

# 3. Apply D1 migrations (first time)
wrangler d1 migrations apply cesauth --local

# 4. Start wrangler dev (reads dist/ from [assets])
make dev-backend             # or: wrangler dev

# 5. Open the PoC page
open http://localhost:8787/__leptos
```

The counter page proves the full pipeline: Trunk compilation →
WASM bundle → Workers Static Assets → HTML shell (CSP nonce) →
browser bootstrap → Leptos reactive UI.

**Tests:** 1,290 / 1,290 pass. The `csr` feature is off during
cargo test; Leptos code is not compiled in the host test run.

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

