# cesauth — CHANGELOG (archive: v0.31.0–v0.40.0)

> This file is part of the changelog archive.
> Current releases are in the root [`CHANGELOG.md`](../../CHANGELOG.md).

## [0.40.0] - 2026-05-03

D1-DO sessions index drift detection (ADR-012 §Q1
detection-only resolution). First security-track release
after the v0.36-v0.39 i18n + feature track sprint. Closes
half of the operator-visibility gap that v0.35.0 left
behind: the daily 04:00 UTC sweep now also walks
`user_sessions`, peeks the corresponding `ActiveSession`
DOs, and emits one `session_index_drift` audit event per
detected drift. Repair is deliberately **not** shipped in
this release — operational visibility comes before
automated D1 mutations.

### Why this matters

v0.35.0's `/me/security/sessions` page is backed by a
denormalized D1 mirror at `user_sessions(session_id,
user_id, created_at, revoked_at, auth_method,
client_id)`. The DO is source of truth; D1 is a
best-effort eventually-consistent index that lets the
page answer "what sessions does this user have" without
DO namespace iteration (which Cloudflare doesn't
support). "Best-effort" means a successful DO write
whose D1 mirror failed leaves the index drifted: users
see ghost rows they can't actually revoke, or miss
legitimate sessions in their list. ADR-012 §Q1
documented the gap and deferred the reconcile tool;
v0.40.0 ships the detection half.

### Why detection-only

Two reasons to ship detection without repair:

1. **Operational visibility comes first.** Until we have
   data on drift volume and pattern, we don't know
   whether automated repair is the right response or
   whether the appropriate response is "alert a human
   and let them decide". The detection signal lets
   operators build the dashboard panel and watch for a
   few weeks before we wire up destructive D1
   mutations.
2. **Repair is safer to ship after observing
   classification.** If the cron emits, say, 10000
   `anomalous_d1_revoked_do_active` events after
   deployment, that's a structural bug in the mirror
   write paths — the right move is fixing the root
   cause, not auto-rewriting D1.

The repair half is now ADR-012 **§Q1.5** (NEW).

### What ships

#### `cesauth_core::session_index` module — pure classification logic

```rust
pub fn classify(d1: &D1SessionRow, do_status: &SessionStatus) -> ReconcileOutcome
```

Four outcome variants:

| Outcome | Meaning | Repair (deferred) |
|---|---|---|
| `InSync` | D1 and DO agree. Dominant case. | none |
| `DoVanished` | D1 says active, DO has no record (likely sweep cascade). | D1 delete row |
| `DoNewerRevoke { do_revoked_at }` | DO is revoked, D1 still says active OR has stale `revoked_at`. | D1 update revoked_at |
| `AnomalousD1RevokedDoActive` | D1 says revoked but DO says active. **No production code path produces this** — implies manual SQL edit or deeper drift. | alert-only; never auto-repair |

The module has no I/O — it's a `(d1_row, do_status) ->
outcome` function. Trivially testable. 11 dedicated
tests covering every (active/revoked) × (active/revoked
/ vanished) cross product including the IdleExpired and
AbsoluteExpired DO terminal states (both classified as
`DoNewerRevoke` because from reconcile's perspective
they're indistinguishable from explicit revoke), plus
two defensive tests for malformed inputs (Active variant
with non-None `state.revoked_at`, Revoked variant with
None `state.revoked_at`).

#### `cesauth_worker::session_index_audit` cron

Extends the existing daily 04:00 UTC scheduled handler.
Walks the first **1000** active rows of `user_sessions`
(oldest-first so long-living drift surfaces even when
the table has many newer rows), peeks each DO, classifies,
emits a `SessionIndexDrift` audit event per drift,
accumulates counters, logs a summary line.

The cap of 1000 is sized for known cesauth deployments;
larger populations need cursor pagination across cron
ticks, tracked under ADR-012 §Q1.5 follow-up.

Per-row DO query failures count as a separate `errors`
counter — distinguishes "drift" (correctness signal) from
"cron is unhealthy" (operational signal). Persistent
errors show up as a growing counter operators alert on
independently.

#### `EventKind::SessionIndexDrift` audit kind

Snake-case `session_index_drift`. Payload:

```json
{
  "session_id":     "...",
  "user_id":        "...",
  "drift_kind":     "do_vanished" | "do_newer_revoke" | "anomalous_d1_revoked_do_active",
  "do_revoked_at":  1714000000     // only for do_newer_revoke
}
```

`do_revoked_at` (where applicable) lets operators see
how stale the D1 mirror was when the cron caught the
drift — useful for sizing the recovery window if/when
auto-repair ships in §Q1.5.

#### Best-effort failure semantics

The cron is non-transactional. A single per-row DO query
failure logs and continues; the next day's cron will
re-walk and either re-detect or self-heal (for transient
conditions). A D1 read failure aborts the cron with an
error log — re-tries the next day. An audit-write failure
is silently dropped (the drift is real, but unsignalled
this run; next day's cron will surface it again).

### Tests

889 → **900** (+11).

- core: 342 → 353 (+11). All 11 in
  `session_index::tests`:
  - `in_sync_when_both_active`
  - `in_sync_when_both_revoked_with_matching_timestamp`
  - `do_vanished_when_d1_active_do_notstarted`
  - `do_vanished_when_d1_revoked_do_notstarted`
  - `do_newer_revoke_when_d1_still_thinks_active`
  - `idle_expired_classifies_as_do_newer_revoke`
  - `absolute_expired_classifies_as_do_newer_revoke`
  - `do_newer_revoke_when_d1_has_stale_timestamp`
  - `anomalous_when_d1_revoked_do_active`
  - `defensive_active_variant_with_revoked_at_set_treated_as_do_newer_revoke`
  - `defensive_revoked_variant_with_no_revoked_at_falls_back_to_created_at`
- ui: 230 → 230 (no UI changes).
- worker: 171 → 171. The cron orchestrator is glue;
  the testable logic is in `cesauth_core::session_index`
  which has full coverage. The cron's D1 query / DO peek /
  audit-write paths are integration-test territory and
  hard to exercise without a workers-rs harness; deferred
  to a future operational-test PR.
- adapter-test, do, migrate, adapter-cloudflare: unchanged.

### Schema / wire / DO

- Schema unchanged from v0.39.0 (still SCHEMA_VERSION 9).
  No migration.
- Wire format unchanged.
- DO state unchanged.
- No new dependencies.
- Cron schedule unchanged (`0 4 * * *` daily). The
  scheduled handler now runs three independent passes
  (sweep, audit_chain_cron, session_index_audit) — each
  failure-isolated from the others.

### Operator-visible changes

- **New audit kind to monitor**: `session_index_drift`.
  Add a panel on the audit dashboard. The expected
  baseline is **0 events per day** in steady state. A
  non-zero count indicates either:
  - Recent operational disturbance (D1 outage during a
    revoke cascade) → expect to see `do_newer_revoke`
    spike then settle.
  - Sweep cascade lag → expect `do_vanished` events for
    sessions whose absolute timeout fired on a day the
    mirror write failed. These should self-clear over
    time once §Q1.5 ships repair.
  - Structural bug → `anomalous_d1_revoked_do_active`
    should always be 0. Any non-zero count is an
    investigation trigger.
- **No production behavior change** for end users. The
  cron is detection-only; D1 and DO state remain exactly
  as the live paths leave them.

### ADR changes

- **No new ADR.** ADR-012 §Q1 marked partially
  resolved; new §Q1.5 (D1 repair) and §Q5 (orphan DOs
  limitation) added inline.
- ADR README + mdBook SUMMARY unchanged (no new ADR
  document).

### Doc / metadata changes

- `Cargo.toml` version 0.39.0 → 0.40.0.
- UI footers + tests bumped to v0.40.0.
- ROADMAP: v0.40.0 Shipped table row added.
- This CHANGELOG entry.

### Upgrade path 0.39.0 → 0.40.0

1. `git pull` or extract this tarball over your working
   tree.
2. `cargo build --workspace --target wasm32-unknown-unknown
   --release`. No new production dependencies.
3. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change. No new bindings. The new cron
   pass piggybacks on the existing `0 4 * * *` schedule.
4. **No operator action required** for the production
   path. The next 04:00 UTC cron tick will run the
   detector for the first time. Watch the audit log for
   `session_index_drift` events over the following few
   days.
5. Add a dashboard panel for the new audit kind.

### Forward roadmap

- **v0.40.1 / v0.41.0** candidate: ADR-012 §Q1.5 D1
  repair tool. Likely a worker admin endpoint
  (auth-gated) plus a `cesauth-migrate sessions repair`
  CLI wrapper. Decision on shape blocked on observing
  v0.40.0 drift patterns for a few weeks.
- **i18n-2 continued (v0.39.1+)**: TOTP recovery codes
  display, TOTP disable confirm, magic link request +
  sent, error pages, `PrimaryAuthMethod::label`,
  Security Center enabled-state recovery-codes row
  (blocked on pluralization — ADR-013 §Q4).
- **Future security-track items still open**: user
  notification on session timeout (ADR-012 §Q2), device
  fingerprint columns (ADR-012 §Q3), bulk revoke other
  sessions (ADR-012 §Q4), introspection
  resource-server audience scoping (ADR-014 §Q1),
  introspection rate limit (ADR-014 §Q2), audit
  retention policy (ADR-014 §Q3), multi-key
  access-token introspection (ADR-014 §Q4).
- **Feature track candidates**: RFC 7009 token
  revocation for confidential clients.

---

## [0.39.0] - 2026-05-03

i18n-2 continued: login + TOTP + Security Center page chrome
migration. Builds on v0.36.0's i18n infrastructure (ADR-013)
to take four high-traffic end-user surfaces from
locale-hardcoded prose to catalog-managed bilingual rendering.
**No new ADR** — the design was anticipated in ADR-013 and
this release is the planned continuation.

### Why this matters

v0.36.0 shipped the catalog + Accept-Language negotiation but
only migrated three small surfaces (flash banners,
`/me/security/sessions` chrome, TOTP enroll wrong-code). The
four largest-by-visibility user-facing pages — login, TOTP
enroll, TOTP verify, Security Center index — were still
locale-hardcoded: login + TOTP pages in English, Security
Center in Japanese. v0.39.0 moves all four through the
catalog so users see content in their negotiated locale
across the entire login+MFA flow.

### What ships

#### Catalog: 48 new `MessageKey` variants

| Surface | Variants |
|---|---|
| Login (`/login`)                          | 10 |
| TOTP enroll (`/me/security/totp/enroll`)  | 11 |
| TOTP verify (`/me/security/totp/verify`)  | 11 + 1 (`TotpVerifyWrongCode`) |
| Security Center (`/me/security`)          | 13 |
| Login `LoginTitle` JA disambiguation      | _existing_ — JA changed from "サインイン" to "サインインする" to differentiate from `SessionsLabelSignIn` ("サインイン" as session-card timestamp label) |

`MessageKey` total: 22 → **70**.

`Locale` set unchanged (Ja, En). All 48 new variants resolve
in both locales, statically guaranteed by the lookup match's
exhaustiveness.

#### Catalog completeness tests refactored

The v0.36.0 catalog completeness tests had hardcoded `all_keys`
arrays (22 elements then) — adding 48 variants would have
meant editing the same list twice in two test functions, and
forgetting one would have silently weakened coverage. v0.39.0
replaces this pattern with `for_each_key(closure)` that pins
exhaustiveness via a compile-time match: adding a new
variant without adding it to the iterator is a build error,
not a missed test. The two existing test bodies
(`every_message_key_resolves_in_every_locale_to_nonempty`,
`no_two_keys_share_text_within_a_locale`) now use the
closure.

The "no two keys share text" test grew an
`is_legitimate_duplicate` allowlist for shared brand strings
and concept-reuse: `"Magic Link"` (brand, same in both
locales), `"Passkey"` / `"パスキー"` (term-of-art shared
between session row + login heading), `"Active sessions"` /
`"アクティブなセッション"` (canonical translation reused
between dedicated page title and Security Center section
heading). Allowlist is exhaustive; any new collision needs
explicit allowlist entry or the test fails.

#### `js_string_literal` helper (`cesauth_ui::js_string_literal`)

Encodes a `&str` as a double-quoted JavaScript string
literal suitable for inlining into `<script>` blocks. Adopted
in v0.39.0 because the migrated login page interpolates the
catalog's passkey-failed error message into inline JS — the
naive concatenation would have broken on translations
containing quotes, backslashes, newlines, or (more likely
for JA) `</script>` patterns.

Specifically escapes:
- `\\`, `"`, `\n`, `\r`, `\t` (named escapes)
- ASCII controls `0x00..=0x1f` (encoded as `\uXXXX`)
- `</` (becomes `<\/` to defeat `</script>` element-end)
- `<!--` (becomes `<\!--`, defensive)

UTF-8 multi-byte sequences pass through unchanged — JS source
files are UTF-8 and the JS engine constructs strings from
those code points correctly. Iterates by `char` (not byte)
so JA codepoints aren't split.

8 dedicated tests in `cesauth_ui::tests`: double-quote +
backslash escape, newlines/tabs/CR, multi-byte UTF-8
passthrough (with JA payload), `</script>` neutralization,
`<!--` neutralization, lone-`<` passthrough, `\uXXXX`
fallback for other controls.

#### Pages migrated

Each page gains a `_for(.., locale)` variant. The plain
function becomes a default-locale shorthand returning Ja —
the same v0.36.0 backward-compat pattern.

- **`login_page_for(csrf, error, sitekey, locale)`** —
  10 catalog lookups for chrome (title, intro, passkey
  heading + button + JS-required notice + JS error message,
  email heading + label + button, page title). The JS
  passkey-failed message is interpolated via
  `js_string_literal` into the inline script.
- **`totp_enroll_page_for(qr_svg, secret_b32, csrf, error, locale)`**
  — 11 catalog lookups (title, intro, QR aria-label, manual
  details summary + meta, confirm heading + intro + label +
  button, cancel link, page title).
- **`totp_verify_page_for(csrf, error, locale)`** — 11
  catalog lookups (title, intro, heading, code label,
  continue button, lost-authenticator details summary,
  recovery intro + aria + label + button, page title).
- **`security_center_page_for(state, flash_html, locale)`**
  — 13 catalog lookups for chrome + nested
  `totp_section_html_for(enabled, recovery_remaining, locale)`
  partial migration. **Disabled-state TOTP rendering** flows
  through the catalog. **Enabled-state + recovery-codes
  status row** intentionally still carries hardcoded JA —
  recovery messages need pluralization (4-tier count
  treatment per plan §3.1 P0-A) and pluralization is
  ADR-013 §Q4 deferred work. `totp_section_html` (without
  `_for`) is the default-locale shim.

#### `TotpVerifyWrongCode` MessageKey

The `/me/security/totp/verify` POST handler's wrong-code
re-render previously emitted a hardcoded `"That code didn't
match. Try again."`. v0.39.0 moves this to a new
`MessageKey::TotpVerifyWrongCode` variant **distinct from
`TotpEnrollWrongCode`**: the enroll surface tells the user
"enter the LATEST 6-digit code" (a setup hint about the
30-second TOTP rotation), while the verify surface just says
"try again" (no setup context, the user already enrolled).
Same general idea, separable translations.

#### Worker handler wire-up

Five handlers now resolve locale and pass it through:

| Handler | File | Page rendered |
|---|---|---|
| `GET /login`           | `routes/ui.rs::login`             | `login_page_for` |
| `GET /authorize` (login fork) | `routes/oidc/authorize.rs` | `login_page_for` |
| `GET /me/security`     | `routes/me/security.rs`           | `security_center_page_for` + `flash::display_text_for` |
| `GET /me/security/totp/enroll`         | `routes/me/totp/enroll.rs::get_handler`         | `totp_enroll_page_for` |
| `POST /me/security/totp/enroll/confirm` (wrong-code re-render) | `routes/me/totp/enroll.rs::post_confirm_handler` | `totp_enroll_page_for` with `TotpEnrollWrongCode` |
| `GET /me/security/totp/verify`         | `routes/me/totp/verify.rs::get_handler`         | `totp_verify_page_for` |
| `POST /me/security/totp/verify` (wrong-code re-render) | `routes/me/totp/verify.rs::post_handler` | `totp_verify_page_for` with `TotpVerifyWrongCode` |

All handlers call `crate::i18n::resolve_locale(&req)` once at
the top — the resolved locale is stable for the request
duration (re-resolving per template would risk a single
response with mixed locales).

### Tests

867 → **889** (+22).

- core: 342 → 342. Catalog grows by 48 variants; the
  exhaustive-iterator pattern means the same two tests
  (`every_message_key_resolves_in_every_locale_to_nonempty`,
  `no_two_keys_share_text_within_a_locale`) cover all of
  them — no test functions added.
- ui: 208 → 230 (+22).
  - 8 new in `cesauth_ui::tests` for `js_string_literal`.
  - 14 new in `cesauth_ui::templates::tests` —
    `login_page_for` EN + JA chrome (4 tests including JS
    interpolation), default-shorthand-returns-JA, TOTP
    enroll EN + JA + aria-label translated EN + JA,
    TOTP verify EN + JA, Security Center EN + JA + EN
    anonymous notice translated.
- worker: 171 → 171. Handler edits, no new tests; existing
  handler tests assert on structural properties (CSRF,
  redirects, status codes) not page-text.
- adapter-test, do, migrate, adapter-cloudflare: unchanged
  (117, 16, 13, 0).

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9). No migration.
- Wire format unchanged for OAuth/OIDC clients.
- DO state unchanged.
- No new dependencies.

### Operator-visible / breaking-change notice

- **Login page default locale changed**: pre-v0.39.0,
  `cesauth_ui::templates::login_page` (no `_for`) returned
  English-hardcoded HTML. Post-v0.39.0, the same shorthand
  returns Japanese (Default = Ja, per the v0.36.0
  convention). Worker handlers all use the negotiated
  `_for(..)` variant, so production traffic with normal
  `Accept-Language` headers is unaffected. Out-of-tree
  callers using the no-locale shorthand get a behavior
  change. Migration: switch to `login_page_for(.., locale)`
  with the locale you want, or rely on `Accept-Language`
  via the worker.
- **TOTP enroll + TOTP verify default locale**: same
  story. Pre-v0.39.0 these were English-hardcoded; the
  no-locale shorthand now returns Japanese. Worker
  handlers use the `_for` variants.
- Security Center page locale was already Japanese
  pre-v0.39.0; the v0.39.0 default is unchanged
  (Japanese), and English consumers now have a working
  path (`Accept-Language: en` or `_for(.., Locale::En)`).

### Deferred to v0.39.1+

- **TOTP recovery codes display** (`totp_recovery_codes_page`)
  — JA-hardcoded, deferred.
- **TOTP disable confirm** (`totp_disable_confirm_page`)
  — JA-hardcoded, deferred.
- **Magic link request + sent** (`magic_link_sent_page`)
  — JA-hardcoded, deferred.
- **Error pages** (`error_page`) — JA-hardcoded, deferred.
- **`PrimaryAuthMethod::label()`** — primary-row label on
  Security Center is independently locale-aware. Migrating
  this enum's labels touches the admin console
  (`PrimaryAuthMethod` is used there too) and is a
  separable thread.
- **Security Center TOTP enabled-state + recovery-codes
  status row** — pluralization needed (count-aware messages
  per plan §3.1 P0-A); blocked on ADR-013 §Q4 (CLDR plural
  rules / cesauth-style integer-substitution).

### ADR changes

- **No new ADR** — the migration was anticipated in
  ADR-013 ("v0.36.0 migrates the flash keys + TOTP wrong-
  code re-render + sessions page chrome. Subsequent
  releases migrate the rest of the end-user surfaces") and
  this release is the planned continuation. ADR-013's
  open questions Q1-Q4 are unchanged.
- Existing ADR-013 status header in ROADMAP narrative
  ("partial") will read accurately again — partial through
  v0.39.0 means recovery codes / disable / magic link /
  error pages, not login + TOTP main flow + Security
  Center.

### Doc / metadata changes

- `Cargo.toml` version 0.38.0 → 0.39.0.
- UI footers + tests bumped to v0.39.0.
- ROADMAP: i18n-2 continued status updated; v0.39.0 Shipped
  table row added.
- This CHANGELOG entry.

### Upgrade path 0.38.0 → 0.39.0

1. `git pull` or extract this tarball over your working
   tree.
2. `cargo build --workspace --target wasm32-unknown-unknown
   --release`. No new production dependencies.
3. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change. No new bindings.
4. **No operator action required for production traffic.**
   Users with `Accept-Language: ja` (or no header) see
   Japanese; users with `Accept-Language: en` see English.
5. Out-of-tree `cesauth-ui` callers using the locale-less
   `login_page` / `totp_enroll_page` / `totp_verify_page`
   shorthands: switch to the `_for(.., Locale::En)` form
   if your previous reliance was on English hardcoded
   output.

### Forward roadmap

- **v0.39.1 / v0.40.0**: continue i18n-2 with the
  remaining surfaces (recovery codes, TOTP disable, magic
  link, error pages, `PrimaryAuthMethod::label`).
- **Future security-track items still open**: D1-DO
  reconciliation tool (ADR-012 §Q1), user notification on
  session timeout (ADR-012 §Q2), device fingerprint
  columns (ADR-012 §Q3), introspection resource-server
  audience scoping (ADR-014 §Q1), introspection rate
  limit (ADR-014 §Q2), audit retention policy (ADR-014
  §Q3), multi-key access-token introspection (ADR-014
  §Q4).
- **Feature track candidates**: RFC 7009 token revocation
  for confidential clients (current `/revoke` is
  user-pressed only).

---

## [0.38.0] - 2026-05-03

RFC 7662 OAuth 2.0 Token Introspection (ADR-014 Accepted).
First feature-track release after the security-track sprint
(v0.34-v0.37) and i18n track (v0.36). Adds a server-side
"is this token currently active?" endpoint that resource
servers can consult, closing the long-standing gap where
refresh tokens were entirely opaque to bearers.

### Why this matters

cesauth has issued access + refresh tokens since v0.4 but
never gave resource servers a way to verify them
authoritatively. Local JWT verification of access tokens
catches signature failures + expiry, but misses revocations
between issuance and access-token expiry (cesauth's default
access-token TTL is 60 minutes). Refresh tokens are 100%
opaque — resource servers can't independently check whether
a presented refresh token is current vs retired vs from a
revoked family.

RFC 7662 specifies the standard introspection endpoint that
fills this gap. v0.38.0 implements it with strong privacy
guarantees on the inactive path (RFC §2.2) and read-only
semantics that prevent abuse.

### What ships

#### `POST /introspect` endpoint

Path is conventional but not spec-mandated; cesauth uses
`/introspect` matching the discovery-document field name.

#### Authentication required (RFC 7662 §2.1)

cesauth accepts:

| Method | Form |
|---|---|
| `client_secret_basic` | `Authorization: Basic base64(id:secret)` — recommended for resource servers |
| `client_secret_post`  | form-body `client_id` + `client_secret` — fallback |

`none` (PKCE-only) is **not accepted** at this endpoint.
The discovery document's
`introspection_endpoint_auth_methods_supported` advertises
only the two valid methods.

The extractor prefers Basic when an Authorization header is
present, falling back to form body **only when no Authorization
header is present at all**. A malformed Basic does NOT fall
through to form — that would be a probing surface.

#### Privacy invariant (RFC 7662 §2.2) at the type level

`IntrospectionResponse::inactive()` is the only public
constructor that produces `active = false`, and it accepts
no claim arguments. The handler literally cannot
accidentally leak a claim into an inactive response. The
serde definition uses `skip_serializing_if =
"Option::is_none"` on every claim field, so the wire output
of an inactive response is exactly `{"active":false}`. Test
`inactive_response_serializes_with_only_active_field` pins
this byte-exact.

#### Read-only by design

Introspection NEVER triggers reuse detection. A retired jti
is reported `active = false` without consuming the family.
A malicious resource server with valid introspection
credentials must NOT be able to revoke families on demand.

#### Hint is advisory

Per RFC 7662 §2.1. Order:
- No hint, or `access_token` hint → try access first
  (cheaper — no DO round-trip on the negative path), fall
  through to refresh.
- `refresh_token` hint → try refresh first, fall through
  to access.

Test `hint_access_with_actually_refresh_token_falls_through_to_refresh_check`
pins fall-through.

#### Client credential verification

New helper `cesauth_core::service::client_auth::verify_client_credentials`
takes `(client_id, client_secret)`, looks up the stored
SHA-256 hash via `ClientRepository::client_secret_hash`,
and does constant-time hex comparison. Failure modes
(unknown client, no secret on file, mismatched hash) all
return the same `CoreError::InvalidClient` to avoid the
enumeration side-channel.

cesauth uses SHA-256-of-secret rather than Argon2/scrypt
because `client_secret` is a server-minted high-entropy
random string (32+ bytes from admin console provisioning),
not a user-chosen password. For high-entropy secrets,
salted password hashes provide no additional protection.

#### HTTP Basic auth parser

New module `cesauth_worker::client_auth` with:

- `extract_from_basic(headers)` — parses `Authorization:
  Basic ...`. RFC 6749 §2.3.1-style percent-decoding of
  the inner `id:secret` after base64 decode.
- `extract_from_form(form)` — form-body credentials.
- `extract(headers, form)` — Basic-or-form dispatch.
- `percent_decode` helper handles `%XX` and `+` →
  space, returns None on truncated/invalid escapes.

#### Discovery document

Two new fields:

```json
{
  "introspection_endpoint": "https://issuer/introspect",
  "introspection_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ]
}
```

#### Audit event `EventKind::TokenIntrospected`

Snake-case `token_introspected`. Payload:

```json
{
  "introspecter_client_id": "rs_demo",
  "token_type":             "access_token" | "refresh_token" | "none",
  "active":                 true | false
}
```

The token itself is **deliberately not in the payload** —
including it would defeat the inactive-privacy invariant.
Operators monitoring for unusual introspection patterns
(e.g., a single resource server hammering the endpoint)
can alert on volume + introspecter_client_id without the
token.

`token_type` is `"none"` when `active = false` — cesauth
doesn't expose to the audit log whether the inactive
result was reached via the access-path or the refresh-
path (another privacy property).

### Tests

839 → **867** (+28).

- core: 320 → 342 (+22).
  - 8 in `service::client_auth::tests` — correct/wrong
    secret, unknown client, public client (no secret on
    file), empty secret, SHA-256 known vectors,
    constant-time helper basic correctness.
  - 13 in `service::introspect::tests` — active refresh,
    retired jti privacy-invariant, revoked family,
    unknown family, malformed token (must be inactive
    not 400), empty token, hint fallback, hint parser,
    type-level invariants (inactive ctor, byte-exact
    wire form, access has Bearer, refresh omits Bearer).
  - 1 in `oidc::discovery::tests` —
    `discovery_introspection_endpoint_requires_authentication`.
- worker: 165 → 171 (+6) in `client_auth::tests` —
  percent-decode passthrough, escape, plus-to-space,
  truncated, invalid hex, hex-digit lookup table.
- ui, adapter-test, do, migrate, adapter-cloudflare:
  unchanged (208, 117, 16, 13, 0).

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9). No migration.
- Wire format adds **`POST /introspect`** as a new endpoint.
- Discovery document gains two fields (additive, spec-
  conformant parsers tolerate).
- DO state unchanged.
- New dependencies: none (sha2 + base64 already in tree;
  `verify_client_credentials` adds no new transitive
  deps).

### Operator-visible changes

- **Provision a confidential client for each resource
  server** that needs introspection. The admin console's
  client-creation UI mints a 32-byte URL-safe random
  secret; store the SHA-256 hash via
  `ClientRepository::create`. The plaintext secret is
  shown to the operator once and never recoverable.
- **Audit dashboards**: add a panel for
  `token_introspected` to monitor for unusual
  patterns. The `active` boolean in the payload is
  useful — a high rate of `active=false` from one
  introspecter may indicate they're rotating
  inappropriately or have stale token data.
- **Discovery clients** see the two new endpoint fields.
  Resource servers using `oauth-discovery`-style
  libraries automatically pick up the introspection
  endpoint URL.

### ADR changes

- **ADR-014: RFC 7662 OAuth 2.0 Token Introspection**
  added, status Accepted. Documents the audit findings,
  the privacy-as-type-invariant design, the read-only
  semantics, the hint-fallback algorithm, the
  client_secret_basic-vs-post extractor priority, the
  no-resource-server-typing limitation (Q1: future
  work), the no-multi-key-fallback limitation (Q4:
  future work).
- ADR README index + mdBook `SUMMARY.md` updated.

### Doc / metadata changes

- `Cargo.toml` version 0.37.0 → 0.38.0.
- UI footers + tests bumped to v0.38.0.
- ROADMAP: feature-track entry for RFC 7662 marked ✅;
  Shipped table row added.
- This CHANGELOG entry.

### Upgrade path 0.37.0 → 0.38.0

1. `git pull` or extract this tarball over your working
   tree.
2. `cargo build --workspace --target wasm32-unknown-unknown
   --release`. No new production dependencies.
3. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change. No new bindings.
4. (Optional, per resource server) Provision a
   confidential client via the admin console; configure
   the resource server with the issued credentials and
   point it at `https://<issuer>/introspect`.
5. Update audit dashboards to monitor
   `token_introspected`.

### Forward roadmap

- **i18n-2 continued**: login + TOTP page chrome
  migration (next track per the user's specified
  ordering).
- **Future security-track items still open**: D1-DO
  reconciliation tool (ADR-012 §Q1), user notification
  on session timeout (ADR-012 §Q2), device fingerprint
  columns (ADR-012 §Q3), tenant-default locale
  (ADR-013 §Q2), introspection resource-server
  audience scoping (ADR-014 §Q1), introspection rate
  limit (ADR-014 §Q2), audit retention policy (ADR-014
  §Q3), multi-key access-token introspection (ADR-014
  §Q4).
- **Feature track**: token revocation via RFC 7009 at
  `/revoke` (already implemented for the user-pressed
  flow; future work surfaces it for confidential
  clients with the same auth pattern as introspection).

---

## [0.37.0] - 2026-05-03

Per-family rate limit on `/token` refresh — security-track
follow-on that resolves ADR-011 §Q1 (the open question
deferred from v0.34.0). Bounds rapid retry attempts against
a single refresh-token family without changing the
atomic-revoke-on-reuse invariant from v0.4: rate limit is
DoS bounding (request-volume gate), reuse detection is
atomic security (token-leak response). The two are
independent and each fires when its own gate is tripped.

### Why this matters

The v0.34.0 audit identified rate limiting as the gap
between "we detect reuse atomically on first replay" and
"an attacker with a leaked-but-current refresh token can
still hammer the rotation endpoint until they win a race
or exhaust the family's `retired_jtis` ring (size 16)".
v0.34.0 deferred the fix because the structural invariant
was already in place; v0.37.0 closes the gap.

### What ships

**`Config::refresh_rate_limit_threshold`** (default 5,
env `REFRESH_RATE_LIMIT_THRESHOLD`) and
**`refresh_rate_limit_window_secs`** (default 60, env
`REFRESH_RATE_LIMIT_WINDOW_SECS`). Threshold = 0 disables
the gate.

**`CoreError::RateLimited { retry_after_secs }`** new
variant. Distinct from `RefreshTokenReuse` because rate
limit fires *before* the family DO is consulted —
they're separable signals. The `retry_after_secs` is
sourced from `RateLimitDecision::resets_in` and
propagates to the wire's `Retry-After` header.

**`rotate_refresh` signature change**: now takes a
`RateLimitStore` generic + threshold + window in the
input. The check happens after `decode_refresh` (we need
`family_id` for the bucket key) but before
`families.rotate(...)` so a tripped limit doesn't even
touch the family DO. Bucket key shape: `refresh:<family_id>`.

**Bucket key choice** (key namespace = family_id):

| Granularity | Why rejected |
|---|---|
| Per-jti | Each rapid attempt may carry a different stale jti — wouldn't catch the leaked-token replay case. |
| Per-user_id | A user with two devices (two families) would have one device's traffic affect the other. |
| **Per-family_id** | Catches "rapid attempts against one logical session" exactly. ✅ |

**Wire response**: HTTP **429 Too Many Requests** with
`Retry-After: <secs>` header (RFC 7231 §6.6 + §7.1.3).
Body code is `invalid_request` (RFC 6749 §5.2 catch-all;
RFC 6749 doesn't define a rate-limit code, but the 429
status is unambiguous to modern clients). `Retry-After`
is clamped to a minimum of 1 second so the header is
always actionable.

**New audit event `EventKind::RefreshRateLimited`**.
Snake-case `refresh_rate_limited`. Payload:

```json
{
  "family_id":         "fam_...",
  "client_id":         "...",
  "threshold":         5,
  "window_secs":       60,
  "retry_after_secs":  42
}
```

`family_id` decoded via the same audit-only
`decode_family_id_lossy` introduced in v0.34.0; a
malformed token doesn't fail-close the audit write.

**Decision is independent of reuse detection.** A
client that hits the rate limit gets `RateLimited`;
the same client that subsequently presents a stale
jti once the rate limit clears would see
`RefreshTokenReuse`. Operators monitoring for
brute-force / scanning attacks should alert on
`refresh_rate_limited`; operators monitoring for
token compromise alert on
`refresh_token_reuse_detected`.

### Tests

833 → **839** (+6).

- adapter-test: 114 → 117 (+3). Three rate-limit
  integration tests pinning the bucket-key pattern that
  `rotate_refresh` uses:
  `refresh_rate_limit_first_5_within_window_allowed_6th_denied`,
  `refresh_rate_limit_isolated_per_family_id` (key
  namespacing — fam_A's saturated bucket must not
  affect fam_B), `refresh_rate_limit_resets_after_window_rolls`.
- worker: 162 → 165 (+3). Three error-mapper tests:
  `rate_limited_maps_to_http_429`,
  `rate_limited_status_is_independent_of_retry_after`,
  `rate_limited_status_distinct_from_other_4xx_oauth_errors`.
- core, ui, do, migrate, adapter-cloudflare: unchanged
  (320, 208, 16, 13, 0).

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9). No
  migration.
- Wire format adds **HTTP 429** as a possible response
  on `/token` refresh. Modern OAuth clients understand
  this; pre-modern clients see a generic 4xx and
  retry-with-backoff (which is the intended effect).
- DO state unchanged.
- No new dependencies.

### Operator-visible changes

- **Default 5 attempts per 60 sec** for `/token` refresh
  per family. Operators with high-frequency rotation
  patterns (long-running IoT sync, batch jobs) may need
  to tune up; operators with high-security tenancies
  may want to tune down.
- Set `REFRESH_RATE_LIMIT_THRESHOLD=0` to disable.
- **Audit dashboards**: add a panel for
  `refresh_rate_limited` to monitor for brute-force /
  scanning. The kind fires before the family DO is
  consulted, so a high rate of these events without
  matching `refresh_token_reuse_detected` events
  indicates someone is probing without (yet) having a
  valid jti.

### ADR changes

- **ADR-011 §Q1** marked **Resolved**. The decision +
  rationale + wire mapping are documented inline in the
  Q1 entry.
- No new ADR — this is a follow-on to ADR-011, not a
  separate decision tree. The design choices (bucket
  key namespace, threshold default, RFC 7231 status
  selection) are all small enough to record in the
  resolved-Q1 paragraph.

### Doc / metadata changes

- `Cargo.toml` version 0.36.0 → 0.37.0.
- UI footers + tests bumped to v0.37.0.
- ROADMAP: ADR-011 §Q1 Shipped row added; future
  security-track item list pruned.
- This CHANGELOG entry.

### Upgrade path 0.36.0 → 0.37.0

1. `git pull` or extract this tarball over your working
   tree.
2. `cargo build --workspace --target wasm32-unknown-unknown
   --release`. No new production dependencies.
3. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change. No new bindings.
4. (Optional) Set `REFRESH_RATE_LIMIT_THRESHOLD` and
   `REFRESH_RATE_LIMIT_WINDOW_SECS` if the defaults (5
   per 60 sec) don't suit your traffic pattern.
5. Update audit dashboards to monitor
   `refresh_rate_limited`.

### Forward roadmap

- **Feature track candidate next**: RFC 7662 Token
  Introspection.
- **i18n-2 continued**: login + TOTP page chrome
  migration.
- **Future security-track items still open**: D1-DO
  reconciliation tool (ADR-012 §Q1), user notification
  on session timeout (ADR-012 §Q2), device fingerprint
  columns (ADR-012 §Q3), tenant-default locale
  (ADR-013 §Q2).

---

## [0.36.0] - 2026-05-03

Internationalization track infrastructure (ADR-013 Accepted).
Pays the i18n debt from `crates/worker/src/flash.rs:215`'s
v0.31.0 TODO. Ships `cesauth_core::i18n` (closed Locale +
MessageKey enums, compile-time exhaustive lookup, RFC 7231
§5.3.5 q-value-aware Accept-Language parser) plus initial
migration of the highest-visibility surfaces (flash banners,
`/me/security/sessions` chrome, TOTP enroll wrong-code error).

This is i18n-1 + partial i18n-2 in the ROADMAP phasing. The
remaining end-user surfaces (login, TOTP page chrome, magic
link, security center index) migrate in subsequent releases.

### Why this matters

cesauth's UI through v0.35.0 was language-mixed without
negotiation. End-user surfaces carried hardcoded JA, the
admin console hardcoded EN, and there was no
`Accept-Language` handling. Users with EN browsers saw JA;
users with JA browsers saw mixed JA + EN. v0.36.0 makes the
locale a per-request property and routes user-visible text
through a typed catalog.

### What changed

#### `cesauth_core::i18n` module

```rust
pub enum Locale { Ja, En }            // closed; recompile to add
pub enum MessageKey { /* PascalCase concepts */ }  // closed
pub fn lookup(MessageKey, Locale) -> &'static str
pub fn parse_accept_language(&str) -> Locale
```

22 MessageKey variants in the v0.36.0 catalog: 5 flash
banners, 1 TOTP wrong-code error, 16 sessions-page chrome
(title, intro, empty state, back link, current-device badge,
disabled button + title, revoke button, four auth-method
labels including unknown, four session-meta labels).

Every variant has every locale's translation, statically
guaranteed by the lookup function's match exhaustiveness.
Adding a key without a translation in every locale is a
compile error.

`Locale::default() = Ja` — preserves pre-i18n rendering for
users without `Accept-Language`.

#### Accept-Language parser

RFC 7231 §5.3.5 lenient subset:

- Splits entries on `,`, parameters on `;`.
- `q=<float>` recognized; missing q implicitly 1.0;
  malformed q permissively treated as 1.0.
- Region subtags stripped (`ja-JP` → `ja`, `en-US` → `en`).
- `q=0` entries dropped (RFC: "not acceptable").
- Wildcard `*` matches `Locale::default()`.
- Ties resolve in document order so first-listed wins.
- Unknown languages skip; all-unknown falls through to
  default.

#### Per-request locale resolution

`cesauth_worker::i18n::resolve_locale(&Request) -> Locale`
is the single per-request locale lookup. v0.36.0 just reads
`Accept-Language`; future iterations may layer on a user-pref
cookie + tenant default (cookie → tenant → header → default).
The resolved locale is stable for the duration of the
request to prevent mixed-locale rendering.

#### Backward-compatible migration pattern

Each migrating call site adds a `_for(..., locale)` variant
alongside the existing function. The plain function becomes
a default-locale shorthand:

```rust
pub fn sessions_page(items, csrf, flash) -> String {
    sessions_page_for(items, csrf, flash, Locale::default())
}
```

Existing callers and tests continue to work. Once every call
site is migrated the shorthands can be removed; for now they
aren't in the way.

#### Migrated surfaces (v0.36.0)

- **Flash banners** — `FlashKey::display_text` routes
  through `lookup`. New `display_text_for(locale)` method;
  legacy `display_text()` is the default-locale shim.
- **`flash::render_view_for(flash, locale)`** — locale-aware
  Flash → FlashView projection. Legacy `render_view(flash)`
  is the shim.
- **`cesauth_ui::templates::sessions_page_for(items, csrf,
  flash, locale)`** — every visible string flows through
  `lookup`. `sessions_page` shorthand returns the JA
  rendering as before.
- **`cesauth_ui::templates::render_session_row_for(row,
  csrf, locale)`** — auth method labels (passkey, magic_link,
  admin, unknown) and session-meta labels go through the
  catalog.
- **`/me/security/sessions` handler** —
  `resolve_locale(&req)` at the top, threads through to
  `sessions_page_for` and `render_view_for`.

### Tests

808 → **833** (+25).

- core: 300 → 320 (+20). 20 new tests in
  `cesauth_core::i18n::tests` covering Locale parsing
  (case-insensitive, region-stripping, unknown returns
  None), Accept-Language parsing (empty, q-value
  priority, q=0 dropped, wildcard, malformed q treated
  as 1.0, all-unknown falls through, tie-breaking in
  document order, browser-typical headers), catalog
  completeness (every key resolves in every locale to
  nonempty, no two keys share text within a locale).
- ui: 203 → 208 (+5). 5 new tests in
  `cesauth_ui::templates::tests` for `sessions_page_for`
  English rendering (chrome, method labels, revoke
  button, current-device badge, default shorthand still
  produces JA).
- worker, adapter-test, do, migrate, adapter-cloudflare:
  unchanged (162, 114, 16, 13, 0).

### Schema / wire / DO

- Schema unchanged from v0.35.0 (still SCHEMA_VERSION 9).
- Wire format unchanged for OAuth/OIDC clients.
- No new DO classes; no migration.
- No new dependencies.

### Operator-visible changes

- Existing JA-default rendering preserved for users without
  `Accept-Language`.
- Users sending `Accept-Language: en` see the migrated
  surfaces in English.
- Future translation work: add a `Locale` variant + match
  arms in `cesauth_core::i18n::lookup`. The compiler tells
  you every place that needs a new arm.

### Migration path for callers (in-tree)

Existing handlers can adopt locale-awareness incrementally:

1. Resolve locale at the top: `let locale =
   crate::i18n::resolve_locale(&req);`
2. Replace `flash::render_view(f)` with
   `flash::render_view_for(f, locale)`.
3. Replace `templates::xxx(...)` with
   `templates::xxx_for(..., locale)`.

Out-of-tree callers (e.g., third-party integrations) see no
break — the shim functions retain the v0.35.0 signatures.

### ADR changes

- **ADR-013: Internationalization infrastructure** added,
  status Accepted. Documents the closed-enum design choice,
  the why-not-runtime-catalogs reasoning, the v0.36.0
  migration scope, deferred items (user-pref cookie,
  tenant default, date/time format, pluralization), and
  rejected alternatives (`fluent-rs`, macro-generated
  lookup, region/script subtag awareness).
- ADR README index + mdBook `SUMMARY.md` updated.

### Doc / metadata changes

- `Cargo.toml` version 0.35.0 → 0.36.0.
- UI footers in `tenancy_console/frame.rs` +
  `tenant_admin/frame.rs` (and matching test asserts)
  bumped to v0.36.0.
- ROADMAP: i18n track i18n-1 + partial i18n-2 marked ✅.
- This CHANGELOG entry.

### Upgrade path 0.35.0 → 0.36.0

1. `git pull` or extract this tarball over your working
   tree.
2. `cargo build --workspace --target wasm32-unknown-unknown
   --release`. No new production dependencies.
3. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change. No new bindings.
4. (Optional) Operators with predominantly EN audiences
   may want to flip `Locale::default()` to `En` and
   redeploy. v0.36.0 ships JA-default to preserve the
   pre-i18n rendering for users without
   `Accept-Language`.

### Forward roadmap

- **i18n-2 continued** (post-v0.36.0): migrate login page,
  TOTP enroll/verify/disable/recover page chrome, magic
  link request/verify pages, security center index page,
  remaining intro paragraphs across user-facing surfaces.
- **i18n-3** — additional locales added on demand. Pull
  requests welcome.
- **i18n-4** — RFC 5646 region/script subtag awareness
  (`zh-Hant`, `pt-BR`, etc.). Defer until i18n-2 ships
  fully and real demand surfaces.
- **Future security-track items**: D1-DO reconciliation
  tool (ADR-012 §Q1), per-family rate limit on `/token`
  refresh (ADR-011 §Q1), user notification on session
  timeout (ADR-012 §Q2), device fingerprint columns
  (ADR-012 §Q3).
- **Feature track** — RFC 7662 Token Introspection.

---

## [0.35.0] - 2026-05-03

Session hardening + user-facing session management surface
(ADR-012 Accepted). The session subsystem grows three things
v0.34.x lacked: an idle timeout consulted on every
authenticated request, a per-user session enumeration
capability backed by a new D1 index, and a
`/me/security/sessions` page where users can see their
active sessions and revoke individual ones.

### Why this matters

A v0.34.x audit against the session BCP guidance surfaced
five gaps: no idle timeout (only absolute lifetime), no
active-touch wiring (the resolver consulted `status()` not
`touch()`, so `last_seen_at` never advanced), no per-user
enumeration, no user-facing revoke UI, and no audit-event
differentiation between user/admin/auto-revocation. v0.35.0
closes all five with code, schema, UI, and audit-catalog
changes.

### What changed

#### Idle timeout — `session_idle_timeout_secs` config (default 30 min)

`Config::session_idle_timeout_secs` defaults to 1800 seconds
(`SESSION_IDLE_TIMEOUT_SECS` env var). Setting to 0 disables
the gate (operator escape hatch for kiosk-style deployments).

`ActiveSessionStore::touch` signature extends to take both
`idle_timeout_secs` and `absolute_ttl_secs`. The DO consults
both gates atomically with the touch update — no race
window between peek and revoke.

`SessionStatus` gains:

```rust
pub enum SessionStatus {
    NotStarted,
    Active(SessionState),
    Revoked(SessionState),
    IdleExpired(SessionState),     // v0.35.0
    AbsoluteExpired(SessionState), // v0.35.0
}
```

The two new variants are populated by the DO with
`revoked_at = Some(now)` before returning, so the caller
can trust the state is durable.

Order: absolute gate consulted FIRST. A session past both
gates reports `AbsoluteExpired` (deeper-cause attribution).
Pinned by test
`session_touch_absolute_takes_priority_over_idle`.

#### Auth resolver wired to `touch()`

The load-bearing v0.35.0 change: `me::auth::resolve_or_redirect`
switches from `sessions.status()` to `sessions.touch()`. Without
this, the new timeouts would be dormant — `touch()` was the
only writer of `last_seen_at` and was never being called from
production.

This is technically a behavior change for existing v0.34.x
sessions: a session created at v0.34.x with `last_seen_at =
created_at` and idle for >30 minutes will be revoked on its
next request after the v0.35.0 deploy. Operators should
communicate the change to users if they expect long-idle
sessions.

#### Per-user session index — D1-backed

New migration `0009_user_session_index.sql` adds a
`user_sessions` table. SCHEMA_VERSION 8 → 9.

```sql
CREATE TABLE user_sessions (
  session_id   TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  revoked_at   INTEGER,
  auth_method  TEXT NOT NULL,
  client_id    TEXT NOT NULL
);
CREATE INDEX user_sessions_user_idx
  ON user_sessions (user_id, created_at DESC);
```

The D1 row is a denormalized index whose only job is "given
a user_id, what session_ids exist". The per-session DO
remains the source of truth for individual session state.

`ActiveSessionStore::list_for_user(user_id, include_revoked,
limit)` is the new port method. Implementations:

- **In-memory**: O(n) scan over the map (test-only).
- **Cloudflare**: D1 SELECT against `user_sessions`. The DO
  is NOT consulted by `list_for_user` — the index page reads
  ONLY from D1. Hot path (touch on every authenticated
  request) is unchanged; D1 is not in that path.

Mirror writes:
- `start()` writes BOTH the DO state AND `INSERT OR IGNORE
  INTO user_sessions`.
- `touch()` returning IdleExpired/AbsoluteExpired triggers a
  best-effort D1 mirror update.
- `revoke()` writes the DO AND mirrors `revoked_at` into D1.

Eventually-consistent: a D1 mirror failure does NOT unwind
the authoritative DO write. The user-facing list may briefly
show stale state — which the per-row "click to revoke" path
self-heals on click-through (the click path peeks the DO
authoritatively).

ADR-012 §"Considered alternatives" documents why we chose
D1 over a second `UserSessionIndex` DO type.

#### `/me/security/sessions` user-facing page

New page renders the authenticated user's active sessions:

- Auth method label (パスキー / Magic Link / 管理者ログイン)
- Sign-in time + last access time
- Client id
- Shortened session id (8 chars + ellipsis)
- Per-row "取り消す" button — except the row matching the
  current cookie's session_id, which shows a "この端末"
  badge and a disabled button instead.

Rationale for disabling the current-row revoke: revoking your
own session via this page would cause the next request to
bounce to /login — surprising UX. The user should use the
explicit logout flow instead.

Cross-linked from the existing Security Center
(`/me/security`).

`POST /me/security/sessions/:session_id/revoke` is the
revoke endpoint. CSRF-guarded. Refuses revoking the current
session (defensive — UI button is disabled for that row
anyway). Refuses revoking another user's session via 403
(ownership check; defense in depth since the page only
renders the caller's sessions).

#### Audit event split

`EventKind` gains four new kinds:

- `SessionRevokedByUser` — user clicked revoke at
  `/me/security/sessions`.
- `SessionRevokedByAdmin` — admin revoked (existing
  `AdminSessionRevoked` event remains the admin's view; this
  is the session's view).
- `SessionIdleTimeout` — auto-revoked by the idle gate.
  Payload includes `{session_id, idle_secs, last_seen_at,
  now}`.
- `SessionAbsoluteTimeout` — auto-revoked by the absolute
  gate. Payload includes `{session_id, ttl_secs, created_at,
  now}`.

The legacy `SessionRevoked` kind remains in the catalog for
backward compatibility with v0.4–v0.34.x audit chain rows.
New code paths use the split kinds.

`me::auth::resolve_or_redirect` emits the timeout kinds when
`touch()` returns IdleExpired/AbsoluteExpired (best-effort,
audit failure does not block the redirect). The user revoke
handler emits `SessionRevokedByUser` with payload
`{session_id, revoked_by: "user", actor_user_id}`.

### Tests

783 → 801 (+18).

- adapter-test: 103 → 114 (+11).
  - 7 idle/absolute timeout tests in
    `cesauth-adapter-test::store::tests`:
    `session_touch_active_bumps_last_seen`,
    `session_touch_idle_window_expired_revokes_atomically`,
    `session_touch_idle_disabled_when_zero`,
    `session_touch_absolute_lifetime_expires_regardless_of_activity`,
    `session_touch_absolute_takes_priority_over_idle`,
    `session_touch_already_revoked_is_idempotent`,
    `session_touch_unknown_returns_not_started`.
  - 4 list_for_user tests:
    `session_list_for_user_returns_only_that_user_newest_first`,
    `session_list_for_user_excludes_revoked_by_default`,
    `session_list_for_user_respects_limit`,
    `session_list_for_user_empty_when_no_sessions`.
- ui: 189 → 196 (+7) sessions_page rendering tests.
- core, worker, do, migrate, adapter-cloudflare: unchanged.

### Schema

SCHEMA_VERSION 8 → 9. Migration `0009_user_session_index.sql`
adds the `user_sessions` table.

**Operators MUST run `wrangler d1 migrations apply` before
the v0.35.0 build can serve traffic.** Without the migration,
`start()` will fail on the D1 INSERT and new sessions cannot
be created. Existing sessions (DO-only) continue working
through `touch()` and `revoke()`; only `start()` and
`list_for_user` need the index.

### Wire format

No change for OAuth clients. The session cookie format is
unchanged.

### Operator-visible changes

- `SESSION_IDLE_TIMEOUT_SECS` env var (default 1800 = 30 min).
  Setting to 0 disables.
- New audit kinds; dashboards may need a panel update to
  alert on `session_revoked_by_user`,
  `session_idle_timeout`, etc.
- D1 write amplification: each session start now writes one
  DO record + one D1 row (was: DO only). Each revoke writes
  one DO update + one D1 update (was: DO only). Hot path
  (touch on every authenticated request) is unchanged — D1
  is not in that path.
- v0.34.x sessions idle for >30 min when v0.35.0 deploys
  will be revoked on their next request. This is correct
  per BCP guidance. Operators should communicate the change
  to users if they expect long-idle sessions.

### ADR changes

- **ADR-012: Session hardening** added, status Accepted.
  Documents the v0.34.x baseline audit, the five gaps, the
  type-layer + schema changes, the DO + D1 hybrid index
  rationale, and the deferred items (per-tenant idle
  override, revoke-all button, auto-revoke flash, D1
  retention sweep).
- ADR README index + mdBook `SUMMARY.md` updated.

### Doc / metadata changes

- `Cargo.toml` version 0.34.0 → 0.35.0.
- UI footers in `tenancy_console/frame.rs` +
  `tenant_admin/frame.rs` (and matching test asserts)
  bumped to v0.35.0.
- ROADMAP: v0.35.0 marked ✅ in the security track.
- This CHANGELOG entry.

### Upgrade path 0.34.0 → 0.35.0

1. `git pull` or extract this tarball over your working tree.
2. `cargo build --workspace --target wasm32-unknown-unknown
   --release`. No new production dependencies.
3. **Run the schema migration:**
   `wrangler d1 migrations apply cesauth --remote` (or
   `--local` for dev environments). This creates the
   `user_sessions` table.
4. `wrangler deploy`.
5. (Optional) Tune `SESSION_IDLE_TIMEOUT_SECS` in your
   `wrangler.toml` if 30 minutes isn't right for your
   deployment. Set to 0 to disable the idle gate while
   keeping the per-user list and revoke surface.
6. Update audit dashboards to monitor the new kinds:
   `session_idle_timeout`, `session_absolute_timeout`,
   `session_revoked_by_user`.

### Forward roadmap

- **i18n track** (parallel) — `MessageKey` lookup
  infrastructure + `ja` / `en` MVP coverage of end-user
  surfaces; the v0.35.0 sessions_page is now part of the
  surface area that needs catalog migration.
- **Future security-track items** (ADR-012 §"Open
  questions"): per-tenant idle override, revoke-all-other-
  sessions button, auto-revoke flash with i18n key, D1
  user_sessions retention sweep.

## [0.34.0] - 2026-05-03

Refresh token reuse hardening (ADR-011 Accepted). The
family-based rotation invariant from RFC 9700 §4.14.2
(formerly OAuth 2.0 Security BCP §4.13.2) was already
implemented and atomic since v0.4 — this release closes
**observability** gaps surfaced by an audit of the
v0.33.0 baseline against the BCP. Reuse detection events
are now emitted as a distinct audit kind with forensic
payload, while the wire-level response stays identical to
`invalid_grant` so attackers can't probe family state via
error-code differentiation.

### What changed

This is a security-track release with no new
deployment-affecting moving parts. Schema unchanged. KV
unchanged. No wire-format break for OAuth clients. The
diff is concentrated in the type layer (refresh family
state + rotate outcome + core error) plus a handful of
worker plumbing lines.

#### `FamilyState` gains forensic fields

```rust
pub struct FamilyState {
    // ... existing fields ...
    pub reused_jti:        Option<String>,
    pub reused_at:         Option<i64>,
    pub reuse_was_retired: Option<bool>,
}
```

All three use `#[serde(default)]` so existing DO storage
records (which don't carry these fields) deserialize cleanly
and just see `None`. **No DO migration needed**; the fields
populate lazily on the next reuse event for any given family.

`reuse_was_retired = Some(true)` means the presented jti was
in `retired_jtis` (= a real, previously-rotated-out token —
the classic leaked-session case).
`reuse_was_retired = Some(false)` means the jti was wholly
unknown (= forged or shotgun attempt). `None` is the
"never had a reuse" state, including admin-revoked
families.

Admin-initiated `revoke()` does NOT populate any reuse
field, and once a family is revoked, subsequent rotation
attempts do NOT overwrite the recorded forensics. The
first reuse is the investigation anchor; later attacker
pokes are recorded only as `AlreadyRevoked` outcomes.

#### `RotateOutcome::ReusedAndRevoked` carries forensic payload

```rust
RotateOutcome::ReusedAndRevoked {
    reused_jti:  String,
    was_retired: bool,
}
```

The caller doesn't have to peek the family again — the
rotate operation already had this information at the
decision point.

#### New `CoreError::RefreshTokenReuse` distinct from `InvalidGrant`

```rust
CoreError::RefreshTokenReuse {
    reused_jti:  String,
    was_retired: bool,
}
```

The service layer's `rotate_refresh` now distinguishes:

- `RotateOutcome::AlreadyRevoked` →
  `CoreError::InvalidGrant("refresh token revoked")` (as
  before).
- `RotateOutcome::ReusedAndRevoked { .. }` →
  `CoreError::RefreshTokenReuse { reused_jti, was_retired }`.

#### Same wire response for both error variants

`oauth_error_response` maps both to `error: "invalid_grant"`
with HTTP 400. Wire-level observers cannot distinguish
reuse from a normally-revoked family — the BCP §4.13 / spec
§10.3 internal/external separation. Internally, audit + logs
see the distinct variants.

The `(code, status)` decision is extracted as
`oauth_error_code_status(&CoreError) -> (&'static str, u16)`
so tests can pin the wire-equivalence without constructing
`worker::Response` (which is wasm-bindgen-backed and panics
on the host test target).

#### New audit event `EventKind::RefreshTokenReuseDetected`

Snake-case discriminant: `refresh_token_reuse_detected`.
Emitted ONLY on `CoreError::RefreshTokenReuse`. Other
rotation failures (already-revoked, expired, malformed
token) continue emitting `token_refresh_rejected`.

Payload JSON:

```json
{
  "family_id":     "fam_...",
  "client_id":     "...",
  "presented_jti": "...",
  "was_retired":   true
}
```

`family_id` is decoded from the presented refresh token
via `decode_family_id_lossy` — a separate, audit-only
decoder that returns `"<malformed>"` rather than fail-
closing on a malformed token. Losing the audit signal is
worse than recording an empty family_id; the authoritative
decoder used by the rotation path stays in core where its
errors propagate normally.

### Tests

777 → 783 (+6).

- adapter-test: 100 → 103 (+3): one strengthened
  `refresh_reuse_burns_family` test now pins the new
  forensic outputs; two new tests for the
  unknown-jti subcase (`refresh_reuse_with_unknown_jti_marks_was_retired_false`)
  and the preserve-first-forensics invariant
  (`refresh_reuse_then_more_attempts_preserve_first_forensics`,
  `admin_revoke_does_not_populate_reuse_forensics`).
- worker: 159 → 162 (+3): three error-mapper tests in
  `error::tests` covering wire-equivalence between
  reuse and revoked, wire-equivalence between
  was_retired=true vs false, and the RFC 6749 §5.2
  `invalid_grant` code pin.
- core, ui, do, migrate, adapter-cloudflare: unchanged
  (300, 189, 16, 13, 0).

### Schema

Unchanged from v0.33.0. SCHEMA_VERSION still 8. No
migration in this release.

### Wire format

Unchanged for OAuth clients. The HTTP-visible response on
refresh-token reuse is byte-identical to the response on
legitimate revocation (`{"error":"invalid_grant"}` with
HTTP 400). This is a deliberate property — see ADR-011
"Same wire-level response for both error variants".

### Operator-visible changes

Audit events split into two streams. Operators monitoring
for compromise should now alert on
`refresh_token_reuse_detected` specifically rather than on
the generic `token_refresh_rejected` (which fires for any
expired/revoked rotation, not just reuse).

A high-confidence "stolen token" alert pattern:

```sql
SELECT * FROM audit_events
WHERE kind = 'refresh_token_reuse_detected'
  AND json_extract(payload, '$.was_retired') = 1
ORDER BY ts DESC LIMIT 50
```

`was_retired = 0` events are also worth reviewing but at
lower urgency.

### ADR changes

- **ADR-011: Refresh token reuse hardening** added,
  status Accepted. Documents the v0.33.0 baseline audit
  findings, the four observability gaps closed in v0.34.0,
  the type-layer changes, the wire-equivalence rationale,
  and the deferred items (per-family rate limiting,
  user notification, admin aggregate view).
- ADR README index updated.
- mdBook `SUMMARY.md` updated with the new ADR entry,
  plus ADR-010's `(Draft)` annotation removed (it
  graduated to Accepted in v0.33.0).

### Doc / metadata changes

- `Cargo.toml` version 0.33.0 → 0.34.0.
- UI footers in `tenancy_console/frame.rs` +
  `tenant_admin/frame.rs` (and matching test asserts)
  bumped to v0.34.0.
- ROADMAP: v0.34.0 marked ✅ in the security track.
- This CHANGELOG entry.

### Notable changes (operator perspective)

- **No DO state migration.** Existing
  `RefreshTokenFamily` DO instances continue to work;
  they'll start populating the new forensic fields on
  their next reuse event (or never, if they never see one).
- **Audit dashboards may need an update.** Any operator
  dashboards keyed only on `token_refresh_rejected` will
  miss the v0.34.0 reuse signal. Add a panel for
  `refresh_token_reuse_detected`.
- **Wire response unchanged.** OAuth clients see no
  difference. Library compatibility unaffected.

### Upgrade path 0.33.0 → 0.34.0

1. `git pull` or extract this tarball over your working tree.
2. `cargo build --workspace --target wasm32-unknown-unknown
   --release`. No new production dependencies.
3. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change. The DO state migration is
   automatic via `#[serde(default)]`.

### Forward roadmap

- **v0.35.0** — Session hardening + `/me/security/sessions`
  page (rotation on login, idle + absolute timeouts, "new
  device" notification, user-facing list of active
  sessions with revoke buttons).
- **i18n track** (parallel) — `MessageKey` lookup
  infrastructure + `ja` / `en` MVP coverage of end-user
  surfaces.
- **Future security-track item** — per-family rate
  limiting on `/token` refresh attempts (ADR-011 §Q1).

---

## [0.33.0] - 2026-05-02

Audit log hash chain Phase 2 — verification surface. ADR-010
graduates from Draft to **Accepted**. The chain mechanism
shipped in v0.32.0 (write path + SHA-256 chain over
`audit_events` rows) is now actively walked by a daily cron,
cross-checked against a chain-head checkpoint stored
separately in Workers KV, and reported in a new admin console
panel. Tamper detection is end-to-end exercised against
deliberate-tampering test fixtures (10 cases covering payload
edits, chain_hash edits, intermediate row deletion, wholesale
rewrite, and tampered genesis row).

### Why this matters

Phase 1 made the audit log internally tamper-evident: editing
any past row breaks the chain at that point and every row
after it. That covers the "edit one row" attack but NOT the
**wholesale rewrite** attack, where an attacker with write
access to `audit_events` rewrites the entire table from any
seq onward and recomputes every chain hash so the chain
verifies internally.

Phase 2 closes that gap with **chain-head checkpoints**: the
verifier records the (seq, chain_hash) of the verified tail to
Workers KV after each successful run; subsequent runs cross-
check the recorded checkpoint against the current row at the
same seq. A wholesale rewrite changes `chain_hash` at every
row including the checkpointed seq — the cross-check catches
it. The defense is asymmetric: an attacker now has to
compromise BOTH D1 and KV synchronously to evade detection.

### What ships

**Pure-ish verifier in core.**
`cesauth_core::audit::verifier::verify_chain` (incremental,
resumes from a checkpoint) and `verify_chain_full`
(operator-triggered, ignores checkpoint). Both functions take
trait-bounded `AuditEventRepository` +
`AuditChainCheckpointStore` references; pure-ish in the same
Approach 2 sense the v0.32.1 TOTP handlers use — port-level
IO is in scope, Env touching is not.

**New port `AuditChainCheckpointStore`** with two records:
`AuditChainCheckpoint` (`last_verified_seq`, `chain_hash`,
`verified_at`) for the resume + cross-check, and
`AuditVerificationResult` (`run_at`, `chain_length`, `valid`,
`first_mismatch_seq`, `checkpoint_consistent`, `rows_walked`)
for the admin UI.

**Two adapters.** `InMemoryAuditChainCheckpointStore` in
`cesauth-adapter-test` (for tests, exposes pre-seed
`with_checkpoint` helper for the wholesale-rewrite test
scenarios). `CloudflareAuditChainCheckpointStore` in
`cesauth-adapter-cloudflare` (production, KV-backed). Per-key
layout under the reserved `chain:` prefix in the existing
`CACHE` namespace: `chain:checkpoint`, `chain:last_result`.
No TTL on either — these are operational records, not cache
values.

**New repository method `fetch_after_seq(from, limit)`** on
`AuditEventRepository`. Returns rows with `seq > from` in
ascending order, capped at the supplied limit (hard cap
1000). The verifier uses it for paged walks (page size = 200)
so memory stays bounded regardless of chain length.

**Daily cron.** The existing 04:00 UTC schedule now invokes
both `sweep::run` (anonymous-trial retention sweep, ADR-004)
and `audit_chain_cron::run` (chain verification, ADR-010
Phase 2) independently. A failure in one doesn't block the
other — they're separate concerns and chaining their
lifecycles would couple unrelated operational hazards.

**Admin verification UI.** `GET /admin/console/audit/chain`
renders status (current chain length, last-run badge,
checkpoint metadata, growth-since-checkpoint hint).
`POST /admin/console/audit/chain/verify` runs an
operator-triggered full re-walk. CSRF-guarded; gated on
`AdminAction::ViewConsole` (any admin role). Cross-linked
from the existing audit search page. Status badges:

- ✓ chain valid (green)
- ⛔ tamper detected at seq=N (red, with the seq surfaced)
- ⛔ chain history mismatch (red, for wholesale-rewrite —
  no internal mismatch but checkpoint cross-check failed)
- no runs yet (neutral, cold-start state)

**Stale UI copy fixed.** The audit search page's "R2 prefix"
input was carried over from the pre-v0.32.0 R2 backend and
no longer matched reality. Removed; the help text now points
operators at the new chain status link.

### Failure semantics

Tamper detection persists the failing result to KV (so the
admin UI surfaces the alarm), logs at `console_error!` level
in Workers, and **does NOT advance the checkpoint** — the
next cron run will re-attempt from the same point. cesauth
KEEPS WRITING audit events: the chain is for forensic value,
not runtime gating, and refusing to write would let an
attacker who forged a mismatch take the audit log offline
(ADR-010 §"Open questions Q3").

The verifier itself returning `PortError` (storage outage)
DOES propagate up so the operator sees "the verifier
couldn't run" distinctly from "the verifier ran and found
tamper".

### Tests

757 → 777 (+20).

- core: 300 → 300 (verifier added but tests live in
  adapter-test due to the dev-dep cycle workaround
  documented in the verifier module).
- adapter-test: 86 → 100 (+14: 4 fetch_after_seq tests in
  the in-memory audit adapter, 10 verifier integration
  tests).
- adapter-cloudflare: 0 → 0 (KV adapter has no unit tests;
  exercised only via the worker layer).
- ui: 183 → 189 (+6 audit chain status template rendering
  tests covering empty / valid / tamper-at-seq /
  wholesale-rewrite / growth-since-checkpoint / CSRF wiring).
- worker: 159 → 159 (no new unit tests; the cron handler
  and admin handlers are thin Env-touching wrappers
  exercised end-to-end through the verifier's port-bound
  tests in adapter-test).
- migrate, do, tenant_admin: unchanged (13, 16, 0).

### Schema

Unchanged from v0.32.0. `SCHEMA_VERSION` remains 8; no
migration in this release. The chain checkpoint records
live in KV, not D1.

### Cookies

Unchanged from v0.32.0. 7 cookies total (the original 5
from v0.30.0 plus `flash` and `login_next` from v0.31.0).

### Bindings

KV binding `CACHE` gains the `chain:` prefix as reserved for
chain checkpoint state. Two keys: `chain:checkpoint`,
`chain:last_result`. No TTL on either (operational records).
No new binding declared in `wrangler.toml` — uses the
existing `CACHE` namespace.

### ADR changes

- **ADR-010 → Accepted** (was Draft v0.32.0). Phase 2 entry
  expanded with the shipped reality. Open Questions Q1
  (checkpoint location) and Q3 (in-flight audit writing on
  tamper) marked resolved. Q2 (input format rotation), Q4
  (per-tenant retention), Q5 (user-facing audit view)
  remain open.

### Doc / metadata changes

- `Cargo.toml` version 0.32.1 → 0.33.0.
- UI footers in `tenancy_console/frame.rs` + `tenant_admin/
  frame.rs` (and matching test asserts) bumped to v0.33.0.
- Operator chapter `docs/src/expert/audit-log-hash-chain.md`
  expanded with a Phase 2 section: what runs and when, what
  verification checks, where the checkpoint lives, how to
  read the status page, how to trigger a full re-verify,
  what to do when a tamper alarm fires (investigation
  recipe + KV inspection commands).
- ROADMAP: v0.33.0 marked ✅ in the audit-log-integrity
  track + a Shipped table row added. v0.34.0 (Refresh token
  reuse hardening) becomes the next active slot.
- This CHANGELOG entry.

### Notable changes (operator perspective)

- **Cron runtime budget.** The verifier walks the chain in
  pages of 200 rows. For deployments with under ~10K events
  the cron finishes well within the daily 04:00 UTC slot's
  CPU budget. Larger deployments may want to monitor
  `console_log!` lines for `rows_walked` — an incremental
  run typically sees a few hundred to a few thousand rows
  per day. Full re-verify scales linearly with chain
  length; the operator chapter covers when to use it.

- **First run is a cold start.** On a fresh v0.33.0 deploy
  the first cron run has no prior checkpoint, walks from
  the genesis row, and writes the first checkpoint. The
  admin UI displays "no runs yet" until that first cron
  fires. Operators who want immediate confirmation can
  click "Verify chain now (full re-walk)" on the admin
  page.

- **Tamper alarms persist.** The KV record at
  `chain:last_result` survives across cron runs until
  overwritten by a successful run. An alarm doesn't
  "expire" — investigators have time to look at the row
  before the next cron tries again.

### Upgrade path 0.32.1 → 0.33.0

1. `git pull` or extract this tarball over your working tree.
2. `cargo build --workspace --target wasm32-unknown-unknown
   --release`. No new production dependencies.
3. `wrangler deploy`. No schema migration. No `wrangler.toml`
   change. The KV checkpoint state is created lazily on the
   first cron run.
4. (Optional) Visit `/admin/console/audit/chain` and click
   "Verify chain now (full re-walk)" to seed a checkpoint
   immediately rather than waiting for the next 04:00 UTC
   cron.

### Forward roadmap

- **v0.34.0** — Refresh token reuse hardening. Detect
  refresh-token reuse, invalidate the chain on detection,
  emit `refresh_token_reuse_detected` audit event.
- **v0.35.0** — Session hardening + `/me/security/sessions`
  page (rotation on login, idle + absolute timeouts, "new
  device" notification, user-facing list of active
  sessions with revoke buttons).
- **i18n track** (parallel) — newly added to ROADMAP per
  user observation. End-user UI is currently a mix of
  hardcoded Japanese and English with no `Accept-Language`
  handling; phasing covers a `MessageKey` lookup
  infrastructure + `ja` / `en` MVP.

---

## [0.32.1] - 2026-05-02

TOTP handler integration tests — landing the P1-B item that was
deferred from v0.31.0 per plan v2 §6.4. This is an internal-only
release: zero wire-surface change, zero schema change, zero
deployment-affecting change. The diff is entirely a
`crates/worker/src/routes/me/totp/*.rs` refactor that extracts
each handler's branching logic into a pure-ish decision function
plus a thin Env-touching handler wrapper, with new tests
exercising the decision functions via the in-memory adapters
in `cesauth-adapter-test`.

### Why a refactor for tests

The blocker for v0.31.0 P1-B (and the reason it was deferred per
plan v2 §6.4) was that the worker crate has no `worker::Env`
mock infrastructure, and standing one up would have inflated
that release past the review-able slice. v0.32.1 takes a
different path — Approach 2 from the v0.32.0 planning
discussion: refactor the handlers so the branching decision
logic doesn't need `Env` at all. The decision functions take
trait-bounded `&impl AuthChallengeStore` /
`&impl TotpAuthenticatorRepository` /
`&impl TotpRecoveryCodeRepository` references that production
satisfies with the Cloudflare D1 / DO adapters and tests
satisfy with the in-memory adapters from `cesauth-adapter-test`.

The user explicitly authorized breaking internal-API refactors
during the v0.32.0 planning conversation: "保守性向上、拡張性向上
を考慮した上で、コード変更を惜しまず、必要であれば破壊的な変更も
許容する". This release exercises that latitude.

### What ships

Six TOTP handlers refactored into `decide_X` + handler-wrapper
pairs. All handler signatures unchanged; production wiring
unaffected.

| Handler | Decision enum | Decision function | New tests |
|---|---|---|---|
| `disable::post_handler` | `DisableDecision` | `decide_disable_post` | 5 |
| `recover::post_handler` | `RecoverDecision` | `decide_recover_post` | 10 |
| `verify::get_handler` | `VerifyGetDecision` | `decide_verify_get` | 4 |
| `verify::post_handler` | `VerifyPostDecision` | `decide_verify_post` | 9 |
| `enroll::get_handler` | `EnrollGetDecision` | `decide_enroll_get` | 4 |
| `enroll::post_confirm_handler` | `EnrollConfirmDecision` | `decide_enroll_confirm_post` | 8 |

Plus 5 pre-existing `attempts_exhausted` boundary tests and 2
`DISABLE_SUCCESS_REDIRECT` constant pins preserved verbatim from
v0.31.0.

40 new integration tests total.

### Decision-extraction pattern

Each `decide_X` function:

- Takes the request-shape inputs the handler has already extracted
  (CSRF tokens, form fields, cookie-resolved handles).
- Takes trait-bounded `&impl Repo` references for the
  storage adapters it needs.
- Takes any expensive Env-resolved values up front
  (encryption_key, encryption_key_id, user_email).
- Returns an enum capturing the decision outcome plus any data
  the handler needs to build the response (user_id +
  auth_method + ar_fields for `complete_auth_post_gate`,
  secret_b32 for re-render, plaintext_codes for the recovery
  page).

Each handler wrapper:

- Does the request-shape extraction (cookies, form data, session).
- Does the Env-touching IO (`load_totp_encryption_key`,
  `read_user_email`).
- Calls the decision.
- Maps each decision variant to a `worker::Response`.

The decisions DO perform port-level IO (challenge `take`/`put`,
`find_active_for_user`, `update_last_used_step`, `confirm`,
`bulk_create`, etc.) — these are part of the domain semantics,
not response-building concerns, and they go through trait
references that tests can satisfy with in-memory adapters.

### Test coverage details

**`decide_disable_post`** (5 tests). Normal happy path, CSRF
mismatch, empty CSRF strings rejected (defense in depth on
`csrf::verify`), authenticators-delete failure surfacing as
AuthDeleteError, recovery-codes-delete failure silently
swallowed (per ADR-009 module doc — best-effort).

**`decide_recover_post`** (10 tests). Happy path, CSRF mismatch
(challenge preserved for retry), empty CSRF strings, empty
code, unknown handle, wrong challenge kind, unknown code (silent
fail-closed for anti-brute-force), storage error vs.
no-matching-code distinction, mark_redeemed race-loss
(MarkRedeemedFailed), code canonicalization (whitespace + case
+ dashes per `hash_recovery_code` contract).

**`decide_verify_get`** (4 tests). Live PendingTotp renders
(peek-not-take pinned), unknown handle is StaleGate, wrong
challenge kind is StaleGate, after-take is StaleGate.

**`decide_verify_post`** (9 tests). Happy path with
last_used_step persistence, CSRF preserves challenge, unknown
handle, find_active = None yields soft-success
NoUserAuthenticator, decryption failure with wrong key,
wrong-code under threshold re-parks with bumped attempts,
wrong-code at threshold yields Lockout (no re-park), malformed
code treated as bad (not 400), find_active storage error
distinct from NoUserAuthenticator.

**`decide_enroll_get`** (4 tests). Happy path inserts
unconfirmed row + returns render data + verifies AAD
round-trippability, wrong-length encryption key short-circuits
before the create() call, repo create failure surfaces as
StoreError, decryption with wrong row_id AAD fails (pins the
AAD-binding contract).

**`decide_enroll_confirm_post`** (8 tests). First enrollment
mints 10 distinct recovery codes + confirms row, additional
authenticator skips recovery codes (ADR-009 §Q6 contract),
CSRF preserves state, user_id mismatch returns
UnknownEnrollment (forged-cookie defense), unknown enroll_id,
already-confirmed returns AlreadyConfirmed without minting
duplicates, wrong-code carries secret_b32 for handler
re-render, decrypt-failure with wrong key.

### Test infrastructure

`crates/worker/Cargo.toml` gained a `[dev-dependencies]` block
adding `tokio` (for `#[tokio::test]` async runtime) and
`cesauth-adapter-test` (for the in-memory port impls). No
production dependencies changed.

Tests use `unimplemented!()` panics in stub repository methods
that the decision under test should NOT call — a passing test
is evidence the decision didn't reach beyond its expected port
contract. This catches regressions where a future refactor
accidentally widens a decision's port surface.

### Tests

717 → 757 (+40).

- worker: 119 → 159 (+40). All in
  `routes::me::totp::{disable,recover,verify,enroll}::tests`.
- core, ui, do, migrate, adapter-test, adapter-cloudflare:
  unchanged (300, 183, 16, 13, 86, 0).

### Doc / metadata changes

- Cargo.toml `version` 0.32.0 → 0.32.1.
- `crates/ui/src/tenancy_console/frame.rs` and
  `crates/ui/src/tenant_admin/frame.rs` footer strings updated;
  matching test asserts in
  `crates/ui/src/tenancy_console/tests.rs` and
  `crates/ui/src/tenant_admin/tests.rs` updated.
- ROADMAP `v0.31.1` slot marked completed-as-v0.32.1; the
  Shipped table gets a v0.32.1 row.
- This CHANGELOG entry.

### Notable changes

None deployment-affecting. Operators upgrading from v0.32.0 do
not need to re-deploy anything operational; they can ship the
new build whenever convenient.

### Forward roadmap

- **v0.33.0** — ADR-010 Phase 2: chain verification cron +
  admin verification UI + chain-head checkpoints. ADR-010
  graduates to Accepted at end of release.
- **v0.34.0** — Refresh token reuse hardening.
- **v0.35.0** — Session hardening + `/me/security/sessions`.

---

## [0.32.0] - 2026-05-02

Audit log hash chain — Phase 1 of ADR-010. cesauth's audit
events move from R2 NDJSON objects to a D1 table with SHA-256
hash chain integrity. The chain makes the audit log
tamper-evident: modifying any past row invalidates every
subsequent `chain_hash`, and the change becomes detectable
linearly with the number of intervening rows.

This release establishes the storage shape, the chain
mechanism, and the write/query paths. The verification cron
and admin verification UI ship as Phase 2 in v0.33.0.

### Architectural decision

ADR-010 (`docs/src/expert/adr/010-audit-log-hash-chain.md`)
records the design and the threat model. Status **Draft** until
Phase 2 lands and the chain has been validated end-to-end
against deliberate tampering scenarios.

The Phase 1 design was settled with the user during the
v0.32.0 planning conversation:

- **Source of truth = D1**, not R2 with a parallel chain
  ledger. The two-store design was rejected because: R2 has no
  read-your-writes guarantee on `list()` (the chain would
  fork under concurrency); cross-store consistency was a
  permanent operational hazard; verification would have been
  N+1.
- **No backward compatibility for historical R2 audit data.**
  The R2 path is retired entirely. Operators retain any
  pre-v0.32.0 R2 objects on their account but cesauth no
  longer reads or writes them. Migration tooling for old
  R2 events into the D1 chain is not provided.
- **Documentation framing** changed to remove "pre-1.0" /
  "production-ready" claims. cesauth is in active development;
  the documents now say so plainly without making maturity
  assertions either way.

### Added

- **D1 schema migration `0008_audit_chain.sql`** introduces
  the `audit_events` table with chain columns
  (`payload_hash`, `previous_hash`, `chain_hash`) plus
  per-field indexed columns (`subject`, `client_id`, `ip`,
  `user_agent`, `reason`) for admin search. Three indexes:
  `(ts)`, `(kind, ts)`, partial `(subject) WHERE subject IS
  NOT NULL`. The migration also INSERTs a genesis row at
  `seq=1` with `kind='ChainGenesis'`, all-zero
  `previous_hash`/`chain_hash`, and empty `{}` payload — the
  anchor point for the chain.

- **`SCHEMA_VERSION`** bumped 7 → 8. `MIGRATION_TABLE_ORDER`
  and `TENANT_SCOPES` extended with `audit_events` (Global
  scope; the chain is deployment-wide, not tenant-scoped).

- **`cesauth_core::audit::chain` module** with pure functions
  for the chain calculation (~150 lines):
  `compute_payload_hash(bytes) -> String` (SHA-256, lowercase
  hex), `compute_chain_hash(prev, payload_hash, seq, ts, kind,
  id) -> String` over the canonical byte layout `prev || ":"
  || payload_hash || ":" || seq || ":" || ts || ":" || kind ||
  ":" || id`, `verify_chain_link(...)` and
  `verify_payload_hash(...)` for Phase 2's verifier. Genesis
  sentinels published as constants (`GENESIS_HASH` = 64 zeros,
  `GENESIS_PAYLOAD_HASH` = SHA-256 of `{}`). 25 unit tests pin
  determinism, sensitivity to every input field, separator
  integrity (seq/ts boundary, kind/id boundary), reference
  vectors with a hash captured at v0.32.0 development time.

- **`cesauth_core::ports::audit::AuditEventRepository` trait**.
  Replaces the v0.31.x `AuditSink`. Three methods: `append`
  (chain-extending, with retry-on-collision in
  implementations), `tail` (Phase 2 verifier needs it), and
  `search` (admin queries). Value types: `AuditEventRow`,
  `NewAuditEvent`, `AuditSearch`.

- **`InMemoryAuditEventRepository`** in `cesauth-adapter-test`
  (~140 lines + 16 tests). Two constructors: `new()` for an
  empty repository (first append starts at `seq=1`) and
  `with_genesis()` mirroring the D1 schema (genesis at
  `seq=1`, real events from `seq=2`). Test coverage: chain
  validity across multiple appends, `previous_hash`-to-
  `chain_hash` linking, `payload_hash` recomputability, search
  filter behavior (kind / subject / since-until / limit /
  combined), tail retrieval at every population state.

- **`CloudflareAuditEventRepository`** in
  `cesauth-adapter-cloudflare` (~250 lines). The append path
  reads the tail, computes the new row's chain hash, attempts
  INSERT with explicit `seq=N+1`. UNIQUE collision (concurrent
  writer beat us) triggers retry; the budget is 3 attempts,
  enough to handle realistic Workers-instance simultaneity.
  The repository's `id`-collision case (caller produced a
  duplicate UUID, vanishingly rare) returns
  `PortError::Conflict` rather than retrying. Search uses
  parameterized SQL with placeholder binding to avoid
  injection; the limit is capped at 1000.

- **`docs/src/expert/audit-log-hash-chain.md`** new operator
  chapter (~250 lines): what's chained, how to read the table
  with `wrangler d1 execute`, chain semantics in plain
  language, what the chain protects against and what it
  doesn't, the genesis row's role, R2-deprecation operator
  notes, failure modes (the chain doesn't tolerate gaps in
  `seq`, so best-effort write failures drop events entirely),
  Phase 2 preview, diagnostic queries. Linked in
  `docs/src/SUMMARY.md` next to the cookies chapter and
  ADR-010.

### Changed (breaking — internal API)

- **`cesauth_core::ports::audit` rewritten.** The v0.31.x
  `AuditSink` trait + `AuditRecord` struct are gone, replaced
  by `AuditEventRepository` + `AuditEventRow` + `NewAuditEvent`
  + `AuditSearch`. Adapters that implemented `AuditSink` need
  to migrate; in this codebase that means
  `CloudflareAuditSink` → `CloudflareAuditEventRepository` and
  `InMemoryAuditSink` → `InMemoryAuditEventRepository`. The
  worker layer's `audit::write` and `audit::write_owned`
  signatures are unchanged — all 90+ call sites continue to
  work without modification.

- **`crates/worker/src/audit.rs` internals rewritten** to use
  the new D1-backed repository. The `EventKind` enum, `Event`
  struct, `write`, and `write_owned` functions all have the
  same signatures and semantics as v0.31.x; only the
  underlying storage changed. `EventKind` gained a public
  `as_str()` method that returns the snake_case discriminant
  string (used as the `kind` column value).

- **`CloudflareAuditQuerySource` rewritten** to query D1
  instead of walking R2. The admin-search code path goes from
  N+1 (one R2 list + N R2 GETs) to a single D1 SELECT. The
  `AuditQuery.prefix` field is preserved as the trait shape
  for backward compatibility but the v0.32.0 D1 backend
  ignores it (use `since`/`until` filters via the search form
  instead). `AdminAuditEntry.key` now contains `seq=N`
  (formatted) rather than an R2 object path; the UI renders
  it verbatim.

- **`r2_metrics` removed** from
  `cesauth-adapter-cloudflare::admin::metrics`. The
  `ServiceId::R2` arm in `snapshot()` returns an empty metric
  list with an explanatory comment. `D1_COUNTED_TABLES`
  gained `audit_events`, so the row count for the audit table
  shows up under `ServiceId::D1` as
  `row_count.audit_events`.

- **`/__dev/audit` route rewritten** to query D1. Query
  parameters now: `kind`, `subject`, `since`, `until`,
  `limit` (capped at 100), `body=1`. Default response is the
  indexed-fields summary; `body=1` includes the full payload
  plus chain metadata (`payload_hash`, `previous_hash`,
  `chain_hash`).

- **`AdminAuditEntry.key` field documentation updated** to
  reflect the v0.32.0 meaning (chain sequence number rather
  than R2 object path). The struct shape is unchanged so
  `cesauth_ui::admin::audit` continues to render it as before.

### Changed (breaking — deployment)

- **`wrangler.toml` removed `[[r2_buckets]] AUDIT`** binding.
  Existing deployments that left the binding in their own
  `wrangler.toml` continue to deploy; cesauth simply doesn't
  reference the binding any more. Removing it is a one-line
  cleanup. The R2 `cesauth-audit` bucket itself remains on
  the operator's Cloudflare account; cesauth does not touch
  it.

- **No migration of historical R2 audit data**. Operators
  upgrading from v0.31.x retain the R2 bucket; if they need
  continuity over the cutover they must export R2 events with
  their own tooling before deploying v0.32.0. This is by
  design (Q2-c during planning) — the chain starts fresh at
  the genesis row inserted by migration 0008.

### Documentation

- New `docs/src/expert/audit-log-hash-chain.md` (operator
  chapter).
- New `docs/src/expert/adr/010-audit-log-hash-chain.md` (ADR,
  Draft).
- `docs/src/SUMMARY.md` and `docs/src/expert/adr/README.md`
  index updated.
- `docs/src/expert/storage.md` "Why R2 for audit" subsection
  rewritten to "Audit lives in D1 with a hash chain".
- `docs/src/deployment/production.md` step 1 drops the
  `cesauth-audit-prod` bucket creation; step 9 monitor list
  drops the R2-audit-bucket-grows note in favor of D1
  `row_count.audit_events`.
- `docs/src/deployment/preflight.md` drops the audit bucket
  preflight item and the R2 audit lifecycle item; updates the
  billing-alert tip to mention D1 row growth.
- `docs/src/deployment/backup-restore.md` rewritten to
  describe audit as part of the D1 backup story; the explicit
  "R2 audit" backup section is replaced with a note that
  audit travels in the D1 dump and the chain hashes survive
  re-import intact.
- `docs/src/deployment/wrangler.md` bindings table drops the
  `AUDIT` row and updates the prose example.
- `docs/src/deployment/data-migration.md` clarifies that
  v0.32.0+ audit events DO travel in dumps with chain
  intact.
- `docs/src/deployment/cron-triggers.md` future-work list
  swaps "R2 audit lifecycle" for "audit chain verification
  (Phase 2 of ADR-010)".
- `docs/src/deployment/environments.md` drops staging audit
  bucket binding from the example wrangler config and
  rephrases the per-env audit isolation note.
- `docs/src/expert/logging.md` "Not audit" framing updated to
  point at D1 instead of R2.
- `docs/src/expert/adr/005-data-migration-tooling.md` notes
  that v0.32.0+ audit IS in the dump (chain travels intact).
- Module-level rustdocs at `crates/adapter-cloudflare/src/ports.rs`
  and `crates/core/src/migrate.rs` updated.

- **Project-status framing softened across the project.**
  Removed "pre-1.0", "production-ready", and "Status: pre-1.0"
  badge/copy from `README.md`, `CHANGELOG.md`, `ROADMAP.md`,
  `TERMS_OF_USE.md`, `docs/src/introduction.md`, and
  `docs/src/expert/tenancy.md`. The new framing is "in active
  development" without making maturity claims either way.
  Operational-language uses of "production deployment" (as
  in "before any production deploy, do X") are preserved
  unchanged — those are descriptions of the deployment
  environment, not status claims.

### Tests

678 → 717 (+39).

- core: 275 → 300 (+25). All in `audit::chain::tests`:
  determinism, output shape (64 lowercase hex), 6 sensitivity
  tests (one per chain-input field), 2 separator-integrity
  tests pinning that `seq:ts` and `kind:id` boundaries can't
  be smuggled past the hash, reference vector pinning the
  v0.32.0 chain layout, verify-chain-link / verify-payload-hash
  positive and negative cases, genesis sentinel correctness,
  constant_time_eq corner cases.
- adapter-test: 72 → 86 (+14). All in `audit::tests`: empty
  repo first-append starts at seq=1, with-genesis variant
  starts user events at seq=2, three-append chain integrity
  with full hash recomputation, rows-in-seq-order invariant,
  tail behavior across all population states, search filter
  per-criterion (kind / subject / time / limit) plus combined
  AND filter, default newest-first ordering, no-match returns
  empty.
- ui, worker, do, migrate: unchanged (183, 119, 16, 13). The
  worker's `audit::write` is signature-compatible so existing
  tests pass without modification.

### Migration notes

Apply the new schema migration:

```sh
wrangler d1 migrations apply cesauth-prod
# applies 0008_audit_chain.sql
```

After deploy:

- The `audit_events` table exists with the genesis row at
  `seq=1`.
- All new audit events flow into D1 with chain extension.
- The R2 `AUDIT` bucket no longer receives writes.
- The `wrangler.toml` example dropped the `AUDIT` binding;
  operators can leave their own copy unchanged or delete the
  three-line block.

If `wrangler d1 migrations apply` fails part-way through (the
genesis-row INSERT in particular), rerun — the migration is
idempotent only at the schema level, but the genesis row uses
`seq=1` explicitly so a duplicate-key error from a re-run is a
benign signal that the migration already completed.

### Forward roadmap

- **v0.31.1** — TOTP handler integration tests (deferred from
  v0.31.0 per plan v2 §6.4). Approach 2 from the v0.32.0
  planning discussion: refactor handler decision logic into
  pure helpers, exercise via `cesauth-adapter-test`. Breaking
  internal-refactor changes are explicitly OK.
- **v0.33.0** — ADR-010 Phase 2: chain verification cron + admin
  verification UI + chain-head checkpoints. ADR-010 graduates
  to Accepted at the end of this release.

---

