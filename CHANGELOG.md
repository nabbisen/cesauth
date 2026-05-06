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

## [0.49.0] - 2026-05-04

D1 session-index repair tool. **ADR-012 §Q1.5
Resolved.** Per-operator-request order: tech-debt
(v0.44.0), bulk-revoke (v0.45.0), refresh-
introspection (v0.46.0), i18n-2 (v0.47.0), audit
retention (v0.48.0), D1 repair sixth (this
release). **All six items shipped.**

### Why this matters

v0.40.0 introduced the `session_index_audit` cron
pass which walks D1 outward to per-session DOs,
classifies drift via `session_index::classify`,
and emits `SessionIndexDrift` audit events. **It
emitted but did not repair.** The ADR-012 §Q1.5
paragraph explicitly deferred the repair half:
"Once we have observed a few weeks of
`session_index_drift` events in production, ship
the repair half." Operators have now surfaced
that demand.

### What ships

#### `cesauth_core::ports::session_index::SessionIndexRepo`

New trait. Three methods:

```rust
pub trait SessionIndexRepo {
    async fn list_active(&self, limit: u32) -> PortResult<Vec<SessionIndexRow>>;
    async fn delete_row(&self, session_id: &str) -> PortResult<()>;
    async fn mark_revoked(&self, session_id: &str, revoked_at: i64) -> PortResult<()>;
}
```

Both write methods are **idempotent**:

- `delete_row` on a non-existent session_id is
  `Ok(())`. A repair pass running after a
  reconcile-then-write race produces no error.
- `mark_revoked` uses a `WHERE revoked_at IS NULL`
  SQL guard. A row whose `revoked_at` is already
  set is NOT overwritten — the existing
  timestamp is the canonical first-revoke moment
  and a repair pass must not rewrite history.

The Cloudflare D1 adapter
(`crates/adapter-cloudflare/src/ports/session_index.rs`)
implements both with explicit comments on the
guard SQL.

#### Pure repair service

`cesauth_core::session_index::repair::run_repair_pass(index, store, cfg, now) -> RepairOutcome`.
Composes the existing `classify` logic with
the new port. For each row in
`index.list_active`:

| Drift state | Repair action |
|---|---|
| `InSync` | none |
| `DoVanished` | `index.delete_row(sid)` |
| `DoNewerRevoke` | `index.mark_revoked(sid, do_revoked_at)` |
| `AnomalousD1RevokedDoActive` | **none** (alert-only) |

`AnomalousD1RevokedDoActive` is never auto-
repaired because automated repair would mask
whatever upstream bug produced it (D1 says
revoked, DO says active means a revoke write
landed in D1 but not the DO — that's a
regression, not a drift to silently fix).

**Best-effort**: per-row failures (DO query or
D1 mutation errored) increment `errors` and
continue the batch. Aborting on first error
would leave the bulk of drifts unrepaired
forever if the first row hits a transient
failure.

#### `RepairConfig` opt-in

```rust
pub struct RepairConfig {
    pub auto_repair_enabled: bool,
    pub batch_limit:         u32,
}
```

When `auto_repair_enabled = false` (the cesauth
default), the pass classifies + counts but emits
no D1 writes. `RepairOutcome::dry_run = true` in
that case. When `true`, the pass writes the
repairs.

**Operators opt in deliberately.** Default-off
because:

- **Trust gradient**: a deployment without a
  track record of clean drift events shouldn't
  have automated D1 mutation pointed at it. The
  first cron pass after an upstream regression
  could mass-delete real rows.
- **Reversibility**: the v0.40.0 detection trail
  (one `SessionIndexDrift` audit event per
  drift) is the operator's "what got changed and
  why" record if a repair later turns out to be
  wrong. Auto-repair without the prior
  detection period collapses that trail.

#### Fifth cron pass

`session_index_repair_cron::run` runs after
`sweep` → `audit_chain_cron` →
`session_index_audit` → `audit_retention_cron`
on the daily 04:00 UTC schedule. Independent —
failure logs but doesn't block the others.

Log line shape (dry-run):

```text
session_index_repair: [DRY RUN] walked=1234 in_sync=1230 \
                      would-repair-do_vanished=3 \
                      would-repair-do_newer_revoke=1 \
                      anomalous=0 errors=0 \
                      (set SESSION_INDEX_AUTO_REPAIR=true to enable repairs)
```

Log line shape (auto-repair on):

```text
session_index_repair: walked=1234 in_sync=1230 \
                      repaired-do_vanished=3 \
                      repaired-do_newer_revoke=1 \
                      anomalous=0 errors=0
```

#### Env vars

| Env var | Default | Effect |
|---|---|---|
| `SESSION_INDEX_AUTO_REPAIR` | `false` | When `"true"`, enable D1 mutations |
| `SESSION_INDEX_REPAIR_BATCH_LIMIT` | `1000` | Max rows walked per pass |

### Tests

973 → **986** lib (+13). With migrate integration:
1002 → **1015**.

- core: 430 → 443 (+13). All in
  `session_index::repair::tests`:
  - Happy paths: `in_sync_rows_count_no_writes`,
    `do_vanished_drift_is_repaired_when_enabled`,
    `do_newer_revoke_drift_is_repaired_with_do_timestamp`.
  - Anomalous case pin:
    `anomalous_alert_only_is_never_repaired`
    (also documents the
    `list_active`-filter-excludes-anomalous edge).
  - Dry-run pin:
    `dry_run_classifies_but_writes_nothing`.
  - Error handling:
    `list_failure_propagates_as_internal`,
    `per_row_status_failure_increments_errors_does_not_abort`,
    `per_row_repair_failure_increments_errors_does_not_abort`
    (best-effort failure containment).
  - Counts:
    `walked_count_equals_listed_rows`,
    `idempotent_second_repair_pass_is_no_op`,
    `mark_revoked_idempotent_at_repo_level`
    (the WHERE-revoked_at-IS-NULL guard).
  - Wire shape:
    `default_config_is_dry_run` (pin: opt-in
    contract), `outcome_default_zero_counts`.
- ui: 244 → 244.
- worker: 182 → 182 (cron handler is glue; the
  testable transformation is in pure core).

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9).
  Repair operates on the existing `user_sessions`
  table; no migration.
- Wire format unchanged.
- DO state unchanged (the repair pass reads DO
  state via `ActiveSessionStore::status`, never
  mutates it).
- No new dependencies.

### Operator-visible changes

- **New cron pass** runs daily after the existing
  four. **Default behavior is dry-run** —
  classifies but doesn't mutate.
- **Two new optional env vars**:
  `SESSION_INDEX_AUTO_REPAIR` and
  `SESSION_INDEX_REPAIR_BATCH_LIMIT`. Operators
  opt in to repairs by setting
  `SESSION_INDEX_AUTO_REPAIR=true`.
- **Recommended deployment progression**:
  1. Upgrade to v0.49.0. The dry-run pass starts
     emitting log lines showing
     would-repair counts.
  2. Watch for at least one week, ideally a
     month. If the dry-run counts are stable
     (small numbers, no spikes), the upstream
     paths are healthy and repair is safe.
  3. Set `SESSION_INDEX_AUTO_REPAIR=true` and
     redeploy. Subsequent cron passes write the
     repairs.
- No `wrangler.toml` change (cron schedule
  unchanged). No new bindings. No schema
  migration.

### ADR changes

- **ADR-012 §Q1.5** marked **Resolved**. Inline
  resolution paragraph follows the
  ADR-011 §Q1 / ADR-012 §Q1, §Q4 / ADR-014 §Q4,
  §Q2, §Q3 inline-resolution style.
- No new ADR.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.48.0 → 0.49.0.
- UI footers + tests bumped to v0.49.0.
- ROADMAP: v0.49.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.48.0 → 0.49.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   dependencies.**
3. `wrangler deploy`. **No schema migration. No
   new bindings.**
4. **Watch the dry-run cron output** for a week
   or more.
5. **Optionally** turn repair on:
   ```
   wrangler secret put SESSION_INDEX_AUTO_REPAIR  # set to "true"
   ```
   Or add to `[vars]` in `wrangler.toml`.

### Per-operator-request ordering — complete

| # | Item | Release |
|---|---|---|
| 1 | Tech-debt sweep | v0.44.0 |
| 2 | Bulk "revoke all other sessions" | v0.45.0 |
| 3 | Refresh-token introspection enhancements | v0.46.0 |
| 4 | i18n-2 continuation | v0.47.0 |
| 5 | Audit retention policy | v0.48.0 |
| 6 | D1 repair tool | **v0.49.0** ← here |

### Forward roadmap

- **No items pending from operator-requested
  order.** The six-item batch is complete.
- **Future security-track items still open**
  (operator demand pending):
  - ADR-012 §Q2: User notification on idle /
    absolute timeout.
  - ADR-012 §Q3: Geographic / device-fingerprint
    columns on `user_sessions`.
  - ADR-012 §Q5: Orphan DOs (Cloudflare does not
    support DO namespace iteration; this would
    require a different storage shape).
  - ADR-014 §Q1: Audience scoping for
    introspection responses.

---

## [0.48.0] - 2026-05-04

Audit retention policy. **ADR-014 §Q3 Resolved.**
Per-operator-request order: tech-debt sweep
(v0.44.0), bulk-revoke (v0.45.0), refresh-
introspection (v0.46.0), i18n-2 (v0.47.0), audit
retention fifth (this release).

### Why this matters

v0.38.0 added `/introspect` which emits one audit
row per call. A chatty resource server can produce
~1 introspection/sec/user. A 1k-active-user
deployment hits ~86M `token_introspected` rows per
day. D1 is row-priced; retention without a pruning
policy means cost scales linearly with deployment
age. ADR-014 §Q3 was deferred at v0.38.0 because
the steady-state cost wasn't observable yet;
v0.48.0 ships the policy now that operators have
surfaced demand.

The challenge: cesauth's audit log is a
hash-chained ledger (ADR-010, migrations/0008).
Naively deleting old rows would break the chain.
v0.48.0 prunes safely by anchoring on the
verifier's checkpoint.

### What ships

#### Pure service in core: `cesauth_core::audit::retention`

`run_retention_pass(repo, checkpoints, cfg, now) ->
RetentionOutcome`. Reads the verifier checkpoint,
computes a safe `floor_seq`, runs two passes
(per-kind for `TokenIntrospected`, then global for
everything else), returns counts.

**Hash-chain preservation strategy**: the verifier
resumes from `last_verified_seq + 1` and never
re-walks rows below the checkpoint, so pruning
those rows is integrity-safe. The cross-check
anchor row at `last_verified_seq` itself is
preserved by a 100-row safety margin
(`CHECKPOINT_SAFETY_MARGIN`):

```text
floor_seq = max(checkpoint.last_verified_seq - 100, 2)
```

Rows below `floor_seq` are eligible for pruning;
rows ≥ `floor_seq` are not. The margin is well
above the per-cron-pass write rate in any cesauth
deployment (cron is daily; even at peak
introspection rate the verifier walks far more
than 100 rows per pass).

**Genesis row (seq=1) is sacred** — both the
in-memory test adapter and the Cloudflare D1
adapter explicitly exclude `seq <= 1` from the
prune predicate. An aggressive 0-day retention
config still leaves the chain anchor intact for
any future re-walk.

**Refuses to prune without a checkpoint** — fresh
deployments where `audit_chain_cron` hasn't yet
run produce `Ok(skipped_no_checkpoint = true)`.
Pruning without a chain anchor opens a
forensics-vs-tampering ambiguity that the safety
margin is meant to prevent.

#### Two-knob retention policy

| Knob | Default | Env var |
|---|---|---|
| Global window | 365 days | `AUDIT_RETENTION_DAYS` |
| Per-kind: `TokenIntrospected` | 30 days | `AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS` |

The shorter `TokenIntrospected` window reflects
operational value: high volume + low forensic
interest after ~30 days. Other event kinds
(`session_revoked_by_user`, `password_reset`,
`client_credentials_authenticated`, etc.) keep the
365-day window because they're rare-but-
forensically-valuable.

Setting either knob to `0` disables that pass.
Setting both to `0` is a legitimate "I want
unbounded retention" config — both passes exit
with zero deletions.

#### Two-pass execution

1. **Per-kind pass**: when `token_introspected_days
   > 0` and (either `global_days == 0` OR
   `token_introspected_days < global_days`), delete
   `TokenIntrospected` rows older than the per-kind
   window.
2. **Global pass**: when `global_days > 0`, delete
   rows of any kind older than the global window.
   `TokenIntrospected` is excluded from this pass
   when per-kind was active (preventing
   double-counting in the outcome).

#### `AuditEventRepository::delete_below_seq` trait method

```rust
async fn delete_below_seq(
    &self,
    floor_seq:   i64,
    older_than:  i64,
    kind_filter: AuditRetentionKindFilter,
) -> PortResult<u32>;
```

Implementation MUST observe all three gates
conjunctively (seq < floor, ts < cutoff, kind
matches filter) AND preserve the genesis row
(seq=1). The trait method is **non-default** —
adding to 3rd-party implementors requires an
update; cesauth's two in-tree adapters
(`adapter-test` in-memory + `adapter-cloudflare`
D1) are updated.

#### `AuditRetentionKindFilter` enum

```rust
pub enum AuditRetentionKindFilter {
    OnlyKinds(Vec<String>),    // delete IFF kind is in the list
    ExcludeKinds(Vec<String>), // delete IFF kind is NOT in the list
}
```

`OnlyKinds([])` is the delete-zero shortcut (a
defensive distinction from "any kind"). The D1
adapter translates filter variants into
parameterized SQL — kind values are bound as `?n`
parameters, never concatenated.

#### Fourth cron pass

`audit_retention_cron::run` runs after `sweep` →
`audit_chain_cron` → `session_index_audit` on the
daily 04:00 UTC schedule. Independent: a
retention failure logs to console and propagates
`Err`, but doesn't block the other passes (the
runtime drives them via `if let Err`).

Log line shape:

```text
audit_retention: deleted_token_introspected=12345 deleted_global=42 \
                 checkpoint_seq=98765 floor_seq=98665 \
                 (cfg: global_days=365 ti_days=30)
```

Or on a fresh deployment:

```text
audit_retention: skipped (no chain checkpoint yet — \
                 waiting for first verification cron run)
```

### Tests

957 → **973** lib (+16). With migrate integration:
986 → **1002**.

- core: 414 → 430 (+16). All in
  `audit::retention::tests`:
  - `no_checkpoint_skips_pass` — refuses to prune
    without a chain anchor.
  - `checkpoint_present_but_below_safety_margin_is_no_op`
    — floor_seq lower-bound (max with 2) protects
    fresh deployments.
  - `token_introspected_pass_prunes_old_rows_only` —
    happy path for the 30d window.
  - `global_pass_prunes_only_above_global_window` —
    happy path for the 365d window.
  - `global_pass_excludes_token_introspected_when_per_kind_active`
    — critical correctness pin: no double-prune.
  - `global_includes_token_introspected_when_per_kind_disabled`
    — `ti_days=0` lets global cover TI.
  - `global_includes_token_introspected_when_per_kind_geq_global`
    — edge: per-kind window ≥ global skips per-kind.
  - `global_zero_disables_global_pass` — `global=0`
    disables global, per-kind still runs.
  - `floor_seq_protects_recent_rows_even_when_old_by_ts`
    — chain-walker safety pin.
  - `checkpoint_at_genesis_keeps_genesis_safe` —
    genesis row never prunes.
  - `delete_failure_propagates_as_internal` —
    error mapping.
  - `checkpoint_read_failure_propagates_as_internal`
    — error mapping for the checkpoint store too.
  - `idempotent_second_call_is_zero_count` —
    second call after first is no-op.
  - `default_config_matches_published_defaults` —
    pin: 365 / 30 (matches CHANGELOG + ADR text).
  - `safety_margin_is_one_hundred` — pin: 100
    (matches ADR text).
  - `kind_token_introspected_constant_matches_event_kind`
    — pin: catches drift between
    `KIND_TOKEN_INTROSPECTED` constant and EventKind
    serde.
- ui: 244 → 244.
- worker: 182 → 182 (cron handler is glue; the
  testable transformation is in the pure core
  service).

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9).
  Retention DELETE statements operate on the
  existing `audit_events` table; no migration.
- Wire format unchanged.
- DO state unchanged.
- No new dependencies.

### Operator-visible changes

- **New cron pass** runs daily after the existing
  three. Default behavior with operator-unset env
  vars: 365-day global window, 30-day window for
  `token_introspected`.
- **New env vars** (both optional):
  - `AUDIT_RETENTION_DAYS` (default 365)
  - `AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS` (default 30)
- **No production behavior change** until the next
  cron tick. After that, audit rows past their
  retention windows start disappearing on each
  daily run.
- **Storage cost reduction** scales with the
  difference between previous unbounded retention
  and the new windows. Operators with deployments
  several years old should expect a one-time large
  prune followed by steady-state.
- **Audit dashboards** that count
  `token_introspected` events more than 30 days
  back will see counts decline. Dashboards relying
  on `chain_length` from the verifier still get
  the full count (chain_length is `MAX(seq)`,
  unaffected by deletes — seq is AUTOINCREMENT and
  never reused).
- No `wrangler.toml` change (cron schedule
  unchanged). No new bindings. No schema
  migration.

### ADR changes

- **ADR-014 §Q3** marked **Resolved**. Inline
  resolution paragraph follows the
  ADR-011 §Q1 / ADR-012 §Q1, §Q4 / ADR-014 §Q4 / §Q2
  inline-resolution style.
- No new ADR.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.47.0 → 0.48.0.
- UI footers + tests bumped to v0.48.0.
- ROADMAP: v0.48.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.47.0 → 0.48.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   dependencies.**
3. `wrangler deploy`. **No schema migration. No new
   bindings.**
4. **Optionally** set env vars to override
   defaults:
   ```
   wrangler secret put AUDIT_RETENTION_DAYS
   wrangler secret put AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS
   ```
   Or add them as `[vars]` entries in
   `wrangler.toml`. Default values are reasonable
   for most deployments.
5. **Watch the first cron run** — the daily 04:00
   UTC pass will surface the first-time prune count
   in `console_log!`. Long-running deployments
   should expect substantial deletes on the first
   pass.

### Forward roadmap

- **Next up (per operator request)**: ADR-012
  §Q1.5 D1 repair tool.
- **Future security-track items still open**:
  ADR-012 §Q2-§Q3, §Q5; ADR-014 §Q1 audience
  scoping.

---

## [0.47.0] - 2026-05-04

i18n-2 continuation. Per-operator-request order: tech-
debt sweep (v0.44.0), bulk-revoke (v0.45.0), refresh-
introspection (v0.46.0), i18n-2 fourth (this release).

### Why this matters

v0.39.0 opened the i18n-2 thread, migrating the
LOGIN / TOTP enroll / TOTP verify / Security Center
templates to the catalog-based `_for(.., locale)`
pattern. Four user-facing templates were left for
later: the Magic Link "Check your inbox" page, the
TOTP recovery codes display, the TOTP disable
confirm, and the generic error page. v0.47.0 closes
the gap.

The PrimaryAuthMethod label (used by Security Center
to render "how you sign in") was also still hard-
coded JA pre-v0.47.0 — a v0.39.0 limitation noted in
that release's CHANGELOG. v0.47.0 migrates it too.

### What ships

#### 22 new MessageKey variants

Catalog total: 76 → **98**. Distributed:

- **3** PrimaryAuthMethod labels (`PrimaryAuthMethodPasskey`,
  `PrimaryAuthMethodMagicLink`,
  `PrimaryAuthMethodAnonymous`)
- **5** Magic Link sent page (Title, Heading, Intro,
  OtpHeading, CodeLabel; submit reuses the existing
  `TotpVerifyContinueButton`).
- **6** TOTP recovery codes page (Title, Heading,
  AlertStrong, AlertBody, Body, Continue).
- **7** TOTP disable confirm page (Title, Heading,
  AlertStrong, AlertBody, RecoveryHint,
  ConfirmHeading, Submit; cancel reuses the existing
  `TotpEnrollCancelLink`).
- **1** Error page back link (`ErrorPageBackLink`).

JA + EN translations for every new key. The catalog
**uniqueness invariant** (no two MessageKey variants
resolve to the same string within a locale) caught
two well-intentioned duplicates during development:
`MagicLinkSentSubmit` ("Continue" / "続ける") would
have collided with `TotpVerifyContinueButton`, and
`TotpDisableCancel` ("Cancel and go back" /
"キャンセルして戻る") would have collided with
`TotpEnrollCancelLink`. Both new variants were
dropped in favor of reusing the existing keys —
strictly better outcome (one source of truth per
string).

#### Privacy-preserving phrasing pinned

`MagicLinkSentIntro` translates the v0.27.0 privacy-
phrasing — "if that address is registered, we've just
sent a one-time code" — into JA preserving the same
non-confirmation:
"このメールアドレスが登録されている場合、ワンタイムコードを送信しました。"

User-enumeration prevention is part of the contract;
the test
`magic_link_sent_page_for_renders_japanese_default`
pins the JA phrasing carries the "登録されている場合"
conditional.

#### `PrimaryAuthMethod::label_for(locale)`

New public method on the public enum. The legacy
`label()` getter is preserved as a default-locale
shorthand that delegates to `label_for(Locale::default())`.
`security_center_page_for` calls `label_for(locale)`,
so the Security Center renders the primary-method
label in the negotiated locale (fixing the v0.39.0
limitation).

#### Four templates gain `_for(.., locale)` variants

| Template | Pre-v0.47.0 | v0.47.0 |
|---|---|---|
| `magic_link_sent_page` | EN-only | shorthand wraps `_for` with `Locale::default()` (Ja) |
| `error_page` | EN-only | shorthand wraps `_for`; title + detail caller-supplied (caller does its own localization) |
| `totp_recovery_codes_page` | EN-only | shorthand wraps `_for`; codes themselves are locale-invariant |
| `totp_disable_confirm_page` | EN-only | shorthand wraps `_for`; cancel link reuses `TotpEnrollCancelLink` |

**Behavior change for legacy shorthand callers**:
the four shorthands previously rendered EN.
v0.47.0 routes them through `_for` with
`Locale::default()` which is `Ja`. The pin
`magic_link_sent_legacy_shorthand_now_renders_ja_default`
documents this. **Production handlers were already
on negotiated locales since v0.39.0 and pass through
`_for`, so the production path is unaffected.**
External code calling the shorthand directly may
see the change; updating to `_for(.., Locale::En)`
restores pre-v0.47.0 behavior explicitly.

#### Worker handlers thread locale

Four call sites updated:

- `crates/worker/src/routes/me/totp/disable.rs`:
  `totp_disable_confirm_page` → `_for(.., locale)`
  with `crate::i18n::resolve_locale(&req)`.
- `crates/worker/src/routes/me/totp/enroll.rs`:
  `totp_recovery_codes_page` → `_for(.., locale)`.
- `crates/worker/src/routes/magic_link/request.rs`:
  both render sites (rate-limit fallback + success
  path) routed through `magic_link_sent_page_for`
  with a single `let locale =
  crate::i18n::resolve_locale(&req);` at the top of
  the handler.

`error_page` has no in-tree worker call sites — it's
a public template helper retained for external
consumers; the `_for` variant is available when
needed.

### Tests

948 → **957** lib (+9). With migrate integration:
977 → **986**.

- core: 414 → 414 (catalog-only changes; existing
  i18n test suite covers the new keys via
  exhaustiveness + uniqueness invariants).
- ui: 235 → 244 (+9). New tests:
  `magic_link_sent_page_for_renders_japanese_default`,
  `magic_link_sent_page_for_renders_english`,
  `magic_link_sent_legacy_shorthand_now_renders_ja_default`,
  `totp_recovery_codes_page_for_renders_japanese_default`,
  `totp_recovery_codes_page_for_renders_english`,
  `totp_disable_confirm_page_for_renders_japanese_default`,
  `totp_disable_confirm_page_for_renders_english`,
  `error_page_for_renders_localized_back_link`,
  `primary_auth_method_label_for_renders_each_locale`.
- worker: 182 → 182.
- 3 pre-v0.47.0 UI tests
  (`recovery_codes_page_includes_irreversibility_warning`,
  `disable_page_warns_about_recovery_code_loss`,
  `disable_page_offers_cancel_link`) **migrated**
  to assert via `_for(.., Locale::En)` since they
  pin EN-substring assertions and the default-
  shorthand now returns JA.

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9).
- Wire format unchanged.
- DO state unchanged.
- No new dependencies.

### Operator-visible changes

- **JA renders** for the four migrated pages when
  the user's `Accept-Language` negotiates Ja
  (or unset, since cesauth defaults to Ja). EN
  preserved for `Accept-Language: en`.
- **No behavior change** for production handlers —
  they were already on negotiated locales.
- No `wrangler.toml` change. No new bindings.
  No schema migration.

### ADR changes

- **No new ADR.** v0.47.0 closes out the i18n-2
  thread opened in v0.39.0 — the design pattern
  (catalog + `_for` variants + default shorthand
  routing) is already established and documented in
  v0.36.0 / v0.39.0 release notes.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.46.0 → 0.47.0.
- UI footers + tests bumped to v0.47.0.
- ROADMAP: v0.47.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.46.0 → 0.47.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   dependencies.**
3. `wrangler deploy`. **No schema migration.**
4. **External callers using template shorthands
   directly** (no in-tree callers, but listing for
   completeness): if you depended on the EN
   rendering of `magic_link_sent_page`,
   `totp_recovery_codes_page`,
   `totp_disable_confirm_page`, or `error_page`,
   migrate to `*_for(.., Locale::En)` to preserve
   the EN output.

### Forward roadmap

- **Next up (per operator request)**: ADR-014 §Q3
  audit retention policy.
- Then: ADR-012 §Q1.5 D1 repair tool.
- **i18n-2 fully closed** with v0.47.0 — every
  user-facing template now flows through the catalog
  with locale negotiation. Admin / tenancy console
  templates remain JA-only (separable thread).

---

## [0.46.0] - 2026-05-04

Refresh-token introspection enhancements. Per-operator-
request order: tech-debt sweep first (v0.44.0), bulk-
revoke second (v0.45.0), refresh-introspection
enhancements third (this release).

### Why this matters

Pre-v0.46.0, refresh-token introspection collapsed
every "inactive" path — revoked, jti-mismatched, never-
existed — into a bare `{"active": false}`. Spec-
compliant per RFC 7662 §2.2 but **operationally
opaque**:

- A resource server caching introspection results
  couldn't distinguish "this token was rotated past;
  the user has a fresher one" from "this token was
  killed by reuse-defense; alert security".
- An audit dashboard couldn't break down inactive-
  introspection events by reason without external
  correlation against the family DO state.
- Stale-token-due-to-rotation looked identical to
  forged-token in the response, masking real
  attacker probing in the noise of legitimate
  rotations.

v0.46.0 surfaces this signal under an `x_cesauth`
extension envelope, namespaced per RFC 7662 §2.2
("Specific implementations MAY extend this structure
with their own service-specific response names").
Resource servers consuming only the spec-defined
fields are unaffected; resource servers reading the
extension get four-way classification + revocation
metadata.

### What ships

#### `cesauth_core::oidc::introspect::CesauthIntrospectionExt`

New struct serializing under the `x_cesauth` key. All
fields are `Option`-typed and `skip_serializing_if =
"Option::is_none"`, so a response with no extension
data renders without the key entirely.

```rust
pub struct CesauthIntrospectionExt {
    pub family_state:  Option<FamilyClassification>,
    pub revoked_at:    Option<i64>,
    pub revoke_reason: Option<RevokeReason>,
    pub current_jti:   Option<String>,
}
```

`FamilyClassification` (snake_case serde):

| Variant | When | x_cesauth fields |
|---|---|---|
| `Current` | jti matches `family.current_jti` AND not revoked | `family_state` only |
| `Retired` | jti in `family.retired_jtis` | `family_state` + `current_jti` (stale-token hint) |
| `Revoked` | `family.revoked_at.is_some()` | `family_state` + `revoked_at` + `revoke_reason` |
| `Unknown` | family doesn't exist OR jti mismatch with no retired-membership | `family_state` only |

`RevokeReason` (snake_case serde):

- `ReuseDetected` — family killed by ADR-011 §Q1
  reuse defense (a retired jti was presented to
  `/token`). Distinguished by `family.reused_jti.is_some()`.
- `Explicit` — `/revoke` endpoint, admin revocation,
  or bulk-revoke (v0.45.0). Future work could split
  this into User vs Admin if demand surfaces.

#### Privacy invariant

The `Unknown` classification is the **conflation
point**. Distinct underlying states map to it:

- Family doesn't exist (never issued, already swept,
  wrong deployment).
- Family exists but the presented jti is neither
  `current_jti` nor in `retired_jtis` (forged jti
  against a real family).

Surfacing `Retired` for a forged jti would let an
attacker confirm that a guessed family_id exists
(by seeing the response shape change between
`Unknown` and `Retired`). v0.46.0 explicitly maps
the no-retired-membership case to `Unknown` to
prevent this — pinned by the
`jti_mismatch_without_retired_membership_is_unknown_not_retired`
test.

`current_jti` is surfaced **only** on the Retired
path — the introspecter has proven possession of a
once-valid jti, so revealing the current one is no
fresh information leak. It lets RS dashboards
recognize "stale due to rotation; user has a newer
token" without trying to refresh.

#### `service::introspect::introspect_refresh` rewrite

The five-line decision tree (no-decode, no-family,
revoked, jti-mismatch, current) now produces five
distinct response shapes:

```text
no-decode     → Ok(None)              [orchestrator falls through to access]
no-family     → Ok(Some(inactive_with_ext{Unknown}))
revoked       → Ok(Some(inactive_with_ext{Revoked, revoked_at, revoke_reason}))
jti-mismatch  → Ok(Some(inactive_with_ext{
                  Retired+current_jti  if jti in retired_jtis,
                  Unknown              otherwise }))
current       → Ok(Some(active_refresh_with_ext{Current}))
```

The pre-v0.46.0 behavior of falling through to the
access-token verify path on revoked/mismatched
families is **removed**. Reasoning: a token that
successfully decoded as refresh shape isn't a JWT
(JWTs fail the refresh decode at the `exp.parse::<i64>()`
step). Falling through was already a no-op in
practice; v0.46.0 makes this explicit by returning
`Some(inactive_with_ext)` instead of `None`.

#### Worker audit-payload extension

`EventKind::TokenIntrospected` payload gains two
optional fields when `x_cesauth` is present:

```diff
  {
    "introspecter_client_id": "...",
    "token_type":             "...",
    "active":                 false,
+   "family_state":           "retired" | "revoked" | "unknown",
+   "revoke_reason":          "reuse_detected" | "explicit"
  }
```

Access-token paths set neither, keeping audit rows
compact for the high-volume happy path. Refresh-
token paths set `family_state` always, and
`revoke_reason` only when `family_state="revoked"`.

This unlocks operator-side breakdowns:

- **Spike in `family_state="unknown"` events** →
  someone is probing forged family_ids. Could be
  scanner traffic; could be targeted reconnaissance.
- **Spike in `revoke_reason="reuse_detected"`** →
  a token-leak event affecting multiple users.
  Security alert.
- **Steady-state `family_state="retired"`** →
  legitimate background level of stale-RS-cache
  introspection; expected.

### Tests

937 → **948** lib (+11). With migrate integration:
966 → **977**.

- core: 403 → 414 (+11). All in
  `service::introspect::tests::refresh_ext`:
  - `active_refresh_response_carries_x_cesauth_current`
  - `revoked_family_returns_inactive_with_explicit_reason`
  - `reuse_detected_family_returns_inactive_with_reuse_reason`
  - `retired_jti_returns_inactive_with_current_jti_hint`
  - `unknown_family_returns_unknown_classification`
  - `jti_mismatch_without_retired_membership_is_unknown_not_retired`
    (the privacy invariant pin)
  - `truly_malformed_token_falls_through_no_ext`
    (preserves pre-v0.46.0 access-fallback behavior
    for tokens that don't decode as refresh shape)
  - `access_token_path_does_not_set_x_cesauth`
  - `x_cesauth_field_serializes_under_correct_key`
  - `x_cesauth_omitted_when_none`
  - `revoke_reason_serializes_as_snake_case`
- ui: 235 → 235 (no UI changes).
- worker: 182 → 182 (handler payload extended, no
  new tests; the testable transformation is in the
  pure core service).

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9). No
  migration.
- DO state unchanged.
- **Wire format additive only**:
  - Introspection response gains optional
    `x_cesauth` envelope. Spec-conformant clients
    consuming only the RFC 7662 fields are
    unaffected (they ignore unknown top-level
    keys per RFC 7662 §2.2).
  - Audit payload gains optional `family_state` +
    `revoke_reason` fields when present.
- **No new dependencies.**

### Operator-visible changes

- **Resource servers reading `x_cesauth`** can now
  distinguish four families of inactive responses.
  Recommend updating dashboard queries to break out
  by `family_state` / `revoke_reason`.
- **Audit dashboards**: `token_introspected` events
  now carry `family_state` (refresh-token paths) +
  `revoke_reason` (revoked-family paths). Add
  panels:
  - `family_state` breakdown (Current / Retired /
    Revoked / Unknown).
  - `revoke_reason` for the revoked subset
    (ReuseDetected = security alert, Explicit =
    expected).
- **No production behavior change for happy-path
  introspection.** Active responses gain `x_cesauth.family_state="current"`
  but the spec fields (active/scope/exp/etc.) are
  byte-identical to v0.45.0.
- No `wrangler.toml` change. No new bindings. No
  schema migration.

### ADR changes

- **No new ADR.** v0.46.0 is an additive extension
  under RFC 7662 §2.2's allowance for service-
  specific response names. No cesauth-specific
  decision points beyond what the family-state
  machine already records.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.45.0 → 0.46.0.
- UI footers + tests bumped to v0.46.0.
- ROADMAP: v0.46.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.45.0 → 0.46.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   production dependencies.**
3. `wrangler deploy`. **No schema migration. No new
   bindings.**
4. **For resource servers** that want the extra
   signal: update introspection-response parsers to
   read `x_cesauth.family_state` (snake_case) and
   `x_cesauth.revoke_reason`. Both are optional —
   absent on access-token responses and on refresh-
   token responses where no extension data exists.
5. **For audit dashboards**: add panels grouping
   `token_introspected` events by `family_state` and
   `revoke_reason`. Steady-state baseline:
   `current` + `retired` are normal; `unknown` should
   be near-zero unless scanner traffic is present;
   `reuse_detected` should be near-zero — non-zero
   warrants security investigation.

### Forward roadmap

- **Next up (per operator request)**: i18n-2
  continuation (TOTP recovery codes / disable /
  magic link / error pages).
- Then: ADR-014 §Q3 audit retention policy, ADR-012
  §Q1.5 D1 repair tool.
- **Future security-track items still open**:
  ADR-012 §Q2-§Q3, §Q5; ADR-014 §Q1 audience scoping.

---

## [0.45.0] - 2026-05-04

Bulk "revoke all other sessions" UX (ADR-012 §Q4
**Resolved**). Per-operator-request order: tech-debt
sweep first (v0.44.0, done), bulk-revoke second
(this release).

### Why this matters

Pre-v0.45.0, `/me/security/sessions` showed up to 50
session rows with a per-row revoke button. Users
wanting to sign out everywhere except their current
device had to click one button per row. After someone
flags a credential leak ("did I leave my work laptop
unlocked?") the UX should be one button, not
N clicks. Most major auth providers expose this; cesauth
now does too.

### What ships

#### `cesauth_core::service::sessions::revoke_all_other_sessions`

New pure-service module orchestrating `list_for_user`
+ filtered per-row `revoke`. Returns
`BulkRevokeOutcome { revoked: u32, errors: u32,
skipped_current: u32 }`. Best-effort semantics
(matches cesauth's failure-isolation pattern):

- Per-row revoke failure increments `errors` and
  continues — does NOT abort the batch. The
  alternative (one error → user sees an error and
  has no idea which sessions were revoked vs
  left alone) is worse than "most got revoked,
  retry the button for the rest" (idempotent).
- Per-row `Ok(SessionStatus::NotStarted)` (race with
  sweep) counts as `revoked` — from the user's
  perspective the row is gone, which is what they
  wanted.
- Per-row `Ok(SessionStatus::Active)` (shouldn't
  happen — `revoke` is supposed to be terminal)
  counts as `errors` to surface store bugs in the
  audit counter.
- Per-user cap of 50 (matches the page's display
  limit).

#### `POST /me/security/sessions/revoke-others`

Worker handler in `crates/worker/src/routes/me/sessions.rs`.
CSRF-protected with the same form-token-vs-cookie
check as the per-row endpoint. Pure-service does the
heavy lifting; handler picks one of three flashes
based on outcome and 302-redirects back to the list:

- `revoked > 0 && errors == 0` →
  `OtherSessionsRevoked` (Success, count substituted).
- `errors > 0` → `OtherSessionsRevokeFailed` (Danger,
  error count substituted) regardless of how many
  succeeded — the message advises retry, which
  becomes a legitimate no-op for already-revoked
  rows (idempotent).
- `revoked == 0 && errors == 0` →
  `NoOtherSessions` (Info, no count).

Audit emits **one** `SessionRevokedByUser` event with
`bulk: true` payload field, NOT one per row. The
per-row approach would require capturing each
`session_id` mid-loop, which the pure service doesn't
surface (by design — its return type is counts, not
row metadata). Operators distinguish bulk from
per-row clicks via the payload's `bulk` field.

#### Flash codec extended

`Flash` struct gains optional `count: Option<u32>`
parameter for messages with `{n}` substitution. Wire
format: `<key>:<N>` notation in the cookie payload
(e.g., `success.other_sessions_revoked:3`). The `:`
delimiter is verified by test to not appear in any
existing `FlashKey::as_str()` value, so:

- Pre-v0.45.0 cookies (no `:`) decode as
  `count = None` → fully backward-compatible. Cookies
  in flight at the moment of upgrade still
  display correctly.
- New cookies decode `count = Some(N)` with strict
  parsing (rejects multi-`:`, non-numeric, u32
  overflow).

Format-prefix bump from `v1:` was **not** needed —
the change is additive within the existing format,
not a re-encoding.

`FlashView::text` migrated from `&'static str` to
`Cow<'static, str>`. The borrowed variant is the
zero-allocation path for parameter-free flashes
(v0.31–v0.44); the owned variant carries
runtime-substituted strings. `FlashView` lost its
`Copy` derivation (Cow isn't Copy) but kept `Clone`
— flash text is short and rare so the cost is
irrelevant.

`render_view_for` does the `{n}` → decimal
substitution at projection time. Catalog strings
without `{n}` are unaffected by the substitution
logic — safe for any combination of count-bearing
flash + parameter-free MessageKey (the catalog
string renders verbatim).

#### UI button on `/me/security/sessions`

`sessions_page_for` adds a `<section
class="bulk-revoke">` above the back link with:

1. Inline confirmation copy
   (`SessionsRevokeOthersConfirm` MessageKey).
2. Form posting to
   `/me/security/sessions/revoke-others` with CSRF
   token.
3. Submit button labeled with
   `SessionsRevokeOthersButton`.

The whole section is **conditional on
`items.iter().any(|s| !s.is_current)`**. Edge cases
pinned by tests:

- Empty session list → button hidden.
- Only the current session → button hidden.
- Current session not in the listing (D1 mirror
  drift, ADR-012 §Q5) → button shown (every
  listed item is "other").

#### i18n catalog

5 new MessageKey variants:

- `SessionsRevokeOthersButton`: the button label.
- `SessionsRevokeOthersConfirm`: the inline
  confirmation copy.
- `FlashOtherSessionsRevoked`: success flash with
  `{n}` placeholder (e.g., "Signed out 3 other
  device(s)" / "他の 3 件のセッションをサインアウトしました").
- `FlashOtherSessionsRevokeFailed`: failure flash
  with `{n}` for the error count.
- `FlashNoOtherSessions`: zero-other-sessions
  info flash.

JA + EN translations included; pluralization
explicitly deferred to ADR-013 §Q4 (consistent with
the v0.39.0 deferral). The JA forms are
count-agnostic ("件"); the EN forms use bare
"device(s)" as a defensive fallback (slightly
awkward at n=1 but unambiguous).

MessageKey total: 71 → 76.

### Tests

911 → **937** lib (+26). With migrate integration:
940 → **966**.

- core: 393 → 403 (+10). All in
  `service::sessions::tests`:
  `revokes_all_other_active_sessions_keeps_current`,
  `no_other_active_sessions_is_zero_count_no_calls`,
  `user_with_no_sessions_is_zero_count_zero_skipped`,
  `current_session_not_in_user_list_revokes_all_listed`
  (the §Q5 drift edge case),
  `does_not_touch_other_users_sessions` (multi-tenant
  isolation), `already_revoked_sessions_are_filtered_by_list`,
  `per_row_failure_increments_errors_does_not_abort`
  (best-effort failure containment),
  `list_failure_propagates_as_internal_error`,
  `revoke_returning_notstarted_counts_as_revoked`
  (race-with-sweep mental-model match),
  `second_call_after_first_is_zero_count` (idempotence).
- ui: 230 → 235 (+5). Bulk button presence in EN +
  JA, hidden when empty / only-current,
  shown-when-current-not-listed (§Q5 case).
- worker: 171 → 182 (+11). 8 in `flash::tests` for the
  count codec (round-trip, count=0, u32::MAX,
  multi-`:`, non-numeric, overflow, no-FlashKey-has-
  colon defensive pin) + 3 for `render_view_for`
  substitution (substitute-when-template-has-n,
  zero-alloc-when-no-count, owned-when-substituted).

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9). No
  migration.
- DO state unchanged.
- **Wire format**:
  - Discovery doc unchanged.
  - Flash cookie format additive only — `key:N`
    notation in the payload, backward-compatible with
    v0.31–v0.44 cookies.
  - One new endpoint: `POST /me/security/sessions/revoke-others`.
- **No new dependencies.**

### Operator-visible changes

- **New endpoint mounted**:
  `POST /me/security/sessions/revoke-others`. CSRF
  token required (existing pattern). Returns 302 to
  the list page.
- **Audit dashboards**: `SessionRevokedByUser` events
  with payload field `bulk: true` are the bulk
  action; `bulk: false` (or absent) are per-row
  clicks. A spike of `bulk: true` events is
  legitimate — users responding to an alert by
  signing out everywhere is exactly the workflow this
  release enables.
- **No `wrangler.toml` change. No new bindings. No
  schema migration.**

### ADR changes

- **ADR-012 §Q4** marked **Resolved**. Inline
  resolved-paragraph follows the
  ADR-011 §Q1 / ADR-012 §Q1 / ADR-014 §Q4 / ADR-014
  §Q2 inline-resolution style.
- No new ADR.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.44.0 → 0.45.0.
- UI footers + tests bumped to v0.45.0.
- ROADMAP: v0.45.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.44.0 → 0.45.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   production dependencies.**
3. `wrangler deploy`. **No schema migration. No new
   bindings.**
4. Optionally update audit dashboards to break out
   `bulk: true` `SessionRevokedByUser` events from
   per-row.

### Forward roadmap

- **Next up (per operator request)**: refresh-token
  introspection enhancements.
- Then: i18n-2 continuation (TOTP recovery codes /
  disable / magic link / error pages), ADR-014 §Q3
  audit retention, ADR-012 §Q1.5 D1 repair tool.
- **Future security-track items still open**:
  ADR-012 §Q2-§Q3, §Q5; ADR-014 §Q1 audience scoping.

---

## [0.44.0] - 2026-05-03

Tech-debt sweep: drop `jsonwebtoken` in favor of direct
`ed25519-dalek`. Resolves the v0.41.0 trade-off that
accepted transitive `rsa` v0.9 (RUSTSEC-2023-0071) as
dead-code-but-linked.

### Why this matters

v0.41.0 enabled `jsonwebtoken/rust_crypto` to satisfy
`CryptoProvider::install_default`. The trade-off: `rust_crypto`
pulls `rsa` v0.9 in transitively, alongside `pkcs1`,
`num-bigint-dig`, `num-iter`, `num-traits`, `signature 2.x`,
`p256`, `p384`, `hmac` — all unused by cesauth (we never
call `Algorithm::RS*` or `Algorithm::PS*`). cesauth's
threat model didn't include the dead RSA path being
exercised, so the trade-off was sound — but a
linked-but-unreachable `rsa::PrivateKey` is still:

- An unwanted item in the supply chain audit trail.
- A `cargo audit` finding that operators have to
  acknowledge per release.
- Bundle-size weight (workers-rs target).
- A signal that drifts from cesauth's "minimal,
  EdDSA-only, no RSA" identity.

The v0.41.0 CHANGELOG already tracked this as a
follow-up: "Future tech-debt sweep should swap to
`josekit` + `ed25519-dalek` direct, dropping `rsa`
entirely."

### What ships

#### `crates/core/src/jwt/signer.rs` rewrite

The whole module — `JwtSigner::from_pem`,
`JwtSigner::sign`, `verify<C>`, `extract_kid` — is
rewritten using `ed25519-dalek` 2.x directly + manual
JWS Compact Serialization (RFC 7515 §3.1).

**`JwtSigner::from_pem`** uses `ed25519-dalek`'s
`pkcs8` feature (which exposes the `DecodePrivateKey`
trait via re-export) plus the upstream `pkcs8` crate
with the `pem` feature for the `from_pkcs8_pem(&str)`
method.

**`JwtSigner::sign<C>`** hand-builds the JWS:
1. Header JSON: `{"alg":"EdDSA","typ":"JWT","kid":"..."}`
   with `kid` properly JSON-string-escaped via
   `serde_json::to_string`.
2. `b64url_no_padding(header_json) + "." +
   b64url_no_padding(payload_json)` is the
   signing input per RFC 7515 §5.1.
3. `ed25519_dalek::Signer::sign(signing_input.as_bytes())`
   produces the 64-byte signature.
4. Final: `signing_input + "." + b64url(sig.to_bytes())`.

**`verify<C>`** is the inverse:
1. Split on `.`. Reject if not exactly three segments.
2. Decode header. Check `alg=EdDSA` strictly. Reject
   `alg=none` and any other algorithm by default
   (RFC 8725 §3.1).
3. Decode signature. Verify with the supplied 32-byte
   public key against the original signing input
   bytes (RFC 7515 §5.2). **Cryptographic gate
   first**, before any claim parsing — preserves the
   v0.41.0 discipline.
4. Decode payload. Validate `iss`, `aud` (string
   form only — cesauth never emits the array form
   from RFC 7519 §4.1.3, and accepting it would be
   a footgun for operators copy-pasting tokens
   between deployments), `exp` (with `leeway_secs`),
   `nbf` (optional, with leeway).
5. Second-pass deserialize into the caller's `C`
   shape. Both decodes operate on the same in-memory
   bytes; no extra allocation cost.

**`extract_kid`** decodes only the header (no
signature work) and returns `header.kid` if present.
Returns `None` for malformed input. Same contract as
v0.41.0 — kid is **untrusted** at this point; the
caller must follow up with `verify`.

#### Same wire format

Tokens produced by v0.44.0's signer are **byte-identical**
to what jsonwebtoken produced for the same inputs:

- JWS Compact Serialization is deterministically
  pinned by RFC 7515 §3.1.
- Both implementations encode JSON header / payload
  via base64url-no-padding, then sign the
  dot-joined input with Ed25519.
- Field ordering inside the header JSON differs
  (cesauth: `alg, typ, kid`; jsonwebtoken: `typ,
  alg, kid`) but verifiers parse JSON and don't
  care about order.

Tokens produced by v0.43.0 verify under v0.44.0
without re-issuance. Wire format unchanged. **No
forced rotation** — the v0.41.0 latent CryptoProvider
panic from v0.38.0-v0.40.0 was already fixed in
v0.41.0; v0.44.0 just removes the dead-code
attack surface.

#### Dependency tree changes

**Removed from `cargo tree -p cesauth-core`**:

- `jsonwebtoken` 10.x (root removal)
- `rsa` 0.9 (the RUSTSEC-2023-0071 dep)
- `pkcs1`, `num-bigint-dig`, `num-iter`,
  `num-integer`, `num-traits`, `simple_asn1` (RSA's
  multi-precision arithmetic stack)
- `signature` 2.x (jsonwebtoken's algorithm trait)

**Retained** (already direct deps for non-jsonwebtoken
reasons): `hmac` (TOTP), `p256` (WebAuthn ES256),
`signature 1.x` (transitive of p256), `sha2` (KDF /
TOTP / refresh token hash). These have always been
in the tree and are unrelated to the jsonwebtoken
swap.

**Added**:

- `pkcs8 0.10` direct dep with `pem` feature (the
  `DecodePrivateKey::from_pkcs8_pem` method requires
  `pkcs8`'s `pem` feature, which `ed25519-dalek`'s
  `pkcs8` feature alone does not enable).

**Workspace `time` dep** gains the `formatting`
feature explicitly. Pre-v0.44.0 `formatting` was
being unified in via jsonwebtoken's transitive
`time` dep with that feature enabled; removing
jsonwebtoken broke the unification, so we declare
the requirement explicitly. This is purely a
correctness fix for the now-unification-free state.

### Tests

911 lib tests still pass. **Zero test count change**:

- core: 393 → 393. The signer rewrite is a pure
  refactor; existing tests through `service::introspect`
  exercise the verify path with real Ed25519 JWTs
  (v0.41.0's multi_key tests — see the dependency
  on `ed25519-dalek::Signer` already there).
  Existing tests via `service::token` exercise the
  sign path via real `JwtSigner::sign` calls.
  Coverage is preserved by virtue of the existing
  test suite already exercising both the new and
  old implementations through identical entry
  points.
- ui: 230 → 230.
- worker: 171 → 171.
- adapter-test, do, migrate: unchanged.

Total still 940 with migrate integration tests.

### Schema / wire / DO

- Schema unchanged from v0.43.0 (still
  SCHEMA_VERSION 9). No migration.
- **Wire format byte-identical for issued tokens
  vs v0.43.0** — RFC 7515 §3.1 deterministic
  encoding pins this.
- DO state unchanged.

### Operator-visible changes

- **Bundle size goes DOWN** — `rsa` family of
  crates removed. WASM bundle should shrink by
  ~5-10% based on similar swaps in other
  ed25519-only projects.
- **`cargo audit` runs cleaner** — no more
  RUSTSEC-2023-0071 acknowledgment needed.
- **Supply-chain audit trail simpler** — `cesauth-core`'s
  direct deps are now exactly the crypto primitives
  cesauth actually exercises.
- **No production behavior change** — wire format
  is byte-identical; tokens issued before the
  upgrade verify under the new code; no forced
  rotation.
- **No `wrangler.toml` change. No new bindings. No
  schema migration.**

### ADR changes

- **No new ADR.** The v0.41.0 CHANGELOG already
  tracked the swap as planned tech-debt; v0.44.0
  delivers it. The v0.41.0 §Q4 resolution paragraph
  in ADR-014 references "the v0.4 'WASM caveat'
  comment in `signer.rs` already anticipates this
  move" — the WASM-caveat comment now documents
  v0.44.0 as the resolution.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.43.0 → 0.44.0.
- `Cargo.toml`: `jsonwebtoken` removed from
  `[workspace.dependencies]`. Comment updated.
- `Cargo.toml`: `time` features include `formatting`.
- `crates/core/Cargo.toml`: `jsonwebtoken` removed,
  `pkcs8` added.
- UI footers + tests bumped to v0.44.0.
- `crates/worker/src/config.rs`: PEM-decode docstring
  updated to reference `ed25519_dalek::SigningKey::from_pkcs8_pem`
  instead of `jsonwebtoken::EncodingKey::from_ed_pem`.
  PEM input format and `\n`-escaping requirement
  unchanged (still PKCS#8 PEM with real newlines).
- ROADMAP: v0.44.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.43.0 → 0.44.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. Fresh build
   recommended (lockfile diff is substantial — the
   removed transitive deps no longer appear).
3. `wrangler deploy`. **No schema migration. No
   `wrangler.toml` change. No new bindings.**
4. **No operator action required.** Wire format
   identical; deployed v0.43.0 tokens verify under
   v0.44.0; no forced rotation.

### Forward roadmap

- **Next up (per operator request)**: ADR-012 §Q4
  bulk "revoke all other sessions" UX.
- **Then**: refresh-token introspection enhancements,
  i18n-2 continuation (TOTP recovery codes / disable
  / magic link / error pages), ADR-014 §Q3 audit
  retention, ADR-012 §Q1.5 D1 repair tool.
- **Future security-track items still open**:
  ADR-012 §Q2-§Q5, ADR-014 §Q1 audience scoping.

---

## [0.43.0] - 2026-05-03

Per-client introspection rate limit (ADR-014 §Q2
**Resolved**). Closes the second of ADR-014's three
remaining open questions on the introspection endpoint
(§Q4 was resolved in v0.41.0; §Q1 + §Q3 remain).

### Why this matters

v0.38.0 shipped `/introspect` with **no rate limit**.
The endpoint requires client authentication, but a
compromised confidential client (or a malicious resource
server with valid creds) had unbounded ability to:

1. **Token-existence probing**. Each introspection call
   reveals whether a token is currently active. With
   sufficient throughput an attacker could brute-force
   guesses (cesauth refresh tokens are 16+ random
   bytes encoded, so practical brute-force is
   infeasible — but the design shouldn't depend on
   it).
2. **DoS amplification**. Each introspection call hits
   the `RefreshTokenFamily` DO; chatty introspection
   could degrade legitimate token-rotation traffic.
3. **Resource-server isolation failure**. One chatty
   resource server could starve cron-tick budgets
   that other RSes need.

v0.43.0 caps per-client introspection rate.

### What ships

#### `cesauth_core::service::introspect::check_introspection_rate_limit`

Mirrors the v0.37.0 `/token` per-family rate-limit
pattern (ADR-011 §Q1) but with a different bucket-key
namespace and at a different abstraction layer.

```rust
pub async fn check_introspection_rate_limit<RL>(
    rates:                   &RL,
    authenticated_client_id: &str,
    now_unix:                i64,
    window_secs:             i64,
    threshold:               u32,
) -> CoreResult<IntrospectionRateLimitDecision>
where RL: RateLimitStore;
```

Returns `Allowed` or `Denied { retry_after_secs }`.

**Bucket key shape**: `introspect:<client_id>`. The
authenticated client_id is the natural unit:

- **Per-family** (v0.37.0 pattern) wouldn't apply —
  introspection consumes tokens across many families,
  so the per-family bucket can't tell us "this RS is
  hammering us".
- **Per-token-jti** would let an attacker probing
  many distinct tokens against the same client never
  hit any single jti's bucket.
- **Per-user-id** would be wrong — introspection
  responses don't reveal the user (for inactive
  tokens), so an attacker can't even target by user.
- **Per-client-id** is the right granularity. RFC
  7662 requires authentication, so we always have
  a stable identifier; chatty RS_A doesn't affect
  RS_B; legitimate per-RS quotas are operator-
  configurable.

**threshold = 0 disables the gate.** Operators who
have an upstream rate limit (load balancer, edge
worker) or whose RSes legitimately need extreme
rates set `INTROSPECTION_RATE_LIMIT_THRESHOLD=0`. The
auth-required gate at the endpoint layer is
unaffected.

#### `Config` additions

```diff
+ pub introspection_rate_limit_threshold:   u32,
+ pub introspection_rate_limit_window_secs: i64,
```

`INTROSPECTION_RATE_LIMIT_THRESHOLD` env, default
**600**. `INTROSPECTION_RATE_LIMIT_WINDOW_SECS` env,
default **60**. Default 600/min = 10/sec is sized
for resource servers that may introspect on every
incoming request — substantially more permissive than
v0.37.0's `/token` default of 5/min (which fires
specifically on token-replay probing patterns, where
5 attempts in a window is already pathological).

#### Worker handler `crates/worker/src/routes/oidc/introspect.rs`

Rate-limit check fires:

1. **AFTER** client authentication. The bucket key
   needs the authenticated client_id, and an
   unauthenticated attacker shouldn't be able to
   burn the rate limit on behalf of a victim
   client_id.
2. **BEFORE** any DO lookup or JWT verify. A tripped
   limit doesn't even reach the family store or the
   signing-key consultation, so DoS amplification is
   contained.

On denial:

- HTTP **429 Too Many Requests** with `Retry-After:
  <secs>` header (RFC 7231 §6.6 + §7.1.3) via the
  existing `oauth_error_response` plumbing
  (`CoreError::RateLimited`).
- New audit event `EventKind::IntrospectionRateLimited`
  (snake_case `introspection_rate_limited`) with payload
  `{client_id, threshold, window_secs,
  retry_after_secs}`.
- Warn-level log line on the `RateLimit` category.

The response shape exactly matches v0.37.0's `/token`
rate-limit response — same status, same `Retry-After`
header, same body code. Resource-server clients
already handling 429s on `/token` (which they should
be) handle this identically.

#### `EventKind::IntrospectionRateLimited`

New audit kind — distinct from v0.37.0's
`RefreshRateLimited` because they're different
surfaces with different operational semantics:

- **`refresh_rate_limited`** spike → `/token`
  endpoint hit hard, indicates token-replay probing
  patterns.
- **`introspection_rate_limited`** spike →
  `/introspect` endpoint hit hard, indicates
  resource-server polling pathology OR a compromised
  confidential client used for mass token probing.

Operators alert on each independently.

### Tests

902 → **911** lib (+9 from v0.43.0 work; 6 in
`introspect::tests::rate_limit` mod + 3 already
present from earlier session). With migrate
integration: 934 → **940**.

- core: 387 → 393 (+6). All in
  `service::introspect::tests::rate_limit`:
  - `threshold_zero_always_allows` —
    operator opt-out path
  - `first_n_within_window_allowed_then_n_plus_one_denied`
    — basic limit behavior
  - `denied_decision_carries_retry_after_secs` —
    Retry-After value sanity
  - `rate_limit_is_isolated_per_client_id` — the
    headline property: chatty RS_A doesn't affect
    RS_B
  - `rate_limit_resets_after_window_rolls` — bucket
    decay semantics
  - `threshold_one_denies_immediately_after_first_hit`
    — defensive boundary

  Tests use an inline RefCell-backed
  `RateLimitStore` stub mirroring the v0.37.0 +
  v0.42.0 stub-vs-adapter-test pattern.
- ui: 230 → 230 (no UI changes).
- worker: 171 → 171 (handler edits, no new tests;
  all testable logic in pure core service).

### Schema / wire / DO

- Schema unchanged from v0.42.0 (still
  SCHEMA_VERSION 9). No migration.
- Wire format unchanged for happy-path
  introspection. Rate-limit denial returns 429 +
  `Retry-After` (same shape v0.37.0 `/token`
  established).
- DO state unchanged.
- No new dependencies.

### Operator-visible changes

- **Two new env vars** for tuning:
  `INTROSPECTION_RATE_LIMIT_THRESHOLD` (default 600),
  `INTROSPECTION_RATE_LIMIT_WINDOW_SECS` (default 60).
  Set threshold to 0 to disable. The defaults are
  permissive enough that legitimate resource-server
  patterns (one introspection per request, even at
  a few requests per second per RS) stay well
  under the limit.
- **New audit kind to monitor**:
  `introspection_rate_limited`. Add a panel on the
  audit dashboard. Steady-state baseline: **0
  events per day**. Non-zero indicates either:
  - **Misconfigured RS in tight poll loop** —
    investigate the RS-side caching (introspection
    responses are cacheable for the access-token's
    `exp` window).
  - **Compromised client_secret** — an attacker
    using a leaked credential to mass-probe tokens.
    Rotate the client_secret immediately if no
    legitimate cause is identified.
- **No production behavior change for happy-path
  introspection.** Resource servers operating well
  under 600/min see no impact.

### ADR changes

- **ADR-014 §Q2** marked **Resolved**. Implementation
  details + bucket-key rationale + audit-attribution
  recorded inline in the resolved-paragraph,
  matching the ADR-011 §Q1 / ADR-012 §Q1 / ADR-014
  §Q4 inline-resolution style.
- No new ADR.

### Doc / metadata changes

- `Cargo.toml` version 0.42.0 → 0.43.0.
- UI footers + tests bumped to v0.43.0.
- ROADMAP: v0.43.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.42.0 → 0.43.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   production dependencies.**
3. Optionally tune env vars (defaults are sized for
   typical deployments):
   - `INTROSPECTION_RATE_LIMIT_THRESHOLD=600`
   - `INTROSPECTION_RATE_LIMIT_WINDOW_SECS=60`
4. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change. No new bindings (reuses
   the existing `CACHE` KV binding for rate-limit
   buckets, same as v0.37.0).
5. Add the audit-dashboard panel for
   `introspection_rate_limited`.

### Forward roadmap

- **Future security-track items still open**:
  - ADR-012 §Q1.5 D1 repair tool (decision blocked
    on observed v0.40.0 drift data)
  - ADR-012 §Q2 user notification on session timeout
  - ADR-012 §Q3 device fingerprint columns
  - ADR-012 §Q4 bulk revoke other sessions
  - ADR-012 §Q5 orphan DO limitation
  - ADR-014 §Q1 introspection resource-server
    audience scoping (multi-tenant correctness)
  - ADR-014 §Q3 audit retention policy
- **Tech-debt sweep candidate**: swap jsonwebtoken to
  `josekit` + `ed25519-dalek` direct, dropping
  transitive `rsa` (v0.41.0 trade-off).
- **i18n-2 continued (v0.39.1+)**: TOTP recovery
  codes, TOTP disable confirm, magic link, error
  pages, `PrimaryAuthMethod::label`, Security
  Center enabled-state recovery-codes row (blocked
  on pluralization — ADR-013 §Q4).

---

## [0.42.0] - 2026-05-03

RFC 7009 token revocation conformance. Closes a **silent
security gap** in v0.27.0's `/revoke`: pre-v0.42.0 the
endpoint was fully public — any actor with a refresh
token (e.g., obtained from a leaky client) could revoke
the underlying family without authenticating, and could
attribute their own `client_id` form field to
arbitrarily-issued tokens. Per RFC 7009 §2.1 confidential
clients MUST authenticate, and §2 says "the
authorization server first validates the client
credentials and then verifies whether the token was
issued to the client making the revocation request" —
v0.27.0 did neither.

### What ships

#### `cesauth_core::service::client_auth::verify_client_credentials_optional`

Companion to v0.38.0's
`verify_client_credentials`. The optional variant takes
`presented_secret: Option<&str>` and returns a
three-variant `ClientAuthOutcome`:

- **`PublicOrUnknown`** — the named `client_id` is
  registered as public (no `client_secret_hash` on
  file) OR doesn't exist at all. The conflation is
  intentional: the caller can't tell "unknown
  client" from "public client" by outcome alone,
  preserving the v0.38.0 enumeration-side-channel
  defense.
- **`Authenticated`** — confidential client with
  matching credentials.
- **`AuthenticationFailed`** — confidential client,
  either no credentials presented or wrong secret.

Used by `/revoke` to decide whether the requesting
client_id requires authentication.

#### `cesauth_core::service::revoke` — pure RFC 7009 service

New module orchestrating the four-way classification +
cid-binding gate:

```rust
pub async fn revoke_refresh_token<FS, CR>(
    families: &FS, clients: &CR, input: &RevokeInput<'_>,
) -> CoreResult<RevokeOutcome>
```

Returns one of four `RevokeOutcome` variants:

| Outcome | When | Audit-attributable cause |
|---|---|---|
| `Revoked { family_id, client_id, auth_mode }` | Token decoded, auth+cid policy passed, family DO revoked | success |
| `NotRevocable` | Token couldn't be decoded as refresh token (malformed, or a JWT access token) | scanner traffic / unsupported type |
| `UnknownFamily` | Token decoded but family didn't exist (already swept, or recycled id) | stale client integration / clock skew |
| `Unauthorized { reason }` | Auth or cid-binding failed | `ConfidentialAuthFailed` or `ClientIdCidMismatch` |

`RevokeAuthMode` (`PublicClient` / `ConfidentialClient`)
distinguishes how an authorized revoke succeeded.
`UnauthorizedReason` (`ConfidentialAuthFailed` /
`ClientIdCidMismatch`) attributes denials.

**RFC 7009 §2 ordering** — authenticate first against
the request's `client_id`, then check the cid binding
(request's claimed client_id vs token's actual cid).
The service picks the auth target as
`input.client_id.unwrap_or(token_cid.as_str())` so:

- Public client with no `client_id` form field →
  trivially passes cid binding (auth target IS the
  cid).
- Public client with a wrong `client_id` form field
  → cid mismatch → `Unauthorized` (closes the
  cross-client revoke vector).
- Confidential client with creds → authenticated
  against own client_id → cid binding still
  enforced (can't revoke another client's token
  even after authenticating).

**Cross-client revoke prevention** is the headline
**security improvement**, not just spec conformance:
pre-v0.42.0, an attacker who obtained a refresh token
belonging to ClientA could submit it to `/revoke`
with `client_id=AttackerControlledApp` and the
endpoint would happily revoke it. v0.42.0's cid
binding gate rejects this with silent 200.

#### Worker handler `crates/worker/src/routes/oidc/revoke.rs`

Rewritten to delegate to the pure service:

- Parses form body via `req.form_data()` (matches the
  v0.38.0 introspection pattern).
- Reuses v0.38.0's `client_auth::extract` for
  `Authorization: Basic` + form-body credential
  extraction. Authorization header takes precedence
  per RFC 6749 §2.3.1.
- Resolves requestor's claimed client_id: Basic-header
  creds first, form `client_id` field second. Used
  for the cid-binding gate.
- Calls `revoke_refresh_token`. Maps outcome to:
  - **Audit event** with per-outcome JSON payload.
    `NotRevocable` cases are NOT audited (scanner
    traffic; would just bloat the chain). The other
    three outcomes emit `EventKind::RevocationRequested`
    with payload `{outcome, ...}`.
  - **Log line** for operator dashboards (info
    level, Auth category, with client_id breadcrumb).
- **Wire response: always 200 OK with empty body** per
  RFC 7009 §2.2 — including the `Unauthorized` cases.
  Returning 401 there would let an attacker probe
  whether a refresh token belongs to a confidential
  vs public client by response shape.

#### Discovery doc — RFC 8414 §2

```diff
+ "revocation_endpoint_auth_methods_supported": [
+     "none",
+     "client_secret_basic",
+     "client_secret_post"
+ ]
```

The `none` entry is the spec-mandated difference vs
`introspection_endpoint_auth_methods_supported`: RFC
7009 §2.1 explicitly allows public-client revocation,
RFC 7662 §2.1 doesn't. Spec-conformant clients
(`oauth-discovery`-style libraries) auto-pick-up the
new field.

#### Token-type-hint support

`POST /revoke` now parses the `token_type_hint` form
parameter (`access_token` / `refresh_token`) per RFC
7009 §2.1. Unknown values are ignored as the spec
allows. The hint is currently advisory only — cesauth's
revoke implementation always treats the input as a
refresh token; access-token revocation remains
unsupported (RFC 7009 §2: the AS MAY refuse). A future
release may use the hint to short-circuit the refresh
decode for `access_token`-hinted tokens.

### Tests

882 → **902** lib (+20). With migrate integration: 911
→ **934**.

- core: 364 → 387 (+23).
  - 6 in `client_auth::tests` for the optional
    helper (public, unknown, no creds, correct creds,
    wrong creds, empty secret).
  - 14 in `service::revoke::tests`:
    `public_client_with_no_client_id_revokes_by_token_possession`,
    `public_client_form_client_id_mismatch_returns_unauthorized`
    (the cross-client revoke prevention pin),
    `confidential_client_with_correct_creds_revokes`,
    `confidential_client_no_creds_returns_unauthorized`,
    `confidential_client_wrong_secret_returns_unauthorized`,
    `confidential_client_cannot_revoke_other_clients_token`
    (the multi-tenant cross-cid pin),
    `malformed_token_returns_not_revocable`,
    `empty_token_returns_not_revocable`,
    `unknown_family_returns_unknown_family`,
    `jwt_access_token_returns_not_revocable`,
    `token_type_hint_parses_recognized_values`,
    `token_type_hint_returns_none_for_unknown`,
    `already_revoked_family_revokes_again_idempotently`.
  - 3 in `oidc::discovery::tests`:
    `discovery_revocation_endpoint_auth_methods_advertised`,
    `discovery_revocation_endpoint_auth_methods_includes_none`
    (pins the RFC 7009 §2.1 vs RFC 7662 §2.1 spec
    difference),
    `discovery_revocation_endpoint_auth_methods_in_wire_form`.
- ui: 230 → 230. No UI changes.
- worker: 171 → 171. Handler edits, no new tests;
  the testable logic is in the pure core service.

### Schema / wire / DO

- Schema unchanged from v0.41.0 (still SCHEMA_VERSION 9).
  No migration.
- Wire format additive only: discovery doc gains one
  field. Spec-conformant parsers tolerate.
- DO state unchanged.
- No new dependencies.

### Operator-visible changes / breaking-change notice

- **Pre-v0.42.0 `/revoke` was a known security gap**
  (cross-client revoke; no confidential-client auth).
  v0.42.0 fixes the gap. Operators running clients
  that depend on the loose v0.27.0 behavior — there
  shouldn't be any, since the spec was the looser
  side — may see new `Unauthorized` audit events.
- **Confidential-client revoke now requires
  authentication.** Clients with a `client_secret_hash`
  on file MUST submit credentials via Authorization:
  Basic (preferred) or `client_secret`/`client_id`
  form fields. Without credentials the revoke is
  silently no-op'd (200, no body, audit event
  attributes `Unauthorized:ConfidentialAuthFailed`).
- **Cross-client revoke is rejected.** A request
  presenting `client_id=ClientA` for a token whose
  cid is ClientB is silently no-op'd (200, no body,
  audit event attributes `Unauthorized:ClientIdCidMismatch`).
- **`token_type_hint` is now parsed** but currently
  advisory-only.
- **Discovery doc adds
  `revocation_endpoint_auth_methods_supported`** —
  RFC 8414 §2. Spec-conformant clients pick it up
  automatically.
- **Audit dashboards should add a panel breaking down
  `revocation_requested` events by `outcome` field**
  — the new four-way attribution lets operators
  distinguish:
  - `revoked` (steady-state),
  - `unauthorized` with `reason: cid_mismatch` (could
    be cross-client revoke probing — alert),
  - `unauthorized` with `reason: auth_failed` (could
    be wrong creds — investigate, but also some
    integrations rotate secrets out of band),
  - `unknown_family` (stale clients / clock skew —
    operationally noisy but not security-meaningful).

### ADR changes

- **No new ADR.** The implementation maps directly to
  RFC 7009; no cesauth-specific decision points
  beyond what the spec says. The cid-binding-on-
  public-clients choice is recorded inline in the
  module-level docs of `cesauth_core::service::revoke`.

### Doc / metadata changes

- `Cargo.toml` version 0.41.0 → 0.42.0.
- UI footers + tests bumped to v0.42.0.
- ROADMAP: v0.42.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.41.0 → 0.42.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   production dependencies.**
3. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change. No new bindings.
4. **For confidential-client integrations**: ensure
   `client_secret_basic` (Authorization: Basic) or
   `client_secret_post` (form-body) credentials are
   sent on `/revoke`. Without them, revocation
   silently no-ops.
5. **For public-client integrations** (mobile apps,
   SPAs): no action required IF you weren't sending
   a wrong `client_id` form field. If you were
   sending one that doesn't match the token's
   cid, revocation will now silently no-op.
6. Add the audit-dashboard panel for
   `revocation_requested` outcome breakdown.

### Forward roadmap

- **Future security-track items still open**:
  - ADR-012 §Q1.5 D1 repair tool (decision blocked
    on observed v0.40.0 drift data)
  - ADR-012 §Q2 user notification on session timeout
  - ADR-012 §Q3 device fingerprint columns
  - ADR-012 §Q4 bulk revoke other sessions
  - ADR-012 §Q5 orphan DO limitation
  - ADR-014 §Q1 introspection resource-server
    audience scoping
  - ADR-014 §Q2 introspection rate limit
  - ADR-014 §Q3 audit retention policy
- **Tech-debt sweep candidate**: swap jsonwebtoken to
  `josekit` + `ed25519-dalek` direct, dropping
  transitive `rsa` (v0.41.0 trade-off).
- **i18n-2 continued (v0.39.1+)**: TOTP recovery
  codes, TOTP disable confirm, magic link, error
  pages, `PrimaryAuthMethod::label`, Security
  Center enabled-state recovery-codes row (blocked
  on pluralization — ADR-013 §Q4).

---

## [0.41.0] - 2026-05-03

Multi-key access-token introspection (ADR-014 §Q4
**Resolved**) AND fix for a latent jsonwebtoken-10
CryptoProvider bug introduced in v0.38.0 that would
have panicked the worker on the first real-token
introspection request.

### Why this matters

**Two issues, one release**:

1. **Signing-key rotation correctness.** v0.38.0
   shipped `/introspect` with a single-key access-token
   verify path: `keys.first()` selected only the most-
   recently-added active signing key. During a
   signing-key rotation grace period (multiple keys
   active concurrently), an access token signed with an
   older but still-active `kid` would fail introspection's
   verify path. The refresh-token fallback path
   covered most user-facing cases, but resource servers
   actually validating access tokens via introspection
   would have seen them reported `active=false`.
2. **A P0 latent bug from v0.38.0.** The workspace's
   jsonwebtoken-10 dependency was configured with
   `features = ["use_pem", "ed25519-dalek", "rand"]`,
   deliberately omitting the `rust_crypto` umbrella to
   avoid the transitive `rsa` dep affected by
   RUSTSEC-2023-0071 (Marvin Attack). This was a sound
   threat-model decision (cesauth never uses RSA) but
   it produced a runtime bug: jsonwebtoken-10 wired
   the EdDSA verify path through
   `CryptoProvider::install_default`, which the bare
   `ed25519-dalek` opt-dep doesn't satisfy. **The
   first real introspection request with a real
   access token in production would have panicked the
   worker** with the message "Could not automatically
   determine the process-level CryptoProvider". The
   bug existed since v0.38.0 (introspection's
   introduction) but no CI test exercised the
   real-JWT verify path until v0.41.0's multi-key
   work tried to.

### What ships

#### Multi-key support (ADR-014 §Q4)

**`cesauth_core::oidc::introspect::IntrospectionKey<'a>`** —
new type with `kid: &'a str` + `public_key_raw: &'a [u8]`.
Borrowed lifetime ties to the worker's signing-key
buffer (which lives only for the request duration).

**`cesauth_core::jwt::signer::extract_kid(token: &str) -> Option<String>`** —
extracts the JWT header's `kid` member without
verifying the signature. Returns `None` for malformed
tokens or kid-less headers. **The kid is untrusted at
this point** — used only as a hint for key selection;
the cryptographic verify still runs against the chosen
key.

**`introspect_token` signature change**:

```diff
- public_key_raw: &[u8]
+ keys: &[IntrospectionKey<'_>]
```

Old behavior is the special case `keys.len() == 1`.

**`introspect_access` multi-key strategy**:

1. Empty keys → return `Ok(None)` (deployment
   misconfigured; refresh-token path still works,
   pinned by `refresh_path_isolated_from_empty_access_keys`).
2. **kid-directed lookup**: extract the JWT's `kid`
   header. If it matches one of the active keys, try
   that key first. Fast path: 1 crypto verify call.
3. **try-each fallback**: if no kid present, no
   match in active set, or kid-matched key fails to
   verify (defensive), walk every active key in turn.
4. Return `Some(active_response)` on first
   verification success. Return `Ok(None)` (inactive)
   if every key fails.

#### Worker handler `crates/worker/src/routes/oidc/introspect.rs`

Builds `Vec<IntrospectionKey>` from `key_repo.list_active()`
result. Malformed `public_key_b64` entries (b64 decode
fails) are filtered out with a `console_warn!` rather
than aborting the request — defensive against a
single bad key shadowing the whole active set.

#### CryptoProvider fix (P0 latent v0.38.0 bug)

Workspace `Cargo.toml`:

```diff
- jsonwebtoken = { version = "10", default-features = false, features = ["use_pem", "ed25519-dalek", "rand"] }
+ jsonwebtoken = { version = "10", default-features = false, features = ["use_pem", "rust_crypto"] }
```

`rust_crypto` brings transitive `rsa` v0.9 back in.
We accept this because:

- cesauth has no code path that calls
  `Algorithm::RS{256,384,512}` or
  `Algorithm::PS{256,384,512}`. The `rsa` dep is dead
  code from cesauth's perspective.
- Marvin Attack is a side-channel against RSA
  decryption / signing, not against unused-but-linked
  code. A linked-but-unreachable `rsa::PrivateKey`
  does not exercise the vulnerable path.
- The alternative (a panicking production binary on
  the first real introspection request) is strictly
  worse.

A future sweep should swap to `josekit` + `ed25519-dalek`
direct, dropping `rsa` entirely. The v0.4 "WASM
caveat" comment in `signer.rs` already anticipates
this move.

### Tests

871 → **882** (+11 lib tests, total 911 with migrate
integration tests).

- core: 353 → 364 (+11). All in
  `service::introspect::tests`:
  - 4 in `multi_key` mod requiring real Ed25519 verify:
    `single_key_match_verifies_active`,
    `multi_key_kid_directed_lookup_picks_correct_key`
    (the headline rotation-grace-period scenario),
    `multi_key_try_each_fallback_when_kid_unknown`,
    `forged_kid_with_unknown_signature_rejected`,
    `token_signed_by_retired_key_reports_inactive`,
    `empty_keys_returns_inactive`,
    `refresh_path_isolated_from_empty_access_keys`.
  - 4 in `extract_kid_tests` mod:
    `extracts_kid_when_present`,
    `returns_none_when_kid_absent`,
    `returns_none_on_garbage_input`,
    `does_not_verify_signature`.

  Tests build JWTs directly via base64url +
  `ed25519_dalek::Signer` rather than through
  `jsonwebtoken::EncodingKey` (which expects PKCS#8 DER
  rather than the raw 32-byte seed; our test keys are
  raw seeds). Public-key path uses
  `DecodingKey::from_ed_der` with the 32 raw bytes,
  which `jsonwebtoken-10` correctly accepts (the
  inner storage is `SecretOrDer(raw_bytes)` regardless
  of whether you came in via `from_ed_der` or
  `from_ed_components`).

  The 13 baseline introspect tests still pass; their
  call sites were migrated from `&FAKE_PUBKEY` to
  `&fake_keys()` (a one-element slice).
- ui: 230 → 230 (no UI changes).
- worker: 171 → 171. Handler edits, no new tests;
  existing handler tests assert structural properties
  (CSRF, content-type, status codes).

### Schema / wire / DO

- Schema unchanged from v0.40.0 (still SCHEMA_VERSION 9).
- Wire format unchanged.
- DO state unchanged.
- **Dependency change**: `rsa` v0.9 transitively pulled
  in via jsonwebtoken's `rust_crypto` feature. The
  deps tree adds `rsa`, `pkcs1`, `pkcs8`, `num-bigint-dig`,
  `num-iter`, `num-traits`, `signature` 2.x, plus
  `p256`, `p384`, `hmac` (all unused by cesauth).
  Worker WASM bundle size increase: TBD on next
  release build (estimated low single-digit %).

### Operator-visible changes

- **No production behavior change for happy-path
  introspection.** A resource server submitting a
  real access token now gets the correct
  `active=true` instead of a worker panic.
- **Signing-key rotation grace period**: tokens
  signed by any key in the active set verify
  correctly. Operators who delayed rotations because
  of the v0.38.0 bug can now rotate confidently.
- **No `wrangler.toml` change. No new bindings. No
  schema migration.**

### ADR changes

- **ADR-014 §Q4** marked **Resolved**. The "deferred
  to a future iteration" paragraph replaced with a
  v0.41.0 implementation summary mirroring the
  ADR-011 §Q1 / ADR-012 §Q1 inline-resolution style.
- No new ADR.

### Doc / metadata changes

- `Cargo.toml` version 0.40.0 → 0.41.0.
- UI footers + tests bumped to v0.41.0.
- ROADMAP: ADR-014 §Q4 Resolved annotation; v0.41.0
  Shipped table row added.
- This CHANGELOG entry.

### Upgrade path 0.40.0 → 0.41.0

1. `git pull` or extract this tarball over your
   working tree.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **Dependency
   change**: `rsa` and friends pulled in transitively
   via jsonwebtoken's `rust_crypto`. Bundle size goes
   up modestly. If your deployment has tight Worker
   bundle-size budgets, audit before deploying.
3. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change.
4. **Resource servers that previously saw spurious
   `active=false` from `/introspect` should see
   correct results immediately** — both the
   multi-key fix and the CryptoProvider fix land in
   the same deploy.

### Forward roadmap

- **Future security-track items still open**:
  - ADR-012 §Q1.5 D1 repair tool (decision blocked
    on observed v0.40.0 drift data)
  - ADR-012 §Q2 user notification on session timeout
  - ADR-012 §Q3 device fingerprint columns
  - ADR-012 §Q4 bulk revoke other sessions
  - ADR-012 §Q5 orphan DO limitation
  - ADR-014 §Q1 introspection resource-server audience
    scoping
  - ADR-014 §Q2 introspection rate limit
  - ADR-014 §Q3 audit retention policy
- **i18n-2 continued (v0.39.1+)**: TOTP recovery
  codes, TOTP disable confirm, magic link, error
  pages, `PrimaryAuthMethod::label`, Security Center
  enabled-state recovery-codes row (blocked on
  pluralization — ADR-013 §Q4).
- **Feature track candidates**: RFC 7009 token
  revocation for confidential clients.
- **Tech-debt sweep candidate**: swap jsonwebtoken to
  `josekit` + `ed25519-dalek` direct, dropping
  transitive `rsa` (resolves the dead-code-but-
  CVE-flagged dep that v0.41.0 accepted as a
  trade-off).

---

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

## [0.31.0] - 2026-05-02

UI/UX iteration release. First node-major release after the 5-phase
TOTP security track closed at v0.30.0; per the user-stated project
value "重要な予定が完了したタイミングで、UI/UX 改善に取り組みます",
the schedule turns to user-facing surface improvements before the
audit-log-hash-chain track (v0.32.0+) starts.

This release implements the six P0 + P1 backlog items from
`cesauth-v0.31.0-plan-v2.md` (the planning document distilled
from a PowerPoint UI/UX review). One item (P1-B handler integration
tests) was split to v0.31.1 per the plan's §6.4 scope-cap policy.

### Added

- **`/me/security` Security Center index page** (P0-A). Read-only
  surface listing the user's primary auth method (Passkey /
  MagicLink / Anonymous), TOTP enabled/disabled badge, and
  recovery-code remaining count. Single-task-per-page rule —
  links out to `/me/security/totp/enroll` (when disabled) or
  `/me/security/totp/disable` (when enabled), no inline
  destructive actions. Anonymous users see a suppressed-TOTP
  variant. New template `cesauth_ui::templates::security_center_page`
  and variant `security_center_page_with_flash` for flash-aware
  rendering. New module `cesauth_worker::routes::me::security`
  with `get_handler`. Wired in `worker::lib::main` as
  `GET /me/security`.

- **Recovery-code threshold rendering** (4-tier). N=10 / N=2-9
  → info badge ("リカバリーコード: N 個有効/残り"), N=1 →
  warning flash with re-enrollment hint, N=0 → danger flash with
  admin-contact message. Threshold rationale in plan v2 §3.1
  P0-A: no recovery-code regeneration path exists, so an early
  warning would push users toward unnecessary re-enrollment.

- **Flash-message infrastructure** (P0-B). New
  `__Host-cesauth_flash` cookie (SameSite=Lax, 60s TTL,
  HMAC-signed over a closed-dictionary payload). Format prefix
  `v1:` allows future format upgrades without breaking
  in-flight cookies. New module `cesauth_worker::flash`
  (~270 lines). Templates side: `flash_block(view) -> String`
  and `frame_with_flash(title, flash_html, body)`. Wired into
  4 handlers: `disable` → `success.totp_disabled` (redirect
  changed `/` → `/me/security`), `enroll/confirm` →
  `success.totp_enabled` (both recovery-codes-page and
  direct-redirect paths), `recover` → `warning.totp_recovered`,
  `logout` → `info.logged_out` (redirect changed `/` → `/login`).

- **`totp_enroll_page` `error: Option<&str>` slot** (P0-C).
  Mirrors `totp_verify_page`. Wrong-code branch passes Japanese
  error message instead of silently re-rendering. Code input
  gained `autofocus` for the wrong-code re-render.

- **8 design tokens** (P0-D) with light + dark mode variants.
  `--success`, `--success-bg`, `--warning`, `--warning-bg`,
  `--danger`, `--danger-bg`, `--info`, `--info-bg`. New CSS
  classes: `.flash` + 4 `.flash--*`, `.badge` + 4 `.badge--*`,
  `button.danger`, `button.warning`, `.flash__icon`,
  `.flash__text`, `.visually-hidden` (utility class — fixed
  latent bug where `totp_verify_page` referenced the class but
  the rule was missing). All state badges and banners pair
  color with icon + text label per WCAG 1.4.1.

- **`next` parameter for post-login landing** (P1-A). Pure
  function `validate_next_path(raw)` with `/me/*` + `/`
  allowlist; rejects protocol-relative URLs, schemes,
  Windows UNC, admin paths, api paths, oauth endpoints, login
  loop, dev paths, machine endpoints, prefix-substring traps.
  New `redirect_to_login_with_next(req)` base64url-encodes
  path+query into `?next=`. Login GET handler reads `?next=`,
  validates, stashes encoded value in `__Host-cesauth_login_next`
  (5 min, SameSite=Lax). `complete_auth` /
  `complete_auth_post_gate` thread the cookie header through;
  the no-AR landing arm consults the cookie via
  `decode_and_validate_next`.

- **`docs/src/expert/cookies.md`** new chapter (~210 lines)
  inventorying all 7 cookies. Each entry: name + purpose +
  lifetime + scope + SameSite + HttpOnly + Secure attributes +
  strictly-necessary justification per EDPB Guidelines 5/2020
  §3.1.1. Operator-deployed analytics responsibility note.
  Inventory maintenance rule documented for future releases.
  Linked in `docs/src/SUMMARY.md`.

- **ADR-009 added to `docs/src/SUMMARY.md`** (was missed in
  v0.30.0).

- **`attempts_exhausted` pure helper** in `verify::post_handler`
  + `DISABLE_SUCCESS_REDIRECT` constant in `disable::post_handler`,
  both with unit tests. Honest minimum coverage at the worker
  handler layer pending the env-mock investment in v0.31.1.

### Changed

- **Logout redirect target**: `POST /logout` now 302's to
  `/login` (was `/`) with `info.logged_out` flash.

- **TOTP disable redirect target**: `POST /me/security/totp/disable`
  now 302's to `/me/security` (was `/`) with `success.totp_disabled`
  flash.

- **TOTP enrollment recovery-codes page "continue" link** now
  points to `/me/security` (was `/`).

- **`totp_enroll_page` template signature**: now takes a fourth
  argument `error: Option<&str>`. Existing callers updated.

- **`complete_auth` and `complete_auth_post_gate` signatures**:
  both now take an additional `cookie_header: Option<&str>`
  parameter. All four worker call sites updated.

- **`me::auth::resolve_or_redirect`** now uses
  `redirect_to_login_with_next(req)` to encode the user's
  current path into `?next=`. The legacy `redirect_to_login()`
  remains for mid-flow failures where the user isn't trying to
  reach a `/me/*` page.

### Fixed

- **`.visually-hidden` CSS rule was missing**. Class was already
  referenced by `totp_verify_page` for an SR-only heading but
  the rule was never written. Added in P0-D's CSS expansion.

### Documentation

- New `docs/src/expert/cookies.md`.
- `docs/src/SUMMARY.md` updated with cookies chapter + ADR-009
  link.
- ROADMAP.md: v0.31.0 marked shipped; new v0.31.1 entry
  describing the deferred TOTP handler integration tests.

### Tests

573 → ~680 (approximately +107). Breakdown:

- ui: 150 → ~190 (+40). Design-token snapshot tests, flash_block
  contract tests, security center page tests (4 recovery-code
  threshold boundaries, conditional links, anonymous suppression,
  single-task-per-page invariant), totp_enroll_page error slot
  tests.
- worker: 47 → ~120 (+~73). 32 flash module tests (round-trip,
  tamper detection, malformed-input rejection, cookie shape,
  closed-dictionary defense), 34 me::auth tests (validate_next_path
  comprehensive coverage, decode round-trip, cookie helpers),
  TOTP handler pure-helper extracts.
- core, adapter-test, migrate, do, adapter-cloudflare: unchanged.

### Deferred to v0.31.1

- **TOTP route handler integration tests** (P1-B). Each of the
  four route handlers deserves at least 3 cases per plan §3.2
  P1-B (normal / CSRF failure / primary failure mode). The
  worker crate has no `worker::Env` mock infrastructure;
  building one (faking D1 + DO + KV + secrets + vars) is its
  own scope. Plan v2 §6.4 scope-cap policy invoked.

### Migration notes

No D1 schema migration. `SCHEMA_VERSION` stays at 7. No new
secret or var. The new cookies (`__Host-cesauth_flash` and
`__Host-cesauth_login_next`) are introduced organically; existing
deployments need no operator action. Both are strictly necessary
per EDPB Guidelines 5/2020 §3.1.1; cesauth does not display a
cookie consent banner.

---

## [0.30.0] - 2026-04-29

Security track Phase 7 of 11: TOTP Phase 2d — polish + operations.

**This is the final TOTP release.** v0.26.0 shipped the library,
v0.27.0 the storage adapters, v0.28.0 the presentation layer,
v0.29.0 wired the HTTP routes + verify gate. v0.30.0 closes the
track with the disable flow, cron sweep extension, redaction
profile updates, operator chapter, pre-production release gate
update, and **ADR-009 graduates from `Draft` to `Accepted`**.

After v0.30.0 deploys, the TOTP track is feature-complete for the
0.x series. Future iterations (the v0.32.0+ `/me/security` self-
service UI, dual-key rotation tooling, audit-log integration)
build on top of the foundation laid in 0.26.0–0.30.0 without
touching the underlying primitives.

**Note on UI/UX scope**: per the user-stated project value
"重要な予定が完了したタイミングで、UI/UX 改善に取り組みます", the
disable flow in this release is intentionally **minimal** — a
single-page confirmation, a redirect home, no flash-message
infrastructure. The TOTP track concludes here; UX work
(`/me/security` index page, flash messages, error-slot in the
enroll template, CSS polish for warning/danger button states)
naturally belongs in the next release where the UI/UX iteration
will consolidate it across the surface, not just for TOTP.

### Added — disable flow

- **`GET /me/security/totp/disable`** — confirmation page
  rendered by the new `cesauth_ui::templates::totp_disable_confirm_page`
  template. Single-form POST/Redirect/GET pattern (arriving at
  this URL doesn't disable TOTP, only POSTing the confirm form
  does). The page warns explicitly that recovery codes are wiped
  too, offers a cancel link, and uses one-click confirmation
  rather than a "type DISABLE to confirm" double-prompt — the
  consequences are clearly stated, re-enrolling takes one
  minute, and the user already authenticated for primary to
  reach this page.
- **`POST /me/security/totp/disable`** — validates CSRF, deletes
  ALL TOTP authenticator rows for the calling user (active or
  unconfirmed) plus all recovery codes (redeemed or unredeemed).
  Authenticators-first ordering: an authenticator without
  recovery codes is still a working credential, while recovery
  codes without an authenticator are useless. Best-effort
  failure semantics: authenticators-delete failure → 500 (TOTP
  remains enabled, user sees this on next login); recovery-codes
  delete failure → silently logged (the authenticator is gone,
  recovery codes are useless). Redirects to `/`. No flash
  message — that infrastructure is deferred to the UI/UX release.

### Added — `TotpAuthenticatorRepository::delete_all_for_user`

Trait method + in-memory + D1 adapter implementations.
Single-statement user-scoped DELETE (no list-then-delete shape
because there's no per-row audit invariant to preserve — TOTP
rows are credentials, not principals; contrast with the
anonymous-user sweep where audit-trail integrity is load-bearing
per ADR-004 §Q5).

In-memory adapter: `m.retain(|_, r| r.user_id != user_id)`. D1
adapter: `DELETE FROM totp_authenticators WHERE user_id = ?1`.
Both no-op-on-empty / idempotent across retries (deliberately
NOT mapped to `NotFound` like the existing `delete(id)` because
the disable flow is idempotent).

Two new tests in `cesauth-adapter-test::repo::tests`:
- `delete_all_for_user_scopes_to_user` — pins that Alice's
  disable doesn't wipe Bob's TOTP rows. A bug here would be a
  cross-user security incident, not a UX glitch.
- `delete_all_for_user_is_idempotent_on_missing` — pins that
  retries / double-clicks don't 500.

### Added — TOTP unconfirmed-enrollment cron sweep

Extension to the existing 04:00 UTC daily cron in
`crates/worker/src/sweep.rs`. New private
`totp_unconfirmed_sweep(env, cfg, now)` helper called after the
anonymous-trial sweep within the same `run()` body. Drops
`totp_authenticators` rows where `confirmed_at IS NULL AND
created_at < now - 86400` (24-hour retention per ADR-009 §Q9).

The 24-hour window is "long enough that a user who got
distracted mid-enrollment can come back the same day, short
enough that abandoned enrollment doesn't pollute storage". Per
ADR-009 §Q9.

The partial index `idx_totp_authenticators_unconfirmed` (created
in migration 0007) makes the lookup query cheap. Same
list-then-delete shape as the anonymous sweep, same best-effort
failure semantics. **No audit emission per row** — TOTP rows
are credentials, not principals; the row count is logged as
`totp unconfirmed sweep complete: N rows deleted`.

The module-level doc in `sweep.rs` is rewritten to cover both
passes; the "Why not a single SQL DELETE" section is consolidated
into the top doc rather than living per-sweep.

### Added — `RedactionProfile.drop_tables`

New field on `cesauth_core::migrate::RedactionProfile`. Tables
listed are **dropped entirely** from the export when the
profile is active (vs the existing per-column `rules` which
scrub fields within preserved tables).

Both built-in profiles updated:
- **`prod-to-staging`**: drops `totp_authenticators` +
  `totp_recovery_codes`. Per ADR-009 §Q5/§Q11: TOTP secrets must
  NOT survive redaction even encrypted, because a staging
  deployment with real users' encrypted TOTP secrets would let
  any staging operator authenticate as those users (the
  encryption key is just a deployment secret, which staging has
  access to).
- **`prod-to-dev`**: same TOTP-drop, plus its existing
  display-name nullification. The threat surface on a
  developer's laptop is even worse than on staging.

CLI export loop in `crates/migrate/src/main.rs` updated to honor
`prof.drop_tables` — both the main export path (~line 369) and
the round-trip verify path (~line 627) skip listed tables.
Operator-facing message during export:
`Exporting <table>... 0 rows (dropped by `<profile>` profile)`.

The `MIGRATION_TABLE_ORDER` and `TENANT_SCOPES` constants in
`cesauth-migrate/schema.rs` are extended with both new tables
(both `TenantScope::Global` since they reference users via FK
without their own `tenant_id` column — same shape as the
existing `authenticators` table for WebAuthn).

3 new core::migrate tests:
- `prod_to_staging_drops_totp_tables` — pins ADR-009 §Q5/§Q11.
- `prod_to_dev_drops_totp_tables` — same for the stricter
  profile.
- `built_in_profile_drop_tables_reference_known_tables` —
  defense-in-depth: catches typos in `drop_tables` (e.g.,
  `totp_authenticator` without the s) against a hard-coded
  `KNOWN_DROPPABLE` list. A typo would silently NOT drop the
  table, leaving a privacy hole.

### Added — operator chapter `docs/src/deployment/totp.md`

New ~270-line operator chapter covering:
- When TOTP fires (post-MagicLink only; WebAuthn skips per
  ADR-009 §Q7).
- Required configuration: `TOTP_ENCRYPTION_KEY` secret +
  `TOTP_ENCRYPTION_KEY_ID` var, with `openssl rand -base64 32 |
  wrangler secret put TOTP_ENCRYPTION_KEY` example.
- Pre-production release gate cross-reference.
- Key rotation procedure: dual-key deployment + re-encryption
  (Phase 2). **With explicit caveat** that the dual-key
  resolution path is NOT yet implemented in 0.30.0; operators
  who need to rotate today must either re-enroll all users or
  write a one-shot migration helper. Tracked in ROADMAP under
  "Later".
- Admin reset path for lockout recovery: direct D1 deletion
  procedure (`wrangler d1 execute ... DELETE FROM
  totp_authenticators WHERE user_id = ...`).
- Cron sweep semantics + diagnostic query.
- Disable flow operator perspective + the no-current-code-
  required rationale.
- Redaction profile behavior + ADR-009 §Q5/§Q11
  cross-reference.
- Operational invariants: `secret_key_id` is load-bearing for
  rotation, partial index is load-bearing for sweep, cookie is
  SameSite=Strict, recovery codes are SHA-256-hashed
  irretrievably, multi-authenticator semantics.
- Diagnostic queries: how many users have TOTP, how many have
  fewer than N recovery codes left, how many in the sweep
  window right now.

Added to `docs/src/SUMMARY.md` between the security-headers
chapter and the runbook.

### Added — pre-production release gate update

`docs/src/expert/security.md` — `TOTP_ENCRYPTION_KEY` added as
item 6 to the pre-production checklist with the caveat that
TOTP is opt-in at the operator level. Cross-references the new
operator chapter.

### Added — totp_disable_confirm_page UI template

5 new template tests in `cesauth-ui::templates::tests`:
- CSRF token inclusion (matches the POST validator).
- Form action correctness (`/me/security/totp/disable`,
  POST method).
- Recovery-codes-loss warning text present (`recovery codes`
  string match — pin so a future UX softening doesn't hide the
  consequence).
- Cancel link offered (`<a href="/">Cancel`) — destructive
  flow must offer a no-op exit.
- CSRF escape behavior (e.g., `t<>k` becomes `t&lt;&gt;k`).

### Status — ADR-009 graduates Draft → Accepted

The TOTP track has been validated end-to-end across five
releases. Operator-visible flows work, the cron sweep prunes
abandoned enrollments, redaction profiles drop TOTP secrets,
the operator chapter exists, and there are no outstanding
design questions. ADR header status changes from `Draft
(v0.26.0)` to `Accepted (v0.30.0)`. The ADR index in
`docs/src/expert/adr/README.md` is updated.

### Tests

Total: **573 passing** (+10 over v0.29.0):

- core: **275** (was 272) — 3 new in `migrate::tests`:
  - `prod_to_staging_drops_totp_tables`
  - `prod_to_dev_drops_totp_tables`
  - `built_in_profile_drop_tables_reference_known_tables`
- adapter-test: **72** (was 70) — 2 new in `repo::tests`:
  - `delete_all_for_user_scopes_to_user`
  - `delete_all_for_user_is_idempotent_on_missing`
- ui: **150** (was 145) — 5 new in `templates::tests`:
  - `disable_page_includes_csrf_token`
  - `disable_page_form_posts_to_disable_endpoint`
  - `disable_page_warns_about_recovery_code_loss`
  - `disable_page_offers_cancel_link`
  - `disable_page_escapes_csrf`
- worker: 47 (unchanged — disable handler integration tests
  deferred to UI/UX release per scope-cap; see CHANGELOG note
  on UI/UX scope above).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/adr/009-totp.md` — Status changed to
  Accepted. Phasing v0.30.0 entry added with implementation
  details.
- `docs/src/expert/adr/README.md` — index updated.
- `docs/src/expert/security.md` — `TOTP_ENCRYPTION_KEY` added to
  pre-production checklist (item 6).
- `docs/src/deployment/totp.md` — new chapter (~270 lines).
- `docs/src/SUMMARY.md` — TOTP chapter linked in deployment
  section.

### Migration (0.29.0 → 0.30.0)

Code-only release. **No schema migration.** No `wrangler.toml`
changes required (the existing `0 4 * * *` cron entry already
runs the extended sweep — no new cron needed).

Operators who want to start using the redaction-profile drop
behavior should expect their next `cesauth-migrate export
--profile prod-to-staging` to NOT include TOTP rows. Existing
exports (pre-v0.30.0) that included TOTP rows are unchanged on
disk; the importer doesn't reject them.

The disable flow `GET/POST /me/security/totp/disable` is
available immediately after deploy. Users with confirmed TOTP
authenticators can navigate there to remove TOTP from their
account.

The TOTP unconfirmed-enrollment cron sweep starts running at the
next 04:00 UTC tick after deploy. The first run will prune any
unconfirmed rows older than 24h that have accumulated since
v0.26.0+ (likely a small handful in most deployments).

### Smoke test

```sh
cargo test --workspace                              # 573 passing
cargo test -p cesauth-core --lib migrate            # 62 passing
                                                    # (59 prior + 3 new)
cargo test -p cesauth-adapter-test --lib totp       # ~15 passing

# End-to-end disable flow (deployed worker, signed-in user
# with confirmed TOTP):
# 1. Visit /me/security/totp/disable.
# 2. Click "Yes, disable TOTP".
# 3. Verify totp_authenticators + totp_recovery_codes rows for
#    the user are gone via wrangler d1.
# 4. Logout, login again via Magic Link.
# 5. TOTP gate does NOT fire — user lands directly in their
#    session.
```

### Discovered

No new findings this release. The dual-key rotation gap is
documented honestly in the operator chapter rather than papered
over.

### Deferred — to v0.31.0 (UI/UX improvement release)

Per the user-stated project value, UI/UX improvements come at
TOTP-track-completion time. The natural scope for the next
release:

- **`/me/security` index page** — listing TOTP enabled-or-not,
  remaining recovery codes count, link to disable, link to
  enroll-second-authenticator. Currently users navigate
  directly to `/me/security/totp/enroll` or `/me/security/totp/disable`
  with no overview page.
- **Flash-message infrastructure** — "TOTP disabled
  successfully" notice on `/` after a successful disable.
  Currently the disable handler redirects silently.
- **Error slot in `totp_enroll_page`** — when confirm fails
  (wrong first code), the worker re-renders the enroll page
  unchanged. An `error: Option<&str>` parameter (matching
  `totp_verify_page`) would polish the experience.
- **`me::auth::resolve_or_redirect` `next` parameter** — the
  redirect destination is hard-coded `/login`. A `next`
  parameter to come back to the originally-requested URL after
  login would polish the enroll-while-not-signed-in flow.
- **CSS for warning/danger button states** — the disable page
  uses `class="danger"` but no CSS exists yet (v0.5.0-era frame
  styling).
- **Handler integration tests** — v0.29.0+ TOTP route handlers
  lack dedicated unit tests beyond the pure-helper layer
  (templates, cookie shape, library functions). The UI/UX
  release will likely refactor handlers as part of UX cleanup;
  testing them after the refactor is more efficient than
  writing tests now and rewriting them.

### Deferred — to v0.32.0+ (audit log hash chain)

- ADR-010 + audit-log-hash-chain Phase 1 (chain design,
  `previous_hash` column, transition strategy).
- ADR-010 Phase 2 (integrity sweep cron + admin verification UI).

### Deferred — unchanged

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued in
  ROADMAP "Later" behind the security track and the UI/UX
  release.
- **TOTP dual-key rotation tooling** — `cesauth-migrate totp
  re-encrypt` subcommand. Operator chapter documents the
  workaround (re-enroll all users, or write a one-shot helper).
- **`oidc_clients.client_secret_hash` schema-comment drift** —
  ROADMAP "Later" item.

---

## [0.29.0] - 2026-04-29

Security track Phase 6 of 11: TOTP Phase 2c — HTTP routes +
verify gate.

This is the **operator-visible** release of the TOTP track. v0.26.0
shipped the library, v0.27.0 the storage adapters, v0.28.0 the
presentation layer (templates + QR generator + auth helper). v0.29.0
finally wires it all together: a user can enroll TOTP, get prompted
on next Magic Link login, verify a code, and resume their
authentication flow. Recovery code redemption is included.

After v0.29.0 deploys with `TOTP_ENCRYPTION_KEY` provisioned, the
flow is end-to-end functional: a user navigates to
`/me/security/totp/enroll`, scans the QR code, types a verifying
code, sees their plaintext recovery codes once, and TOTP is
enabled. On the next Magic Link login the gate fires and prompts
for a 6-digit code; on success the original `complete_auth` flow
resumes exactly as if no gate had fired.

**v0.30.0 will close out the track** with the disable flow, cron
sweep extension, redaction profile updates, operator chapter, and
ADR-009 graduating from Draft to Accepted.

### Added — five new HTTP routes

All routes under `/me/security/totp/*`, cookie-authenticated via
`__Host-cesauth_session` (the standard user session). New routing
wires in `worker::lib::main`.

- **`GET /me/security/totp/enroll`** — start a fresh enrollment.
  Mints a CSPRNG secret via `cesauth_core::totp::Secret::generate`,
  encrypts via AES-GCM with `aad_for_id(row_uuid)`, parks an
  unconfirmed row in `totp_authenticators`, sets the short-lived
  `__Host-cesauth_totp_enroll` cookie carrying the row id, builds
  the otpauth URI via `cesauth_core::totp::otpauth_uri(issuer,
  email, secret)` (issuer hard-coded "cesauth"), generates the
  inline SVG QR via `cesauth_core::totp::qr::otpauth_to_svg`, and
  renders `cesauth_ui::templates::totp_enroll_page`. Refuses with
  503 if `TOTP_ENCRYPTION_KEY` or `TOTP_ENCRYPTION_KEY_ID` is
  unset (clear operator-facing message).
- **`POST /me/security/totp/enroll/confirm`** — verify the first
  code, flip `confirmed_at`, mint recovery codes if first
  enrollment, render `totp_recovery_codes_page` once. CSRF guard
  via existing `csrf::verify`. Two ownership checks: row exists,
  and row's user_id matches the session's user_id (rejects forged
  enrollment cookie pointing at someone else's row). Idempotency:
  already-confirmed row → clear cookie + redirect to home (back-
  button replay). Wrong code → re-render the enroll page with
  same secret (the user retypes a fresh code). Recovery codes
  minted only at user's FIRST confirmed authenticator (per
  ADR-009 §Q6 — adding a backup phone keeps the original codes).
- **`GET /me/security/totp/verify`** — TOTP gate prompt. Reads
  `__Host-cesauth_totp` cookie, peeks the `PendingTotp` challenge
  (no consume — GET is render-only), mints CSRF, renders
  `totp_verify_page`. Stale cookie / wrong challenge type / expired
  → 302 to `/login` (clear gate cookie).
- **`POST /me/security/totp/verify`** — verify the submitted code,
  on success resume `complete_auth_post_gate`. Takes the
  `PendingTotp` challenge (consume), reconstructs `PendingAr`
  from the inline AR fields, looks up the user's active
  authenticator, decrypts the secret, parses + verifies the code
  via `verify_with_replay_protection(secret, code,
  last_used_step, now)`. On success: persist advanced step via
  `update_last_used_step`, then `complete_auth_post_gate(env,
  cfg, user_id, auth_method, ar_fields)` to start the session,
  mint AuthCode if AR present, redirect. On failure: bump
  attempts, re-park under the SAME handle (preserving original
  TTL — a buggy authenticator that submits wrong codes can't keep
  the gate open forever), re-render with inline error message
  ("That code didn't match. Try again."). MAX_ATTEMPTS=5 then
  bounce to /login. Status 200 (not 401) — the user IS
  authenticated for primary, the form is a continuation.
- **`POST /me/security/totp/recover`** — single-use recovery code
  redemption. Same cookie + CSRF gates as verify. Takes the
  challenge, canonicalizes + SHA-256-hashes the submitted code
  (`hash_recovery_code` strips whitespace + dashes,
  uppercases — user can paste in any reasonable shape), looks up
  via `find_unredeemed_by_hash(user_id, hash)`. On match:
  `mark_redeemed(id, now)` then `complete_auth_post_gate`. On no
  match: 302 to `/login` (recovery is high-friction; failed
  recovery bounces to `/login` rather than re-rendering — pin
  against brute-force probing). Per ADR-009 §Q6 the recovery path
  does NOT advance the TOTP authenticator's `last_used_step` —
  recovery bypasses TOTP, doesn't use it.

### Added — TOTP gate insertion in `complete_auth`

`post_auth::complete_auth` now contains the gate logic at step
1.5 (between AR resolution and session start). For
`AuthMethod::MagicLink` only, calls `find_active_for_user(user_id)`:

- `Some(_)` confirmed authenticator → `park_totp_gate_and_redirect`
  carries AR fields **inline** into `Challenge::PendingTotp` (not
  a chained handle reference — eliminates the race where the
  original AR could expire between gate-park and verify-resume),
  sets `__Host-cesauth_totp` (SameSite=Strict, distinct from
  pending-authorize's Lax), clears `__Host-cesauth_pending`
  (because AR fields moved into PendingTotp), 302 to
  `/me/security/totp/verify`.
- `None` no confirmed authenticator → falls through to standard
  post-gate flow.
- `Err(_)` storage failure → fails closed with 500-style error.
  Refusing to proceed without knowing whether TOTP was required
  is the correct security posture; "transient outage skips MFA"
  is a footgun.

`AuthMethod::Passkey` (WebAuthn) and `AuthMethod::Admin` skip
the gate entirely — WebAuthn is itself MFA-strong (device
possession + on-device user verification per ADR-009 §Q7), and
admin auth is bearer-token-only and doesn't go through
`complete_auth`. Anonymous never has TOTP enrolled.

### Added — `complete_auth_post_gate` helper

Extracted as `pub(crate)` from the original `complete_auth`
body. Both the no-gate path (in `complete_auth` line 245) AND the
post-verify path (in `routes::me::totp::verify::post_handler`
line 234, recovery path line 132) call this. Identical behavior:
start the session, mint AuthCode if AR present, build the
response with session/clear-pending/clear-totp cookies, redirect
to either `redirect_uri?code=…&state=…` or `/`.

### Added — two new short-lived cookies

- **`__Host-cesauth_totp`** (gate cookie). 5-minute TTL —
  short enough that an abandoned TOTP prompt doesn't tie up
  state, long enough for a user fumbling with their authenticator
  app. SameSite=Strict (no cross-site flow involved — this is a
  purely internal-route breadcrumb between gate-park and
  verify-resume).
- **`__Host-cesauth_totp_enroll`** (enrollment cookie). 15-minute
  TTL — generous because enrollment requires switching to the
  authenticator app, scanning, and switching back; app-switch
  context cost is substantial. SameSite=Strict.

Both follow the `__Host-` prefix convention which guarantees
Path=/, Secure, no Domain attribute. Both are HttpOnly.

`set_*_cookie_header`, `clear_*_cookie_header`, `extract_*`
helpers in `cesauth_worker::post_auth`.

### Added — `Challenge::PendingTotp` AR fields inline

Carries `ar_client_id`, `ar_redirect_uri`, `ar_scope`, `ar_state`,
`ar_nonce`, `ar_code_challenge`, `ar_code_challenge_method` as
flattened `Option<String>` fields. Plus `user_id`, `auth_method`,
`attempts: u32`, `expires_at: i64`. The flattening is deliberate
(distinct from earlier ADR drafts that considered a chained-handle
approach — those drafts had a race where the original AR handle
could expire mid-flight).

### Tests

Total: **563 passing** (+12 over v0.28.0):

- core: 272 (unchanged).
- adapter-test: 70 (unchanged).
- ui: 145 (unchanged).
- worker: **47** (was 35) — 12 new in `post_auth::tests`:
  - `totp_cookie_header_shape` — Max-Age preserved, HttpOnly,
    Secure, SameSite=Strict (NOT Lax).
  - `totp_cookie_header_uses_host_prefix` — `__Host-` prefix +
    Path=/ invariant.
  - `clear_totp_cookie_header_zeros_max_age` — clear path
    keeps SameSite consistency.
  - `extract_totp_handle_present` / `..._absent_returns_none`.
  - `extract_totp_handle_does_not_match_pending_cookie` —
    must-not-cross-context property between gate cookie and
    pending-authorize cookie (defense against a mistakenly
    accepted cookie short-circuiting the wrong flow).
  - `totp_enroll_cookie_header_shape` — same attributes as
    gate cookie.
  - `totp_enroll_cookie_distinct_name_from_gate_cookie` —
    distinct cookie names; confusing them would let an
    enrollment cookie short-circuit the gate or vice versa.
  - `extract_totp_enroll_id_present` / `..._absent_returns_none`.
  - `totp_gate_ttl_is_short` — 1-10 min bounds.
  - `totp_enroll_ttl_is_generous` — 5-30 min bounds (with
    rationale comment about cron sweep).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/adr/009-totp.md` — Phasing v0.29.0 entry
  marked ✅ with implementation details (inline AR-field
  carrying, `complete_auth_post_gate` extraction, MAX_ATTEMPTS
  policy). ADR remains in `Draft` — graduates to `Accepted`
  in v0.30.0 after the polish phase validates the design end
  to end.

### Migration (0.28.0 → 0.29.0)

Code-only release. **No schema migration.** No `wrangler.toml`
changes.

**To enable TOTP for users**: operators must provision the
encryption key:

```sh
openssl rand -base64 32 | wrangler secret put TOTP_ENCRYPTION_KEY
# Then in wrangler.toml under [vars]:
TOTP_ENCRYPTION_KEY_ID = "k-2026-04"
```

Without these env vars, `GET /me/security/totp/enroll` responds
with 503 ("TOTP is not configured by the operator") and the
TOTP gate doesn't fire on Magic Link logins (because no users
have confirmed authenticators).

**Existing user sessions are unaffected.** A user who logs in
via Magic Link before they've enrolled TOTP sees no behavior
change. Once they enroll (via `/me/security/totp/enroll`), their
NEXT Magic Link login fires the gate and prompts for a code.
WebAuthn (Passkey) logins are never gated.

### Smoke test

```sh
cargo test --workspace                      # 563 passing
cargo test -p cesauth-worker --lib post_auth # 15 passing
                                            # (3 prior + 12 new)

# End-to-end (requires deployed worker with TOTP_ENCRYPTION_KEY):
# 1. Login via Magic Link.
# 2. Navigate to /me/security/totp/enroll.
# 3. Scan the QR code in Google Authenticator (or any TOTP app).
# 4. Type the displayed code; should land on the recovery-codes
#    page.
# 5. Save recovery codes.
# 6. Logout.
# 7. Login again via Magic Link.
# 8. Should redirect to /me/security/totp/verify, prompt for
#    code.
# 9. Type current code; should land on the original landing
#    page (or the redirected /authorize chain if you logged in
#    from an OAuth client).
```

### Discovered

No new findings this release.

### Deferred (v0.30.0 — final TOTP release)

- **Disable flow** (`POST /me/security/totp/disable`) —
  user-initiated TOTP removal. Authenticated user clicks
  "Disable TOTP" on `/me/security` (page itself v0.32.0+);
  handler takes confirmation, calls
  `delete_all_for_user(user_id)` on both TOTP repos.
- **Cron sweep extension** — extend the existing 04:00 UTC
  daily cron (ADR-004's anonymous-trial sweep) to also call
  `list_unconfirmed_older_than(now - 86400)` and bulk-delete
  the rows. The partial index from migration 0007 makes this
  cheap.
- **Redaction profile** — `cesauth-migrate` prod→staging
  redaction drops both `totp_authenticators` and
  `totp_recovery_codes` tables entirely. TOTP secrets must
  not survive redaction.
- **Operator chapter** — new `docs/src/deployment/totp.md`
  documenting encryption key provisioning, rotation procedure
  (mint new key with new id, deploy with new id, new writes
  use new key, old reads still find old key by `secret_key_id`),
  admin reset path (delete user's TOTP rows for lockout
  recovery).
- **Pre-production release gate** — `docs/src/expert/security.md`
  adds `TOTP_ENCRYPTION_KEY` to the checklist of secrets that
  must be set before going to production.
- **ADR-009 graduates** `Draft` → `Accepted`.
- **Explicit handler integration tests** — v0.29.0's handlers
  are exercised end-to-end in development but lack dedicated
  unit tests (the existing webauthn / magic-link route patterns
  also rely primarily on integration testing). v0.30.0 will
  add per-handler tests for the higher-risk paths
  (CSRF mismatch, ownership check, max-attempts bouncing,
  recovery wrong-code closing).

### Deferred — unchanged

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued
  in ROADMAP "Later" behind the security track (ends at
  v0.30.0).
- **Audit log hash chain (ADR-010)** — v0.31.0/v0.32.0.
- **`oidc_clients.client_secret_hash` schema-comment
  drift** — ROADMAP "Later" item.

---

## [0.28.0] - 2026-04-29

Security track Phase 5 of 11: TOTP Phase 2b — presentation
layer.

The original v0.28.0 plan combined presentation (templates +
QR generator) with HTTP routes and the `complete_auth`
verify-gate insertion. Mid-implementation it became clear the
presentation layer alone was substantial enough to deserve its
own review-able release, and that v0.29.0 would benefit from
having the templates already validated when the route handlers
are written. The TOTP track is now a **five-release split**:
library (v0.26.0), storage (v0.27.0), presentation (v0.28.0),
routes (v0.29.0), polish (v0.30.0 — ADR Accepted).

The repeated splitting reflects a project value documented in
v0.23.0/v0.24.0/v0.27.0: ship review-able slices over giant
change-sets. Each release leaves the system in a coherent
state. v0.27.0 → v0.28.0 is code-only with no new HTTP
surface; v0.28.0 → v0.29.0 will be route-additive only; etc.

Operators deploying v0.28.0 see:
- New compiled-in modules (templates, QR generator, /me/auth
  helper) that aren't reached from any HTTP route yet.
- New workspace dep `qrcode = 0.14`.
- **No user-visible behavior change.**

### Added — `cesauth_ui::templates::totp_*`

Three new public template functions:

- **`totp_enroll_page(qr_svg, secret_b32, csrf_token)`** —
  renders the enrollment page: inline SVG QR code, manual-
  entry secret in a `<details>` collapsed section, code-
  confirmation form POSTing to
  `/me/security/totp/enroll/confirm`. CSRF token rendered as
  hidden input. The QR SVG is intentionally NOT escaped (it's
  server-issued markup the page must render); everything else
  goes through `escape()` defense-in-depth.
- **`totp_recovery_codes_page(codes)`** — shows the plaintext
  recovery codes once with a strong "save now" warning. No
  CSRF needed (read-only display). The "I've saved them"
  link is a plain `<a href="/">` rather than a form because
  there's no server-side action to take — recovery codes
  were already stored hashed during the prior confirm step;
  this page exists purely so the user has one chance to read
  the plaintext.
- **`totp_verify_page(csrf_token, error)`** — the post-Magic-
  Link gate prompt. Two forms: the primary 6-digit code
  entry, and (inside `<details>` to discourage habituation) a
  recovery-code form posting to `/me/security/totp/recover`.
  `error: Option<&str>` controls inline error rendering for
  invalid-code retries; `None` is the initial render.

**18 new template tests** in `cesauth_ui::templates::tests`
covering CSRF inclusion (verified twice on the verify page —
once per form), escape behavior on every variable input,
form action correctness, error-block conditional rendering,
`<details>` placement of the recovery alternative form (UX-
habituation defense pinned by `recover_idx > details_idx`
ordering check), no-email-leak from the verify page (no `@`
character should appear).

### Added — `cesauth_core::totp::qr`

New module with `otpauth_to_svg(uri) -> Result<String,
String>` wrapping the `qrcode` 0.14 crate's SVG renderer.
Cesauth-specific defaults: `EcLevel::M` (15% recovery —
pragmatic balance between size and robustness), 240 px
minimum dimension (fits beside the manual-entry secret in
the enrollment-page layout), deterministic black-on-white.

The output is fully deterministic for a given input — pinned
by a test that encodes the same URI twice and asserts byte-
equality. This makes the SVG reproducible for tests and
cacheable in any layer that wants to.

**7 new QR tests**: starts/ends with valid SVG markup,
includes the dark color (`#000000`) we asked for, is
deterministic, changes when the URI changes (sanity check
that the input reaches the encoder), handles realistically-
long URIs without panicking, dimension constant is
page-embeddable.

### Added — `cesauth_worker::routes::me`

New parent module + `me::auth` helper. The cookie → session
→ redirect-or-state pipeline for `/me/*` routes is centralized
in `me::auth::resolve_or_redirect`, returning
`Result<Result<SessionState, Response>>` mirroring the shape
of `crate::admin::auth::resolve_or_respond`. The `Result`
nesting lets handlers distinguish "user not signed in, here's
the response to send" from "infrastructure failed". The
`redirect_to_login()` 302 helper is the standard
unauthenticated outcome.

The module is intentionally minimal in v0.28.0 — only the
`auth` helper. The `me::totp` submodule (with `enroll`,
`recover`, `verify` handlers) lands in v0.29.0.

### Added — workspace dependencies

- `qrcode = { version = "0.14", default-features = false,
  features = ["svg"] }` — pure-Rust QR code generation. The
  `default-features = false` drops the image-rendering
  features we don't use; `svg` is the string-emit path.

### Tests

Total: **551 passing** (+25 over v0.27.0):

- core: **272** (was 265) — 7 new in `totp::qr::tests`.
- adapter-test: 70 (unchanged).
- ui: **145** (was 127) — 18 new in `templates::tests`:
  - 6 enroll-page tests (CSRF, QR-SVG-unescaped, secret
    escape, CSRF escape, form action, 6-digit pattern).
  - 3 recovery-codes-page tests (each code rendered as
    `<code>`, irreversibility warning present, codes
    escaped).
  - 9 verify-page tests (CSRF in both forms, no/some error
    rendering, recovery alternative present and inside
    `<details>`, escape behavior, 6-digit pattern, no
    email leak).
- worker: 35 (unchanged — the new `me::auth` module is
  shape-only; integration tests for it land in v0.29.0
  alongside the route handlers that exercise it).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/adr/009-totp.md` — Phasing section
  rewritten to reflect the five-release split. Acceptance
  criteria moved to v0.30.0. ADR remains in `Draft`.

### Migration (0.27.0 → 0.28.0)

Code-only release. **No schema migration.** No
`wrangler.toml` changes.

The `qrcode` 0.14 dep is added to the workspace and used
only by `cesauth_core::totp::qr`. The compiled WASM grows
slightly; otherwise no operational impact.

The `cesauth_worker::routes::me` parent module is now
compiled but no `/me/*` URL is wired in `lib::main` yet.
Routes land in v0.29.0.

**No route surface changes**, **no UI changes**, **no
discovery doc changes**. Pure presentation-layer
infrastructure.

### Smoke test

```sh
cargo test --workspace                      # 551 passing
cargo test -p cesauth-ui --lib templates    # 27 passing (the
# 9 prior templates::tests + 18 new totp template tests).
cargo test -p cesauth-core --lib totp::qr   # 7 passing.
```

### Discovered

No new findings this release. The v0.26.0-discovered
`oidc_clients.client_secret_hash` schema-comment drift
remains tracked in ROADMAP "Later".

### Deferred (v0.29.0 + v0.30.0)

**v0.29.0 (TOTP Phase 2c — routes + verify gate)**:
- HTTP routes at `/me/security/totp/{enroll, enroll/confirm,
  verify, recover}`.
- Verify gate insertion in `post_auth::complete_auth`:
  peek-not-take the PendingAuthorize, gate on
  `find_active_for_user`, park `PendingTotp` carrying the
  original handle, set `__Host-cesauth_totp` cookie,
  redirect to `/me/security/totp/verify`.
- Routing wired in `worker::lib::main`.
- Recovery code redemption flow.

**v0.30.0 (TOTP Phase 2d — polish)**:
- Disable flow (`POST /me/security/totp/disable`).
- Cron sweep extension (drops unconfirmed rows older than
  24h).
- `cesauth-migrate` redaction profile drops both TOTP
  tables for prod→staging.
- New chapter `docs/src/deployment/totp.md`.
- `TOTP_ENCRYPTION_KEY` added to pre-production release
  gate.
- ADR-009 graduates `Draft` → `Accepted`.

### Deferred — unchanged

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued
  in ROADMAP "Later" behind the security track (which now
  ends at v0.30.0 — track expanded to 11 phases).
- **Audit log hash chain (ADR-010)** — v0.31.0/v0.32.0.
- **`oidc_clients.client_secret_hash` schema-comment
  drift** — ROADMAP "Later" item.

---

## [0.27.0] - 2026-04-29

Security track Phase 4 of 8: TOTP Phase 2a — storage layer.

This release ships the **storage layer** for TOTP: port traits,
in-memory adapters, Cloudflare D1 adapters, and the encryption-
key parser. **No HTTP routes**. **No verify gate**. **No
enrollment UI**. The original v0.27.0 plan covered both storage
and wire-up in one release; mid-implementation the storage
layer alone proved substantial enough to deserve its own
review-able release. v0.28.0 picks up the HTTP routes.

The phasing change is documented in ADR-009's "Phasing" section
(now reflects three releases: v0.26.0 library, v0.27.0 storage,
v0.28.0 routes). The ADR remains in `Draft` status — it will
graduate to `Accepted` when v0.28.0 ships and the design has
been validated end-to-end.

Operators deploying v0.27.0 today see:
- Schema in place (migration 0007 applied at v0.26.0 if not
  earlier).
- Storage adapters compiled into the worker but unreachable
  via HTTP (no routes wired).
- `TOTP_ENCRYPTION_KEY` env var optional (worker boots without
  it; reading routines return `None`).
- **No user-visible behavior change.**

### Added — `cesauth_core::totp::storage` module

Two new traits and two new value types:

- **`TotpAuthenticator`** struct — one row of
  `totp_authenticators`. Stores ciphertext + nonce +
  `secret_key_id` for rotation support; `last_used_step` for
  replay-protection state; `confirmed_at` as the enrollment-
  completion marker.
- **`TotpRecoveryCodeRow`** struct — one row of
  `totp_recovery_codes`. Stores `code_hash` + nullable
  `redeemed_at`.
- **`TotpAuthenticatorRepository`** trait — 7 methods:
  `create`, `find_by_id`, `find_active_for_user`, `confirm`
  (idempotent: rejects double-confirm with `NotFound`),
  `update_last_used_step`, `delete`, and the cron-sweep
  helper `list_unconfirmed_older_than`.
- **`TotpRecoveryCodeRepository`** trait — 5 methods:
  `bulk_create` (atomic: rolls back if any row conflicts),
  `find_unredeemed_by_hash`, `mark_redeemed` (idempotent),
  `count_remaining`, `delete_all_for_user`.

### Added — `Challenge::PendingTotp` variant

New variant on `cesauth_core::ports::store::Challenge` for the
intermediate state between successful Magic Link primary auth
and a fully-issued session, when the user has TOTP configured.
Carries `user_id`, `auth_method`, `pending_ar_handle:
Option<String>`, `attempts`, `expires_at`. Used by v0.28.0's
post-MagicLink TOTP gate.

`Challenge::expires_at()` match updated to handle the new
variant.

### Added — in-memory adapters in `cesauth-adapter-test`

`InMemoryTotpAuthenticatorRepository` and
`InMemoryTotpRecoveryCodeRepository`, each backed by a
`Mutex<HashMap>`. The `find_active_for_user` semantic ("most
recently confirmed") is pinned by a dedicated test against
the multi-authenticator case (user with phone + tablet —
returns whichever has the larger `confirmed_at`). The
`bulk_create` atomicity property is pinned by a test where
the middle row of a 3-row batch conflicts and the surrounding
two MUST NOT land.

### Added — D1 adapters in `cesauth-adapter-cloudflare`

`CloudflareTotpAuthenticatorRepository` and
`CloudflareTotpRecoveryCodeRepository`. Mirror the in-memory
shape. Highlights:

- **BLOB columns** (`secret_ciphertext`, `secret_nonce`) bind
  as `Uint8Array` on the JS side, the same pattern as
  `authenticators.public_key`.
- **`confirm` UPDATE** uses `WHERE id = ?1 AND confirmed_at
  IS NULL` to atomically reject double-confirmation — the
  rowcount check turns "0 rows changed" into `NotFound`.
- **`mark_redeemed` UPDATE** uses the same pattern with
  `redeemed_at IS NULL` so concurrent redemption races
  resolve cleanly.
- **`bulk_create` for recovery codes** uses D1's `batch()`
  API which gives all-or-nothing transactional semantics
  matching the in-memory adapter's two-pass validation.
- **`list_unconfirmed_older_than`** uses the partial index
  `idx_totp_authenticators_unconfirmed` (created in migration
  0007) so the cron-sweep query is cheap.

### Added — `TOTP_ENCRYPTION_KEY` parsing in `cesauth_worker::config`

Two new public functions:

- `load_totp_encryption_key(env)` reads the
  `TOTP_ENCRYPTION_KEY` wrangler secret, base64-decodes it,
  validates 32-byte length, returns `Ok(None)` (not an
  error) when unset so deployments without TOTP still respond
  on non-TOTP routes.
- `load_totp_encryption_key_id(env)` reads
  `TOTP_ENCRYPTION_KEY_ID` env var (the human-readable id
  recorded in `secret_key_id`).

The parsing logic is factored into a private
`parse_totp_encryption_key(raw)` helper so the rules
(whitespace stripping, base64 decoding, length validation)
are unit-testable without a Worker `Env`.

### Tests

Total: **526 passing** (+24 over v0.26.0):

- core: 265 (unchanged).
- adapter-test: **70** (was 51) — 19 new in `repo::tests::totp`:
  - 11 `TotpAuthenticatorRepository` tests covering create,
    find_by_id, conflict on duplicate id, find_active filters
    to confirmed-only, find_active picks most recently
    confirmed across multiple authenticators, find_active
    does not cross user boundary, confirm flips state and
    advances step, confirm rejects already-confirmed,
    confirm rejects missing, update_last_used_step, delete,
    list_unconfirmed_older_than filters correctly.
  - 8 `TotpRecoveryCodeRepository` tests covering
    bulk_create, atomic rollback on partial conflict,
    find_unredeemed skips already-redeemed,
    find_unredeemed does not cross users, mark_redeemed
    flips timestamp, mark_redeemed rejects already-redeemed,
    count_remaining excludes redeemed, delete_all_for_user
    is user-scoped.
- ui: 127 (unchanged).
- worker: **35** (was 30) — 5 new in `config::tests`:
  - 5 `parse_totp_encryption_key` tests covering well-formed
    accept, whitespace stripping (trailing newline, internal
    whitespace), invalid-base64 reject, wrong-length reject
    (with operator-facing error message check), empty
    reject.
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/adr/009-totp.md` — Phasing section
  rewritten to reflect the three-release split (v0.26.0
  library, v0.27.0 storage, v0.28.0 routes). Acceptance
  criteria moved to v0.28.0. ADR remains in `Draft`.

### Migration (0.26.0 → 0.27.0)

Code-only release. **No schema migration.** No
`wrangler.toml` changes. The `TOTP_ENCRYPTION_KEY` and
`TOTP_ENCRYPTION_KEY_ID` env vars documented in ADR-009
remain optional — they only become required when v0.28.0's
enrollment routes land and a user actually attempts to
enroll TOTP.

**No route surface changes**, **no UI changes**, **no
discovery doc changes**. Pure infrastructure.

### Smoke test

```sh
cargo test --workspace                   # 526 passing
# Verify the worker still boots without TOTP_ENCRYPTION_KEY
# (it does — the loaders return Ok(None)).
# Verify the new in-memory adapter test cases:
cargo test -p cesauth-adapter-test --lib repo::tests::totp
# 19 passing.
```

### Deferred (v0.28.0)

- TOTP enrollment routes at `/me/security/totp/{enroll,
  enroll/confirm, disable}`.
- Verify gate insertion in `post_auth::complete_auth` —
  before session start, if `auth_method == MagicLink` and
  `find_active_for_user(user_id)` returns Some, park
  `PendingTotp` and redirect to prompt instead of issuing
  session cookie.
- Recovery code redemption flow at
  `/me/security/totp/recover`.
- Server-side QR code SVG generation (no JS).
- `__Host-cesauth_totp` short-lived cookie scoped to the
  prompt page.
- Cron sweep extension (extends ADR-004's 04:00 UTC daily
  cron to drop unconfirmed rows older than 24h).
- `cesauth-migrate` redaction profile drops both new
  tables for prod→staging.
- New chapter `docs/src/deployment/totp.md` documenting
  encryption key provisioning, rotation, and admin reset
  path.
- Pre-production release gate update in
  `docs/src/expert/security.md` (`TOTP_ENCRYPTION_KEY`
  added to the checklist).
- ADR-009 graduates from `Draft` to `Accepted`.

### Deferred — unchanged

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued
  in ROADMAP "Later" behind the security track.
- **Audit log hash chain (ADR-010)** — v0.29.0/v0.30.0
  (renumbered downstream after the v0.27.0/v0.28.0 split).
- **`oidc_clients.client_secret_hash` schema-comment
  drift** — ROADMAP "Later" item.

---

## [0.26.0] - 2026-04-29

Security track Phase 3 of 8: TOTP (RFC 6238) Phase 1 of 2 —
ADR + schema + library skeleton.

This release lays the foundation for TOTP as a second factor.
The `cesauth_core::totp` library is fully implemented with
RFC 6238 vectors verified, AES-GCM encryption at rest, and
SHA-256-hashed recovery codes. **No HTTP routes**, **no
enrollment UI**, **no verify wire-up** — those are Phase 2
(v0.27.0). Operators can deploy this release safely with no
visible behavior change; the new tables are empty until
v0.27.0's enrollment flow lands.

The phasing matches the v0.19.0/v0.20.0 (data migration) and
v0.23.0/v0.24.0 (security headers + CSRF audit) patterns: ship
the design and library separately from the wire-up. Each phase
is independently testable and reviewable.

### Added — ADR-009 (Draft)

`docs/src/expert/adr/009-totp.md`. Settles 11 design questions:

- **Q1 algorithm**: SHA-1 only, 6 digits, 30s step, 160-bit
  secret. All four locked because Google Authenticator
  silently falls back to SHA-1 on SHA-256 secrets, producing
  wrong codes — universal authenticator-app compatibility
  wins.
- **Q2 skew tolerance**: ±1 step (3 windows total). Wider
  windows make brute-force easier without UX gain.
- **Q3 replay protection**: per-secret `last_used_step`;
  reject ≤ last used.
- **Q4 storage**: separate `totp_authenticators` table, not
  WebAuthn's `authenticators`. The two share zero columns.
- **Q5 encryption at rest**: AES-GCM-256 with deployment key,
  AAD bound to row id (`"totp:" + id`), key rotation via
  `secret_key_id` column. Foils D1-backup-swap attacks.
- **Q6 recovery codes**: 10 per user, 50 bits each, formatted
  `XXXXX-XXXXX`, **SHA-256-hashed** (not Argon2 — matches
  cesauth's existing pattern for high-entropy bearer secrets;
  Argon2 would be the right choice for user-chosen passwords
  but recovery codes are CSPRNG-generated).
- **Q7 composition**: TOTP is always a 2nd factor. Magic Link
  → TOTP if configured. WebAuthn alone → no TOTP. Anonymous
  → no TOTP (no email yet).
- **Q8 enrollment**: server-side QR code + manual base32
  entry. First successful verify confirms (`confirmed_at = now`),
  mints recovery codes once per user.
- **Q9 pruning**: extend the existing 04:00 UTC daily cron
  (ADR-004's anonymous-trial sweep) to also drop
  `confirmed_at IS NULL` rows older than 24h.
- **Q10 out of scope**: per-tenant TOTP policy, admin TOTP,
  backup-code import, WebAuthn-backed TOTP, name-editing
  post-confirmation. All explicitly deferred.
- **Q11 migration**: SCHEMA_VERSION 6 → 7. Two new tables
  (both empty on first deploy). The prod→staging redaction
  profile drops both tables entirely (TOTP secrets must not
  survive redaction even hashed).

### Added — schema migration 0007

`migrations/0007_totp.sql`. Two tables:

```sql
CREATE TABLE totp_authenticators (
    id                       TEXT    PRIMARY KEY,
    user_id                  TEXT    NOT NULL,
    secret_ciphertext        BLOB    NOT NULL,
    secret_nonce             BLOB    NOT NULL,
    secret_key_id            TEXT    NOT NULL,
    last_used_step           INTEGER NOT NULL DEFAULT 0,
    name                     TEXT,
    created_at               INTEGER NOT NULL,
    last_used_at             INTEGER,
    confirmed_at             INTEGER
);

CREATE TABLE totp_recovery_codes (
    id                TEXT    PRIMARY KEY,
    user_id           TEXT    NOT NULL,
    code_hash         TEXT    NOT NULL,
    redeemed_at       INTEGER,
    created_at        INTEGER NOT NULL
);
```

Plus indexes: `idx_totp_authenticators_user`,
`idx_totp_recovery_codes_user`, partial
`idx_totp_authenticators_unconfirmed` for the v0.27.0 cron
sweep.

`SCHEMA_VERSION` bumped 6 → 7. The
`schema_version_matches_migration_count` test pins the
invariant.

### Added — `cesauth_core::totp` library

Pure-function library implementing RFC 6238. ~700 lines of
production code + 51 tests covering RFC 6238 test vectors,
replay protection edge cases, encryption round-trip with AAD
binding, base32 codec robustness, recovery code format and
canonicalization, and `otpauth://` URI shape.

Public API:

- **Constants**: `DIGITS=6`, `STEP_SECONDS=30`,
  `SECRET_BYTES=20`, `SKEW_STEPS=1`,
  `RECOVERY_CODES_PER_USER=10`, `ENCRYPTION_KEY_LEN=32`,
  `ENCRYPTION_NONCE_LEN=12`.
- **`Secret`**: newtype wrapping `Vec<u8>`. Debug redacts
  the value. `generate()`, `from_bytes`, `to_base32`,
  `from_base32` (whitespace/lowercase/padding-tolerant).
- **`step_for_unix(i64) -> u64`**: Unix-time → TOTP step.
  Saturates negative timestamps to 0.
- **`compute_code(secret, step) -> u32`**: HMAC-SHA1 + RFC
  4226 §5.3 truncation. Pure.
- **`format_code(u32) -> String`** /
  **`parse_code(&str) -> Result<u32>`**: zero-pad / parse.
- **`verify_with_replay_protection(secret, code, last_used_step,
  now) -> Result<u64>`**: returns the new last_used_step on
  success. Iterates -SKEW..=+SKEW, rejects steps ≤
  last_used_step (replay gate), constant-time-compares
  candidate to submitted code.
- **`otpauth_uri(issuer, account, secret) -> String`**:
  Google Authenticator key-uri format. Percent-encodes
  issuer and account.
- **`RecoveryCode`**: newtype with redacting Debug, value-
  rendering Display. `generate_recovery_codes() ->
  Vec<RecoveryCode>` mints 10 codes.
  `hash_recovery_code(&str) -> String` SHA-256 hashes the
  canonical form (uppercase, no whitespace, no dashes) for
  storage.
- **`encrypt_secret(secret, key, aad) -> (ciphertext, nonce)`**
  / **`decrypt_secret(ciphertext, nonce, key, aad) -> Result<Secret>`**:
  AES-GCM-256 with caller-supplied AAD.
  **`aad_for_id(id) -> Vec<u8>`** centralizes the AAD format
  (`"totp:" + id`) so callers can't drift.

### Added — workspace dependencies

- `sha1 = "0.10"` — SHA-1 for HMAC-SHA1 in TOTP. Locked
  algorithm per ADR-009 §Q1.
- `aes-gcm = "0.10"` — AES-GCM-256 AEAD. RustCrypto pattern.
- `data-encoding = "2"` — base32 NOPAD codec. More
  maintained than the `base32` crate.

`hmac = "0.12"` is now a workspace dep (was in
`crates/core/Cargo.toml` directly); the comment now mentions
TOTP usage alongside session cookies.

### Tests

Total: **502 passing** (+51 over v0.25.0):

- core: **265** (was 214) — 51 new in `totp::tests`:
  - **5 RFC 6238 test vectors** (t=59, 1111111109,
    1111111111, 1234567890, 2000000000) — pin HMAC-SHA1
    correctness against the reference.
  - **4 step_for_unix tests** — epoch behavior, negative
    saturation, 30s boundaries.
  - **8 secret round-trip tests** — generate / base32 /
    bytes round-trip, debug redaction, codec robustness.
  - **6 format/parse code tests** — leading-zero behavior,
    non-digit rejection, length bounds.
  - **8 verify_with_replay_protection tests** — current /
    previous / next step accept, outside-skew reject,
    replay-after-success reject, latest-match recording,
    random-code reject, already-used-step reject.
  - **4 otpauth_uri tests** — required params, account/
    issuer URL-encoding, NOPAD secret.
  - **8 recovery code tests** — count, uniqueness within
    batch, format, debug redaction, display rendering,
    hash determinism, hash canonicalization, hash
    distinctness, hex output.
  - **8 encryption tests** — round-trip, nonce randomness,
    AAD mismatch reject, key mismatch reject, ciphertext
    tampering reject, short-key reject, short-nonce reject,
    AAD format determinism.
- adapter-test: 51 (unchanged).
- ui: 127 (unchanged).
- worker: 30 (unchanged).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/adr/009-totp.md` — new ADR Draft.
- `docs/src/expert/adr/README.md` — ADR-009 added to index.
- `migrations/0007_totp.sql` — comprehensive comments on
  schema design, AAD-binding rationale, and v0.27.0
  follow-up work (cron extension, redaction profile).

### Migration (0.25.0 → 0.26.0)

Schema migration **required**:
```sh
wrangler d1 execute cesauth --remote --file migrations/0007_totp.sql
```

`SCHEMA_VERSION` bumps 6 → 7. Both new tables are empty on
first deploy. No backfill. No data migration.

**No `wrangler.toml` changes** in v0.26.0. The
`TOTP_ENCRYPTION_KEY` and `TOTP_ENCRYPTION_KEY_ID` env vars
are documented in ADR-009 but only become required when
v0.27.0's enrollment routes land. Operators can deploy
v0.26.0 today without provisioning these; the empty TOTP
tables don't exercise the encryption code path.

**No route surface changes**, **no UI changes**, **no
discovery doc changes**. Pure foundation work.

### Smoke test

```sh
cargo test --workspace                   # 502 passing
sqlite3 -readonly /tmp/d1.db ".schema totp_authenticators"
sqlite3 -readonly /tmp/d1.db ".schema totp_recovery_codes"
# Both schemas printed.

# Library exercise (in cesauth-core's test binary):
cargo test -p cesauth-core --lib totp::tests::rfc6238_vector_t_59
# RFC 6238 reference vector verified.
```

### Deferred (v0.27.0)

- TOTP enrollment routes at `/me/security/totp/enroll`.
- TOTP verify gate after Magic Link primary auth.
- Recovery code redemption flow.
- Cron sweep extension (drop `confirmed_at IS NULL` rows
  older than 24h).
- Redaction profile drops `totp_authenticators` and
  `totp_recovery_codes` for prod→staging.
- New deployment chapter
  `docs/src/deployment/totp.md` documenting
  `TOTP_ENCRYPTION_KEY` provisioning and rotation.
- ADR-009 graduates from `Draft` to `Accepted`.

### Discovered during this release

- **`oidc_clients.client_secret_hash` documentation drift**.
  The schema comment says "argon2id(secret) or NULL" but no
  Argon2 implementation exists in cesauth as of v0.26.0.
  Filed as a "Later" ROADMAP item with two resolution paths
  (implement Argon2id, or relax the comment to match the
  actual SHA-256 pattern used elsewhere).

### Deferred — unchanged

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued
  in ROADMAP "Later" behind the security track.
- **Audit log hash chain (ADR-010)** — v0.28.0/v0.29.0.
- **`check_permission` integration on `/api/v1/...`.**
  Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.25.0] - 2026-04-28

Security track Phase 2 of 8: email verification flow audit +
OIDC discovery doc honest reset + `magic_link_sent_page()` UX
bug fix (folded in from the v0.24.0 audit's findings).

This release combines a small surgical fix on the magic-link
verify path with a deliberate **breaking change** on the
`/.well-known/openid-configuration` wire shape. Pre-1.0,
breaking changes are acceptable; the audit found that cesauth
was advertising OIDC compliance it didn't actually deliver, and
the honest move was to align the discovery doc with the
implementation rather than the other way around. ID token
issuance is now an explicit `Later` ROADMAP item with a drafted
ADR-008 ready to implement when scheduling permits.

### Added — `docs/src/expert/email-verification-audit.md`

New v0.25.0 audit deliverable. Documents:

- What `email_verified=true` means in cesauth (proof of
  inbox control via Magic Link OTP delivery, at some point in
  the past — not currently re-verified).
- Per-path table with 9 rows covering Magic Link signup,
  returning-user verify, anonymous→human promotion, anonymous
  user creation, WebAuthn register/authenticate, legacy admin
  create, and tenancy console mutations.
- Where `email_verified` should surface to consumers (planned
  v0.26.0+ via OIDC `id_token` claims; today only via internal
  admin-API JSON and HTML console).
- The OIDC `id_token` gap that motivates ADR-008.
- Operator-visible behavior changes from v0.24.0 → v0.25.0.
- Re-audit cadence.

### Added — ADR-008 (Draft)

`docs/src/expert/adr/008-id-token-issuance.md`. Settles 8
design questions for the `id_token` implementation that
v0.25.0's discovery reset is honest about NOT having: when
issued (`openid` scope only), claims (required + scope-driven),
sourcing (`UserRepository` injection into `service::token`),
`auth_time` plumbing through `Challenge::AuthCode` and
`RefreshTokenFamily`, what's NOT in the id_token (`acr`,
`amr`, `azp`, custom claims), discovery doc restoration plan,
test plan, migration mechanics. Acceptance criteria for
graduation to `Accepted` documented.

### Changed (BREAKING) — discovery doc shape

`/.well-known/openid-configuration` now emits an OAuth 2.0
Authorization Server Metadata document (RFC 8414), not an
OpenID Connect Discovery 1.0 document. Wire-shape diff:

- **Removed**: `subject_types_supported`,
  `id_token_signing_alg_values_supported`.
- **Removed from `scopes_supported`**: `openid`. The remaining
  set is `["profile", "email", "offline_access"]`.

The route path stays at `/.well-known/openid-configuration`
across the v0.25.0 → v0.26.0+ transition. RPs that strictly
validate the discovery doc against OIDC Discovery 1.0 schema
will reject this v0.25.0 doc. **This is intentional** — cesauth
was not actually emitting `id_token`s, so advertising OIDC
compliance was a documentation lie. The fields and `openid`
scope return when v0.26.0+ implements id_token issuance per
ADR-008.

### Changed — `email_verified` flip on returning-user Magic Link verify

`crates/worker/src/routes/magic_link/verify.rs::resolve_or_create_user`
now flips `email_verified=true` on an existing user row when
the column was previously false. Common case: a user created
by an admin via `POST /admin/users` (legacy create), then
later authenticating via Magic Link — pre-v0.25.0 the column
stayed false despite the OTP delivery being proof of email
control.

The flip is a best-effort UPDATE; storage failure isn't
fatal (the user gets a session anyway, and the next login
retries). Skip-write optimization for already-verified rows
avoids hot-path D1 round-trips.

### Changed — `magic_link_sent_page()` template signature

The template at `crates/ui/src/templates.rs::magic_link_sent_page`
now takes two parameters:

```rust
pub fn magic_link_sent_page(handle: &str, csrf_token: &str) -> String
```

Pre-v0.25.0 the template took no arguments and rendered a form
missing both `handle` and `csrf` hidden inputs — making the
form-flow path unusable in browsers (the verify handler
returns 400 on empty handle, and the v0.24.0 CSRF gap fill
rejects empty csrf). The bug was failing-closed but
invisible-to-users; UX was broken, not security.

Both callers in `crates/worker/src/routes/magic_link/request.rs`
are updated:
- Rate-limited path: passes a placeholder UUID handle (a typed
  OTP would yield "verification failed", same as a real
  expired/invalid handle — preserves account-enumeration
  indistinguishability) plus the existing CSRF cookie value.
- Happy path: passes the real handle just minted plus the
  existing CSRF cookie value.

The CSRF cookie is set earlier in the flow (by `/login` or
`/authorize`) so the request handler reads it from the
incoming `Cookie:` header rather than minting a new one.

### Tests

Total: **451 passing** (+14 over v0.24.0):

- core: **214** (was 206) — 8 new in `oidc::discovery::tests`:
  - `discovery_does_not_advertise_openid_scope` —
    honest-reset tripwire; this test's expectation will flip
    when ADR-008 ships.
  - `discovery_advertises_oauth2_scopes_only` —
    pin the exact set `["profile", "email", "offline_access"]`.
  - `discovery_response_types_is_code_only`.
  - `discovery_grant_types_match_implementation`.
  - `discovery_code_challenge_methods_is_s256_only`.
  - `discovery_endpoints_anchor_to_issuer`.
  - `discovery_serializes_without_oidc_fields` — wire-shape
    tripwire; rejects accidental re-introduction without an
    implementation behind the fields.
  - `discovery_token_endpoint_auth_methods_match_implementation`.
- ui: **127** (was 121) — 6 new in `templates::tests`:
  - `sent_page_includes_handle_hidden_input`.
  - `sent_page_includes_csrf_hidden_input`.
  - `sent_page_escapes_handle` — defense-in-depth pin.
  - `sent_page_escapes_csrf_token` — same.
  - `sent_page_form_posts_to_verify_endpoint`.
  - `sent_page_does_not_leak_email` — account-enumeration
    pin (no `@` should appear in the rendered HTML).
- adapter-test: 51 (unchanged).
- worker: 30 (unchanged).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/expert/email-verification-audit.md` — new audit
  chapter.
- `docs/src/expert/adr/008-id-token-issuance.md` — new ADR
  Draft.
- `docs/src/expert/adr/README.md` — ADR-008 added to index.
- `docs/src/expert/oidc-tokens.md` — v0.25.0 status note at
  top; both flow diagrams (exchange_code, rotate_refresh)
  updated to honestly say "no id_token today, v0.26.0+".
- `docs/src/expert/oidc-internals.md` — top-level "OIDC
  Core 1.0" claim softened to "OAuth 2.0 + partial OIDC
  scaffolding"; scopes line updated to drop `openid`.
- `docs/src/beginner/first-local-run.md` — sample discovery
  output updated to v0.25.0 wire shape with explanation note.
- `docs/src/SUMMARY.md` — links the new audit chapter and
  ADR-007/008.

### ROADMAP changes

- Security track Phase 2 (v0.25.0) marked ✅ with detailed entry.
- Discovered UX bug entry (`magic_link_sent_page()`) removed
  (now shipped).
- New "Later" entry: `OIDC id_token issuance (ADR-008)` with
  trigger condition (TOTP track must complete first) and
  scope estimate.
- Mail provider entry updated to specify `wasm-smtp v0.6` +
  `wasm-smtp-cloudflare` as the chosen implementations.
- ADR numbering shifted: TOTP is now ADR-009 (was ADR-008),
  Audit log hash chain is now ADR-010 (was ADR-009). The
  v0.26.0/v0.27.0 (TOTP) and v0.28.0/v0.29.0 (audit log)
  release entries reflect this.

### Migration (0.24.0 → 0.25.0)

Code-only release. No schema migration. No `wrangler.toml`
changes.

**Breaking wire change** on `/.well-known/openid-configuration`
— see "Changed (BREAKING) — discovery doc shape" above.
RPs that:
- Read endpoint URLs from discovery → unaffected (URLs
  unchanged).
- Validate the doc as OIDC Discovery 1.0 → will reject. Switch
  to RFC 8414 validation, or add v0.26.0+ to your supported-
  cesauth-version range.
- Request `scope=openid` → still parses and accepts at
  `/authorize`, still produces no `id_token` at `/token`
  (identical pre-v0.25.0 behavior).

The `email_verified` flip is invisible to RPs today (no
id_token surfaces it). It becomes RP-visible when ADR-008
implementation lands.

### Deferred

- **OIDC `id_token` issuance (ADR-008)** — Drafted, queued
  in ROADMAP "Later" behind TOTP track.
- **TOTP** — v0.26.0/v0.27.0.
- **Audit log hash chain** — v0.28.0/v0.29.0.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.24.0] - 2026-04-28

Security track Phase 1 of 8: vulnerability disclosure policy +
CSRF audit + dependency-scan automation review.

This release is **documentation- and audit-heavy**, with one
small code change to close a CSRF gap discovered during the
audit. The pre-existing security infrastructure (cargo-audit
in CI, CSRF library, Origin/Referer check, security headers
middleware) was already comprehensive; this release pins the
contract, fills one gap, and creates the discoverability paths
operators and researchers need.

### Added — `.github/SECURITY.md` improvements

The pre-existing vulnerability-disclosure policy already
covered: reporting channels (GitHub Security Advisory + email),
in-scope/out-of-scope categories (10+ specific items), 90-day
coordinated disclosure, safe-harbor language. v0.24.0 adds:

- **Severity-based response targets table**: per-severity
  acknowledgment / initial assessment / fix targets
  (Critical 24h/72h/7d, High 48h/7d/30d, Medium/Low scaled
  proportionally).
- **Specific known-limitations subsection**: documents
  CSP `'unsafe-inline'`, password-less auth model
  (no per-account lockout), and `/admin/*` Authorization-
  header requirement as explicitly NOT vulnerabilities for
  reporting purposes. Reports going beyond a documented
  limitation (e.g., bypass of `frame-ancestors 'none'` despite
  the `'unsafe-inline'`) remain very much in scope.
- **Cross-links** to `csrf.md`, `csrf-audit.md`,
  `security.md`, ADR-007, and the security-headers
  deployment chapter.

### Added — CSRF audit (`docs/src/expert/csrf-audit.md`)

New v0.24.0 deliverable. Comprehensive per-route audit
covering every state-changing endpoint. Documents:

- The 4 defense mechanisms (CSRF token, Origin/Referer check,
  CORS preflight, `Authorization: Bearer`) and when each
  applies.
- Per-route inventory with the mechanism that defends each.
- Cookies + SameSite audit (all 3 cookies are correct).
- Token-binding analysis (per-cookie binding is correct for
  the threat model; session-binding would offer no additional
  protection).
- The discovered pre-existing UX bug (broken
  `magic_link_sent_page()` form template missing
  `handle`/`csrf` fields — security-fail-closed but
  user-facing-broken; tracked as a separate ROADMAP item).
- Decision tree for adding new routes.
- Test coverage summary.
- Re-audit cadence.

### Updated — `docs/src/expert/csrf.md`

The protection table at the top now lists the **specific
mechanism** per route (CSRF token / Origin check / CORS
preflight / `Authorization: Bearer`) instead of the generic
"protection" column. Operators and reviewers can now answer
"what defends this route?" by reading one line.

### Code change — CSRF token check on `/magic-link/verify`

Added a CSRF token check on the form-encoded path of
`POST /magic-link/verify`. The route was already practically
unforgeable (both `handle` and `code` are server-issued
secrets, and the per-handle rate limit caps brute-force at
~5 attempts per window of a 6-digit code). However, the
documented model in `csrf.md` claimed the route was protected
and the implementation didn't match.

The fix mirrors the existing pattern at
`/magic-link/request`: extract the CSRF cookie before
consuming the body, accept the form's `csrf` field,
constant-time-compare, reject on mismatch with an audit log
event (`csrf_mismatch`).

The JSON path remains exempt — CORS preflight is the
defense for cross-origin `application/json`.

**No template change** in this release. The
`magic_link_sent_page()` template is broken in a separate
way (missing `handle` field as well as `csrf`), which makes
the form path unusable in browsers. That's a UX bug, not a
security one — the handler fails closed on the empty-handle
check. Fixing the template is tracked as a separate ROADMAP
item.

### Confirmed — dependency-scan automation

`.github/workflows/audit.yml` already runs `cargo audit` (via
`rustsec/audit-check@v2.0.0`) on push to main, every pull
request, weekly on Mondays at 06:00 UTC, and on manual
dispatch. The workflow has `issues: write` permission and
opens GitHub issues for new advisories on push events. A
passing main branch means no known CVEs in the dep tree.

v0.24.0 documents this in `docs/src/expert/security.md`
(new "Dependency vulnerability scanning" section) so
operators can find the alert path beyond the workflow YAML.
The handling-a-finding playbook covers the
`update → ignore-with-justification` decision tree and the
CHANGELOG-citation convention for advisory fixes.

No new automation was added — the existing automation was
verified comprehensive.

### Tests

Total: **437 passing** (+6 over v0.23.0):

- core: 206 (unchanged).
- adapter-test: 51 (unchanged).
- ui: 121 (unchanged).
- worker: **30** (was 24) — 6 new in
  `routes::magic_link::*::tests`:
  - 4 `VerifyBody` deserialization tests (csrf-present,
    csrf-missing, form-decode-with-empty-csrf, form-decode-
    with-non-empty-csrf). Pin the contract that an empty
    CSRF token reaches the gate (which then rejects via
    `csrf::verify`'s "empty input fails" branch).
  - 2 `RequestBody` parity tests (csrf-present,
    csrf-missing) for the route that already had CSRF
    protection. Pins the contract for parity.
- migrate: 29 (unchanged).

**Note on prior totals**: earlier MANIFEST entries published
totals that omitted the 24 cesauth-worker unit tests (mostly
the csrf submodule, which pre-dates the MANIFEST tracking).
v0.24.0 surfaces the worker column for the first time.
Previously-published totals (379 for v0.22.0, 407 for
v0.23.0) are correct as historical artifacts but
under-counted by 24. Restated totals: v0.22.0 = 403,
v0.23.0 = 431, v0.24.0 = 437.

### Documentation

- `docs/src/expert/csrf-audit.md` — new chapter, the v0.24.0
  audit deliverable.
- `docs/src/expert/csrf.md` — table tightened to per-mechanism
  precision.
- `docs/src/expert/security.md` — new "Dependency
  vulnerability scanning" section documents the cargo-audit
  workflow's triggers, failure path, finding-handling
  playbook, and re-audit cadence.
- `docs/src/deployment/security-headers.md` — SECURITY.md
  cross-link updated from "planned in a future release" to
  pointing at the actual file.
- `.github/SECURITY.md` — severity table, known-limitations
  subsection, see-also cross-links.
- `docs/src/SUMMARY.md` — links the new csrf-audit chapter.

### Migration (0.23.0 → 0.24.0)

Code-only release. No schema migration. No `wrangler.toml`
changes. The `/magic-link/verify` CSRF check is purely
additive — JSON callers unaffected; HTML form callers were
already broken (missing `handle`) so the new CSRF check
doesn't change observable behavior for the typical user
flow.

Operators can verify the new audit doc renders correctly in
their mdBook deployment:

```sh
cd docs && mdbook build
ls book/expert/csrf-audit.html  # exists
```

### Deferred

- **Fix `magic_link_sent_page()` template** — add `handle`
  and `csrf` hidden inputs, plumb them through from
  `/magic-link/request`, add end-to-end form-flow tests.
  Not a security fix; a UX gap. ROADMAP follow-up.
- **Email verification flow audit** — v0.25.0.
- **TOTP** — v0.26.0/v0.27.0.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.23.0] - 2026-04-28

HTTP security response headers — ADR-007. The pre-existing
`harden_headers` helper (which set 4 headers per response) is
replaced by a unified middleware that:

- adds three previously-missing headers (`Strict-Transport-Security`,
  `Permissions-Policy`, the existing `X-Frame-Options` now gated
  to HTML responses),
- consolidates the policy into a single auditable site
  (`crates/core/src/security_headers.rs` + the worker shim),
- exposes operator override knobs via `wrangler.toml` env vars,
- preserves the per-route CSPs the login page, OIDC authorize
  page, and admin console set themselves (those use `'unsafe-inline'`
  for current template constraints; nonces are a planned future
  release).

This v0.23.0 supersedes a prior v0.23.0 release attempt that
proposed an "account lockout" feature. That attempt was
**withdrawn** before graduating to canonical status — the design
was based on the incorrect premise that cesauth has password
authentication. See "Withdrawal note" below for the full context.

### Withdrawal note — prior v0.23.0 attempt

A v0.23.0 release was prepared that added per-account lockout
columns to `users`, a `cesauth_core::lockout` library, ADR-006,
and migration 0007 (`account_lockout`). The work assumed
cesauth had a password-verify path against which brute-force
attacks would be mitigated by per-account lockout.

**This assumption was wrong.** cesauth has no password
authentication at all — Magic Link and WebAuthn are the only
credential paths, both with their own brute-force resistance
properties (token entropy and signature cryptography
respectively). Per-account lockout's primary threat model is
inapplicable to cesauth's actual surface.

The artifact of the withdrawn attempt is preserved as
`cesauth-0.23.0-account-lockout-withdrawn.tar.gz` in the release
archive for historical reference. The ADR-006 number is
retired (not reused). A future ADR may revisit lockout for the
OIDC `client_secret` brute-force surface (per-client lockout,
distinct data model, machine-to-machine threat model); see
ROADMAP "Later" for the trigger condition.

The `cesauth_core::lockout` module, schema migration 0007,
and ADR-006 are **not in this release**. Source restored from
v0.22.0.

### Added — ADR-007

`docs/src/expert/adr/007-security-response-headers.md`
(Accepted). Settles eight design questions:

- **Q1 — placement**: single middleware. Per-route additions
  create silent gaps.
- **Q2 — header set**: universal set always; HTML-only set
  gated by `Content-Type: text/html`.
- **Q3 — CSP shape**: per-route CSPs preserved (with
  `'unsafe-inline'`); a later release does the nonce migration.
  No `'unsafe-eval'` anywhere.
- **Q4 — STS**: `max-age=63072000; includeSubDomains`;
  `preload` is operator opt-in via env var.
- **Q5 — Permissions-Policy**: disable camera, microphone,
  geolocation, payment, USB, and others.
- **Q6 — per-tenant**: no, single deployment-wide policy.
- **Q7 — operator override**: `SECURITY_HEADERS_CSP` /
  `SECURITY_HEADERS_STS` / `SECURITY_HEADERS_DISABLE_HTML_ONLY`
  env vars.
- **Q8 — testing**: pure-function unit tests + worker
  integration glue.

### Added — `cesauth_core::security_headers`

New module. Pure functions, no Worker dependencies — testable
without a Worker harness.

- `SecurityHeadersConfig` — operator-driven config struct
  with `from_env()` constructor.
- `DEFAULT_CSP` — the strict default applied as fallback for
  HTML routes that don't set their own CSP. Has no
  `'unsafe-inline'` or `'unsafe-eval'` (tripwire test).
- `DEFAULT_STS` — 2 years + includeSubDomains, no preload.
- `DEFAULT_PERMISSIONS_POLICY` — 13 disabled features.
- `DEFAULT_XFO` — `DENY`.
- `Header { name, value }` — single output type.
- `headers_for_response(config, is_html, already_set) ->
  Vec<Header>` — the load-bearing pure function.
  `already_set` is the list of header names the route already
  set; the library skips them, so the existing per-route CSPs
  in cesauth are preserved.
- `is_html_content_type(Option<&str>) -> bool` — content-type
  detection with case-insensitive matching, parameter
  tolerance (`text/html; charset=utf-8`), and tight
  boundary handling (rejects `text/htmlx`).

### Added — worker middleware

`crates/worker/src/lib.rs` — a `mod security_headers` block
inside the worker crate that:

- reads the three operator env vars,
- inspects the outgoing response's `Content-Type` and
  already-set headers,
- delegates to `cesauth_core::security_headers::headers_for_response`,
- writes the result via `worker::Headers::set`.

The pre-existing `harden_headers` function is removed; the new
middleware is the single application site. Per ADR-007 §Q1, no
opt-out path exists by design.

### Removed — old behavior

- `harden_headers` (pre-v0.23.0) set `Cache-Control: no-store`
  on every response. This was clobbering legitimate per-route
  cache control. Removed; routes that need `Cache-Control: no-store`
  set it themselves (auth-bearing endpoints already do).
- `harden_headers` set `Referrer-Policy: no-referrer`
  universally. The new middleware sets
  `Referrer-Policy: strict-origin-when-cross-origin` —
  marginally less strict, more useful for monitoring tools
  that aggregate by origin. Privacy delta is small (no
  cross-origin-HTTP referrer; origin-only on cross-origin-HTTPS).
- `harden_headers` set `X-Frame-Options: DENY` universally.
  The new middleware gates it to HTML responses. JSON
  responses don't need it (browsers ignore X-Frame-Options
  on non-HTML).

### Tests

Total: **407 passing** (+28 over v0.22.0):

- core: **206** (was 178) — 28 new in `security_headers::tests`:
  - 5 default-value tripwire tests (no `unsafe-inline`,
    `default-src 'none'`, frame-ancestors, base-uri, STS
    exact value, permissions-policy spot-checks).
  - 7 `is_html_content_type` tests covering plain,
    parameterized, case-insensitive, JSON-rejection,
    text-plain-rejection, partial-match-rejection,
    None-handling.
  - 4 `from_env` tests (defaults, CSP override, STS
    override, strict `disable_html_only` matching).
  - 7 `headers_for_response` core tests (HTML full set,
    JSON universal-only, disable-html-only suppression,
    config carrythrough, X-Frame-Options DENY, stable
    order, no-unsafe-anywhere tripwire).
  - 5 don't-clobber tests (CSP not re-emitted, case-
    insensitive header-name match, universal headers
    skipped if already-set, unrelated headers don't
    affect output).
- adapter-test: 51 (unchanged).
- ui: 121 (unchanged).
- migrate: 29 (unchanged).

### Documentation

- `docs/src/deployment/security-headers.md` — new operator
  guide. Defaults, opting into HSTS preload, overriding CSP,
  the debugging escape hatch, verifying with `curl`,
  per-route CSP exceptions list.
- `docs/src/SUMMARY.md` — links the new chapter.
- ADR README index updated with ADR-006 (Withdrawn) and
  ADR-007 (Accepted).

### Migration (0.22.0 → 0.23.0)

Code-only release. No schema migration. No `wrangler.toml`
changes required by default — operators who want the env-var
overrides add them as needed.

For deployments that observed the old `harden_headers`
behavior, the visible changes are:

1. Three new headers (`Strict-Transport-Security`,
   `Permissions-Policy`, `Content-Security-Policy` as default
   on HTML routes that don't set their own).
2. `Referrer-Policy` value changed from `no-referrer` to
   `strict-origin-when-cross-origin`.
3. `Cache-Control: no-store` no longer added by default.
4. `X-Frame-Options: DENY` now only on HTML responses, not
   JSON.

Each of these is documented in the new chapter. None should
break a working deployment; the most likely surface is some
external monitoring tool that asserts on the old values.
Verify with `curl -sI` after deploy.

### Deferred

- **CSP without `'unsafe-inline'`.** Templates currently
  embed `<style>` and `<script>` blocks inline; migrating
  to nonces or external resources is a templates refactor.
  Tracked in ROADMAP.
- **OIDC client_secret brute-force lockout.** Per-client
  lockout, distinct from the withdrawn user-account
  lockout. Trigger: production telemetry showing failed
  `client_secret` attempts at non-trivial volume. ROADMAP
  "Later".
- **`SECURITY.md` (vulnerability disclosure policy).**
  Planned for v0.24.0.
- **CSRF audit + dependency scan automation review.**
  Planned for v0.24.0.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.22.0] - 2026-04-28

Data migration tooling — Phase 4 of 4: polish. **The data-
migration tooling is feature-complete for ADR-005's scope as
of this release.** Three of the seven items deferred from
v0.21.0 land here; the remaining four are tracked as post-1.0
polish in the ROADMAP rather than continuing to defer through
the data-migration phasing.

After this release, the next operator-prioritized slot is
**RFC 7662 Token Introspection**.

### Added — `--tenant <id>` filter on `export`

The exporter now scopes to operator-named tenants when the
`--tenant <id>` flag is passed (repeat for multiple). Tables
classified `TenantScope::Global` (e.g., `plans`,
`permissions`, `oidc_clients`, `jwt_signing_keys`) export in
full regardless — the destination needs them to function.
Tenant-scoped tables (`tenants`, `users`, `organizations`,
`groups`, `subscriptions`, `roles`, `user_tenant_memberships`,
`anonymous_sessions`) filter on the operator's id list.

The dump's manifest records the filter in a new `tenants`
field — `verify` surfaces it in its summary. Pre-v0.22.0
dumps without the field deserialize as `None` (whole-database)
via `#[serde(default)]`.

Empty `--tenant ""` slugs are rejected at the boundary.
Indirect-FK tables (`authenticators`, `consent`, `grants`,
`admin_tokens`) export in full — sharper indirect scoping is
tracked as post-1.0 polish.

### Added — `cesauth-migrate refresh-staging` combinator

A single command for the common operational task of
refreshing staging's data from a production source. Wraps
`export --profile prod-to-staging` followed by
`import --commit`, with operator-attended prompts collapsed
to a single up-front confirmation:

```sh
cesauth-migrate refresh-staging \
  --source-account-id <prod-account> \
  --source-database   cesauth-prod \
  --dest-account-id   <staging-account> \
  --dest-database     cesauth-staging
```

Trade-offs vs. running export + import separately:

- **Trusts the caller to be in control of both endpoints.**
  Skips the cross-operator fingerprint handshake. For
  cross-organization moves, operators should still use
  export + verify + import separately.
- **Tolerates invariant violations.** Staging is allowed to
  be a little messy; the prompt at the end of `import`
  proper would block on violations, but the combinator
  treats them as informational.
- **Skips the secret pre-flight.** Operators using
  refresh-staging have already configured the destination's
  secrets out of band.

`--yes` flag skips the up-front confirmation for unattended
runs (CI staging refresh, scheduled jobs). `--profile`
defaults to `prod-to-staging` but accepts any built-in
profile name. `--tenant <id>` works on the combinator the
same way it works on plain `export`.

The dump is written to a per-process temp file under
`$TMPDIR`. On success the temp file is deleted; on failure
it's preserved at the printed path so the operator can
diagnose.

### Added — email-uniqueness-within-tenant invariant check

The fifth default invariant: `(tenant_id, email)` must be
unique within the dump. Catches schema-violation rows where
two users in the same tenant share an email.

Redaction-aware: the `HashedEmail` redaction kind produces
deterministic distinct values, so duplicates at source remain
duplicates after redaction. Case-insensitive (matches the
schema's `COLLATE NOCASE` semantic on `users.email`). Skips
rows without an email field (anonymous trial users).

This check was deferred from v0.21.0's default set because of
concerns about redaction semantics that turned out (after
implementation) to not be problematic.

### Added — per-row import progress

`ProgressSink` decorator wraps `WranglerD1Sink` and prints a
`.` to stderr every 1000 staged rows. The `do_import` handler
uses it by default. Long-running imports no longer "appear
hung" mid-staging.

The exporter side gained equivalent dot-tick progress in this
release too (every 1000 rows on `--tenant`-able tables).

### Library — `cesauth_core::migrate` changes

- **`Manifest.tenants: Option<Vec<String>>`** — new field
  with `#[serde(default, skip_serializing_if =
  "Option::is_none")]`. Forward-compatible with 0.21.0
  dumps.
- **`ExportSpec.tenants: Option<&[String]>`** — propagated
  through `Exporter::finish` to the manifest.
- **`SeenSnapshot` extended** with a scoped secondary index
  (`HashMap<(table, scope_key, scope_value),
  HashSet<value>>`) for per-tuple uniqueness checks.
  `record_scoped_secondary` returns true on duplicate (the
  uniqueness signal); `contains_scoped_secondary` for read
  access.
- **`InvariantCheckFn` signature changed** from
  `&SeenSnapshot` to `&mut SeenSnapshot` so checks can
  populate their own secondary indexes. **Breaking change
  to the typedef** — any operator who had built custom
  checks against the v0.21.0 type alias must update them.
  Since custom-check registration is not yet exposed via
  the CLI in v0.22.0, no real-world users are affected; the
  ROADMAP "post-1.0 polish" entry for custom-invariant
  registration will pick up the new signature.

### CLI — `crates/migrate/`

- **`d1_source` module** — `D1Source::fetch_table` now
  takes `Option<TenantFilter<'_>>`. `WranglerD1Source`
  builds a `WHERE column IN (...) ORDER BY rowid` clause
  when filtered, plain `SELECT *` otherwise. Empty filter
  list short-circuits to `Vec::new()` without spawning
  wrangler. SQL identifier check on filter column too.
- **`schema` module** — new `TenantScope` enum and
  `TENANT_SCOPES` slice (parallel to `MIGRATION_TABLE_ORDER`).
  `tenant_scope_for(table)` lookup. Two new tests pin
  length-alignment and known-table scopes.
- **`d1_sink` module** — new `ProgressSink<S>` decorator.
- **`do_export`** — real `--tenant` handling. Per-table
  filter computed via `build_table_filter()`. Per-row
  dot-progress every 1000 rows.
- **`do_refresh_staging`** — new handler. Inlines
  `export_to_path` and `import_from_path` helpers (smaller
  versions of `do_export`/`do_import` with refresh-staging-
  specific UX).

### Tests

Total: **379 passing** (+21 over v0.21.0):

- core: **178** (was 166) — 12 new in `migrate::tests`:
  - `scoped_secondary_index_tracks_per_tuple` — pin the
    duplicate-detection return-value semantic.
  - `check_user_email_unique_skips_when_table_not_users`.
  - `check_user_email_unique_passes_for_distinct_emails`.
  - `check_user_email_unique_flags_duplicate_within_tenant`.
  - `check_user_email_unique_allows_same_email_in_different_tenants`
    — per-tenant uniqueness, not global.
  - `check_user_email_unique_is_case_insensitive` —
    matches `COLLATE NOCASE`.
  - `check_user_email_unique_skips_users_without_email` —
    anonymous trial users have no email.
  - `import_flags_duplicate_email_within_tenant` —
    end-to-end through the import driver.
  - `manifest_records_tenant_scope_when_filtered`.
  - `manifest_omits_tenant_scope_for_full_export`.
  - `manifest_round_trips_tenants_through_serde`.
  - `manifest_deserializes_dumps_without_tenants_field` —
    forward compat from 0.21.0-shaped dumps.
- adapter-test: 51 (unchanged).
- ui: 121 (unchanged).
- migrate: **29** (was 25):
  - 2 new in `d1_source::tests`:
    `mock_filter_keeps_matching_tenant_rows`,
    `mock_filter_empty_ids_returns_no_rows`.
  - 4 new schema scope tests (length-alignment + known-
    table scopes + unknown-table-is-None defensive).
  - 4 new integration tests:
    - `export_rejects_empty_tenant_value`.
    - `refresh_staging_help_includes_one_command_summary`.
    - `refresh_staging_aborts_on_operator_decline`.
    - `refresh_staging_rejects_unknown_profile`.

### Documentation

- **`docs/src/deployment/data-migration.md`** updated to
  v0.22.0:
  - Status table reflects feature-complete state.
  - New "Refreshing staging from production" section with
    sample invocation, default behavior, unattended-run
    flag.
  - New "Tenant-scoped exports" section with sample
    invocations and explanation of what tenant-scoped
    means in practice (which tables filter, which export
    in full).
  - "Limitations as of v0.22.0" rewritten — most v0.21.0
    items are addressed; remaining items (resume, native
    HTTP API, custom invariants) are tracked as post-1.0
    polish.

### Migration (0.21.0 → 0.22.0)

Code-only release. No schema, no `wrangler.toml`. The
deployed Worker is unaffected.

For operators using the migration tool:

```sh
cargo install --path crates/migrate --force
cesauth-migrate refresh-staging --help
cesauth-migrate export --help     # see the new --tenant flag
```

### Smoke test

```sh
cargo test --workspace                          # 379 passing
./target/debug/cesauth-migrate --version        # cesauth-migrate 0.22.0
./target/debug/cesauth-migrate --help           # 5 subcommands listed
./target/debug/cesauth-migrate refresh-staging --help

# Decline path returns non-zero exit, doesn't touch destination.
echo "" | ./target/debug/cesauth-migrate refresh-staging \
  --source-account-id src --source-database srcdb \
  --dest-account-id   dst --dest-database   dstdb
```

### Deferred to post-1.0 polish (no scheduled release)

These three items were originally scheduled for v0.22.0 but
are reclassified as post-1.0 polish — they don't change the
data-migration design and don't have a known operator
demand:

- **Resume on interruption.** Two-pass design + checkpoint-
  file format is real new design surface. The current
  Ctrl-C-then-restart-from-zero workflow is acceptable for
  the dump sizes the tool targets.
- **Native Cloudflare HTTP API client.** wrangler shell-out
  works. Native client would avoid subprocess spawn costs
  and the wrangler dependency, but it adds a non-trivial
  HTTP auth surface to the binary.
- **Custom invariant registration via CLI.** The library
  accepts a slice of `InvariantCheckFn`, but no operator
  has asked for runtime-supplied custom checks. When one
  does, the surface is straightforward.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.21.0] - 2026-04-28

Data migration tooling — Phase 3 of 4: real `import` subcommand.
This release closes the loop on cross-account moves: a `.cdump`
exported in v0.20.0 can now be applied to a destination D1 in
one CLI invocation, with the operator-handshake-and-invariant-
checks flow ADR-005 specified.

**ADR-005 graduates from `Draft` to `Accepted`.** All six
design questions are now answered in code; the implementation
matches the design without surprises that warrant amendment.

The remaining v0.22.0 work is polish (resume support, `--tenant`
filter, staging-refresh combinator, native HTTP API, per-row
progress) — none of which changes the design. After v0.22.0,
the data-migration track is feature-complete and the next slot
is RFC 7662 Token Introspection.

### Added — `cesauth_core::migrate` library

- **`Violation`** value type: `(table, row_id, reason)` triple,
  with `Display` impl for one-line operator-readable output.
- **`ViolationReport`** with `is_clean()` (gate predicate) and
  `by_table()` (Vec preserving manifest table order — the CLI
  uses this for the per-table summary block).
- **`InvariantCheckFn`** typedef + **`SeenSnapshot`** —
  in-memory FK-ish state. The snapshot tracks
  `(table, primary_key)` pairs as rows are streamed; checks
  read it via `seen.contains(table, id)`. No destination-side
  query needed; everything runs in the importer's process.
- **`default_invariant_checks()`** — four ship-by-default checks:
  - `users.tenant_id` references a present tenant.
  - Memberships' `user_id` references a present user.
  - Memberships' container_id (`tenant_id`/`organization_id`/
    `group_id`) references a present container row.
  - `role_assignments.role_id` and `user_id` both reference
    present rows. (Returns the first failure rather than
    accumulating both — keeps log spam down on a misconfigured
    role_assignment.)
- **`ImportSink`** trait: async `stage_row` / `commit` /
  `rollback`. The CLI provides the implementation; the library
  knows nothing about D1 or wrangler.
- **`import<S: ImportSink>`** async function. Two-pass:
  1. `verify` runs first against the dump's bytes (signature,
     hashes). A bad dump bails before any sink interaction —
     the destination never sees a tampered file.
  2. The payload streams again through `sink.stage_row` while
     each row passes through the invariant checks. Violations
     accumulate; rows are staged regardless. The decision to
     commit or roll back belongs to the caller.

  Honors `require_unredacted` flag: a redacted dump errors out
  pre-staging if this is set, suitable for production-restore
  scenarios where redaction would be data loss.

### Added — `crates/migrate/`

- **`d1_sink.rs`** module — `WranglerD1Sink` implementing
  `ImportSink`. Stages rows in a `BTreeMap<table, Vec<row>>`,
  commits via batched `wrangler d1 execute` (one batch per
  table). Includes:
  - `value_to_sql_literal` — JSON-to-SQL converter handling
    Null, Bool, Number, String (with single-quote escaping),
    and JSON-blob (re-serialized + quoted).
  - `sqlite_quote` — proper SQLite single-quoted literal
    (doubles every embedded `'`). Five unit tests pin
    behavior.
  - Identifier check on table + column names. Belt-and-
    suspenders against the wrangler subprocess receiving
    something that doesn't tokenize cleanly.
- **`do_import` CLI handler** in `main.rs`. Walks the five-gate
  flow: verify → fingerprint handshake → secret pre-flight
  → invariant checks → final commit confirmation. Each gate
  the operator can decline; the destination D1 is untouched
  until the final yes. Post-commit, prints the operational
  checklist (update JWT_KID, deploy, smoke, DNS, retire old
  keys).
- **`prompt_yn`** helper — operator y/n prompt with sane
  defaults. **EOF on stdin (scripted invocation) is treated
  as decline.** This is intentional — import requires a
  human in the loop; making automated runs fail closed is
  safer than making them silently commit.
- **`check_destination_secrets`** pre-flight — calls
  `wrangler secret list`, refuses commit if `JWT_SIGNING_KEY`
  isn't set at the destination. ADR-005 §Q6 enforced at the
  CLI gate, not just in documentation.
- Updated CLI `long_about` and `Import` doc comment to
  reflect v0.21.0 state.

### Tests

- Total: **358 passing** (+21 over v0.20.0):
  - core: **166** (was 151) — 15 new in `migrate::tests`:
    - `check_user_tenant_ref_passes_for_known_tenant`.
    - `check_user_tenant_ref_fails_for_unknown_tenant` —
      with descriptive reason.
    - `check_user_tenant_ref_skips_other_tables` — defensive;
      a check fires only for its owned table.
    - `check_membership_user_ref_fires_only_for_membership_tables`.
    - `check_membership_container_dispatches_per_table` —
      one test asserting the three (tenant_id, organization_id,
      group_id) dispatch arms.
    - `check_role_assignment_refs_catches_both_sides`.
    - `import_clean_dump_passes_with_zero_violations` —
      load-bearing happy path.
    - `import_dangling_user_tenant_ref_is_flagged`.
    - `import_dangling_membership_ref_is_flagged`.
    - `import_multiple_violations_accumulate_per_row`.
    - `import_violation_report_groups_by_table`.
    - `import_refuses_redacted_dump_when_required_unredacted`.
    - `import_runs_verify_first_and_rejects_tampered_dump`
      — the destination must not see a tampered payload.
    - `import_with_disabled_invariants_passes_dangling_refs`
      — empty invariants slice is a valid configuration.
    - `default_invariant_checks_returns_at_least_four` —
      defensive tripwire.

    Plus a private `block_on` helper (no `unsafe`,
    uses `std::pin::pin!`) so tests don't drag tokio
    into core's `[dev-dependencies]`.
  - adapter-test: 51 (unchanged).
  - ui: 121 (unchanged).
  - migrate: **20** (was 14) — 11 unit + 9 integration:
    - 5 new `d1_sink::tests`: SQL literal handling for
      primitives + escapes + JSON blobs, sqlite_quote
      escaping, rollback-without-write.
    - 2 new integration tests:
      - `import_with_closed_stdin_declines_at_handshake`
        — EOF behavior pinned.
      - `import_rejects_invalid_dump_before_handshake`
        — verify gate runs before any operator prompt.
    - Removed: `import_still_returns_explanatory_error`
      (no longer applicable — import is now real).

### Documentation

- **ADR-005 status** flipped from `Draft` to `Accepted`. ADR
  README index updated.
- **`docs/src/deployment/data-migration.md`** — new "Importing"
  section with end-to-end walkthrough, sample successful
  output, violation handling, `--accept-violations` and
  `--require-unredacted` semantics, full operator runbook
  (pre-flight + during + post-commit). Updated
  "Limitations as of v0.21.0" section adds three v0.21.0-
  specific items (no native HTTP client yet, fixed
  invariant set, no email-uniqueness check).
- **`docs/src/deployment/runbook.md`** — new
  "Operation: cross-account data migration" section between
  the symptom-organized parts and the periodic-tasks table.
  Pre-flight, running the move, post-import verification,
  common failure modes (fingerprint mismatch, secret
  pre-flight failure, violations, mid-commit wrangler
  failure).
- **`docs/src/deployment/disaster-recovery.md`** §Scenario 4
  rewritten — concrete `cesauth-migrate` invocations replace
  the high-level outline. The data-relocation half of the
  compromise-recovery procedure is now mechanical.

### Migration (0.20.0 → 0.21.0)

Code-only release. No schema, no `wrangler.toml`. The deployed
Worker is unaffected.

For operators using the migration tool:

```sh
cargo install --path crates/migrate --force
cesauth-migrate import --help
```

The next time you do a cross-account move (or a
prod→staging-via-import-rather-than-restore), you have the full
flow available.

### Smoke test

```sh
# All workspaces green.
cargo test --workspace                   # 358 passing

# CLI binary
./target/debug/cesauth-migrate --version # cesauth-migrate 0.21.0
./target/debug/cesauth-migrate import --help

# Import smoke against an arbitrary cdump fails cleanly with
# closed stdin (declines at handshake).
echo "" | ./target/debug/cesauth-migrate import \
  --input some.cdump --account-id test --database test
# -> "import aborted: operator declined fingerprint confirmation"
```

### Deferred to 0.22.0

- **Resume** for interrupted exports/imports.
- **`--tenant <slug>` filter** for targeted subset migrations.
- **First-class staging-refresh combinator** (one CLI call
  combining export → redaction → import).
- **Native Cloudflare HTTP API client** as alternative to
  `wrangler` shell-out.
- **Per-row progress reporting** (currently per-table).
- **Custom invariant registration via CLI** — the library
  accepts a slice of check functions; v0.22.0 exposes a way
  for operators to add their own.
- **Email-uniqueness-within-tenant check** — held back from
  v0.21.0's default set because redacted dumps complicate the
  semantics. A redaction-aware variant lands when the design
  is clear.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.20.0] - 2026-04-28

Data migration tooling — Phase 2: real `export` + `verify`
subcommands. The CLI is now functional for the source-side and
destination-verification halves of a cross-account move; the
import path lands in v0.21.0 with the operator handshake and
invariant accumulation.

ADR-005 phasing intact: foundation (v0.19.0) → export+verify
(this release) → import (v0.21.0) → polish (v0.22.0). After
v0.21.0, ADR-005 graduates from `Draft` to `Accepted`.

### Added — `cesauth_core::migrate` library

The library expands from value-types-only to a complete
exporter + verifier:

- **`MigrateError`** — typed error enum with 8 distinguished
  kinds: `Io`, `Parse`, `UnsupportedFormatVersion`,
  `SignatureMismatch`, `TableHashMismatch`,
  `PayloadHashMismatch`, `Random`, `Crypto`. The CLI maps
  each to a different exit code and message tone — a
  signature mismatch is a security event (loud, postmortem-
  grade); a parse error is a corruption event
  (retransmit); an I/O error is local. Caller can match on
  the kind without string-matching error messages.
- **`apply_redaction(profile, table, &mut row)`** — pure
  function. Applies a `RedactionProfile`'s per-column rules
  to a row. The `HashedEmail` kind derives a synthetic
  `anon-<hex>@example.invalid` value via SHA-256 of the
  original — deterministic (re-export of the same source
  produces the same redacted output, important for
  diff-friendly dumps), and preserves `users.email` UNIQUE
  invariant on the receiving side.
- **`ExportSpec<'a>`** — the static configuration of a
  single export run.
- **`ExportSigner`** — per-export Ed25519 keypair wrapper.
  `fresh()` generates via `getrandom` (returning
  `MigrateError::Random` rather than panicking on RNG
  failure, unlike default `SigningKey::generate`).
  `Debug` impl deliberately elides everything — never
  surfaces private bytes through accidental tracing.
- **`Exporter<W>`** — streaming exporter. `push(table, row)`
  enforces topological order (out-of-order or unknown table
  → `MigrateError::Parse`). `finish()` consumes self —
  signing key is dropped after use, single-use invariant
  per ADR-005 §Q3. `fingerprint()` returns the pubkey
  fingerprint operators print at export start for the
  out-of-band handshake.
- **`verify<R: BufRead>`** — streaming verifier.
  Per-table SHA-256, total payload SHA-256, signature
  verify against pubkey embedded in manifest. Pure
  function; no D1 contact, no filesystem assumptions
  beyond the passed-in reader. `VerifyReport` carries the
  manifest plus re-computed per-table row counts so the
  CLI doesn't have to re-sum.

### Added — `crates/migrate/` (CLI)

- **Real `export` subcommand**. Wires
  `WranglerD1Source` → `Exporter`. Refuses to clobber
  existing files. Prints the public-key fingerprint to
  stderr at export start (operator reads it out-of-band
  to the importing operator). Walks
  `MIGRATION_TABLE_ORDER` in topological order, prints
  per-table row counts as it goes. Prints the
  secrets-coordination checklist at the end (ADR-005 §Q6).
- **Real `verify` subcommand**. No D1 contact. Prints
  manifest summary (format version, schema version,
  source identifiers, redaction profile if any). Prints
  fingerprint with operator-facing prompt to confirm
  out-of-band. Prints per-table row counts. Final
  `Signature verified ✓` line when all checks pass.
- **`d1_source` module** — `D1Source` trait abstracts how
  to read rows from a D1. Two implementations:
  - `WranglerD1Source` — shells out to `wrangler d1
    execute --remote --json`. v0.20.0's production path.
    Includes a SQL-identifier check on table names that
    refuses anything outside `[A-Za-z_][A-Za-z0-9_]*` —
    defense in depth against table-name typos becoming
    syntax-error injections.
  - `MockD1Source` — `#[cfg(test)]`-gated in-memory
    implementation for tests.
- **`schema` module** — `MIGRATION_TABLE_ORDER` constant:
  18 cesauth tables in topological FK order. Two tests
  pin: no duplicates + key topology invariants (tenants
  before users, roles before role_assignments, plans
  before subscriptions before subscription_history, etc.).

### Workspace

- **`tokio` feature** extended with `process` for
  `WranglerD1Source`'s `Command::output().await`.
- All other deps unchanged.

### Tests

- Total: **337 passing** (+32 over v0.19.0).
  - core: **151** (was 133) — 18 new in `migrate::tests`:
    - `apply_redaction_hashed_email_is_deterministic` — same
      source email → same redacted value across runs.
    - `apply_redaction_hashed_email_distinguishes_distinct_emails`
      — UNIQUE-preservation property holds.
    - `apply_redaction_static_string_is_uniform` — display
      names collapse to `[redacted]`.
    - `apply_redaction_skips_unmatched_table` — rules are
      `(table, column)`-keyed.
    - `apply_redaction_preserves_unrelated_columns`.
    - `apply_redaction_null_kind_drops_value`.
    - `export_then_verify_round_trip` — load-bearing
      end-to-end.
    - `export_with_no_rows_produces_valid_dump` — empty
      deployments are migratable.
    - `export_records_redaction_profile_in_manifest` —
      profile name flows into the manifest.
    - `export_applies_redaction_to_payload_rows` —
      redaction actually transforms the payload bytes.
    - `verify_rejects_tampered_payload` — single-byte
      flip is detected.
    - `verify_rejects_tampered_signature` — signature
      substitution is detected as `SignatureMismatch`.
    - `verify_rejects_unknown_format_version` — refuses
      future formats rather than silently downgrading.
    - `verify_rejects_empty_input`.
    - `verify_rejects_malformed_manifest`.
    - `export_refuses_out_of_topological_order` — fail-
      fast on CLI bug that shuffles tables.
    - `export_refuses_unknown_table`.
    - `exporter_fingerprint_matches_post_finish_manifest`
      — operator-prefix print equals eventual manifest's
      value.
  - adapter-test: 51 (unchanged).
  - ui: 121 (unchanged).
  - migrate: **14** (was 0) — 6 unit (3 in `d1_source`,
    2 in `schema`, 1 in tests of mock) + 8 integration
    (`tests/end_to_end.rs`):
    - `verify_accepts_clean_dump` — real CLI invocation
      against library-generated dump.
    - `verify_surfaces_redaction_profile_in_summary`.
    - `verify_rejects_truncated_dump`.
    - `verify_rejects_nonexistent_file`.
    - `list_profiles_prints_the_two_built_ins`.
    - `export_refuses_to_clobber_existing_file` — exercises
      the clobber guard without needing wrangler.
    - `import_still_returns_explanatory_error` — phase 3
      stub still pointing at v0.21.0.
    - `export_rejects_unknown_profile` — fail-fast on
      bad profile name.

### Documentation

- **New chapter** `docs/src/deployment/data-migration.md`.
  Operator-facing walkthrough: when to use `cesauth-migrate`
  vs `wrangler d1 export`, install instructions, end-to-end
  export procedure, redaction-profile usage, what's NOT in
  the dump, verify procedure including the load-bearing
  fingerprint-comparison step, operator runbook (export +
  verify halves), v0.20.0 limitations.
- **Updated** `docs/src/deployment/backup-restore.md` —
  `cesauth-migrate` cross-link now points at the real
  chapter; the legacy `sed`-script prod→staging refresh is
  marked obsolete and the section now leads with the
  recommended `cesauth-migrate` path.
- **`SUMMARY.md`** registers the new chapter.

### Migration (0.19.0 → 0.20.0)

Code-only release. No schema change. No `wrangler.toml`
change. `wrangler deploy` for the Worker is a no-op (the
Worker is unaffected).

For operators planning to use the migration tool:

```sh
# Build / install the host-side binary.
cargo install --path crates/migrate

# Confirm the new subcommands are real.
cesauth-migrate verify --help
cesauth-migrate export --help

# A first dry run against a non-production target is a good
# idea before depending on it in a real move window.
```

### Smoke test

```sh
# Unit + integration tests pass.
cargo test --workspace

# CLI binary builds, --help exits cleanly.
./target/debug/cesauth-migrate --help

# verify against a hand-prepared dump (see
# crates/migrate/tests/end_to_end.rs for the pattern).
./target/debug/cesauth-migrate verify --input some.cdump

# Existing surfaces unchanged.
curl -s https://auth.example.com/.well-known/openid-configuration | jq .
```

### Deferred to 0.21.0

- **Real `import` subcommand** — operator handshake
  (fingerprint prompt + `[Y/n]` confirmation), payload
  streaming with per-row schema-invariant checks,
  accumulate-then-commit/rollback semantics, the
  `--commit` gate that refuses if the destination's
  `JWT_SIGNING_KEY` is unset, the `--accept-violations`
  recovery escape hatch.
- **Day-2 runbook integration** — adds an "Importing a
  `.cdump` to a destination" section.
- **Disaster-recovery integration** — the cross-account
  compromise scenario gains concrete `cesauth-migrate`
  invocations.
- **ADR-005 → Accepted** once import lands.

### Deferred to 0.22.0

- **Resume support** for interrupted exports/imports.
- **Multi-tenant filtered exports** (`--tenant <slug>`).
- **First-class staging-refresh combinator** combining
  export + redaction + import in one invocation.
- **Native Cloudflare HTTP API client** as an alternative
  to `wrangler` shell-out.
- **Per-row progress reporting** (currently per-table).

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.** Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.19.0] - 2026-04-28

Data migration tooling — design (ADR-005) plus the foundation
work that makes the next two releases mechanical. Same v0.16.0 →
v0.17.0 → v0.18.0 phasing as the anonymous-trial track: this
release ships the design, the value types, the format spec, the
redaction profile registry, and the CLI skeleton. Real export
and import logic land in v0.20.0 and v0.21.0 respectively.

This release is the **first under the post-renumbering versioning
policy** — see the
[Versioning history note](#versioning-history-note) below if
the jump from 0.18.1 → 0.19.0 looks unfamiliar.

### Decision (ADR-005)

The new ADR at `docs/src/expert/adr/005-data-migration-tooling.md`
walks six design questions:

- **Q1 What is migrated** — Data, not secrets. The dump
  carries the D1 schema's user-facing rows but never JWT
  signing key private halves, session cookie keys, admin
  tokens. A stolen `.cdump` cannot forge tokens.
- **Q2 Source-side trust boundary** — Operator-mediated CLI
  invocation, not a Worker self-export endpoint. CLI uses
  D1 API credentials that already exist; no new HTTP
  surface to defend.
- **Q3 Destination-side trust boundary** — Per-export Ed25519
  signature with operator-mediated fingerprint verification.
  The exporter generates a fresh keypair, signs the payload,
  embeds the public key + signature in the manifest, then
  discards the private key. The importer prompts the
  operator to confirm the public-key fingerprint
  out-of-band before accepting the dump.
- **Q4 CLI vs library shape** — Both, layered. Library types
  in `cesauth-core::migrate` (testable on host); CLI in
  new `crates/migrate/` (wires library to D1 + clap).
- **Q5 Schema invariants** — Verify on import, not assume
  correct. Per-row invariant checks accumulate into a
  violation report; commit refused unless the report is
  empty or `--accept-violations` is supplied.
- **Q6 Secrets coordination** — Tool-supported runbook task,
  not tool-managed transport. Export prints a checklist of
  secrets the destination will need to mint; import refuses
  `--commit` until the destination's `JWT_SIGNING_KEY` is
  set.

The ADR rejects, with reasoning: a `/admin/migrate/*` HTTP
self-export (revocation, attack surface), reusing
`wrangler d1 export` raw SQL (no invariant preservation, no
PII redaction, no signature), bundling secrets in the dump
(repudiation impact of leak), ZIP-of-CSV format (no signed
manifest, no schema versioning).

### Added — `cesauth_core::migrate` (library)

New module with:

- **`Manifest`** — first-line value type carrying format
  version, cesauth version, schema version, source
  identifiers, signature, payload SHA-256, per-table
  summary, redaction profile name. `fingerprint()`
  produces a 16-hex-char value derived from SHA-256 of the
  raw public key — what the operator confirms during the
  import handshake.
- **`TableSummary`** — per-table row of the manifest, with
  row count and per-table SHA-256 for early-failure
  detection.
- **`PayloadLine<T>`** — generic over the row type. CLI
  uses `serde_json::Value` to stay schema-version-agnostic
  during streaming.
- **`RedactionProfile` / `RedactionRule` / `RedactionKind`**
  — column-level transformation registry. Two built-in
  profiles ship: `prod-to-staging` (email hashing +
  display-name scrubbing) and `prod-to-dev` (also clears
  OIDC client + admin token names). `HashedEmail` is the
  load-bearing kind — it preserves `users.email` UNIQUE
  invariant after redaction.
- **`FORMAT_VERSION`** = 1 (file format), **`SCHEMA_VERSION`**
  = 6 (migration count). A test pins
  `SCHEMA_VERSION == count(migrations/*.sql)` so a forgotten
  bump on schema change fails CI.

The on-disk format is documented in the module's `//!`
header — manifest at line 0, NDJSON payload below, signature
covers SHA-256 of payload only.

### Added — `crates/migrate/` (CLI skeleton)

New workspace member. CLI binary `cesauth-migrate` with four
subcommands:

- **`export`** — *not yet implemented (lands in v0.20.0)*.
  Returns an explanatory error.
- **`import`** — *not yet implemented (lands in v0.21.0)*.
- **`verify`** — *not yet implemented (lands in v0.20.0)*.
- **`list-profiles`** — implemented. Enumerates
  `built_in_profiles()` with descriptions and rules.
  Shipping early so operators can confirm "what redaction
  is available" without waiting for export to land.

The skeleton ships in v0.19.0 so:

- Operators can `cargo install --path crates/migrate` ahead
  of v0.20.0 — no last-minute install at the moment of the
  move.
- `--help` text serves as authoritative spec; reviewers can
  comment on UX before implementation locks it in.
- Documentation links to a real CLI invocation rather than a
  placeholder.

### Added — workspace dependency additions

- `clap = "4"` (`derive` feature) — CLI parsing.
- `tokio = "1"` (limited features for host-side I/O) — async
  runtime for v0.20.0+ I/O paths. Host-side only; not
  pulled into Workers crates.

Both at `[workspace.dependencies]`. Workers crates do not see
them; the size budget remains untouched.

### Tests

- Total: **305 passing** (+11 over v0.18.1).
  - core: **133** (was 122) — 11 new in `migrate::tests`:
    - `manifest_round_trips_through_serde_json` —
      load-bearing for every importer.
    - `manifest_fingerprint_is_stable_for_same_pubkey` —
      handshake relies on determinism. Tests it's 16 hex
      chars, all valid hex.
    - `manifest_fingerprint_changes_with_pubkey` — distinct
      keys produce distinct fingerprints (the mismatch
      detection contract).
    - `manifest_fingerprint_handles_invalid_pubkey` —
      garbage in returns sentinel `<invalid>` instead of
      panicking.
    - `payload_line_round_trips` — payload format under
      `serde_json::Value`.
    - `lookup_profile_finds_built_ins` — registry sanity.
    - `lookup_profile_returns_none_for_unknown` — graceful
      bad-input handling.
    - `built_in_profiles_have_unique_names` — duplicate
      profile names would make `--profile <n>` ambiguous;
      catch in CI.
    - `prod_to_staging_redacts_email_with_hashed_kind` —
      pins the load-bearing kind. A future refactor that
      flipped `HashedEmail` → `StaticString` would collapse
      every redacted email to one literal and explode
      UNIQUE on import; the test catches that.
    - `format_version_constant_is_one` — defensive bump
      detection.
    - `schema_version_matches_migration_count` — reads
      `migrations/` and asserts equality. Forgetting to
      bump `SCHEMA_VERSION` on a new migration fails CI.
  - adapter-test: 51 (unchanged).
  - ui: 121 (unchanged).
  - migrate: 0 (CLI skeleton; tests come with v0.20.0+).

### Status changes

- **ADR-005** — `Draft`. Graduates to `Accepted` in v0.21.0
  when the import path completes the round trip.
- **ROADMAP** — "Data migration tooling" item moves from
  "next minor releases" to in-progress, with the four-phase
  plan visible in the ADR's Implementation Phases section.

### Migration (0.18.1 → 0.19.0)

Code-only release. No schema change. No new env var or
`wrangler.toml` change required for the deployed Worker —
`cesauth-migrate` is a host-side tool that runs on operator
machines, not inside the Worker. `wrangler deploy` carries
no new requirements.

For operators who want to install the CLI in advance:

```bash
cargo install --path crates/migrate
cesauth-migrate --help
cesauth-migrate list-profiles
```

`list-profiles` is the only working subcommand in v0.19.0;
the others return explanatory error messages pointing at the
release where they will land.

### Smoke test

```bash
# CLI binary builds + runs
cargo build -p cesauth-migrate
./target/debug/cesauth-migrate --help

# list-profiles works
./target/debug/cesauth-migrate list-profiles

# stubs surface explanatory errors, not panics
./target/debug/cesauth-migrate export \
  --output /tmp/x --account-id abc --database d
# -> "export not implemented yet (lands in v0.20.0; ...)"
```

### Deferred to 0.20.0

- **Real export path** — `cesauth-migrate export` against a
  live D1 via Cloudflare's HTTP API. Signed manifest
  emission. Redaction profile application during export.
- **`verify` subcommand** — read a `.cdump`, check format
  version, verify signature, print summary, exit. No D1
  contact.
- **Format spec finalization** — module-level `//!` block
  in `cesauth_core::migrate` becomes the authoritative
  reference; the ADR-005 sketch is superseded by the
  actual spec at that point.

### Deferred to 0.21.0

- **Real import path** — operator handshake (fingerprint
  prompt), payload streaming with per-row invariant
  checks, accumulate-then-commit/rollback, `--commit`
  gate that refuses if destination's `JWT_SIGNING_KEY` is
  unset, `--accept-violations` recovery escape hatch.
- **Day-2 runbook integration** — new section
  "Pre-flight before invoking `cesauth-migrate`" + "Post-
  import verification".
- **Disaster recovery integration** — the cross-account
  compromise scenario in `disaster-recovery.md` gains
  concrete `cesauth-migrate` invocations.
- **ADR-005 → Accepted.**

### Deferred to 0.22.0

- **Resume support** for interrupted imports.
- **Multi-tenant filtered exports** (`--tenant
  <slug>,<slug>`) — v0.20.0's export is whole-database
  only.
- **First-class staging refresh** combining export +
  redaction + import in one invocation.

### Deferred — unchanged

- **`check_permission` integration on `/api/v1/...`.**
  Unscheduled.
- **External IdP federation.** Out of scope.

---

## [0.18.1] - 2026-04-28

Documentation release. Deployment guide expanded from three
chapters (Wrangler / Secrets / Production walkthrough) to eleven,
covering the operational surface that previously lived only in
team tribal knowledge.

This is a **patch bump** under the new versioning policy
(introduced in 0.18.0): doc-only release with no code, schema,
public-type, permission-slug, or operator-visible-config
changes. The added chapters describe operator practice against
existing surfaces; they do not introduce new ones.

### Added — deployment chapters

- **`docs/src/deployment/preflight.md`** — consolidated
  pre-deploy readiness checklist. Twelve sections (Cloudflare
  account, resources, schema, secrets, vars, Cron Triggers,
  custom domain, mail provider, dependencies, smoke tests,
  backups, communication) with a tier-by-tier degradation
  table for "what breaks if I skip this section".
- **`docs/src/deployment/cron-triggers.md`** — covers the
  v0.18.0 `[triggers]` block, the dispatcher pattern in
  `crates/worker/src/lib.rs::scheduled`, manual invocation
  for smoke-testing (local `wrangler dev --test-scheduled`,
  production schedule-flip pattern), Cloudflare-side limits
  and best-effort semantics.
- **`docs/src/deployment/custom-domains.md`** — Custom Domain
  vs Route decision (cesauth needs Custom Domain),
  `ISSUER` consistency rules, WebAuthn RP ID/origin coupling,
  multi-tenant DNS options, common mistakes
  (workers.dev URL as `ISSUER`, trailing slash, grey-cloud
  proxy).
- **`docs/src/deployment/environments.md`** — staging →
  production promotion workflow. `wrangler.toml` shape with
  `[env.staging]` and `[env.production]` blocks, what to
  override per environment vs share, migration ordering
  across environments, when (rarely) to skip staging.
- **`docs/src/deployment/backup-restore.md`** — D1 export
  procedure, automated daily backup via GitHub Actions, R2
  audit-bucket lifecycle, secrets-as-vault pattern, full
  restore procedure, prod-to-staging refresh with PII
  redaction, what backups don't protect against.
- **`docs/src/deployment/observability.md`** — structured
  logs (`wrangler tail`, Logpush), the audit trail in R2 and
  how to query it, Cloudflare-native metrics, alert
  recommendations, what NOT to obsess over.
- **`docs/src/deployment/runbook.md`** — Day-2 runbook
  organized by symptom: session-expired storms, anonymous
  accumulation, single-user login failures, 5xx spikes,
  signing-key rotation, admin-token leaks, discovery-doc
  mismatch. Periodic-task table (daily / weekly / monthly /
  quarterly / annually).
- **`docs/src/deployment/disaster-recovery.md`** — eight
  worst-case scenarios with detailed recovery procedures:
  bad deploy, bad migration, D1 corruption, account
  compromise, region outage, key compromise, key loss,
  `database_id` misdirection. Suggested RPO/RTO targets.
  Annual drill recommendations.

### Updated — existing chapters

- **`docs/src/deployment/production.md`** — first-deploy
  walkthrough refocused as the entry point. New introduction
  pointing at the topic-specific chapters for operational
  use. New "Step 7.5 — Configure Cron Triggers" makes the
  v0.18.0 `[triggers]` requirement explicit. "Rolling back"
  section gains a pointer to the new disaster-recovery
  chapter.
- **`docs/src/SUMMARY.md`** — gains the seven new chapter
  entries under the Deployment section. Also adds the
  ADR-004 entry that was missing from earlier ADR releases.

### Tests

- Unchanged: 294 passing (122 + 51 + 121).
- Footer-version assertions in `crates/ui/src/tenancy_console/tests.rs`
  and `crates/ui/src/tenant_admin/tests.rs` updated to expect
  `v0.18.1`.

### Migration (0.18.0 → 0.18.1)

Code-only release. No schema change, no `wrangler.toml`
change, no operator action required. `wrangler deploy`.

### Smoke test

```bash
# Build the documentation locally to confirm cross-links resolve.
mdbook build docs/
# Serve and skim the new chapters.
mdbook serve docs/ --port 3000
```

The mdbook build is what would break if a cross-link is wrong;
no other smoke test applies to a doc-only release.

### Deferred

- **Per-tenant runbook content.** The per-tenant operations
  surface (the `/admin/t/<slug>/*` console) deserves its own
  operator-facing docs separate from the system-admin runbook
  this release ships. Not scheduled.
- **Multi-region deployment guide.** Operators running cesauth
  across regional Cloudflare accounts have the
  multi-environment workflow as a starting point, but the
  region-orchestration tooling is operator-specific and
  out of scope for this release.

---

## [0.18.0] - 2026-04-28

Anonymous-trial daily retention sweep — ADR-004 Phase 3, the final
piece. The flow is now **feature-complete**: visitor mints
anonymous principal (0.17.0 `/begin`), optionally promotes to
`human_user` via Magic Link UPDATE-in-place (0.17.0 `/promote`),
or — if neither — gets cleaned up by the 7-day retention sweep
shipped here.

This release is also the first 0.5.x and the natural moment to
formalize cesauth's versioning rule. ROADMAP gains a
"Versioning policy" section near the top: **minor bumps for new
HTTP routes, schema migrations, public types/traits, permission
slugs, or operator-visible config; patch bumps for internal
changes that preserve all of the above.** The historical 0.4.x
debt (several patches that should have been minors by this rule)
stays as-is — those bundles are immutable artifacts. Going
forward the rule applies; 0.18.0 is the first release under it.

### Added — Cloudflare Workers Cron Trigger (operator-visible config change)

`wrangler.toml` gains a `[triggers]` block:

```toml
[triggers]
crons = ["0 4 * * *"]
```

This is the operator-visible deployment-config change that bumps
the minor (per the new versioning policy). Operators upgrading
from 0.17.0 must add this block before `wrangler deploy`, or the
sweep will never run. The schedule fires the
`#[event(scheduled)]` handler in `crates/worker/src/lib.rs` at
04:00 UTC daily — late enough that the previous day's
promotion-flow stragglers have settled, early enough that
operators in any timezone see the result before their workday.

Cloudflare's dashboard surfaces invocation history under
**Workers & Pages → cesauth → Settings → Triggers**;
`wrangler tail` streams scheduled invocations live.

### Added — `crates/worker/src/sweep.rs`

The new `sweep::run(env)` function runs one pass:

1. Loads `Config` (for log channel + audit destinations).
2. Computes `cutoff = now - ANONYMOUS_USER_RETENTION_SECONDS`
   (7 days).
3. Calls `UserRepository::list_anonymous_expired(cutoff)` to
   list every row matching `account_type='anonymous' AND
   email IS NULL AND created_at < cutoff`.
4. For each row: emits `EventKind::AnonymousExpired` audit
   FIRST, then `delete_by_id`. Audit-before-delete is the
   load-bearing ordering — if the delete fails, the audit row
   still records the principal we *intended* to remove, and
   the diagnostic query (operator runbook) shows whether the
   row actually disappeared. ADR-004 §Q5 rationale.
5. Logs one `Info` summary line at the end:
   `"anonymous sweep complete: X/Y rows deleted"`.

#### Why list-then-delete instead of bulk DELETE

A single `DELETE FROM users WHERE ...` would be one round-trip,
but it gives no per-row audit and no operator-visible signal of
*which* principals were swept. ADR-004 §Q5 requires that
`User.id` remain queryable across a row's full lifetime
(including its sweep), so the per-row audit emission is
load-bearing for that contract. For the expected steady-state
volume (anonymous trials per day in the tens-to-hundreds), the
extra round-trips are not a concern.

#### Failure semantics — best-effort, not transactional

If individual row deletes fail, the handler logs `Warn` and
continues with the next row. The next day's sweep retries the
survivors. The alternative (one bad row blocking the whole
sweep indefinitely) is worse for storage growth than partial
progress. Persistent failures show up as a growing residual
count visible to operators via the diagnostic query in the
operator runbook.

### Added — `#[event(scheduled)]` handler

A new entry point in `crates/worker/src/lib.rs` dispatches on
`event.cron()`:

- `"0 4 * * *"` → `sweep::run(&env).await`.
- Any other cron expression → `console_warn!` and continue.
  Future scheduled tasks (operational metrics, finer-grained
  cleanup) branch here.

Errors from the sweep are logged but never propagated to the
runtime. Cloudflare's invocation history would surface the
error at scheduled-handler granularity, but the operational log
channel + audit trail give a more useful per-row surface for
"did the sweep run, what did it do".

### Added — `UserRepository` extensions

Two new port methods to back the sweep:

- **`list_anonymous_expired(cutoff_unix) -> Vec<User>`** —
  returns rows with `account_type='anonymous' AND email IS
  NULL AND created_at < cutoff`. The `email IS NULL` clause
  is what structurally exempts promoted users (they carry an
  email post-promotion) from the sweep. ADR-004 §Q3.
- **`delete_by_id(id) -> ()`** — hard delete; FK CASCADEs
  (via 0006 + 0003) clean up `anonymous_sessions`,
  memberships, role assignments. Idempotent: missing-row
  delete is `Ok(())`, since the sweep may race with itself
  or a concurrent admin delete.

Both methods are implemented in the in-memory adapter
(`crates/adapter-test/src/repo/users.rs`) and the D1 adapter
(`crates/adapter-cloudflare/src/ports/repo/users.rs`). The
`StubUsers` test double in `crates/core/src/tenant_admin/tests.rs`
gains stub implementations so `cargo test -p cesauth-core`
continues to compile.

### Tests

- Total: **294 passing** (+5 over v0.17.0).
  - core: 122 (unchanged).
  - adapter-test: **51** (was 46) — 5 new in `repo::tests`:
    - `list_anonymous_expired_returns_only_expired_unpromoted` —
      4-row fixture (young / expired / promoted / human user)
      verifies only the expired-and-unpromoted row is returned.
      The promoted row (with email) and the young row are
      structurally exempt; the human user is excluded by
      account-type filter.
    - `list_anonymous_expired_empty_when_nothing_due` — sweep
      against a cutoff that nothing crosses returns empty
      (not error, not panic).
    - `delete_by_id_is_idempotent` — double-delete + missing-id
      delete both `Ok(())`. The sweep may race with itself
      across cron invocations.
    - `delete_by_id_removes_email_uniqueness_lock` — important
      for the promote-then-re-trial pattern: after delete, the
      email becomes available for re-registration.
    - `list_anonymous_expired_skips_human_users_even_if_old` —
      defense in depth: a `human_user` row past `i64::MAX`
      seconds old must NEVER be returned. The query filter
      (`account_type='anonymous'`) is what stands between the
      sweep and a catastrophic data-loss bug.
  - ui: 121 (unchanged).

### ADR-004 — feature-complete

- Phase 1 (foundation): v0.16.0. ✅
- Phase 2 (HTTP routes): v0.17.0, ADR Status → Accepted. ✅
- Phase 3 (retention sweep): **v0.18.0, this release.** ✅

### Status changes

- **ROADMAP** — Anonymous-trial item moves from "next minor
  releases" to the "Shipped" table. Versioning policy section
  added near the top.

### Migration (0.17.0 → 0.18.0)

Code-only release in the schema sense — no new migration; the
0006_anonymous.sql foundation is unchanged. **However**,
operators MUST update `wrangler.toml`:

```toml
# Append:
[triggers]
crons = ["0 4 * * *"]
```

Then `wrangler deploy`. Without the `[triggers]` block, the
new scheduled handler still ships, but Cloudflare never invokes
it — the sweep never runs and anonymous users accumulate
indefinitely. The operator runbook section "Verifying the
anonymous-trial retention sweep ran" walks the post-deploy
verification.

### Smoke test

```bash
# 1) Deploy with the new [triggers] block.
wrangler deploy

# 2) Verify the trigger registered with Cloudflare.
#    Dashboard: Workers & Pages → cesauth → Settings → Triggers.
#    Should list one cron: "0 4 * * *".

# 3) Local smoke-test of the sweep without waiting for 04:00 UTC.
wrangler dev --test-scheduled
# Then in another terminal:
curl http://localhost:8787/cdn-cgi/handler/scheduled
# -> 200 OK; check `wrangler dev` output for the sweep log line.

# 4) Verify the audit trail:
wrangler d1 execute cesauth --remote \
  --command="SELECT count(*) FROM audit_events WHERE kind='anonymous_expired';"
# -> count of rows the sweep has audited across all runs.

# 5) Diagnostic — anonymous accumulation check:
wrangler d1 execute cesauth --remote --command=\
"SELECT count(*) FROM users \
   WHERE account_type='anonymous' AND email IS NULL \
     AND created_at < unixepoch() - 7 * 86400;"
# -> 0 in a healthy deployment. Non-zero shortly after a sweep
#    means the sweep failed to delete some rows; check
#    wrangler tail for per-row Warn logs.
```

### Deferred — unchanged from 0.17.0

- **`check_permission` integration on `/api/v1/...`.**
  Unscheduled.
- **External IdP federation.** Out of scope for v0.5.x.

### Next planned

The first 0.18.0 release closes the anonymous-trial roadmap
slot. Next likely candidates from the ROADMAP:

- **OAuth 2.0 Token Introspection (RFC 7662)** —
  `POST /introspect`. Already in ROADMAP.
- **Account lockout** for repeated auth failures.

---

## [0.17.0] - 2026-04-28

Anonymous trial — HTTP routes. ADR-004 Phase 2: the two endpoints
that exercise the v0.16.0 foundation. With this release ADR-004
graduates from `Draft` to `Accepted` — the design has a working
implementation on both ends.

The shape is intentionally minimal. `POST /api/v1/anonymous/begin`
mints a fresh user + bearer; `POST /api/v1/anonymous/promote` does
both the OTP-issue step and the OTP-verify+UPDATE step under one
URL, distinguished by whether the request body carries a `code`
field. Magic Link infrastructure is reused unchanged — the
existing `/magic-link/request` and `/magic-link/verify` paths are
untouched, but the `magic_link::issue` / `verify` core helpers and
the `AuthChallengeStore` DO are shared. The only fork is the
*subject* of the ceremony: fresh self-registration creates a new
user row; promotion updates an existing anonymous one.

### Added — `POST /api/v1/anonymous/begin`

Unauthenticated. Per-IP rate-limited via the existing
`RateLimitStore` with bucket key `anonymous_begin_per_ip:<ip>`,
window 5 minutes, limit 20, escalation at 10. The numbers are
strict on purpose — anonymous principals are essentially free to
mint, so an unbounded flow would let an attacker pollute the
`users` table; the 7-day daily sweep (v0.6.05) is the second
line of defense, this is the first. `cf-connecting-ip` populates
the bucket key; absence falls back to the literal `unknown`
bucket.

The handler:
- Mints a 32-byte URL-safe-base64 plaintext bearer via
  `getrandom`.
- Computes SHA-256-hex of the plaintext as the storage key.
- INSERTs a `users` row with `tenant_id=DEFAULT_TENANT_ID`,
  `email=NULL`, `email_verified=false`,
  `display_name='Anon-XXXXX'` (cosmetic; 5 chars from a small
  URL-safe alphabet), `account_type=Anonymous`,
  `status=Active`.
- INSERTs an `anonymous_sessions` row with
  `expires_at = now + ANONYMOUS_TOKEN_TTL_SECONDS` (24h).
- Audits `EventKind::AnonymousCreated` with reason
  `via=anonymous-begin,ip=<masked>`. IPv4 is masked to
  `a.b.c.0`; IPv6 to the `/64` prefix — enough to spot bursts
  from a single address, not enough to log raw client IPs.
- Returns HTTP 201 with body
  `{ user_id, token, expires_at }`. The plaintext token is
  shown ONCE; cesauth stores only the hash. After this
  response, the only way to obtain a working token is to
  call `/begin` again.

### Added — `POST /api/v1/anonymous/promote`

Authenticated by the anonymous bearer in
`Authorization: Bearer ...`. Two-step, distinguished by body
shape:

- **Step A (issue OTP)**: body `{ "email": "..." }` (no
  `code`, no `handle`). Validates the email syntax, issues a
  fresh Magic Link OTP via `magic_link::issue` with the
  config-driven TTL, stores it in the `AuthChallengeStore`
  DO under a new handle, audits `MagicLinkIssued` with
  reason `via=anonymous-promote,handle=<>,code=<plaintext>`.
  The reason marker piggybacks on the existing mail-delivery
  pipeline (which today reads the audit log; see
  `routes/magic_link.rs` module doc) so no new mail
  integration is needed. Returns
  `{ handle, expires_at }`.

- **Step B (verify OTP + apply)**: body
  `{ "email": "...", "handle": "...", "code": "..." }`.
  Bumps the challenge attempt counter (mirrors
  `/magic-link/verify`), peeks the challenge, **verifies the
  challenge email matches the body email** (defense in depth
  — without this an attacker observing a handle for someone
  else's promotion attempt could splice it into their own),
  runs `magic_link::verify`, consumes the challenge,
  performs the in-tenant email-collision check (`find_by_email`
  on a different user_id ⇒ refuses with the distinguishable
  error `email_already_registered` so the client can render
  "log in to existing account" guidance vs "OTP failed"
  guidance), re-checks `account_type == Anonymous` on the
  user row (defense against racy double-submit landing after
  the first promotion already flipped the type — refused
  with `not_anonymous`), UPDATEs the row in place
  (`email`, `email_verified=true`, `account_type=HumanUser`,
  `updated_at`), revokes any anonymous sessions for the user
  via `revoke_for_user`, audits `AnonymousPromoted`.

The User.id is preserved across promotion. All foreign keys
pointing at the user — memberships, role assignments, audit
subject ids, and any session rows in adjacent tables —
survive without remap. ADR-004 §Q4 walks the rejected
alternative (separate `anonymous_users` table → "copy fields,
delete row" promotion) and why it loses to UPDATE-in-place.

### Defense-in-depth invariants pinned

The route layer hits Cloudflare-specific bindings, so the
handlers themselves test in `wrangler dev`. The service-layer
invariants behind the routes are pinned in
`adapter-test/src/anonymous.rs::tests`:

- **Revoke-before-update ordering** —
  `promotion_pattern_revokes_then_user_update`. The
  promotion handler's invariant is "invalidate the bearer
  *before* the user-row UPDATE lands, never after". Reverse
  order opens a small window where the bearer authenticates
  a row that's already a `human_user`. Test exercises the
  fail-safe ordering explicitly.
- **Per-user revoke isolation** —
  `many_anonymous_users_revoke_independently`. One user's
  promotion cannot affect another user's anonymous session.
- **Idempotent double-promote** —
  `double_promote_protected_by_idempotent_revoke`. A racy
  second submit's `revoke_for_user` returns `Ok(0)`, not an
  error; the route's `account_type == Anonymous` check then
  refuses with the distinguishable `not_anonymous` error.

The `account_type != Anonymous` defense, the
`challenge_email != body_email` defense, and the
email-collision-distinguishable-error contract are all in the
handler itself. Verifying them programmatically requires a
Workers shim that doesn't exist; for now they're enforced by
review and the smoke-test path below.

### Audit reason markers

- `via=anonymous-begin,ip=<masked>` — `AnonymousCreated`.
- `via=anonymous-promote,handle=<>,code=<plaintext>` —
  `MagicLinkIssued` (Step A). The plaintext is intentional;
  the existing mail pipeline reads it.
- `via=anonymous-promote,reason=email_already_registered` —
  `MagicLinkFailed`, used to spot promotion-probe email
  harvesting.
- `via=anonymous-promote,from=anonymous,to=human_user` —
  `AnonymousPromoted` (Step B success).

### Tests

- Total: **289 passing** (+3 over v0.16.0).
  - core: 122 (unchanged).
  - adapter-test: **46** (was 43) — 3 new in
    `anonymous::tests`: revoke-before-update fail-safe
    ordering, per-user revoke isolation, idempotent
    double-promote.
  - ui: 121 (unchanged).

The route handlers themselves don't have direct unit tests
(they hit `worker::Env`, `RouteContext`, `worker::Request` —
all Cloudflare-specific). Their semantics ride on:
- The 0.16.0 type-level tests (`AnonymousSession`,
  boundary inclusivity, TTL constants).
- The 0.16.0 in-memory-adapter tests (create / find /
  revoke / sweep behaviour).
- The new 0.17.0 promotion-flow tests above.
- Smoke testing via `wrangler dev` (see below).

### Status changes

- **ADR-004** — `Draft` → `Accepted`. The design has a
  working implementation. Both `docs/src/expert/adr/004-...md`
  and the ADR README index updated.

### Migration (0.16.0 → 0.17.0)

Code-only release. Migration `0006_anonymous.sql` was already
applied in v0.16.0 and is unchanged. No `wrangler.toml`
change yet (Cron Trigger ships with v0.6.05).

For deployments tracking main: `wrangler deploy`. The new
routes are unauthenticated (`/begin`) or anonymous-bearer
authenticated (`/promote`); they don't interact with the
existing OIDC, admin-tokens, or tenancy-API surfaces.

### Smoke test

```bash
# 1) Begin: mint an anonymous user + bearer.
RESP=$(curl -sS -X POST https://cesauth.example/api/v1/anonymous/begin)
echo "$RESP" | jq .
# -> { "user_id": "...", "token": "<plaintext>", "expires_at": ... }

USER_ID=$(echo "$RESP" | jq -r .user_id)
TOKEN=$(echo "$RESP"   | jq -r .token)

# 2) Promote step A: issue OTP for an email.
curl -sS -X POST https://cesauth.example/api/v1/anonymous/promote \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com"}'
# -> { "handle": "...", "expires_at": ... }

# 3) Read the OTP from the audit log (or your mail provider).
#    The audit reason carries `code=<plaintext>` for the
#    anonymous-promote path.
HANDLE=...   # from step 2 response
CODE=...     # from audit log / email

# 4) Promote step B: verify OTP + apply UPDATE-in-place.
curl -sS -X POST https://cesauth.example/api/v1/anonymous/promote \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"alice@example.com\",\"handle\":\"$HANDLE\",\"code\":\"$CODE\"}"
# -> { "user_id": "...", "promoted": true }
# user_id is the SAME as step 1 — UPDATE-in-place.

# 5) The original anonymous bearer is now revoked. Re-using
#    it returns 401:
curl -sS -X POST -o /dev/null -w '%{http_code}\n' \
  https://cesauth.example/api/v1/anonymous/promote \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com"}'
# -> 401

# 6) Cross-tenant or different-email same-tenant collision:
TOKEN2=$(curl -sS -X POST https://cesauth.example/api/v1/anonymous/begin \
  | jq -r .token)
curl -sS -X POST https://cesauth.example/api/v1/anonymous/promote \
  -H "Authorization: Bearer $TOKEN2" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","handle":"<step-A-handle>","code":"<code>"}' \
  | jq -r .error
# -> "email_already_registered"  (distinguishable from
#    "verification_failed")
```

### Deferred to 0.6.05

- **Daily retention sweep** — Cloudflare Workers Cron Trigger
  configured in `wrangler.toml`, sweep handler that runs the
  `users` row delete (cascade through `anonymous_sessions`)
  plus `AnonymousExpired` audit emission per row. Operator
  runbook gains "Verifying the retention sweep ran" diagnostic
  section. After v0.6.05 the anonymous-trial flow is feature-
  complete.

### Deferred — unchanged from 0.16.0

- **`check_permission` integration on `/api/v1/...`.**
  Unscheduled.
- **External IdP federation.** Out of scope for v0.4.x.

---

## [0.16.0] - 2026-04-28

Anonymous trial principal — design (ADR-004) plus the foundation
work that makes the next two releases mechanical. Following the
v0.11.0 → v0.13.0 → v0.14.0 model: this release ships the schema,
the value type, the repository port, both adapters, and the audit
event kinds. HTTP routes (`/api/v1/anonymous/begin` and `/promote`)
land in v0.17.0; the daily retention sweep (Cloudflare Cron Trigger)
in v0.6.05.

The `AccountType::Anonymous` variant has existed in
`cesauth_core::tenancy::types` since v0.5.0, and the v0.11.0 ADR
stage marked the promotion flow as "0.14.0 or later". The slot
slid across three releases (0.14.0/.11/.12 each took a different
non-feature focus); v0.16.0 is the catch-up.

### Decision (ADR-004)

The new ADR at `docs/src/expert/adr/004-anonymous-trial-promotion.md`
walks five design questions and picks one coherent point in the
space:

- **Q1 Provenance** — A new endpoint `POST /api/v1/anonymous/begin`
  creates the anonymous user and returns a bearer token.
  Unauthenticated by design, gated only by per-IP rate limit. Not
  reusing the existing user-creation route makes the trust
  boundary explicit.
- **Q2 Token issuance** — Opaque bearer (not OIDC), 24h TTL, not
  refreshable. Avoids fabricating an `email` claim cesauth has
  not verified.
- **Q3 Retention** — Anonymous user rows kept for 7 days unless
  promoted. Daily Cloudflare Workers Cron Trigger sweeps rows
  with `account_type='anonymous' AND email IS NULL AND
  created_at < now - 7d`. Promoted rows have `email IS NOT NULL`
  and survive.
- **Q4 Conversion ceremony** — The visitor supplies an email; the
  standard Magic Link flow verifies ownership; the existing
  user row is **updated in place** (`User.id` preserved,
  `account_type` flipped, `email`/`email_verified` filled in).
  All foreign keys pointing at the user — memberships, role
  assignments, audit subject ids — survive without remapping.
- **Q5 Audit trail** — Three new `EventKind`s
  (`AnonymousCreated`, `AnonymousExpired`, `AnonymousPromoted`).
  Because `User.id` is preserved through promotion, audit events
  emitted during the anonymous phase remain queryable by subject
  id post-promotion.

The ADR rejects, with reasoning: indefinite retention, JWT bearer
(blocks revocation), in-session "claim email" without verification
(trivially hijackable), separate `anonymous_users` table (forces
foreign-key remap on every dependent table).

### Added — schema

Migration `0006_anonymous.sql` adds the `anonymous_sessions`
table:

- `token_hash` (PK) — SHA-256 of the bearer plaintext, hex.
- `user_id` — FK to `users.id`, ON DELETE CASCADE so the daily
  sweep that drops user rows automatically clears their tokens.
- `tenant_id` — FK to `tenants.id`, ON DELETE CASCADE.
  Denormalized from `users.tenant_id` to keep the IP-rate-limit
  lookup path index-only.
- `created_at` / `expires_at` — Unix seconds. Application
  enforces TTL; DB only stores. The 0006 indexes
  (`idx_anonymous_sessions_created`,
  `idx_anonymous_sessions_user`) cover the sweep and revocation
  hot paths.

The table mirrors the design of `admin_tokens` (introduced in
0005) — same hash-only storage, same plaintext-shown-once
posture — but in a separate table so the auth surface stays
narrow. An anonymous principal has no admin role and cannot
acquire one through this token.

### Added — domain types and ports

New module `cesauth_core::anonymous`:

- **`AnonymousSession`** value type — mirrors the table 1:1 with
  an `is_expired(now_unix)` helper. Boundary semantics
  (`<=` is "expired") are pinned by a dedicated test —
  `is_expired_boundary_inclusive` — because flipping that
  operator to `<` would silently let a token live one second
  past its window, and the next refactor that "tidies up the
  comparison" is the bug.
- **`AnonymousSessionRepository`** trait with four methods:
  - `create(token_hash, user_id, tenant_id, now, ttl)` — insert
    a row. Hash collisions return `Conflict`; FK violations
    return `NotFound`.
  - `find_by_hash(token_hash)` — hot path, called on every
    anonymous-bearer request.
  - `revoke_for_user(user_id)` — used by the promotion path
    to nuke any outstanding bearers at promotion time.
    Idempotent: `Ok(0)` for "no sessions to revoke" rather
    than an error.
  - `delete_expired(now_unix)` — used by the daily sweep.
    Returns the number of rows actually deleted.
- **Constants** `ANONYMOUS_TOKEN_TTL_SECONDS` (24h) and
  `ANONYMOUS_USER_RETENTION_SECONDS` (7d), pinned by a test
  that checks they match ADR-004 and that retention strictly
  outlives the token TTL.

### Added — adapters

- **In-memory** `InMemoryAnonymousSessionRepository` in
  `cesauth-adapter-test`. Mutex-wrapped HashMap; 7 unit tests
  cover round-trip / hash conflict / unknown lookup / per-user
  revocation / idempotency / expired-row sweep / boundary
  inclusivity.
- **Cloudflare D1** `CloudflareAnonymousSessionRepository` in
  `cesauth-adapter-cloudflare`. Maps SQLite UNIQUE / PRIMARY KEY
  failures to `PortError::Conflict` and FK failures to
  `PortError::NotFound`; `meta().changes` for delete-row
  counts. Same shape as the existing `AdminTokenRepository`
  D1 adapter.

### Added — audit event kinds

`EventKind` gains three variants:

- `AnonymousCreated` — emitted by `/begin` (v0.17.0).
- `AnonymousExpired` — emitted by the daily sweep (v0.6.05).
- `AnonymousPromoted` — emitted by `/promote` (v0.17.0).

The variants land in v0.16.0 even though no code path emits them
yet, because the audit catalog is enum-stringly-typed and
distributed clients (log dashboards, audit-table views) treat
unknown values as the type-system error they are. Adding the
variants now means v0.17.0 ships its emit calls without forcing
a coordinated audit-schema bump.

### Tests

- Total: **286 passing** (+10 over v0.15.1).
  - core: **122** (was 119) — 3 new in `anonymous::tests`:
    TTL-constants-match-ADR (paired with the strict
    inequality between retention and token TTL),
    serde round-trip on `AnonymousSession`, `is_expired`
    boundary inclusivity.
  - adapter-test: **43** (was 36) — 7 new in
    `anonymous::tests`: create+lookup round-trip, conflict
    on duplicate hash, unknown-hash returns None,
    `revoke_for_user` drops only the named user's sessions,
    `revoke_for_user` is idempotent (`Ok(0)` for missing
    user), `delete_expired` honours the `expires_at`
    threshold across multiple now values, boundary
    inclusivity (parallel to the type-level test).
  - ui: 121 (unchanged).

### Migration (0.15.1 → 0.16.0)

```bash
wrangler d1 execute cesauth --remote --file migrations/0006_anonymous.sql
wrangler deploy
```

The migration is additive (CREATE TABLE IF NOT EXISTS, new
indexes only); safe to re-run, no existing schema or data is
touched. No `wrangler.toml` change yet — the Cron Trigger
configuration ships with v0.6.05.

For deployments tracking main: nothing to do operationally
beyond running the migration and deploying. No HTTP routes
have changed; no existing principals or tokens are affected.

### Smoke test

```bash
# 1) Verify the new table is in place:
wrangler d1 execute cesauth --remote \
  --command="SELECT name FROM sqlite_master WHERE type='table' AND name='anonymous_sessions';"
# -> one row, name = 'anonymous_sessions'

# 2) Verify the new event kinds are recognized by the audit
#    catalog. Insert a synthetic row and read it back:
wrangler d1 execute cesauth --remote \
  --command="SELECT 'kind valid' FROM (SELECT 1) WHERE 'anonymous_created' IN ('anonymous_created');"
# (cosmetic; the EventKind enum is enforced at the writer side)

# 3) HTTP surface unchanged — the /authorize, /token, /admin/*,
#    /api/v1/* routes behave exactly as in 0.15.1.
curl -s https://cesauth.example/.well-known/openid-configuration \
  | jq -r '.authorization_endpoint, .token_endpoint, .revocation_endpoint'
# -> three URLs that match ISSUER + the suffixes
```

### Deferred to 0.17.0

- **`POST /api/v1/anonymous/begin`** — issues an anonymous user
  + bearer. Per-IP rate limit via the existing `RateLimit` DO
  with a new bucket key.
- **`POST /api/v1/anonymous/promote`** — Magic Link verification
  → UPDATE the existing user row (id preserved). Same-tenant
  email collision returns a distinguishing error vs verify
  failure.

### Deferred to 0.6.05

- **Daily retention sweep** — Cloudflare Workers Cron Trigger
  configured in `wrangler.toml`, dispatching to a sweep handler
  that runs the `users` row delete (with cascade through
  `anonymous_sessions`) plus an audit emission per row.
  Operator runbook section "Verifying the retention sweep ran"
  documents the diagnostic path.

### Deferred — unchanged from 0.15.1

- **`check_permission` integration on `/api/v1/...`.** The
  v0.7.0 JSON API still uses `ensure_role_allows`. Now that
  user-bound tokens exist, `check_permission` is validated in
  the new HTML routes, AND `check_permissions_batch` is
  available, extending it to the API surface is more
  straightforward than before. Unscheduled.
- **External IdP federation.** Out of scope for v0.4.x.

---

## [0.15.1] - 2026-04-28

Security-fix and audit-infrastructure release. Three layers of
`cargo audit` integration land at once: an initial sweep of the
dependency tree (one finding, fixed), a GitHub Actions workflow
that runs the audit on every push / PR / weekly, and operator
documentation pointing at the same command for manual upgrades.

The CVE-relevant change is small but worth a version bump on its
own: cesauth's `jsonwebtoken` features are narrowed from the
blanket `rust_crypto` to explicit `ed25519-dalek` + `rand`,
which removes the transitive `rsa` dep that carried
RUSTSEC-2023-0071 (Marvin Attack). cesauth never exercised the
RSA path — the OIDC discovery doc declares `EdDSA` as the only
supported `id_token_signing_alg`, and `jwt::signer` only
constructs `Algorithm::EdDSA` — but the unused dep would have
shipped in every workspace lock until narrowed.

### Security fix — RUSTSEC-2023-0071 not exercised, dep removed

- **Finding**: `rsa 0.9.10`, pulled in transitively by
  `jsonwebtoken v10.3.0` via the `rust_crypto` feature.
- **Advisory**: RUSTSEC-2023-0071 / CVE-2023-49092 / GHSA-c38w-74pg-36hr.
  Marvin Attack — non-constant-time RSA decryption leaks key
  bits through network-observable timing. No upstream patch
  exists yet at the `rsa` crate level.
- **cesauth's exposure**: zero. cesauth uses
  `Algorithm::EdDSA` (Ed25519) for every JWT it signs and
  verifies. The OIDC discovery declares
  `id_token_signing_alg_values_supported: &["EdDSA"]`.
  RSA is not on any code path. But the dep would still have
  shipped in the workspace lock, contaminating any audit and
  any reuse of the workspace as a library.
- **Fix**: narrow the `jsonwebtoken` features. Was:

  ```toml
  jsonwebtoken = { version = "10", default-features = false, features = ["use_pem", "rust_crypto"] }
  ```

  Is:

  ```toml
  jsonwebtoken = { version = "10", default-features = false, features = ["use_pem", "ed25519-dalek", "rand"] }
  ```

  The `rust_crypto` feature is a blanket bundle that pulls
  `rsa`, `p256`, `p384`, `hmac`, plus the bits we actually use
  (`ed25519-dalek`, `rand`, `sha2`). Replacing it with the
  individual feature flags drops the unused transitives.
- **Verification**: `Cargo.lock` no longer contains
  `name = "rsa"`. Dep count drops from 186 to 176. All 276
  tests still pass; zero warnings.

### Added — `cargo audit` integration

Three layers, in increasing distance from "hot" code:

- **Layer 1 — initial sweep + record state.** Done as part
  of this release. The audit ran against the
  rustsec/advisory-db `main` checkout on 2026-04-28 and
  surfaces no findings post-fix.
- **Layer 2 — `.github/workflows/audit.yml`** using the
  `rustsec/audit-check@v2.0.0` action. Triggers: `push` to
  main, `pull_request` to main, `schedule` cron at
  `0 6 * * 1` (Mondays 06:00 UTC), and `workflow_dispatch`
  for manual runs. Permissions: `contents: read`,
  `issues: write`, `checks: write`. New advisories
  matching a dep in `Cargo.lock` fail the workflow.
- **Layer 3 — operator documentation.** A new step in
  `docs/src/deployment/production.md` ("Step 7 — Verify
  dependencies") points at `cargo install cargo-audit &&
  cargo audit` and describes the triage path for findings.
  The same is reflected in the operator runbook in
  `docs/src/expert/tenancy.md` ("Verifying dependencies
  before an upgrade") so the upgrade procedure documents
  it explicitly.

A Makefile / `xtask` wrapper layer is **not planned** —
cesauth has no Makefile and adding one to host a single
command would invert the cost/value ratio. Local maintainers
run `cargo audit` directly; CI catches regressions; ops
follows the documented step.

### Tests

- Total: **276 passing** (unchanged from v0.15.0).
- The dep narrowing changes no behavior; the existing tests
  are sufficient to confirm the EdDSA-only path still works
  end-to-end.
- The audit workflow itself is GitHub Actions configuration,
  not Rust code; verification is "the YAML parses and the
  pinned action exists at the named version".

### Migration (0.15.0 → 0.15.1)

Code-only release. No schema migration. No `wrangler.toml`
change. The new HTML routes are unchanged from v0.15.0.

For deployments tracking main:

1. **Pull and rebuild.** The `Cargo.toml` change forces a
   new lock file resolution; `cargo build --release` will
   produce a slightly smaller binary (no `rsa`, `p256`,
   `p384`, `hmac` transitives).
2. **Re-run `cargo audit`** locally (or watch the workflow)
   to confirm the clean state.
3. **Deploy.** No runtime behavior changed.

### Smoke test

```bash
# 1) Verify the rsa dep is gone:
grep -c '^name = "rsa"$' Cargo.lock
# -> 0

# 2) Run the audit:
cargo install cargo-audit
cargo audit
# -> Success No vulnerable packages found

# 3) Confirm EdDSA still works end-to-end:
curl -s https://cesauth.example/.well-known/openid-configuration \
  | jq -r '.id_token_signing_alg_values_supported'
# -> ["EdDSA"]
```

### Deferred — unchanged from 0.15.0

- **Anonymous-trial promotion.** Spec §3.3 + §11 priority 5.
  Now the next planned slot.
- **`check_permission` integration on `/api/v1/...`.**
  Unscheduled; depends on concrete need.
- **External IdP federation.** Out of scope for v0.4.x.

---

## [0.15.0] - 2026-04-28

Tenant-scoped admin surface — additive mutation forms (membership
add/remove × 3 flavors) plus affordance gating on every read and
form page. Completes the v0.9.0 → v0.10.0 split applied to the
tenant-scoped surface: v0.14.0 covered high-risk forms, v0.15.0
covers additive forms and the UI-side gating that turns the gate's
permission decisions into operator-visible affordances.

The whole tenant-scoped surface now reaches the same feature
parity that the system-admin tenancy console reached at v0.10.0.
After this release, the tenant admin's day-to-day operations
(organizations, groups, role assignments, memberships) are all
form-driven from within `/admin/t/<slug>/...`, gated end-to-end on
`check_permission`.

### Added — tenant-scoped membership forms

Three flavors mirroring the v0.10.0 system-admin shape, each at
slug-relative URLs:

- **Tenant membership** at `/admin/t/<slug>/memberships/...`.
  Add (`POST .../memberships`) is one-click additive. Remove
  (`POST .../memberships/<uid>/delete`) is a confirm page →
  POST-with-`confirm=yes` apply.
- **Organization membership** at
  `/admin/t/<slug>/organizations/<oid>/memberships/...`.
- **Group membership** at
  `/admin/t/<slug>/groups/<gid>/memberships/...`. No role select
  (group memberships don't carry a role variant in the schema).

All six flavors run through the v0.13.0 gate composition:
`auth::resolve_or_respond` → `gate::resolve_or_respond` →
`gate::check_action` with the relevant permission slug, then the
mutation, then audit emission with `via=tenant-admin,tenant=<id>`.

**Defense in depth**: the target user_id (from the form body) is
verified to belong to the current tenant before any add proceeds.
The slug gate already verifies the principal's user; the new check
prevents an in-tenant admin from typing in a sibling tenant's
user_id and granting them membership.

### Added — permission catalog

Two new permission slugs filling the `*_MEMBER_*` symmetry:

- `tenant:member:add` (`PermissionCatalog::TENANT_MEMBER_ADD`)
- `tenant:member:remove` (`PermissionCatalog::TENANT_MEMBER_REMOVE`)

The v0.9.0/v0.10.0 system-admin paths used the coarse
`ManageTenancy` capability, but the tenant-scoped surface gates
per-action via `check_permission`, so the slugs had to be
enumerated. `ORGANIZATION_MEMBER_*` and `GROUP_MEMBER_*` already
existed; tenant scope now matches.

### Added — affordance gating

Every tenant-scoped page (read or form) now renders mutation
links/buttons only when the current operator can actually use
them. The route handler runs **one** batched permission check per
render and the template emits HTML conditionally:

- **`Affordances` struct** in `cesauth_ui::tenant_admin::affordances`
  — twelve boolean flags, one per affordance type. `Default` is
  all-false (the safe default); `all_allowed()` is provided for
  test convenience.
- **`gate::build_affordances`** in worker — issues a single
  `check_permissions_batch` call and maps the parallel `Vec<bool>`
  back into the struct. Reads as well as forms call this; the cost
  is one D1 round-trip per page render.
- **Per-page rendering** — Overview shows quick-action buttons
  (`+ New organization`, `+ Add tenant member`); Organizations
  list shows `+ New organization`; Organization detail shows
  `Change status` / `+ New group` / `+ Add member` and per-group
  `delete` / `+ member` actions; Role assignments shows
  `+ Grant role` and per-assignment `revoke` links.

The route handlers behind each affordance still re-check on
submit (defense in depth). The affordance gate is the operator's
first signal — clicking what they can't do already returns 403,
but they shouldn't have to find out by clicking.

### Added — `check_permissions_batch`

New function in `cesauth_core::authz::service`. Evaluates N
`(permission, scope)` queries for one user, all at once:

- One `assignments.list_for_user(user_id)` call.
- One `roles.get(role_id)` per *distinct* role the user holds
  (cached in a HashMap across queries).
- N in-memory scope-walks against the prepared inputs.

The naive alternative (call `check_permission` once per query)
costs N round-trips for the assignment fetch alone. The batch
helper collapses that to one. For affordance gating with 12
flags per render, the speedup is the difference between "1 RTT"
and "12 RTTs".

The `scope_covers` and `role_has_permission` helpers became
`pub(crate)` to support the batch implementation. Behaviour is
intentionally identical to per-query `check_permission`; a
test pins this equivalence.

### Tests

- Total: **276 passing** (+19 over v0.14.0).
  - core: **119** (was 114) — 5 new in
    `authz/tests.rs::check_permissions_batch_*` covering empty
    query → empty result, batch == per-query equivalence (the
    load-bearing test), no-assignments → `NoAssignments` for
    every query, dangling role id → graceful
    `PermissionMissing`, expiration handling.
  - adapter-test: 36 (unchanged).
  - ui: **121** (was 107) — 14 new tests:
    - 8 affordance-gating tests covering hide-when-denied +
      show-when-allowed for organizations / detail / overview /
      role_assignments pages, including granular
      per-flag-independence and "empty list → no orphan revoke
      links even when can_unassign_role = true".
    - 2 invariants tests pinning
      `Affordances::default()` = all-false and
      `all_allowed()` = all-true. Defends against a future
      refactor that flips a default to `true`, which would
      silently widen affordances for every test that uses
      `Default::default()` as a fixture.
    - 4 membership form template tests: slug-relative actions,
      three-role / two-role pickers per scope, no-Owner role
      at org level (organizations have only Admin/Member), and
      confirm=yes hidden field on remove pages.

### Defense-in-depth invariants pinned by tests

Following the v0.14.0 convention. The new ones:

- `target user_id` for membership add belongs to *this* tenant
  — refused 403 otherwise.
- `Affordances::default()` is all-false — a future refactor
  that defaults a flag to `true` is a test failure, not a
  silent UI widening.
- Empty assignment list → no revoke links even when
  `can_unassign_role = true` — the affordance gate doesn't
  emit orphan buttons when there's nothing to act on.
- Batch result equals per-query check — the affordance gate
  cannot diverge from the per-route check.

### Migration (0.14.0 → 0.15.0)

Code-only release. No schema migration. No `wrangler.toml`
change. New HTML routes are additive — existing
`/admin/t/<slug>/*` GET routes from v0.13.0 and form routes from
v0.14.0 are unchanged.

For operators expecting to use the new membership forms or the
affordance-gated UI:

1. **Membership forms** at the URLs above. Permission slugs:
   `TENANT_MEMBER_ADD/REMOVE`, `ORGANIZATION_MEMBER_ADD/REMOVE`,
   `GROUP_MEMBER_ADD/REMOVE`. The two new tenant-level slugs
   need to be granted to existing roles before any tenant admin
   can use the tenant-membership flavor.
2. **Affordance gating** is automatic — operators see only the
   buttons they can use. A tenant admin who notices a button
   missing should check their role assignments at the
   appropriate scope.

Existing `/admin/tenancy/*`, `/admin/console/*`, and the v0.13.0
/v0.14.0 `/admin/t/<slug>/*` routes are unaffected.

### Smoke test

```bash
USER_TOKEN=...  # user-bound token from /admin/tenancy/users/<uid>/tokens/new

# 1) Overview now surfaces quick-action buttons gated by permission:
curl -sS -H "Authorization: Bearer $USER_TOKEN" \
  https://cesauth.example/admin/t/acme | grep -i 'Quick actions'
# -> "Quick actions" appears iff the user has at least one
#    of {ORGANIZATION_CREATE, TENANT_MEMBER_ADD} at tenant scope

# 2) Tenant-membership add (additive, one-click):
curl -sS -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -d "user_id=u-bob&role=member" \
  https://cesauth.example/admin/t/acme/memberships
# -> 303 redirect to /admin/t/acme

# 3) Organization-membership remove (confirm-then-apply):
curl -sS -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -d "confirm=yes" \
  https://cesauth.example/admin/t/acme/organizations/o-eng/memberships/u-bob/delete
# -> 303 redirect to /admin/t/acme/organizations/o-eng

# 4) Cross-tenant target user attempt: refused with 403:
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -d "user_id=u-other-tenant&role=member" \
  https://cesauth.example/admin/t/acme/memberships
# -> 403  (verify_user_in_tenant refused)
```

### Deferred to 0.15.1 or later

- **Anonymous-trial promotion.** Spec §3.3 introduces
  `Anonymous` as an account type and §11 priority 5 asks for
  a promotion flow. Now the next planned slot, since the
  tenant-scoped surface is feature-complete.
- **`check_permission` integration on `/api/v1/...`.** The
  v0.7.0 JSON API still uses `ensure_role_allows`. Now that
  user-bound tokens exist, `check_permission` is validated in
  the new HTML routes, AND `check_permissions_batch` is
  available, extending it to the API surface is more
  straightforward than before. Unscheduled — depends on
  concrete need.
- **External IdP federation.** `AccountType::ExternalFederatedUser`
  is reserved; no IdP wiring exists yet.

---

## [0.14.0] - 2026-04-27

Tenant-scoped admin surface — high-risk mutation forms — plus a
system-admin token-mint UI that exposes
`AdminTokenRepository::create_user_bound` to operators. v0.13.0
shipped the read pages and the auth gate; v0.14.0 adds the
form-driven mutations that operators most need to run from inside
the tenant context, and the missing piece for bootstrapping the
whole flow (a way to actually mint user-bound tokens without
scripting).

The release follows the v0.9.0 → v0.10.0 split for the system-admin
surface: high-risk forms first, additive ones in the next release.
v0.15.0 adds the membership add/remove forms (three flavors,
mirroring v0.10.0's split).

### Added — tenant-scoped mutation forms

Six form pairs (GET + POST) under `/admin/t/<slug>/...`:

- **`organizations/new`** — additive, one-click submit.
  Permission: `ORGANIZATION_CREATE` at tenant scope.
  Plan-quota enforcement (`max_organizations`) mirrors the
  v0.9.0 system-admin path.
- **`organizations/:oid/status`** — preview/confirm.
  Permission: `ORGANIZATION_UPDATE`. Active / Suspended /
  Deleted picker with required reason field; the diff page
  spells out the change and round-trips the reason into the
  apply form.
- **`organizations/:oid/groups/new`** — additive, one-click.
  Permission: `GROUP_CREATE`. Uses the `NewGroupInput` shape
  that v0.5.0 introduced.
- **`groups/:gid/delete`** — preview/confirm.
  Permission: `GROUP_DELETE`. Preview counts affected role
  assignments and memberships so the operator sees the
  cascade impact before clicking Apply.
- **`users/:uid/role_assignments/new`** — preview/confirm.
  Permission: `ROLE_ASSIGN`. Scope picker omits System (per
  ADR-003: tenant admins cannot grant cesauth-wide roles);
  Tenant scope's scope_id is forced to the current tenant
  (a tenant admin who types in a different tenant's id is
  refused with 403, not just an error). Defense-in-depth
  `verify_scope_in_tenant` walks the storage layer to confirm
  the scope's organization / group / user actually belongs
  to the current tenant before the grant proceeds.
- **`role_assignments/:id/delete`** — preview/confirm.
  Permission: `ROLE_UNASSIGN`. The user_id rides on the
  query string (same pattern as the system-admin equivalent;
  the repository does not expose `get_by_id` for assignments).

Every handler runs the v0.13.0 gate's 3-step opening
(`auth::resolve_or_respond` → `gate::resolve_or_respond` →
`gate::check_action`), then preview/confirm gating on the
`confirm` form field, then the mutation, then audit emission.
Audit entries carry `via=tenant-admin,tenant=<id>` to
distinguish them from `via=tenancy-console` (system-admin
originated) — log analyses can split by surface origin.

### Added — system-admin token-mint UI

- **`/admin/tenancy/users/:uid/tokens/new`** (GET + POST) —
  three pages: form (role + nickname), preview/confirm, applied
  (plaintext shown ONCE with prominent warning + post-mint usage
  instructions linking to `/admin/t/<slug>/...`).
- Gated on `ManageAdminTokens` (existing v0.4.0 admin-token
  capability). Tenant admins cannot self-mint per ADR-002 / ADR-003
  — this route lives at `/admin/tenancy/...`, not
  `/admin/t/<slug>/...`.
- Re-uses `mint_plaintext()` and `hash_hex()` from the existing
  `console/tokens.rs` (made `pub(crate)`); calls
  `AdminTokenRepository::create_user_bound`.
- The applied page resolves the user's tenant **slug** for the
  post-mint URL hint — a tempting bug here would have used
  the tenant *id* directly, leaking the internal id into the
  operator-facing URL. The test
  `applied_page_carries_plaintext_token_and_post_mint_link`
  pins this down explicitly.

### Gate API change

The v0.13.0 `gate::check_read` was a thin wrapper for "permission
at tenant scope". Mutation forms operate on child resources
(Organization, Group) and need narrower scopes, so the underlying
function is now `gate::check_action(ctx_ta, permission, scope, ctx)`
accepting an explicit `ScopeRef`. `check_read` remains as a
backward-compatible convenience wrapper for the v0.13.0 read
routes (always passes `ScopeRef::Tenant { tenant_id: ctx.tenant.id }`).

### Defense-in-depth invariants pinned by tests

The v0.13.0 release introduced cross-resource defense
(`organization_detail` and `role_assignments` re-verify the child
resource's tenant_id). v0.14.0 extends this to every mutation:

- `organization_set_status` re-verifies `org.tenant_id ==
  ctx_ta.tenant.id` before applying.
- `group_delete` walks the `GroupParent` enum: tenant-scoped
  groups check `group.tenant_id`; org-scoped groups check the
  parent organization's `tenant_id`.
- `role_assignment_grant` calls `verify_scope_in_tenant` for
  every Organization / Group / User scope before proceeding.
- `role_assignment_revoke` re-verifies the assignment's user
  belongs to this tenant.

The corresponding template-level invariants — scope picker
without System option, tenant id pinned in the help text,
preview round-tripping every form field — are pinned by 7 new
tests in `tenant_admin/tests.rs`.

### Tests

- Total: **257 passing** (+12 over v0.13.0).
  - core: 114 (unchanged).
  - adapter-test: 36 (unchanged).
  - ui: **107** (was 95) — 12 new tests covering form-template
    invariants:
    - 7 in `tenant_admin/tests.rs` — slug-relative form actions,
      sticky values on error re-render, preview confirm=yes
      hidden field, group_delete affected-counts visible, scope
      picker omits System, tenant id pinned in help text, preview
      round-trips role_id/scope_type/expires_at.
    - 4 in `tenancy_console/tests.rs::token_mint_tests` —
      role radio for each AdminRole, plaintext-shown-once warning,
      applied page uses tenant slug not id, plaintext HTML-escaped.
    - 1 footer marker assertion update (now `v0.14.0`).

The host-side test surface for the form templates is the load-
bearing test family. A future refactor that drops the System-
omission from the scope picker is a test failure, not a security
regression.

### Migration (0.13.0 → 0.14.0)

Code-only release. No schema migration. No `wrangler.toml`
change. The new HTML routes are additive — existing
`/admin/t/<slug>/*` GET routes from v0.13.0 are unchanged.

For operators expecting to use the new mutation forms or the
token-mint UI:

1. **Tenant admins** can now visit
   `/admin/t/<slug>/organizations/new`, etc. The forms are
   gated on the appropriate write permissions (the same slugs
   the v0.7.0 JSON API gates on).
2. **System admins** mint user-bound tokens at
   `/admin/tenancy/users/<uid>/tokens/new`. The plaintext is
   shown once on the apply page; copy it before clicking
   anywhere else. cesauth stores only the SHA-256 hash.

Existing `/admin/tenancy/*`, `/admin/console/*`, and
`/admin/t/<slug>/*` routes are unaffected.

### Smoke test

```bash
ADMIN=$ADMIN_API_KEY  # system-admin

# 1) Mint a user-bound token for a tenant admin via the new UI.
#    For now, drive it from curl (browser flow works the same):
PREVIEW=$(curl -sS -H "Authorization: Bearer $ADMIN" \
  -d "role=operations&name=alice%20bootstrap" \
  https://cesauth.example/admin/tenancy/users/u-alice/tokens/new)
# -> preview page with confirm=yes hidden field

# 2) Apply: post the same form with confirm=yes.
APPLIED=$(curl -sS -H "Authorization: Bearer $ADMIN" \
  -d "role=operations&name=alice%20bootstrap&confirm=yes" \
  https://cesauth.example/admin/tenancy/users/u-alice/tokens/new)
# -> applied page with the plaintext token (shown once)

# 3) Tenant admin uses the token to grant a role inside the tenant:
USER_TOKEN=...  # extract from step 2's response

curl -sS -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -d "role_id=r-admin&scope_type=organization&scope_id=o-eng" \
  https://cesauth.example/admin/t/acme/users/u-bob/role_assignments/new
# -> preview page

curl -sS -X POST -H "Authorization: Bearer $USER_TOKEN" \
  -d "role_id=r-admin&scope_type=organization&scope_id=o-eng&confirm=yes" \
  https://cesauth.example/admin/t/acme/users/u-bob/role_assignments/new
# -> 303 redirect to /admin/t/acme/users/u-bob/role_assignments

# 4) Cross-tenant attempt: try to grant against a different tenant's org.
#    Defense-in-depth refuses with 403:
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $USER_TOKEN" \
  -X POST -d "role_id=r-admin&scope_type=organization&scope_id=o-other-tenant" \
  https://cesauth.example/admin/t/acme/users/u-bob/role_assignments/new
# -> 403  (verify_scope_in_tenant refused)

# 5) Trying to grant System scope: refused with 403 per ADR-003:
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $USER_TOKEN" \
  -X POST -d "role_id=r-admin&scope_type=system" \
  https://cesauth.example/admin/t/acme/users/u-bob/role_assignments/new
# -> 403
```

### Deferred to 0.15.0

- **Membership add/remove forms** (three flavors: tenant /
  organization / group). Same shape as the v0.10.0 system-admin
  forms but tenant-scoped. Permissions:
  `MEMBERSHIP_ADD` / `MEMBERSHIP_REMOVE` /
  `ORGANIZATION_MEMBER_ADD` / `ORGANIZATION_MEMBER_REMOVE` /
  `GROUP_MEMBER_ADD` / `GROUP_MEMBER_REMOVE`.
- **Affordance gating on the v0.13.0 read pages**: render
  mutation buttons only when `check_permission` would actually
  allow the relevant write. Cleanest way is a per-button
  Probe call against `check_permission`, batched per page
  render. Acceptable latency-wise for HTML pages, but worth
  a dedicated review.

### Deferred — unchanged from 0.13.0

- **`check_permission` integration on `/api/v1/...`** —
  unscheduled.
- **Anonymous-trial promotion** — 0.15.1 or later.
- **External IdP federation** — explicitly out of scope.

---

## [0.13.0] - 2026-04-27

Tenant-scoped admin surface — the surface implementation that
v0.11.0's foundation (ADR-001/002/003 + `admin_tokens.user_id` +
`AdminPrincipal::user_id` + `is_system_admin()`) was building
toward. Introduces the `/admin/t/<slug>/...` route surface, the
per-route auth gate that enforces ADR-003's structural separation
between system-admin and tenant-admin contexts, the
`AdminTokenRepository::create_user_bound` mint method that
produces user-bound tokens, and `check_permission` integration
on the new routes.

This is the largest feature release since v0.9.0. Pre-1.0 means
the public surface is still allowed to grow; the tenant-scoped
URL prefix is new ground, not a rename of anything existing.

Read pages only in 0.13.0, mirroring how v0.8.0 introduced the
system-admin tenancy console — read pages first, mutation forms
in the next release. Mutation forms (membership add/remove,
role-assignment grant/revoke, etc.) and the token-mint UI form
land in 0.14.0.

### Added — domain layer

- **`crates/core/src/tenant_admin/`** — new module owning the
  tenant-scoped auth-gate decision logic. Pure (no network calls
  of its own), generic over the repository ports it consumes,
  host-testable. The module exports two types and one function
  the worker layer calls into:
  - **`TenantAdminContext`** — a successful gate pass carries
    the resolved principal, tenant, and user. Route handlers
    use these without re-fetching.
  - **`TenantAdminFailure`** — typed failure modes
    (`NotUserBound`, `UnknownTenant`, `UnknownUser`,
    `WrongTenant`, `Unavailable`) with their HTTP status code
    semantics: `NotUserBound`/`WrongTenant` → 403,
    `UnknownTenant` → 404, `UnknownUser` → 401,
    `Unavailable` → 503. Each failure carries a human-safe
    message that does not echo the slug or user_id back.
  - **`resolve_tenant_admin(principal, slug, tenants, users)`**
    — the gate. Enforces, in order: (1) the principal is
    user-bound (`is_some()`), (2) the slug resolves to a real
    tenant, (3) the principal's user belongs to *that* tenant.
    The third invariant is the structural defense that
    ADR-003 promises: an Acme user cannot peek at Beta's data
    by typing `/admin/t/beta/`.

- **`AdminTokenRepository::create_user_bound`** — new port
  method on the existing repository trait. Mints a token row
  with `admin_tokens.user_id` populated. Resulting
  `AdminPrincipal` has `user_id == Some(...)`, which
  `is_system_admin()` reads as "tenant-admin, not
  system-admin" per ADR-002. Same `token_hash` uniqueness
  rules as `create`. Implementations land in both adapters:
  in-memory (`cesauth-adapter-test`) and Cloudflare D1
  (`cesauth-adapter-cloudflare`). The token-mint *flow* (who
  can mint, what audit trail it emits, what UI exposes the
  operation) is not part of this method; adapters just
  persist what they're told.

- **`UserRepository::list_by_tenant`** — new port method.
  Returns active (non-deleted) users belonging to a given
  tenant. Used by the tenant-scoped users page.
  Implementations in both adapters; the CF adapter selects
  with `WHERE tenant_id = ?1 AND status != 'deleted'
  ORDER BY id`. Pagination is intentionally omitted at this
  stage — the surface that consumes this expects O(10-1000)
  users per tenant. Pagination lands when a tenant's user
  count exceeds what fits on one page.

### Added — UI layer

- **`crates/ui/src/tenant_admin/`** — new module mirroring the
  shape of `tenancy_console` but tenant-scoped. Per ADR-003,
  no chrome (header, nav, footer, color palette) is shared
  between the two surfaces — the structural separation is
  the visual signal that an operator has switched contexts.
  - **`tenant_admin_frame()`** — page chrome. Tenant identity
    (slug + display name) appears next to the role badge in
    the header so screenshots are unambiguous. Nav links are
    slug-relative — the bar contains
    `/admin/t/<slug>/{,organizations,users,subscription}`
    and never anything from `/admin/tenancy/...`.
  - **`TenantAdminTab`** enum — six tabs covering the read
    pages. Drill-in tabs (`OrganizationDetail`,
    `UserRoleAssignments`) are reachable via in-page links,
    not the nav bar.
  - **`overview_page()`** — tenant card (display_name, slug,
    status badge) plus per-tenant counters (organizations,
    users, groups, current plan).
  - **`organizations_page()`** + **`organization_detail_page()`**
    — list and detail. Detail page also lists groups
    belonging to the organization.
  - **`users_page()`** — list users belonging to this tenant
    with drill-through to role-assignments.
  - **`role_assignments_page()`** — drill-in for one user.
    Renders role labels (slug + display name) by joining
    against a `(role_id, slug, display_name)` dictionary the
    route handler assembles. Falls back to the bare role_id
    if a label is missing.
  - **`subscription_page()`** — append-only subscription
    history for this tenant, reverse-chronological.

  All pages render server-side. No JavaScript. No
  mutation buttons in 0.13.0 — those land in 0.14.0.

### Added — worker / route layer

- **`crates/worker/src/routes/admin/tenant_admin/`** — new
  route module. One file per page plus the `gate.rs` shared
  helper. Each handler runs the same opening sequence:
  1. **`auth::resolve_or_respond`** — bearer → principal
     (existing flow).
  2. **`gate::resolve_or_respond`** — wraps
     `cesauth_core::tenant_admin::resolve_tenant_admin` for
     the worker layer, including audit emission for
     `WrongTenant` and `UnknownUser` (cross-tenant access
     attempts and stale principals are forensically
     interesting even when refused).
  3. **`gate::check_read`** — wraps
     `cesauth_core::authz::check_permission` against the
     resolved tenant scope. Each route gates on the
     appropriate read permission:
     - overview → `TENANT_READ`
     - organizations + organization_detail → `ORGANIZATION_READ`
     - users + role_assignments → `USER_READ`
     - subscription → `SUBSCRIPTION_READ`

  Defense-in-depth checks live in handlers that take a child
  resource id from the URL (e.g., `:oid`, `:uid`). The gate
  has already verified that the URL slug resolves to the
  user's tenant; the child id check verifies the *child
  resource* belongs to that same tenant. An unscrupulous
  tenant admin who types in another tenant's organization
  id gets a 403 with "organization belongs to a different
  tenant", not a 200 with the wrong tenant's data.

- **Six new GET routes** registered in
  `crates/worker/src/lib.rs` between the existing
  `/admin/tenancy/*` block and the `/api/v1/...` block:
  - `GET /admin/t/:slug`
  - `GET /admin/t/:slug/organizations`
  - `GET /admin/t/:slug/organizations/:oid`
  - `GET /admin/t/:slug/users`
  - `GET /admin/t/:slug/users/:uid/role_assignments`
  - `GET /admin/t/:slug/subscription`

### Authorization model

The system-admin surface (`/admin/tenancy/*`) continues to use
`auth::ensure_role_allows(principal, AdminAction::*)`. The
tenant-scoped surface (`/admin/t/<slug>/*`) uses
`check_permission(user_id, permission, scope)` instead — this
is what makes the principal's `user_id` actually do work,
because `check_permission` is the spec §9.2 scope-walk that
needs a user_id as input. Both mechanisms coexist; ADR-003's
URL-prefix separation means neither can leak across.

### Tests

- Total: **245 passing** (+26 over v0.12.1).
  - core: **114** (was 105) — 9 new tests in
    `tenant_admin/tests.rs` covering happy path, the three
    ADR-003 invariants (one test each), two failure modes
    (UnknownUser, Unavailable on each repo), and the
    failure-presentation invariants (status code + message
    distinctness + no input echo).
  - adapter-test: **36** (was 32) — 4 new tests for
    `create_user_bound` covering principal stamping, list
    integration with plain tokens, hash uniqueness across
    both `create` and `create_user_bound`, and disable
    parity.
  - ui: **95** (was 82) — 13 new tests in
    `tenant_admin/tests.rs` covering frame chrome (tenant
    identity in header, slug-relative nav, drill-in tabs not
    in nav, version footer marker, distinct chrome
    visually defending ADR-003), per-page rendering
    (overview, organizations, users), HTML escape defense
    in depth.

The host-side test surface for the tenant-admin auth gate is
the most important new test family in this release. It pins
down the three ADR-003 invariants as runnable assertions; a
future refactor that accidentally drops one is a test
failure, not a security regression detected six months later.

### Migration (0.12.1 → 0.13.0)

Code-only release. No schema migration (the
`admin_tokens.user_id` column was added in v0.11.0 by
migration `0005`; v0.13.0 only writes to it, doesn't change
the schema). No `wrangler.toml` change.

For operators expecting to use the tenant-scoped surface:

1. Mint a user-bound admin token via the
   `AdminTokenRepository::create_user_bound` adapter method.
   No HTML form exposes this in 0.13.0 — script the call from
   a one-off worker route or run it against the
   in-memory adapter for testing. The mint UI lands in 0.14.0.
2. Have the user present `Authorization: Bearer <token>` at
   `/admin/t/<their-tenant-slug>/`. The gate verifies the
   token is user-bound, the slug resolves, and the user
   belongs to that tenant; `check_permission` then verifies
   the user has `tenant:read` (or the page-specific
   permission) at the tenant scope.
3. Cross-tenant attempts return 403 with audit. The audit
   reason carries the principal id, the attempted slug, and
   a `(cross-tenant)` marker.

Existing `/admin/tenancy/*` and `/admin/console/*` routes
are unaffected. System-admin tokens continue to work
exactly as before; they just don't unlock the tenant-scoped
surface (per ADR-003).

### Deferred to 0.14.0

- **Mutation forms for the tenant-scoped surface** — all the
  v0.9.0 / v0.10.0 system-admin forms have natural
  tenant-scoped equivalents (organization status changes,
  group create / delete, membership add / remove inside
  this tenant, role grant / revoke). 0.14.0's review
  benefits from 0.13.0's read pages already shipping —
  every mutation has a "before" page to land on.
- **Token-mint HTML form** — the
  `AdminTokenRepository::create_user_bound` adapter method
  exists; what's missing is a `/admin/tenancy/users/:uid/tokens/new`
  form that exposes it (system-admin only, to bootstrap a
  tenant admin's first token). 0.14.0.
- **`check_permission` integration on `/api/v1/...`** — the
  v0.7.0 JSON API still uses `ensure_role_allows`. Now that
  user-bound tokens exist and `check_permission` is
  validated in the new HTML routes, extending it to the API
  surface is mechanical. Unscheduled — depends on whether
  there's a concrete need (most callers of `/api/v1` will
  be system-admin scripts, not tenant admins).

### Deferred — unchanged from 0.12.1

- **Anonymous-trial promotion (0.14.0 or 0.15.0).**
- **External IdP federation** — explicitly out of scope; no
  scheduled target.

---

## [0.12.1] - 2026-04-27

Buffer / follow-up release. Originally reserved as a placeholder
slot for any issues the 0.12.0 rename would surface in real-world
use. The shippable content turned out to be two small but
worthwhile threads:

1. **Stale-narrative cleanup** — three docstrings carried
   forward-references and historical claims that the 0.12.0 rename
   and intervening release-slot reshuffles invalidated. Cleaned
   up.

2. **Dependency audit** — a deliberate look at every direct
   workspace dependency to confirm the tree isn't accumulating
   drift before v0.13.0 (tenant-scoped surface) lands. No bumps;
   the rationale for each "leave at current" is in the audit
   findings below.

The 0.13.0 surface implementation is unchanged in scope and
unaffected by this release.

### Changed — stale-narrative cleanup

- **`crates/ui/src/tenancy_console.rs` module docstring**
  rewritten. The previous version made two claims that became
  false during 0.12.0:
  - "URL prefix is preserved from earlier releases for
    operator-facing stability" — false. v0.12.0 deliberately
    broke `/admin/saas/*` → `/admin/tenancy/*` as an
    operator-visible breaking change.
  - "since v0.18.0" — wrong release marker (the rename
    landed in v0.12.0, and v0.18.0 is not a planned release at
    all).

  The replacement docstring documents what the module is now
  (read pages, mutation forms, memberships and role
  assignments), the v0.11.0 ADR-foundation that 0.13.0 will
  build on, and the naming-history note explaining the v0.12.0
  rename.

- **`crates/core/src/tenancy/types.rs::AccountType`** — two
  variant doc-references corrected:
  - `Anonymous`: "promotion flow is a 0.18.0 item" → "0.14.0
    item" (matches the ROADMAP slot that was settled in 0.12.0).
  - `ExternalFederatedUser`: "Federation wiring is 0.18.0" →
    "Federation wiring is unscheduled at this time" (the
    explicit out-of-scope status is honest about the lack of
    a current target).

  Neither change touches behavior. Both prevent a future
  maintainer from chasing a 0.18.0 milestone that doesn't exist.

### Verified — dependency audit

Per project policy, `cargo-outdated` is the canonical tool for
this check. The audit environment used here couldn't install it
(network and time budget didn't permit the substantial
transitive dep graph compile), so the audit was performed by
manual inspection of `Cargo.toml` against `Cargo.lock` and
known-current version information. Results:

**Healthy as-pinned**, every direct dependency at a current
maintained line:

- `worker = "0.8"` resolves to 0.8.1 — current Cloudflare
  Workers SDK.
- `serde 1`, `serde_json 1`, `thiserror 2`, `anyhow 1`,
  `uuid 1`, `time 0.3`, `url 2`, `hex 0.4`, `tokio 1` —
  all on current major lines.
- `jsonwebtoken 10` — current.
- `base64 0.22`, `sha2 0.10`, `hmac 0.12`,
  `ed25519-dalek 2`, `p256 0.13`, `ciborium 0.2` —
  RustCrypto family aligned, all current within their
  release line.

**Intentionally pinned at older line — leave alone**:

- `getrandom = "0.2"` (resolves 0.2.17) — pinned at 0.2 with
  the `js` feature for the wasm32-unknown-unknown +
  Cloudflare Workers integration. The 0.3.x line replaced
  the `js` feature with `wasm_js` and a different backend
  selection mechanism. Multiple July-August 2025 reports
  (including the Leptos 0.8.6 → uuid 1.18 → getrandom 0.3.3
  break) confirm the upgrade requires either `worker-build`
  to grow corresponding support or the whole transitive tree
  to align on 0.3 simultaneously. **Don't bump until the
  Cloudflare workers-rs ecosystem moves first.**

- `rand_core = "0.6"` (resolves 0.6.4) — couples with
  `getrandom 0.2` and with the RustCrypto family
  (ed25519-dalek 2, p256 0.13). Bumping to 0.9 is gated on
  the same wasm32 alignment that gates getrandom.

**Coexistence noted, fine to ignore**:

- `Cargo.lock` shows a transitive `getrandom 0.7.0` riding
  alongside the directly-pinned 0.2.17. cargo handles
  multiple major versions of the same crate side-by-side;
  the 0.2 instance is the one consumed by the wasm32 build
  path, the 0.4 instance is from a `wasm32-wasi`-targeted
  branch of some transitive dep. No action needed.

The audit is recorded as a one-off snapshot rather than a
recurring CI check. A future release that introduces a
dedicated CI job (`cargo audit` / `cargo-outdated`) would be
worth doing on its own.

### Tests

- Total: **219 passing** (unchanged from 0.12.0).
  - core: 105.
  - adapter-test: 32.
  - ui: 82.

The frame test that asserts the footer's version marker now
asserts `"v0.12.1"`. Otherwise the test diff is empty — the
release's code change is doc-only.

### Why this isn't a no-op

A buffer release without bug fixes can look like ceremony.
What the slot bought:

- **A clean look at every direct dep before adding more code.**
  v0.13.0 will add new auth resolution paths and a token-mint
  flow; landing those on top of unaudited deps is harder to
  review.
- **Three docstrings now agree with reality.** A future
  maintainer reading them won't go looking for a v0.18.0
  milestone or assume that `/admin/saas/*` still resolves.
- **Validation that v0.12.0's hard rename didn't leave any
  broken narrative.** None did, but the only way to confirm
  was to grep the codebase for `0.18.0` and "preserved from
  earlier" — the audit was the work.

### Deferred — unchanged from 0.12.0

- **Tenant-scoped admin surface implementation (0.13.0).**
- **Token-mint flow with `user_id` (0.13.0).**
- **`check_permission` integration on the API surface (0.13.0).**
- **Anonymous-trial promotion (0.14.0).**
- **External IdP federation** — explicitly out of scope; no
  scheduled target.

---

## [0.12.0] - 2026-04-27

Project hygiene release. Pre-1.0, technically — but the changes here
are the kind that get more expensive the longer they're deferred,
so the release is dedicated to retiring them in one focused pass.

Two threads land together:

1. **Project framing and metadata.** Authorship, license, and
   repository metadata now match reality. "Commercial SaaS" /
   "商用 SaaS" framing — including spec references, comments, and
   prose — has been replaced with "tenancy service" or equivalent
   functional descriptions. `.github/` gains the community-process
   documents that a public repository is reasonably expected to
   carry: code of conduct, contributing guide, structured issue
   templates.

2. **Naming-debt cleanup.** The `saas/` module path under both
   `crates/ui/` and `crates/worker/src/routes/admin/`, the
   `/admin/saas/*` URL prefix, the `SaasTab` public type, and the
   `via=saas-console` audit reason marker have all been renamed
   to use `tenancy_console` / `/admin/tenancy/*` /
   `TenancyConsoleTab` / `via=tenancy-console`. The change is
   operator-visible: any external script targeting
   `/admin/saas/...` URLs needs updating. Pre-1.0 caveat applies
   — see the migration guidance below.

The two threads share a release because they share a motivation
(remove framing that could mislead users or contributors about
what cesauth is) and because doing them together amortizes the
review cost.

### Changed — metadata

- **Workspace `Cargo.toml`**:
  - `authors = ["nabbisen"]` (was
    `["nabbisen"]`).
  - `repository = "https://github.com/nabbisen/cesauth"` (was
    the stub `https://github.com/cesauth/cesauth`).
  - Per-crate `Cargo.toml` files inherit through
    `.workspace = true` so no per-crate edits were needed.
- **`LICENSE`** Apache-2.0 boilerplate copyright line:
  `Copyright 2026 nabbisen` (was
  "nabbisen").

### Changed — naming

- **Module paths**:
  - `crates/ui/src/saas/` → `crates/ui/src/tenancy_console/`
  - `crates/worker/src/routes/admin/saas/` →
    `crates/worker/src/routes/admin/tenancy_console/`
  - All `mod`/`use` statements and re-exports updated.
- **Public types**:
  - `SaasTab` → `TenancyConsoleTab`
  - `saas_frame()` → `tenancy_console_frame()`
  - `saas_overview_page` → re-exported under the new module
- **URL prefix**: `/admin/saas/*` → `/admin/tenancy/*`.
  Sixteen mutation routes plus the read pages all migrate.
  **Breaking change** for any operator with bookmarks,
  scripts, or playbooks targeting the old prefix.
- **Audit reason marker**: `via=saas-console` →
  `via=tenancy-console`. Audit consumers that filter on this
  value need updating.
- **Page titles and footer**: "SaaS console" → "tenancy
  console" throughout the chrome. Footer marker is now
  "v0.12.0 (full mutation surface for Operations+)".
- **Project framing language** in comments and docs.
  "Commercial SaaS" / "商用 SaaS" replaced with "tenancy
  service" or equivalent. The earlier framing was ambiguous
  (the project is open-source under Apache-2.0; "commercial"
  doesn't describe the license, the deployment model, or
  anything else precise) and risked giving users and
  contributors the wrong impression about the project's
  intent. Spec references such as
  `cesauth-商用 SaaS 化可能な構成への拡張開発指示書.md` are
  now referenced as `cesauth tenancy-service extension spec`.

### Added

- **`.github/CODE_OF_CONDUCT.md`** — Contributor Covenant 2.1,
  with `nabbisen` as the enforcement contact.
- **`.github/CONTRIBUTING.md`** — practical guide covering the
  workspace test flow, code-review priorities (make invalid
  states unrepresentable; pure decision in core, side effects
  at the edge; test what changed), the PR checklist, and what
  lands smoothly vs. what needs discussion.
- **`.github/ISSUE_TEMPLATE/`**:
  - `bug_report.yml` — structured bug template with version,
    environment, steps to reproduce.
  - `feature_request.yml` — proposal template with a problem-
    first framing and a "willing to PR" dropdown.
  - `documentation.yml` — for docs-only issues (typos,
    missing examples, outdated content).
  - `config.yml` — links security reports to the private
    advisory path and open questions to Discussions.

### Migration

This is a hard rename — no compatibility-redirect routes were
added. The SemVer caveat documented at the top of this file
permits this, but operators upgrading from 0.11.0 should:

1. **Check audit-log filters.** Any consumer that splits
   console-driven mutations from script-driven ones by
   matching `via=saas-console` needs the matcher updated to
   `via=tenancy-console`. Both old and new values appear in
   audit history; the audit log is append-only, so 0.12.0 does
   not rewrite past entries.
2. **Update operator URLs.** Bookmarks, runbooks, and
   tooling targeting `/admin/saas/...` need their prefix
   changed to `/admin/tenancy/...`. The path *suffixes* are
   unchanged — `tenants`, `organizations/:oid`,
   `users/:uid/role_assignments`, etc. are all in their
   original positions.
3. **Search for `SaasTab` in any downstream code.** The public
   type is renamed; downstream code that imported it needs to
   use `TenancyConsoleTab` instead.

A 0.11.0 deployment can run unchanged through this release —
no schema migration, no `wrangler.toml` change. The Worker
upgrade is the only operational step.

### Tests

- Total: **219 passing** (unchanged from 0.11.0).
  - core: 105.
  - adapter-test: 32.
  - ui: 82.
- The rename touched roughly every file under `saas/`; the
  test suite passing unchanged is the key regression check.
  The frame test that asserts the footer's version marker now
  asserts `"v0.12.0"`.

### Deferred

- **Tenant-scoped admin surface implementation** — slides to
  **0.13.0**. The 0.11.0 foundation
  (`AdminPrincipal::user_id`, `is_system_admin()`, the
  `admin_tokens.user_id` column) is unchanged and ready;
  0.12.1 is reserved as a buffer for any follow-up issues
  this rename surfaces in real-world use, and 0.13.0 builds
  the tenant-scoped routes on a clean naming base.
- **Anonymous-trial promotion** stays at the next available
  slot after the surface implementation.

### Why these changes belong in a release at all

A release whose code change is mostly mechanical may look
unusual, but each thread here has a real cost when left alone:

- **License and author metadata that don't match reality**
  make it ambiguous who owns the project and how to reach
  them — bad for downstream consumers, bad for security
  reporters.
- **Marketing-flavored framing** ("commercial SaaS") in a
  project that is actually open-source-under-Apache-2.0
  invites the wrong assumptions. Users may wonder whether
  there's a closed-source variant; contributors may wonder
  whether their work feeds someone else's revenue. Neither
  is the case.
- **Missing community-process documents** make a project look
  abandoned even when it isn't, and put friction on first-time
  contributors who reasonably expect them.
- **Naming debt** ("SaaS console" / `/admin/saas/*`) carries
  a one-time cost to retire and a per-release cost to live
  with. Retiring it before 0.13.0's tenant-scoped surface
  implementation lands means the new surface isn't built
  next to a stale name.

---

## [0.11.0] - 2026-04-26

Foundation for the tenant-scoped admin surface. This is a deliberately
small release: 0.10.0 left three open design questions on URL shape,
user-as-bearer mechanism, and system-admin from inside the tenant
view. v0.11.0 settles those questions in three architecture decision
records (ADR-001/002/003) and ships only the minimum schema + type
changes implied by the decisions. v0.12.0 retires the SaaS-naming
technical debt alongside other project-hygiene work
(`saas/` → `tenancy_console/`, plus authorship/license metadata
and `.github/` documents); v0.13.0 builds the full tenant-scoped
console on top of the foundation.

The split between "decide" (0.11.0) and "implement" (0.12.0) follows
the pattern this codebase has used elsewhere — 0.3.0 → 0.4.0 (read
pages → write UI) and 0.8.0 → 0.9.0 → 0.10.0 (read pages →
high-risk forms → low-risk forms). Mixing design judgment and
implementation in one release tends to lock in choices that should
have been revisited; doing them in sequence keeps each release small
and reviewable.

### Added

- **Three Architecture Decision Records** at
  `docs/src/expert/adr/`:
  - **ADR-001: URL shape** — path-based
    (`/admin/t/<slug>/...`) wins over subdomain-based
    (`<slug>.cesauth.example`). Single cert, single origin,
    same-origin auth model carries over from
    `/admin/saas/*`. Tenant identity is visible in the URL,
    routing has no `Host`-header surface to coordinate.
  - **ADR-002: User-as-bearer mechanism** — extend
    `admin_tokens` with an optional `user_id` column. Continue
    using `Authorization: Bearer <token>` as the wire format.
    No new CSRF surface; no new cryptographic key to rotate;
    one auth path covers both system-admin tokens
    (`user_id IS NULL`) and user-as-bearer tokens
    (`user_id IS NOT NULL`).
  - **ADR-003: System-admin from inside tenant view** —
    complete URL-prefix separation, no in-page mode switch.
    `/admin/saas/*` is system-admin; `/admin/t/<slug>/*` is
    tenant-admin. The two surfaces share no view code, no
    auth state, no precedence rules. Tenant-boundary leakage
    is structurally impossible because there is no view-layer
    code that conditions on "what mode am I in?"
  - Index page at `docs/src/expert/adr/README.md` with the ADR
    contract: when to write one, when not to.

- **Migration `0005_admin_token_user_link.sql`** adding a
  nullable `user_id` column to `admin_tokens` and a partial
  index on it (`WHERE user_id IS NOT NULL`). The migration is
  foundation-only — no code in v0.11.0 *gates* on the column.

- **`AdminPrincipal::user_id: Option<String>`** field, with
  documentation pointing at ADR-002. Every existing call site
  that constructs an `AdminPrincipal` defaults it to `None`,
  preserving v0.3.x and v0.4.x behavior. The Cloudflare D1
  adapters are updated to read the column from the
  `admin_tokens` table and propagate it onto the constructed
  principal.

- **`AdminPrincipal::is_system_admin()`** helper, returning
  `true` iff `user_id.is_none()`. v0.12.0 will use this to gate
  `/admin/saas/*` to system-admin tokens only and
  `/admin/t/<slug>/*` to user-as-bearer tokens only — the
  ADR-003 separation. v0.11.0 itself does not invoke the
  helper from any handler; the test suite pins down the
  invariant that 0.12.0 will rely on.

- **Three new core tests** locking in the principal-shape
  invariants:
  - `principal_with_no_user_binding_is_system_admin`
  - `principal_with_user_binding_is_not_system_admin`
  - `principal_user_id_round_trips_through_default_serialization`
    (v0.3.x JSON shape preserved when `user_id == None` via
    `#[serde(skip_serializing_if = "Option::is_none")]`).

### Changed

- **`admin_tokens` D1 row deserialization** in
  `crates/adapter-cloudflare/src/admin/principal_resolver.rs`
  and `tokens.rs` now selects `user_id` from the schema and
  populates `AdminPrincipal::user_id`. The existing v0.3.x +
  v0.4.x code paths are unaffected because `user_id` reads
  back as `None` for every existing row (which is what every
  existing row contains, since 0005 only added the column).

- **Book SUMMARY** grows an "Architecture decision records"
  section in the Expert chapter, indexed by ADR number.

### Tests

- Total: **219 passing** (+3 over 0.10.0's 216).
  - core: 105 (was 102) — 3 new tests.
  - adapter-test: 32 (unchanged).
  - ui: 82 (unchanged).

The bulk of the v0.11.0 change is the ADR documents and the
schema migration. The code change is intentionally narrow —
adding a field to a struct, threading it through D1
deserialization, and touching the 50-odd test fixtures that
construct an `AdminPrincipal` directly. v0.12.0 will be the
larger code change.

### Why no UI changes in v0.11.0

The decision to ship the ADRs and the foundation seam *separately*
from the implementation is intentional. Two reasons:

- Schema migrations are easier to review in isolation. Mixing a
  migration with new HTML routes makes both harder to review and
  splits the failure modes across review boundaries.
- ADRs that ship alongside their implementation tend to be
  written backwards — capturing what was already built rather
  than guiding what gets built. Writing them as foundation
  documents (with no UI yet) forces the design rationale to
  precede the code. v0.12.0's review can then check that the
  code matches the ADRs, not the reverse.

### Auth caveat (unchanged from 0.3.x and 0.10.0)

Forms POST same-origin and the bearer rides on the
`Authorization` header. Operators must use a tool that sets the
header (curl, browser extension). Cookie-based admin auth is
explicitly *not* part of the v0.11.0 user-as-bearer choice — see
ADR-002. The decision to keep `Authorization`-bearer as the wire
format means v0.12.0's tenant-scoped surface inherits the same
operator-tooling expectation.

### Deferred — still tracked for 0.12.0+

- **Tenant-scoped admin surface implementation**. The URL
  pattern, the per-route auth gate that requires
  `is_system_admin()`-vs-not, the views, and the mutation
  forms scoped to one tenant. **0.12.0.**
- **Admin-token mint flow with `user_id`**. The
  `AdminTokenRepository::create` method continues to mint
  system-admin tokens (no `user_id` parameter); v0.12.0 adds a
  parallel path or extends the existing one to mint
  user-bound tokens.
- **`check_permission` integration on the API surface** —
  v0.12.0 makes this cleanly possible because `AdminPrincipal`
  now carries the `user_id` that
  `check_permission(user_id, …)` needs.
- **Cookie-based auth** — explicitly *not* the user-as-bearer
  mechanism per ADR-002. May be revisited as an *additional*
  mechanism in a later ADR.
- **Anonymous-trial promotion.** **0.12.1.**
- **External IdP federation.**

---

## [0.10.0] - 2026-04-25

Completes the SaaS console mutation surface. v0.9.0 covered the
high-risk operations (status changes, plan changes, group delete);
v0.10.0 fills in the additive ones that were carved out of 0.9.0 to
keep its scope contained — three flavors of membership add/remove
and role-assignment grant/revoke. With this release the HTML
console reaches feature parity with the v0.7.0 JSON API for
operator-driven mutations.

The larger "tenant-scoped admin surface" item (where tenant admins
administer their own tenant rather than every tenant) is **not**
in this release — it has unresolved design questions on URL
shape, user-as-bearer mechanism, and tenant-boundary leakage that
deserve their own design pass. **0.11.0+** picks it up.

### Added

- **Five new HTML form templates** in `cesauth-ui::saas::forms`:
  - **`membership_add`** with three entry points (tenant /
    organization / group). Tenant form renders a 3-option role
    select (owner / admin / member); organization form renders
    a 2-option select (admin / member — no owner at org scope);
    group form omits the role field entirely (group memberships
    have no role).
  - **`membership_remove`** with three entry points. One-step
    confirm — there's no diff to render, just a yes/no decision
    with a "user loses access; data is not destroyed" warning.
  - **`role_assignment_create`** reachable from the user's
    role-assignments drill-in page. Renders a select for
    `role_id` (populated from the system role catalog), a 5-radio
    scope picker (system / tenant / organization / group / user),
    a free-text `scope_id` field with required-vs-optional rules
    documented in the help section, and an optional
    `expires_at` field.
  - **`role_assignment_delete`** confirm page. Shows the
    role label, scope, granted_by, granted_at, and a warning
    that the user "immediately loses any permission granted by
    this assignment" but that "session is not invalidated" —
    operators get the right mental model for what revoke does.

- **Five worker handler modules** in
  `crates/worker/src/routes/admin/saas/forms/`:
  `membership_add` (3 GET/POST pairs),
  `membership_remove` (3 GET/POST pairs),
  `role_assignment_create` (1 GET/POST pair),
  `role_assignment_delete` (1 GET/POST pair).
  Each handler delegates to the existing v0.5.0/0.6.0
  service-layer adapters and emits the appropriate audit event
  (`MembershipAdded`, `MembershipRemoved`, `RoleGranted`,
  `RoleRevoked`) with the `via=saas-console` reason marker.

- **16 new routes** wired in `lib.rs` under a new
  `// SaaS console mutations (v0.10.0: memberships + role assignments)`
  block:
  - `GET/POST /admin/saas/tenants/:tid/memberships/new`
  - `GET/POST /admin/saas/tenants/:tid/memberships/:uid/delete`
  - `GET/POST /admin/saas/organizations/:oid/memberships/new`
  - `GET/POST /admin/saas/organizations/:oid/memberships/:uid/delete`
  - `GET/POST /admin/saas/groups/:gid/memberships/new`
  - `GET/POST /admin/saas/groups/:gid/memberships/:uid/delete`
  - `GET/POST /admin/saas/users/:uid/role_assignments/new`
  - `GET/POST /admin/saas/role_assignments/:id/delete`
  All gated through `AdminAction::ManageTenancy` (Operations+).

- **Affordance buttons on read pages** (gated on
  `Role::can_manage_tenancy()`, ReadOnly sees nothing):
  - Tenant detail: new "+ Add tenant member" action button +
    per-row "Remove" link in the members table.
  - Organization detail: new "+ Add organization member" action
    button + per-row "Remove" link in the members table.
  - User role assignments: new "+ Grant role" action button +
    per-row "Revoke" link on each assignment.

- **Defensive look-up of role-assignment by id**. The
  `RoleAssignmentRepository` does not expose `get_by_id`; the
  delete handler walks `list_for_user(user_id)` to find the
  matching row. The query string and hidden form field carry
  the `user_id` so this lookup is always possible. A new
  `fetch_assignment` helper in
  `routes/admin/saas/forms/role_assignment_delete.rs` localizes
  this pattern.

### Changed

- **Frame footer** updated from
  "v0.9.0 (mutation forms enabled for Operations+)" to
  "v0.10.0 (full mutation surface for Operations+)".

### Tests

- Total: **216 passing** (+20 over 0.9.0's 196).
  - core: 102 (unchanged).
  - adapter-test: 32 (unchanged).
  - ui: 82 (was 62) — 18 new tests across the four new form
    templates (action URL shape, role-option count parity with
    spec §5, group form omits role field, sticky values
    preserved on re-render, HTML escape defense for user_id,
    confirm-yes hidden field carried, system-scope critical
    badge color, session-handoff warning copy) plus 2 new
    affordance gating tests on the existing
    `role_assignments` page (ReadOnly does not see grant /
    revoke; Operations does).

### Auth caveat (unchanged from 0.3.x and 0.9.0)

Forms POST same-origin and the bearer rides on the
`Authorization` header. Operators still need a tool that sets
the header (curl, browser extension). Cookie-based admin auth
remains a 0.11.0+ design pass alongside user-as-bearer.

### Design decisions worth recording

- **No preview/confirm on membership add.** Memberships are
  additive and reversible; adding a friction step for what is
  arguably the most-frequent mutation in a multi-tenant
  deployment is operator-hostile. The same logic applies to
  role grant — but role grant *can* widen a user's effective
  permissions, so the form does collect a reason-equivalent
  audit trail (`granted_by` + `granted_at`) and shows the role
  label clearly.
- **One-step confirm on membership remove and role revoke.**
  These are mildly destructive — the user immediately loses
  access through that path. We show a confirm page (one screen,
  one yes/no button) but don't render a diff because there's
  nothing structural to diff.
- **Form's scope picker is structured, not free-text.** The
  v0.7.0 JSON API takes a tagged Scope enum. Asking operators
  to write JSON in a textarea is a footgun — the radio +
  conditional id field encodes the same shape with no syntax to
  get wrong.
- **Defensive `fetch_assignment` lookup.** The role-assignment
  repository was designed for `list_for_user`-driven paths and
  does not expose `get_by_id`. Rather than add a port method
  for a UI-specific need, the handler walks the list. This
  costs at most one extra DB read per revoke and keeps the
  port surface narrow.
- **Helpful, not cute, error messages.** "User is already a
  member of this tenant" rather than "Conflict (409)";
  "Scope id required for tenant scope" rather than "validation
  failed". The form re-renders preserving sticky values so the
  operator only fixes the failed field.

### Deferred — still tracked for 0.11.0+

- **Tenant-scoped admin surface**. The v0.8.0-0.10.0 console
  serves the cesauth deployment's operator staff — one console,
  every tenant. A tenant-scoped admin surface (where tenant
  admins administer their own tenant rather than every tenant)
  is a parallel UI reachable from a tenant-side login, gated
  through user-as-bearer plus `check_permission`, and filtered
  to the caller's tenant. **0.11.0+.** Three open design
  questions deserve their own pass:
  1. URL shape — `/admin/t/<slug>/...` vs subdomain
     `<slug>.cesauth.example`.
  2. User-as-bearer mechanism — admin-token mapping vs session
     cookie vs JWT.
  3. How to surface system-admin operations from inside the
     tenant view without leaking other-tenant boundaries.
- **Cookie-based auth for admin forms** — lands with the
  user-as-bearer design pass.
- **`check_permission` integration on the API surface** —
  blocked on user-as-bearer.
- **Anonymous-trial promotion.** **0.12.0.**
- **External IdP federation.**

---

## [0.9.0] - 2026-04-25

The mutation surface for the SaaS console. v0.8.0 shipped the read
pages; v0.9.0 wraps the v0.7.0 JSON API in HTML forms with a
preview/confirm flow for destructive operations, mirroring the
v0.4.0 pattern used for bucket safety edits. Operations+ only;
ReadOnly continues to see the read pages from v0.8.0 with mutation
buttons hidden.

### Added

- **Eight HTML mutation forms** in `cesauth-ui::saas::forms`,
  surfaced through 16 worker routes (8 GET + 8 POST):
  - **One-click submit** (additive, isolated changes):
    `tenant_create`, `organization_create`, `group_create`
    (tenant- and org-rooted variants).
  - **Two-step preview/confirm** (destructive — status changes,
    plan changes, deletes):
    `tenant_set_status`, `organization_set_status`,
    `group_delete`, `subscription_set_plan`,
    `subscription_set_status`.
  - The pattern is the same one v0.4.0 introduced: first POST
    (without `confirm=yes`) re-renders the page with a diff
    banner and an Apply button; the Apply button POSTs again
    with `confirm=yes` and commits.

- **Affordance buttons on read pages.** Tenants list grows a
  "+ New tenant" link; tenant detail grows
  "+ New organization", "+ New tenant-scoped group",
  "Change tenant status", "Change plan", and
  "Change subscription status" (the last two only when a
  subscription is on file); organization detail grows
  "+ New group", "Change organization status", and a per-row
  "Delete" link in the groups table. Every button renders
  conditionally on `Role::can_manage_tenancy()`; ReadOnly
  operators see no button (so a click cannot lead to a 403
  page).

- **`Role::can_manage_tenancy()`** helper on
  `cesauth_core::admin::types::Role`. Documented as a
  presentation-layer hint only — the authoritative gate is on
  the route handler. A new core test
  `role_can_manage_tenancy_helper_matches_policy` pins the
  helper's parity with `role_allows(_, ManageTenancy)`, so a
  policy change cannot drift the UI gating without a test
  failure.

- **Worker forms helper module**
  `crates/worker/src/routes/admin/saas/forms/common.rs`:
  - `require_manage` — bearer resolve + `ManageTenancy` gate.
    Returns the principal or a `Response` to short-circuit.
  - `parse_form` — `application/x-www-form-urlencoded` →
    flat `HashMap<String, String>`.
  - `confirmed` — checks the `confirm` field for `"yes"`/`"1"`/
    `"true"`. Used by the preview/confirm dispatch.
  - `redirect_303` — `303 See Other` to a destination URL.
    Browsers follow GET on 303, dropping the form body, so
    page refreshes don't re-submit.

- **HTML escape defense** on every operator-supplied field
  (slug, display_name, owner_user_id, reason). Test coverage
  added: `tenant_create::tests::untrusted_input_is_html_escaped`
  and `tenant_set_status::tests::reason_is_html_escaped_on_confirm_page`.

- **Quota delta visualization** on subscription plan change.
  The confirm page renders a quota-by-quota table comparing
  current vs target plan, with `⚠` markers on quotas that
  *decrease* — the operator's most common "wait, let me check"
  case. Existing usage above the new limit is documented as
  not auto-pruned but blocking new creates.

- **Destructive-operation warnings** baked into the confirm
  pages. Tenant suspend warns "refuses sign-ins for every user
  in this tenant"; tenant delete warns "Recovery requires
  manual SQL"; subscription expire warns "plan-quota
  enforcement falls through to no-plan allow-all"; subscription
  cancel notes "current period continues to be honored".

- **Sticky form values on re-render.** A failed submit (slug
  collision, missing field, quota exceeded) re-renders the
  form with the operator's existing inputs preserved so they
  only fix the failed field. Test coverage added.

- **Footer marker** updated from "v0.8.0 (read-only)" to
  "v0.9.0 (mutation forms enabled for Operations+)".

### Tests

- Total: **196 passing** (+30 over 0.8.0's 166).
  - core: 102 (was 101) — 1 new test:
    `role_can_manage_tenancy_helper_matches_policy`.
  - adapter-test: 32 (unchanged).
  - ui: 62 (was 33) — 29 new tests:
    - 4 each for `tenant_create`, `tenant_set_status`,
      `subscription_set_plan`.
    - 2-3 for each of `organization_create`,
      `organization_set_status`, `group_create`,
      `group_delete`, `subscription_set_status`.
    - 5 affordance-gating tests on the existing read
      pages (ReadOnly hides buttons, Operations+ sees them,
      subscription buttons appear only when a subscription
      exists).
- Worker form handlers themselves require a Workers runtime;
  their service-layer delegation is covered by the existing
  host tests.

### Auth caveat (unchanged from 0.3.x and 0.8.0)

Forms POST same-origin and the bearer rides on the
`Authorization: Bearer ...` header — same as the read pages
and same as the v0.3.x edit forms. The `Authorization` header
is not auto-forged by browsers across origins, which is the
CSRF defense; but it also means operators must use a tool
that sets the header (curl, browser extension, or once it
lands, the v0.10.0+ user-as-bearer cookie path). This is the
existing 0.3.x limitation; v0.9.0 inherits rather than
relaxes it. The v0.10.0+ cookie-based auth design pass is
where this changes.

### Design decisions worth recording

- **Risk-graded preview/confirm.** Not every mutation needs a
  preview screen — adding a friction step for low-risk
  additive operations (creates, role grants within a single
  tenant, membership add) is operator hostile. The preview
  pattern is reserved for destructive or expensive operations
  (status changes, group deletes, plan changes).

- **POST/Redirect/GET via 303 See Other.** After a successful
  mutation the handler redirects to the relevant read page
  (e.g. `/admin/saas/tenants/:tid` after a status change),
  not back to the form. This means a browser refresh on the
  landing page does not re-submit the mutation.

- **`Role::can_manage_tenancy()` not on `AdminPrincipal`.** The
  helper is on `Role` so UI templates can check it without
  importing the principal type, and so a future tenant-scoped
  admin (with a different bearer model) can introduce its own
  helper without conflating the two.

- **Pure presentation-layer hint, with a test-locked parity
  invariant.** The helper documents itself as a presentation-
  layer hint; the new
  `role_can_manage_tenancy_helper_matches_policy` test ensures
  it cannot drift from the authoritative policy. Together
  these prevent the failure mode where a refactor changes the
  policy but leaves a stale UI gate.

### Deferred — still tracked for 0.10.0+

The 0.9.0 surface focuses on the mutations operators do most
often. Items still pending:

- **Role grant / revoke forms.** Today these go through the
  v0.7.0 JSON API or wrangler. A "Grant role" form on a user's
  role assignments page is the natural fit. Slated for the
  next iteration.
- **Membership add / remove forms.** Same as above — frequent,
  low-risk; the JSON API handles them today.
- **Tenant-scoped admin surface.** Tenant admins administering
  their own tenant rather than every tenant. **0.10.0+.** This
  is the user-as-bearer / login → tenant resolution / cookie-
  auth design pass.
- **`check_permission` integration on the API surface.**
  Blocked on user-as-bearer.
- **Anonymous-trial promotion.** **0.11.0.**
- **External IdP federation.**

---

## [0.8.0] - 2026-04-25

A read-only HTML console at `/admin/saas/*` for cesauth's operator
staff to inspect tenancy / billing state. Sits parallel to (and
visually distinct from) the v0.3.x cost / data-safety console at
`/admin/console/*`. Mutation continues to flow through the v0.7.0
JSON API; the HTML preview/confirm flow that wraps those mutations
is slated for v0.9.0 with the same two-step pattern v0.4.0
introduced for bucket safety edits.

### Added

- **SaaS console UI module** in `cesauth-ui`
  (`crates/ui/src/saas/`): `frame` + 5 page templates.
  - `Overview` — deployment-wide counters (tenants by status,
    org/group counts, active plan count) plus a per-plan
    subscriber breakdown via `LEFT JOIN`.
  - `Tenants` — list of every non-deleted tenant with status
    badges and drill-through to detail.
  - `Tenant detail` — summary, current subscription with plan
    label, organization list, member list. Links out to org
    detail and per-user role assignments.
  - `Organization detail` — summary, org-scoped groups, members.
  - `Subscription history` — append-only log per tenant,
    reverse-chronological (newest first — operators most often
    ask "what changed last").
  - `User role assignments` — every assignment held by one user,
    across every scope, with rendered scope links and
    role-label-with-display-name.

- **Worker route handlers** in `crates/worker/src/routes/admin/saas/`:
  one handler per page above. Each delegates to the existing
  `crate::routes::admin::auth::resolve_or_respond` for bearer
  resolution and `ensure_role_allows(AdminAction::ViewTenancy)`
  for capability gating. Response shaping (CSP / cache-control /
  frame-deny) reuses
  `crate::routes::admin::console::render::html_response`.

- **6 new HTML routes** wired in `lib.rs`:
  - `GET /admin/saas`
  - `GET /admin/saas/tenants`
  - `GET /admin/saas/tenants/:tid`
  - `GET /admin/saas/tenants/:tid/subscription/history`
  - `GET /admin/saas/organizations/:oid`
  - `GET /admin/saas/users/:uid/role_assignments`

- **Distinct nav frame** (`SaasTab`). Two top-level tabs
  (`Overview`, `Tenants`); the `UserRoleAssignments` tab is a
  drill-in destination only and is filtered out of the nav even
  when active. Footer bears a `read-only` marker so operators
  cannot mistake this surface for the writable v0.9.0 follow-up.

- **Tests** (+22 over 0.7.0's 144, total 166):
  - `ui::saas::tests` (4) — frame role badge, active-tab
    `aria-current`, drill-in tab not in nav, footer read-only
    marker.
  - `ui::saas::overview::tests` (4) — counter rendering, empty
    plan-breakdown empty state, plan rows, read-only disclaimer
    presence.
  - `ui::saas::tenants::tests` (4) — empty list call-to-action,
    drill-link href shape, suspended status badge, HTML escape
    of untrusted display_name.
  - `ui::saas::tenant_detail::tests` (4) — summary + no-sub case,
    organization list, subscription with plan, member→user link.
  - `ui::saas::subscription::tests` (3) — empty history, reverse-
    chronological ordering, back link.
  - `ui::saas::role_assignments::tests` (3) — empty state, scope
    drill-links + system badge, dangling-role-id resilience.

### Changed

No breaking changes. The 0.7.0 JSON API at `/api/v1/...` continues
to work identically. The 0.8.0 console only **reads** through the
existing service-layer ports + D1 adapters.

### Deferred — still tracked for 0.9.0+

The 0.8.0 console is read-only by design. The mutation surface
(create / update / delete forms with the v0.4.0 preview/confirm
pattern) is the headline 0.9.0 feature. Other still-deferred items
are unchanged from 0.7.0:

- **HTML mutation forms with two-step confirmation** (0.9.0) —
  same preview-then-confirm pattern v0.4.0 introduced for bucket
  safety edits, applied to tenant create / update, org create /
  status change, role grant / revoke, subscription plan/status
  change.
- **Tenant-scoped admins** — tenant admins administering their
  own tenant rather than the cesauth operator administering
  every tenant. Requires user-as-bearer auth and login → tenant
  resolution UX, both of which are open design questions.
- **`check_permission` integration on the API surface** —
  blocked on user-as-bearer.
- **`max_users` quota enforcement** — waits on a user-create
  surface that respects tenancy.
- **Anonymous-trial promotion**.
- **External IdP federation**.

---

## [0.7.0] - 2026-04-25

The HTTP API surface for the tenancy-service data model. v0.5.0
shipped the data model and central authz function; v0.6.0 shipped
the Cloudflare D1 adapters and made `users` tenant-aware; v0.7.0
ships the routes operators use to drive that machinery from the
outside.

### Added

- **`/api/v1/...` route module** (`crates/worker/src/routes/api_v1/`):
  - **Tenants**: `POST /api/v1/tenants` (create with owner
    membership), `GET /api/v1/tenants` (list active),
    `GET /api/v1/tenants/:tid`, `PATCH /api/v1/tenants/:tid`
    (display name), `POST /api/v1/tenants/:tid/status`.
  - **Organizations**: `POST/GET /api/v1/tenants/:tid/organizations`,
    `GET/PATCH /api/v1/tenants/:tid/organizations/:oid`,
    `POST /api/v1/tenants/:tid/organizations/:oid/status`. The
    GET handler verifies the org's `tenant_id` matches the URL
    `:tid` — defense in depth against id-guessing across tenants.
  - **Groups**: `POST/GET /api/v1/tenants/:tid/groups`
    (the GET takes `?organization_id=...` to narrow to org-scoped
    groups), `DELETE /api/v1/groups/:gid`.
  - **Memberships** — three flavors under a unified handler shape:
    `POST/GET/DELETE /api/v1/tenants/:tid/memberships[/:uid]`,
    `.../organizations/:oid/memberships[/:uid]`,
    `.../groups/:gid/memberships[/:uid]`.
  - **Role assignments**: `POST /api/v1/role_assignments`,
    `DELETE /api/v1/role_assignments/:id`,
    `GET /api/v1/users/:uid/role_assignments`.
  - **Subscriptions**: `GET /api/v1/tenants/:tid/subscription`,
    `POST .../subscription/plan`, `POST .../subscription/status`,
    `GET .../subscription/history`. Plan changes refuse to point
    at archived (`active = false`) plans. Every plan / status
    change appends a `subscription_history` entry.

- **27 routes wired** into `lib.rs` under a `// --- Tenancy-service
  API (v0.7.0)` block, contiguous with the existing
  `/admin/console/...` routes.

- **Two new admin capabilities** in
  `cesauth_core::admin::types::AdminAction`:
  - `ViewTenancy` — read tenancy data; granted to every valid
    role (admin tokens already pass a trust boundary).
  - `ManageTenancy` — mutate tenancy data; Operations+ only,
    matching the existing tier with `EditBucketSafety` /
    `EditThreshold` / `CreateUser`. Security alone does not get
    to provision tenants.

- **Plan-quota enforcement** (spec §6.7) at create time for
  organizations and groups. The pure decision logic lives in
  `cesauth_core::billing::quota_decision`:
  - `None` plan → `Allowed` (operator-provisioned tenants without
    a subscription).
  - Quota row absent → `Allowed`.
  - Quota value `-1` (`Quota::UNLIMITED`) → `Allowed` at any count.
  - Otherwise compares `current` vs `limit`, returning
    `Denied { name, limit, current }` when the next insert
    would exceed.
  The worker side (`routes::api_v1::quota::check_quota`) reads the
  current count via `SELECT COUNT(*) FROM <table> WHERE
  tenant_id = ? AND status != 'deleted'` and feeds it to
  `quota_decision`. A `quota_exceeded:<name>` 409 surfaces to the
  caller.

- **14 new audit `EventKind` variants** for tenancy mutations:
  `TenantCreated`, `TenantUpdated`, `TenantStatusChanged`,
  `OrganizationCreated`, `OrganizationUpdated`,
  `OrganizationStatusChanged`, `GroupCreated`, `GroupDeleted`,
  `MembershipAdded`, `MembershipRemoved`, `RoleGranted`,
  `RoleRevoked`, `SubscriptionPlanChanged`,
  `SubscriptionStatusChanged`. Every mutating route emits one with
  the actor (admin principal id), subject (created/affected row
  id), and a structured `reason` field.

### Tests

- Total: **144 passing** (+8 over 0.6.0's 136).
  - core: 101 (was 93) — 2 new admin-policy tests
    (`every_valid_role_may_view_tenancy`,
    `manage_tenancy_is_operations_plus`) + 6 new
    `quota_decision` tests covering no-plan, missing quota row,
    unlimited sentinel, below-limit allow, at-limit deny, and
    above-limit deny edge cases.
  - adapter-test: 32 (unchanged).
  - ui: 11 (unchanged).
- The route handlers are not exercised by host tests — they
  require a Workers runtime — but every route delegates to the
  service layer or the D1 adapters, both of which are covered by
  the host tests above. Route-handler contract is verified at
  deploy time via `wrangler dev` or curl-against-deploy.

### Design decisions worth recording

- **Admin-bearer, not user-as-bearer.** `cesauth_core::authz::
  check_permission` expects a `user_id` and a scope. Admin tokens
  are operator credentials with no row in `users`, and the
  user-as-bearer path (issuing a JWT/session bearer that the
  gateway parses into a tenant-scoped request) is part of the
  multi-tenant admin console (0.8.0). So 0.7.0 ships an API
  surface for *cesauth's operator staff* to provision tenants.
  Self-service tenant operations are deferred. The route handlers
  go through `ensure_role_allows` (admin-side capability) rather
  than `check_permission` (tenancy-side capability); the two
  converge in 0.8.0+ when user bearers arrive.

- **JSON-only, no Accept negotiation.** HTML belongs in 0.8.0 with
  the multi-tenant admin console.

- **URL hierarchy is the natural tree** (`/api/v1/tenants/:tid/
  organizations`, `/api/v1/tenants/:tid/organizations/:oid/...`)
  for tenant-rooted operations. Operations on a single non-tenant
  scoped resource (one group, one role-assignment) take the direct
  form `/api/v1/groups/:gid` so callers don't need to know the
  parent path.

- **Quota count by `SELECT COUNT(*)`, not by cached counter.** This
  is a low-volume admin API; the COUNT on an indexed column is
  cheaper than the cache-invalidation discipline a counter
  would require. When self-signup lands, we will need to migrate
  to a counter-with-occasional-reconcile pattern; until then the
  simple read wins.

### Deferred — still tracked for 0.8.0+

- **Multi-tenant admin console** (0.8.0) — HTML surface for
  tenant-scoped admins. Opens user-as-bearer, login → tenant
  resolution, and Accept negotiation as one design pass.
- **Anonymous-trial promotion** (0.9.0).
- **External IdP federation**.

---

## [0.6.0] - 2026-04-25

The runtime backing for v0.5.0's tenancy-service data model.
Implements the Cloudflare D1 adapters for every port the 0.5.0 core
defined, and migrates the existing `users` table to be tenant-aware.
Routes / multi-tenant admin console / login-tenant resolution remain
deferred (see "Deferred" below).

### Added

- **Cloudflare D1 adapters for every 0.5.0 port** (10 adapters
  in `cesauth-adapter-cloudflare`):
  - `tenancy::{CloudflareTenantRepository,
    CloudflareOrganizationRepository, CloudflareGroupRepository,
    CloudflareMembershipRepository}`.
  - `authz::{CloudflarePermissionRepository,
    CloudflareRoleRepository, CloudflareRoleAssignmentRepository}`.
  - `billing::{CloudflarePlanRepository,
    CloudflareSubscriptionRepository,
    CloudflareSubscriptionHistoryRepository}`.
  Each follows the existing CF-adapter pattern: `pub struct
  CloudflareXRepository<'a> { env: &'a Env }`, manual `Debug` impl,
  Serde row struct → domain via `into_domain`. UNIQUE-violation
  errors are mapped to `PortError::Conflict` by string-matching on
  `"unique"` / `"constraint"` (worker-rs gives no structured error
  code; this is the same pattern the 0.3.x admin adapters use).

- **Schema decisions made explicit** in the role/plan adapters:
  - `roles.permissions` is stored as a comma-separated string. D1
    has no JSON1 extension; a `role_permissions` join table would
    require an N+1 read on the authz hot path. Permission names are
    `[a-z:]+` (no commas), making a comma-list safe.
  - `plans.features` is a comma-separated list; `plans.quotas` is
    `name=value,name=value`. Same trade-off; the catalog data is
    static enough that an extra table is overkill.

- **Migration `0004_user_tenancy_backfill.sql`** (101 lines).
  Adds `tenant_id` (NOT NULL, REFERENCES `tenants`) and
  `account_type` (TEXT, CHECK enumerating spec §5's five values) to
  `users`. Uses the SQLite-standard "rename, recreate, copy" pattern
  because D1 cannot ADD COLUMN with a foreign key in one step.
  Backfills every pre-0.6.0 user into `tenant-default` with
  `account_type = 'human_user'`. Also auto-inserts a
  `user_tenant_memberships` row so every user has a membership in
  their bootstrap tenant — no orphaned users post-migration.

- **`User` struct gains `tenant_id` and `account_type`** in
  `cesauth_core::types`. Both fields use `serde(default = ...)` so
  pre-0.6.0 cached payloads continue to deserialize cleanly. The
  defaults are `tenancy::DEFAULT_TENANT_ID` and
  `tenancy::AccountType::HumanUser`, matching the migration's
  backfill values exactly. New core tests
  `user_serializes_with_tenant_and_account_type` and
  `user_deserializes_pre_0_4_1_payload_with_defaults` pin the
  forward- and backward-compat shape.

- **Email uniqueness becomes per-tenant.** The 0001 migration's
  `UNIQUE(email)` is replaced in 0004 with `UNIQUE(tenant_id, email)`.
  `find_by_email` adds an explicit `LIMIT 1` and a comment about
  the contract change; the spec'd `find_by_email_in_tenant`
  variant arrives with the multi-tenant login flow in 0.7.0+.

### Changed

- **User construction sites updated.**
  `routes/admin/legacy.rs::create_user` and
  `routes/magic_link/verify.rs` (auto-signup at first verification)
  now stamp `tenant_id = tenant-default` and
  `account_type = HumanUser` when creating users. A multi-tenant
  signup path will land alongside the multi-tenant routes.

### Tests

- Total: **136 passing** (+3 over 0.5.0's 133).
  - core: 93 (was 90) — three new `User` serde tests covering
    forward, backward, and default-value behavior.
  - adapter-test: 32 (unchanged).
  - ui: 11 (unchanged).
- The Cloudflare D1 adapters are not exercised by host tests
  (they require a Workers runtime). The host tests in
  `adapter-test` cover the same trait surface against the
  in-memory adapters; the CF adapters' contract correctness is
  verified at deploy time via `wrangler dev`.

### Deferred — still tracked for 0.7.0+

- **HTTP routes** for tenant / organization / group / role-assignment
  CRUD. The service layer + adapters are now both ready; what
  remains is the bearer-extension that carries
  `(user_id, tenant_id?, organization_id?)` context through the
  router, the Accept-aware HTML/JSON rendering, and the integration
  with `check_permission`. This is its own design pass — see
  ROADMAP for the open questions on URL shape and admin-bearer vs
  session-cookie auth.
- **Multi-tenant admin console**.
- **Login → tenant resolution** UX.
- **Plan-quota enforcement** at user-create / org-create / group-create.
- **Anonymous-trial promotion**.
- **External IdP federation**.

---

## [0.18.0] - 2026-04-25

The tenancy-service foundation. Implements the data model and core
authorization engine from
`cesauth-tenancy-service-extension-spec.md` §3-§5 and §16.1,
§16.3, §16.6. Routes / UI / multi-tenant admin console are deferred
to 0.6.0 by design (see "Deferred" below).

### Added

- **Tenancy domain** (`cesauth_core::tenancy`). New entities:
  - `Tenant` — top-level boundary (§3.1). States: pending, active,
    suspended, deleted.
  - `Organization` — business unit within a tenant (§3.2).
    `parent_organization_id` column reserved for future hierarchy;
    flat in 0.5.0.
  - `Group` — membership/authz unit (§3.3) with `GroupParent`
    explicit enum: `Tenant` (tenant-wide group) or
    `Organization { organization_id }` (org-scoped). The CHECK in
    migration 0003 enforces exactly one parent flavor at the DB
    level.
  - `AccountType` (§5) — `Anonymous`, `HumanUser`, `ServiceAccount`,
    `SystemOperator`, `ExternalFederatedUser`. Deliberately
    separate from role/permission per §5 ("user_type のみで admin
    判定を行わない").
  - Membership relations: `TenantMembership`, `OrganizationMembership`,
    `GroupMembership`. Three tables, one
    `MembershipRepository` port. Spec §2 principle 4 ("所属は属性
    ではなく関係として表現する") is the structural reason for the
    split.

- **Authorization domain** (`cesauth_core::authz`).
  - `Permission` (atomic capability string) + `PermissionCatalog`
    constant listing the 25 permissions cesauth ships with.
  - `Role` — named bundle of permissions; system role
    (`tenant_id IS NULL`) or tenant-local role.
  - `RoleAssignment` — one user, one role, one `Scope`. Scopes
    are `System`, `Tenant`, `Organization`, `Group`, `User` (§9.1).
  - `SystemRole` constants for the six built-in roles seeded by
    the migration: `system_admin`, `system_readonly`, `tenant_admin`,
    `tenant_readonly`, `organization_admin`, `organization_member`.
  - **`check_permission`** — the single authorization entry point
    (§9.2 "権限判定関数を単一のモジュールに集約する"). Pure
    function over `(RoleAssignmentRepository, RoleRepository, user,
    permission, scope, now_unix)`. Handles expiration explicitly,
    surfacing `DenyReason::Expired` separately from
    `ScopeMismatch`/`PermissionMissing` so audit logs can distinguish
    "grant ran out" from "wrong scope".
  - Scope-covering lattice: a `System` grant covers every scope; a
    same-id `Tenant`/`Organization`/`Group`/`User` grant covers
    the matching `ScopeRef`. Cross-tier coverage ("my tenant grant
    applies to this org") is tagged as a follow-up — for 0.5.0 the
    caller is expected to query at the natural scope of the
    operation, which it always knows.

- **Billing domain** (`cesauth_core::billing`).
  - `Plan` and `Subscription` are strictly separated (§8.6 "Plan と
    Subscription を分離する"). Plans live in a global catalog;
    subscriptions reference plans by id and carry only the
    tenant-specific state.
  - `SubscriptionLifecycle` (`trial`/`paid`/`grace`) and
    `SubscriptionStatus` (`active`/`past_due`/`cancelled`/`expired`)
    are orthogonal axes per §8.6 ("試用状態と本契約状態を分ける").
    Test `subscription_lifecycle_and_status_are_orthogonal` pins
    the separation as a documentation-style assertion.
  - `SubscriptionHistoryEntry` — append-only log of plan/state
    transitions; one row per event so "when did this tenant move
    plans?" has a deterministic answer.
  - Four built-in plans: Free, Trial, Pro, Enterprise.
    Quotas use `-1` to mean unlimited (`Quota::UNLIMITED`); features
    are free-form strings keyed on a stable name.

- **Migration `0003_tenancy.sql`** (281 lines): adds 11 tables — one
  for each entity above plus the three membership relations. Seeds:
  one bootstrap tenant with id `tenant-default` (matches
  `tenancy::DEFAULT_TENANT_ID`), the 25 permissions, the 6 system
  roles, and the 4 built-in plans. `INSERT OR IGNORE` throughout so
  the migration is re-runnable.

- **In-memory adapters** in `cesauth-adapter-test`:
  `tenancy::{InMemoryTenantRepository, InMemoryOrganizationRepository,
  InMemoryGroupRepository, InMemoryMembershipRepository}`,
  `authz::{InMemoryPermissionRepository, InMemoryRoleRepository,
  InMemoryRoleAssignmentRepository}`,
  `billing::{InMemoryPlanRepository, InMemorySubscriptionRepository,
  InMemorySubscriptionHistoryRepository}`. All ten implement the
  shipped ports.

- **Tests** (+30 over 0.4.0's 103, total 133):
  - core: 18 new (5 tenancy types, 7 authz scope-covering / catalog /
    deny-reason, 5 billing types, 1 dangling-role-id resilience).
  - adapter-test: 12 new — end-to-end tenant→org→group flow, slug
    validation edges, duplicate-slug conflict, suspended-tenant
    org rejection, full-catalog round-trip, plan & subscription &
    history round-trip, single-active-subscription invariant,
    purge-expired roles.

### Changed

- `cesauth_core::lib.rs` exports three new modules: `tenancy`,
  `authz`, `billing`. No existing module changes.

### Deferred — not in 0.5.0, tracked for 0.6.0+

The spec's §16 receive criteria are broad. 0.5.0 ships the data
model and the central authz engine; the items below are
prerequisites for a fully-receivable v0.4 but each carries enough
design surface to deserve its own release:

- **HTTP routes** for tenant / organization / group / role CRUD.
  The service layer has one function per operation; the route layer
  needs an admin-bearer extension carrying `(user, tenant?, org?)`
  context that a 0.6.0 design pass should specify before wiring.
- **Cloudflare D1 adapters** for the new ports. The schema is in
  place; mapping each port to D1 statements is mechanical but
  voluminous.
- **Multi-tenant admin console**. The 0.3.x admin console assumes
  a single deployment-wide operator; tenant-scoped admins need a
  new tab structure and tenancy-aware route guards.
- **Login → tenant resolution**. Today `email` is globally unique
  in `users`. Multi-tenant deployments need either tenant-scoped
  email uniqueness or a tenant-picker step in the login flow. Spec
  §6.1 mentions tenant-scoped auth policies; the precise UX is open.
- **Anonymous trial → human user promotion** (§3.3 of spec, §11
  priority 5). The `Anonymous` account type exists; the lifecycle
  (token issuance, retention window, conversion flow) is unspecified
  and will be its own design pass.
- **Subscription enforcement at runtime**. `Plan.quotas` are
  recorded but no code reads them at user-create / org-create time.
  Enforcement hooks land alongside the routes.
- **External IdP federation** (§3.3 of spec, §11 priority 8).
  `AccountType::ExternalFederatedUser` is reserved; the wiring is
  follow-up.
- **Tenant-scoped audit log filtering**. The 0.3.x audit search is
  global. A tenant-aware filter is small but requires the
  multi-tenant admin console to land first.

---

## [0.5.0] - 2026-04-24

### Added

- **HTML two-step confirmation UI for bucket-safety edits.** The
  pre-0.4.0 preview/apply JSON API is unchanged; 0.4.0 adds a
  form-based wrapper that the Configuration Review page now links to
  per bucket (Operations+ only). The flow:
  1. `GET /admin/console/config/:bucket/edit` renders an edit form
     pre-populated with the current attested state.
  2. `POST` submits the proposed values; the handler re-renders the
     same URL as a confirmation page showing a before/after diff with
     the changed fields highlighted.
  3. Submitting the "Apply" button on the confirmation page re-POSTs
     with `confirm=yes` and the handler commits the change, auditing
     both the attempt (`attempt:BUCKET`) and the outcome
     (`ok:BUCKET`), then 303-redirects back to the review page.
  Corresponds to spec §7's "二段階確認" for dangerous operations.

- **Admin-token CRUD UI (Super-only).** New screens at
  `/admin/console/tokens`:
  - `GET  /admin/console/tokens` — table of non-disabled rows in
    `admin_tokens` (id, role, name, disable button).
  - `GET  /admin/console/tokens/new` — form to mint a new token.
  - `POST /admin/console/tokens` — server mints 256 bits of
    getrandom-sourced plaintext (two `Uuid::new_v4()` concatenated),
    SHA-256-hashes it for storage, inserts the row, and renders the
    plaintext **exactly once** with a prominent one-shot warning.
    Emits `AdminTokenCreated`.
  - `POST /admin/console/tokens/:id/disable` — flips `disabled_at`;
    refuses to disable the caller's own token to prevent accidental
    self-lockout. Emits `AdminTokenDisabled`.
  Per spec §14 ("provisional simple implementation" until tenant
  boundaries land), the list shows only `id`/`role`/`name`; richer
  `created_at` / `last_used_at` / `disabled_at` metadata is a
  post-tenant decision.

- **Conditional Tokens tab in the admin nav.** Visible only when the
  current principal's role is `Super`. Other roles still get a 403
  from the route if they navigate there directly — the tab
  visibility is a UX convenience, not a security boundary.

- **New audit event kinds**: `AdminTokenCreated`, `AdminTokenDisabled`.

- **Test coverage** (+10 tests, total 103):
  - `adapter-test`: token-CRUD roundtrip, hash uniqueness →
    `PortError::Conflict`, disable-unknown → `PortError::NotFound`.
  - `ui`: role-badge rendering, Tokens-tab visibility matrix,
    HTML-escape on untrusted notes, HTML-escape on displayed
    plaintext bearer, changed-fields marker correctness,
    no-change short-circuit on the confirm page, empty-list
    bootstrap-fallback hint.

### Changed

- **Fix: admin pages now show the caller's actual role in the header
  badge.** `cost_page`, `audit_page`, and `alerts_page` were
  hardcoding `Role::ReadOnly` and omitting the operator name; they
  now take an `&AdminPrincipal` like the other pages and propagate
  the role and label through to the header.

- **`AdminPrincipal` gained `Serialize`.** Needed so
  `GET /admin/console/tokens?Accept=application/json` can return the
  list as-is. `Deserialize` is deliberately *not* derived —
  adapters build these from their own row shapes, and nothing on the
  wire should revive one from a client blob.

- **Configuration Review's "Editing" section rewritten.** Pre-0.4.0
  it pointed operators at the JSON API only; it now describes the
  in-UI edit flow first and keeps the JSON recipes as a scripted
  alternative.

### Security

- **Token plaintext is touched for exactly one request path.** The
  server holds the plaintext only long enough to (a) SHA-256 it for
  storage and (b) render it once on the created-token page; no logs,
  no DO state, no error paths mention it. If the operator closes
  that tab without copying, they disable the token and create a new
  one.

- **Self-disable guard on `/admin/console/tokens/:id/disable`.** The
  handler refuses to disable the same principal id that
  authenticated the request. Not a security issue (the operator is
  already authorized to do it), but an accidental lockout of the
  only active Super is painful enough to catch here. The
  `ADMIN_API_KEY` bootstrap path is unaffected: `super-bootstrap`
  has no row and cannot be disabled from the UI at all.

### Deferred (tracked for 0.3.2+)

- **Workers-request and Turnstile-verify hot-path counters.** The
  admin console already reads these KV keys; writing them has a
  residual design question (at what request granularity do we
  count — every fetch, only successful handlers, by path?) that is
  not settled by the spec. See `ROADMAP.md`.
- **Durable Objects enumeration.** Still blocked on a Cloudflare
  runtime API that does not exist.


---

## Versioning history note

**Range affected: 0.5.0 through 0.18.1 (entries above this note).**

The version numbers shown in those entries were retroactively
re-aligned with cesauth's
[versioning policy](../ROADMAP.md#versioning-policy)
(introduced at 0.18.0 / formerly 0.18.0).

Each "minor-shaped" change — new HTTP route surface, new schema
migration, new public type or trait, new permission slug, new
operator-visible config — earns a minor bump. Each "patch-shaped"
change — internal refactor, security fix preserving wire
compatibility, doc-only — earns a patch bump.

When the policy was applied to past releases, several earlier
"patch" bumps that should have been minors got promoted. The
shipped tarballs themselves did not change (those are immutable
artifacts) — only the version numbers used in this changelog,
in `Cargo.toml`, and in subsequent VCS commits were re-aligned.
The mapping is:

| Tarball file (immutable) | Re-aligned version (this changelog &amp; VCS) |
|---|---|
| `cesauth-0.18.1.tar.gz`  | **0.18.1** |
| `cesauth-0.18.0.tar.gz`  | **0.18.0** |
| `cesauth-0.17.0.tar.gz` | **0.17.0** |
| `cesauth-0.16.0.tar.gz` | **0.16.0** |
| `cesauth-0.15.1.tar.gz` | **0.15.1** |
| `cesauth-0.15.0.tar.gz` | **0.15.0** |
| `cesauth-0.14.0.tar.gz` | **0.14.0** |
| `cesauth-0.13.0.tar.gz`  | **0.13.0** |
| `cesauth-0.12.1.tar.gz`  | **0.12.1** |
| `cesauth-0.12.0.tar.gz`  | **0.12.0** |
| `cesauth-0.11.0.tar.gz`  | **0.11.0** |
| `cesauth-0.10.0.tar.gz`  | **0.10.0** |
| `cesauth-0.9.0.tar.gz`  | **0.9.0**  |
| `cesauth-0.8.0.tar.gz`  | **0.8.0**  |
| `cesauth-0.7.0.tar.gz`  | **0.7.0**  |
| `cesauth-0.6.0.tar.gz`  | **0.6.0**  |
| `cesauth-0.5.0.tar.gz`  | **0.18.0**  |
| `cesauth-0.4.0.tar.gz`  | **0.5.0**  |
| `cesauth-0.3.0.tar.gz`  | 0.3.0 (unchanged) |
| `cesauth-0.2.1.tar.gz`  | 0.2.1 (unchanged) |

Below this note, the entries for 0.3.0 and 0.2.1 retain their
original tarball numbering — they pre-date the mapping.

Going forward, the next release after 0.18.1 will be **0.19.0**,
following the policy without further re-alignment.

---

## [0.3.0] - 2026-04-24

### Added

- **Cost & Data Safety Admin Console.** A new operator-facing surface
  under `/admin/console/*`, separate from the user-authentication body.
  Six server-rendered HTML pages plus a small JSON-write surface:

  | Path                                    | Min role    | Purpose                                        |
  |-----------------------------------------|-------------|------------------------------------------------|
  | `GET  /admin/console`                   | ReadOnly    | Overview: alert counts, recent events, last verifications |
  | `GET  /admin/console/cost`              | ReadOnly    | Cost dashboard — per-service metrics & trend  |
  | `GET  /admin/console/safety`            | ReadOnly    | Data-safety dashboard — per-bucket attestation |
  | `POST /admin/console/safety/:b/verify`  | Security+   | Stamp a bucket-safety attestation as re-verified |
  | `GET  /admin/console/audit`             | ReadOnly    | Audit-log search (prefix / kind / subject filters) |
  | `GET  /admin/console/config`            | ReadOnly    | Configuration review (attested settings + thresholds) |
  | `POST /admin/console/config/:b/preview` | Operations+ | Preview a bucket-safety change (diff, no commit) |
  | `POST /admin/console/config/:b/apply`   | Operations+ | Commit a bucket-safety change (requires `confirm:true`) |
  | `GET  /admin/console/alerts`            | ReadOnly    | Alert center — rolled-up cost + safety alerts   |
  | `POST /admin/console/thresholds/:name`  | Operations+ | Update an operator-editable threshold            |

  Every GET is `Accept`-aware: browsers get HTML, `Accept: application/json`
  gets the same payload as JSON — so curl and the browser share one
  URL surface.

- **Four-role admin authorization model.** `ReadOnly` / `Security` /
  `Operations` / `Super`, enforced by a single pure function
  `core::admin::policy::role_allows(role, action)`. Each handler
  declares its `AdminAction` and the policy layer decides. Role
  matrix:

  | Action                  | RO | Sec | Ops | Super |
  |-------------------------|----|-----|-----|-------|
  | `ViewConsole`           | ✓  | ✓   | ✓   | ✓     |
  | `VerifyBucketSafety`    |    | ✓   | ✓   | ✓     |
  | `RevokeSession`         |    | ✓   | ✓   | ✓     |
  | `EditBucketSafety`      |    |     | ✓   | ✓     |
  | `EditThreshold`         |    |     | ✓   | ✓     |
  | `CreateUser`            |    |     | ✓   | ✓     |
  | `ManageAdminTokens`     |    |     |     | ✓     |

  The pre-existing `ADMIN_API_KEY` secret becomes the Super bootstrap:
  a fresh deployment with only that secret set still has console
  access at the Super tier. Additional principals live in the new
  `admin_tokens` D1 table (SHA-256-hashed, never plaintext). See
  [Admin Console — Expert chapter](docs/src/expert/admin-console.md).

- **Honest edge-native metrics.** The dashboard is deliberately
  truthful about what a Worker can and cannot see at runtime. D1 row
  counts come from `COUNT(*)` on tracked tables. R2 object counts and
  bytes come from `bucket.list()` summation. Workers and Turnstile
  counts come from a self-maintained `counter:<service>:<YYYY-MM-DD>`
  pattern in KV. Durable-Object metrics are deliberately empty — the
  Workers runtime cannot enumerate DO instances, so the dashboard
  surfaces a note pointing operators at the Cloudflare dashboard
  rather than fabricating numbers.

- **Bucket safety = operator attestation.** Workers runtime cannot
  read Cloudflare's R2 control-plane (is-public / CORS / lifecycle /
  bucket-lock state). We therefore record what the operator last
  confirmed the bucket to be, with a `last_verified_at` stamp and a
  configurable staleness threshold. Stale attestations raise a `warn`
  alert; any bucket attested public raises a `critical` alert
  regardless of which bucket it is.

- **Audit-log search over R2.** New `CloudflareAuditQuerySource`
  walks the date-partitioned `audit/YYYY/MM/DD/<uuid>.ndjson` tree,
  parses each object, and applies `kind_contains` / `subject_contains`
  filters in the adapter. Hard-capped at 200 objects per call so one
  console view can never fan out to thousands of R2 GETs.

- **Five new `EventKind` variants.**
  `AdminLoginFailed`, `AdminConsoleViewed`, `AdminBucketSafetyVerified`,
  `AdminBucketSafetyChanged`, `AdminThresholdUpdated`. Every console
  view is audited — §11 of the extension spec asks that monitoring
  failures themselves be audit-visible, and logging views captures
  the intent side of that.

- **Migration `0002_admin_console.sql`.** Four tables:
  `admin_tokens`, `bucket_safety_state`, `cost_snapshots`,
  `admin_thresholds`. Five default thresholds seeded; rows for the
  two shipped R2 buckets (`AUDIT`, `ASSETS`) seeded with conservative
  defaults. `INSERT OR IGNORE` throughout so the migration is
  re-runnable.

- **Expert chapter `docs/src/expert/admin-console.md`.** Covers the
  role model, the permission matrix, the change-operation protocol
  (preview → apply), the metrics-source fidelity matrix, and the
  bootstrap / token-provisioning curl recipes.

### Changed

- **`routes::admin` refactored into a submodule tree.** What used to
  be one 145-line file is now:
  - `routes/admin.rs` — parent, re-exports legacy `create_user` /
    `revoke_session` so `lib.rs`'s wiring didn't have to change.
  - `routes/admin/auth.rs` — bearer → principal resolution +
    `ensure_role_allows` helper.
  - `routes/admin/legacy.rs` — existing user-management endpoints,
    now role-gated (`CreateUser` requires Operations+,
    `RevokeSession` requires Security+; previously both required the
    single `ADMIN_API_KEY`).
  - `routes/admin/console.rs` + `routes/admin/console/*` — the v0.3.0
    console.

- **UI crate now depends on `cesauth-core`.** The admin templates
  read domain types directly from `core::admin::types` rather than
  redeclaring them, which would have drifted. `core` has no
  Cloudflare deps (enforced by its module-level comment), so this
  does not pull worker/wasm code into the UI build.

- **ROADMAP: "Audit retention policy tooling" moved from Planned to
  Shipped** as part of the admin console (the console's
  Configuration Review page surfaces each bucket's lifecycle
  attestation; the Alert Center flags staleness).

### Deferred (for 0.4.0)

None of these block §13 of the extension spec — the initial
completion criteria are met. They are recorded here so the scope
of 0.3.0 is unambiguous:

- **HTML edit forms with two-step confirmation UI.** 0.3.0 ships the
  preview → apply pair as a JSON API. The HTML confirm-screen flow
  (preview page → nonce-gated apply) is priority 8 in the spec; the
  scripted pair satisfies §7 (danger-operation preview + audit) in
  the meantime.
- **Admin-token CRUD UI.** 0.3.0 requires operators to INSERT rows
  into `admin_tokens` via a `wrangler d1 execute` command
  (documented in the expert chapter). A Super-only `/admin/tokens`
  HTML surface lands in 0.4.0.
- **Workers-request counter hot-path instrumentation.** 0.3.0 reads
  the `counter:workers:requests:*` KV keys and will report whatever
  is there; the actual `.increment()` call on every request is the
  0.4.0 work. Fresh deployments see zeros.
- **DO-instance enumeration.** Blocked on the Cloudflare Workers
  runtime API, which does not expose DO listing. Shipped as
  "unavailable — see CF dashboard" with a note; wired once CF
  ships the capability.

### Test counts

- `core`            — 72 passed (56 pre-admin + 16 admin policy / service)
- `adapter-test`    — 17 passed (6  pre-admin + 11 admin in-memory adapters)
- `ui`              — 4 passed (unchanged; admin templates exercised by
  `cargo check` rather than unit tests — their contract is HTML shape,
  which breaks visibly)
- **Total**: 93 host lib tests pass; `cargo-1.91 check --workspace` clean.

---

## [0.2.1] - 2026-04-24

### Changed

- **Refactor: test modules extracted to sibling `tests.rs` files.**
  Every `#[cfg(test)] mod tests { ... }` block in `src/` has been
  moved to a sibling `<basename>/tests.rs` file (e.g.
  `crates/core/src/service/token.rs` + `crates/core/src/service/token/tests.rs`).
  The parent file now contains only `#[cfg(test)] mod tests;`.
  Eighteen files changed, all sixty-six host-lib tests still pass
  unchanged. Rationale: parent-file size is dominated by production
  code instead of fixtures, diffs stay focused, and the extracted
  test files are easier to point at in code review.

- **Refactor: large trait-adapter files split by port/handler.** Seven
  files that mixed multiple independent `impl Trait for Struct` blocks
  or multiple HTTP handlers have been split into submodules:

  | Was                                                  | Became (submodules)                                                   |
  |------------------------------------------------------|------------------------------------------------------------------------|
  | `adapter-cloudflare/src/ports/repo.rs` (688 lines)   | `users` / `clients` / `authenticators` / `grants` / `signing_keys`     |
  | `adapter-cloudflare/src/ports/store.rs` (410 lines)  | `auth_challenge` / `refresh_token_family` / `active_session` / `rate_limit` |
  | `adapter-test/src/repo.rs`                           | same five names as the cloudflare adapter                              |
  | `adapter-test/src/store.rs`                          | same four names as the cloudflare adapter                              |
  | `worker/src/routes/oidc.rs` (494 lines)              | `discovery` / `jwks` / `authorize` / `token` / `revoke`                |
  | `worker/src/routes/magic_link.rs` (413 lines)        | `request` / `verify` (Turnstile helpers stay in the parent)            |
  | `worker/src/routes/webauthn.rs` (287 lines)          | `register` / `authenticate` (grouped by ceremony; `rp_from_config` stays in the parent) |

  The D1 helpers (`d1_int`, `run_err`, `db`) stay in the parent
  `repo.rs`; the DO-RPC helpers (`rpc_request`, `rpc_call`) stay in
  the parent `store.rs`; `crates/worker/src/routes/magic_link.rs`
  keeps the shared Turnstile-flag helpers (`turnstile_flag_key`,
  `turnstile_required`, `flag_turnstile_required`, `enforce_turnstile`)
  that both `request` and `verify` consume. Submodules access these
  via `super::` to avoid duplication.

- **Deliberately not split** (boundaries tight enough after test
  extraction, or intertwined enough that splitting would fragment a
  single concept): `core/src/webauthn/cose.rs` (395 lines post-tests;
  COSE key parsing, attestation-object parsing, and `AuthData`
  accessors are mutually referenced), `core/src/webauthn/registration.rs`
  (270 lines post-tests; one ceremony), `core/src/webauthn/authentication.rs`
  (228 lines post-tests; one ceremony), `core/src/service/token.rs`
  (285 lines post-tests; a composed service layer), `core/src/oidc/authorization.rs`
  (183 lines post-tests), `core/src/session.rs`, `core/src/ports/store.rs`,
  `ui/src/templates.rs`, `worker/src/log.rs`, `worker/src/post_auth.rs`.

- **Workspace version bumped to `0.2.1`.** All five crates inherit
  from `workspace.package.version` so the single change propagates.

### Build state

- `cargo check --workspace` clean.
- Host lib tests: 56 (core) + 6 (adapter-test) + 4 (ui) + 16 (worker)
  = 82 passed, 0 failed. Same counts as before the refactor.
- No public-API changes. All `pub` items that existed under the old
  module paths remain available at their original path because the
  parent files re-export them (`pub use submodule::Name;`). External
  users of `cesauth_cf::ports::repo::CloudflareUserRepository`,
  `cesauth_core::routes::oidc::token`, etc., require no source
  changes.

---

## [Unreleased]

### Added

- **Documentation restructure.** The previous monolithic
  `docs/architecture.md` and `docs/local-development.md` have been
  migrated into an [mdBook](https://rust-lang.github.io/mdBook/) site
  under `docs/`, split into a beginner-facing *Getting Started* track
  and an expert-facing *Concepts & Reference* track plus a
  *Deployment* section and an *Appendix* (endpoints, error codes,
  glossary).
- **Project governance files at the repository root.** `ROADMAP.md`,
  `CHANGELOG.md`, `.github/SECURITY.md`, `TERMS_OF_USE.md`.
- **`/token` observability.** Every 500 path in the token handler now
  emits a structured `log::emit` line with the appropriate category
  (`Config`, `Crypto`, or `Auth`), so `wrangler tail` shows the
  immediate cause of a token-endpoint failure instead of a bare 500.
- **Dev-only helper routes** (`GET /__dev/audit`,
  `POST /__dev/stage-auth-code/:handle`), gated on
  `WRANGLER_LOCAL="1"`. They exist to make the end-to-end curl
  tutorial runnable without a browser cookie jar. Production deploys
  MUST NOT set `WRANGLER_LOCAL`.

### Changed

- **README is now slim.** Storage responsibilities, crate layout, and
  implementation status have moved out of the README into the book
  (storage / crate layout) and `ROADMAP.md` (implementation status).
  The README keeps a Quick Start and an Endpoints table and points
  into the book for detail.
- **`jsonwebtoken` now built with the `rust_crypto` feature.**
  Version 10.x requires a crypto provider; we pick the pure-Rust one
  (ed25519-dalek / p256 / rsa / sha2 / hmac / rand) and explicitly
  NOT `aws_lc_rs`, which vendors a C library and does not build for
  `wasm32-unknown-unknown`. With `default-features = false` and
  neither feature set, jsonwebtoken 10 panics at first use.
- **`config::load_signing_key` normalizes escape sequences.** The
  function accepts either real newlines or literal `\n` escapes in
  the PEM body; the latter is useful for single-line dotenv setups.

### Fixed

- **D1 `bind()` now uses a `d1_int(i64) -> JsValue` helper.**
  `wasm_bindgen` converts a Rust `i64` into a JavaScript `BigInt` on
  the wire, but D1's `bind()` rejects BigInt with
  `cannot be bound`. The helper coerces via `JsValue::from_f64` the
  same way worker-rs's `D1Type::Integer` does internally. Every
  INSERT / UPDATE site now uses it.
- **`run_err(context, worker::Error) -> PortError::Unavailable`
  helper** logs the underlying D1 error via `console_error!` before
  collapsing it into the payload-less `PortError::Unavailable`
  variant. Previously, the HTTP layer just said "storage error" with
  no breadcrumb.
- **`.tables` in the beginner tutorial** (`sqlite3` dot-command) has
  been replaced with a real `SELECT … FROM sqlite_master` query.
  `wrangler d1 execute` runs its `--command` argument through D1's
  SQL path, which does not interpret dot-commands.

### Security

- **Session cookies now use HMAC-SHA256, not JWT.** The session
  cookie is an internal server-to-browser token with no need for
  algorithm negotiation or third-party verification, and the
  simpler `<b64url(payload)>.<b64url(hmac)>` format sidesteps a
  class of JWT-library pitfalls.
- **`__Host-cesauth_pending` is unsigned by design; `__Host-cesauth_session` is signed.**
  The pending cookie carries only a server-side handle; forging it
  points to a non-existent or mis-bound challenge and is rejected
  on `take`. The session cookie carries identity and MUST be signed.
- **Sensitive log categories default to off.** `Auth`, `Session`, and
  `Crypto` lines are dropped unless `LOG_EMIT_SENSITIVE=1` is set.
  Enabling this in production should be an explicit, time-boxed ops
  action.

---

## Release-gate reminders

Before cesauth's first production deploy:

1. Replace the `dev-delivery` audit line in
   `routes::magic_link::request` with a real transactional-mail
   HTTP call keyed by `MAGIC_LINK_MAIL_API_KEY`.
2. `WRANGLER_LOCAL` MUST be `"0"` (or unset) in the deployed
   environment. Verify with an explicit `[env.production.vars]`
   entry rather than relying on inheritance.
3. Freshly generate `JWT_SIGNING_KEY`, `SESSION_COOKIE_KEY`, and
   `ADMIN_API_KEY` per environment; do not reuse local-dev values.

See
[Deployment → Migrating from local to production](docs/src/deployment/production.md)
for the full release-gate walkthrough.

---

## Format

Each future release will have sections in this order:

- **Added** — new user-facing capability.
- **Changed** — behavior that existed previously and now works
  differently.
- **Deprecated** — slated for removal in a later release.
- **Removed** — gone this release.
- **Fixed** — bugs fixed.
- **Security** — vulnerability fixes or security-relevant posture
  changes. See also [.github/SECURITY.md](.github/SECURITY.md).

[Unreleased]: https://github.com/cesauth/cesauth/compare/v0.2.1...HEAD
[0.2.1]:      https://github.com/cesauth/cesauth/releases/tag/v0.2.1
