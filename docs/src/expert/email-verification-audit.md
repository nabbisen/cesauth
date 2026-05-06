# Email verification audit (v0.25.0)

What `email_verified=true` means in cesauth, where it gets set,
where it doesn't, and what consumers can rely on. This audit was
delivered as part of the security track Phase 2 (v0.25.0).

## What `email_verified=true` means

A `users.email_verified=true` row asserts that **at some point in
the past, the holder of `users.email` proved control of that
inbox** by receiving an out-of-band Magic Link OTP and submitting
it back. The exact provenance:

- **First-login signup via Magic Link**: the user typed an email,
  received the OTP, submitted it. The successful submission is
  the proof. `email_verified=true` is set at row creation.
- **Returning-login via Magic Link** (added v0.25.0): if the row
  pre-existed with `email_verified=false`, a successful OTP
  submission flips the column to `true`. Same proof, applied
  retroactively.
- **Anonymous → human promotion via Magic Link** (ADR-004): the
  promotion ceremony requires OTP submission for the new email.
  Successful verify flips `email_verified=true` and changes
  `account_type` from `Anonymous` to `HumanUser` in the same
  UPDATE.

What it does NOT assert:

- That the email is **currently** under the holder's control.
  Email accounts can be hijacked, recovered by an attacker, or
  simply lost. cesauth does not periodically re-verify.
- That the email is unique to one human. Disposable-email
  services and email-aliasing routes (`+` addresses) work
  trivially.
- Anything about the WebAuthn credentials registered to the
  user. WebAuthn proves device possession, not email control.

## Per-path table

| Path | Sets `email_verified` | Audit verdict |
|---|---|---|
| `POST /magic-link/verify` (new signup) | `true` at row creation | ✅ Correct since v0.4.x |
| `POST /magic-link/verify` (existing user, `email_verified=false`) | `true` (flip + UPDATE) | ✅ **Added in v0.25.0**. Pre-v0.25.0, the column stayed false despite OTP delivery |
| `POST /magic-link/verify` (existing user, `email_verified=true`) | unchanged (no UPDATE) | ✅ Hot-path optimization; skip the D1 round-trip |
| `POST /api/v1/anonymous/promote` | `true` after OTP verify | ✅ ADR-004. The promotion ceremony itself proves email control |
| `POST /api/v1/anonymous/sessions` (anonymous user creation) | `false` (email is `None`) | ✅ Anonymous users have no email; the column being `false` is meaningless on those rows |
| `POST /webauthn/register/finish` | unchanged (does not touch column) | ✅ WebAuthn proves device possession, not email |
| `POST /webauthn/authenticate/finish` | unchanged (does not touch column) | ✅ Same |
| `POST /admin/users` (legacy admin create) | `false` at row creation | ✅ Admin-minted users have not yet proven email control. The next Magic Link login will flip it (v0.25.0+) |
| Tenancy console mutations (`/admin/tenancy/...`) | unchanged | ✅ These touch organization/membership/role rows, not user email state |

## Where the column should surface to consumers

The `email_verified` column is meant to flow through to OIDC
relying parties via the `email_verified` claim in the id_token.
**As of v0.25.0, no id_token is issued at all** (see "OIDC id_token
gap" below). The column is correct internally but invisible to
RPs.

Internal consumers today:

- The `/admin/users/<id>` admin API surfaces it in the JSON
  response.
- The HTML admin console renders a verified/unverified badge.
- The audit log carries the column value in user-create and
  user-update events.

## OIDC `id_token` gap

The audit also surfaced a substantial OIDC compliance gap that
is **separate from email_verified itself but motivates v0.26.0**:

- `cesauth_core::service::token::exchange_code` returns
  `id_token: None` regardless of the `openid` scope being
  requested.
- `rotate_refresh` likewise returns `id_token: None`.
- `IdTokenClaims` struct is defined in `cesauth_core::jwt::claims`
  but never constructed.
- The pre-v0.25.0 discovery doc advertised
  `id_token_signing_alg_values_supported: ["EdDSA"]` and
  `subject_types_supported: ["public"]` and listed `openid` in
  `scopes_supported` — all aspirational, not implemented.

**v0.25.0 honest reset of the discovery doc** (this release):

- Drop `id_token_signing_alg_values_supported` from the wire
  output.
- Drop `subject_types_supported`.
- Drop `openid` from `scopes_supported`. The remaining advertised
  scopes are `["profile", "email", "offline_access"]`.
- The discovery route itself stays at
  `/.well-known/openid-configuration` — the path is stable
  across the v0.25.0 → v0.26.0 transition. cesauth's posture
  changes from "OIDC OP claiming features it doesn't have"
  to "OAuth 2.0 Authorization Server with RFC 8414 metadata".

**v0.26.0 plan** (ADR-008, drafted alongside this release):

- Implement `id_token` issuance in `exchange_code` when the
  `openid` scope is requested. (`rotate_refresh` similarly when
  `openid` is in the carried scopes.)
- Plumb `UserRepository` into `service::token` so claims can be
  populated from `users` row state (sub, email, email_verified,
  name).
- Add `auth_time` (from session creation), `nonce` (from
  authorize request), and standard claims.
- Discovery doc gains the OIDC fields back; `openid` returns to
  `scopes_supported`.
- Add `claims_supported` to discovery so RPs know which claims
  to expect.
- Re-test end-to-end: the v0.25.0 fix to flip
  `email_verified=true` on returning-user Magic Link verify
  becomes RP-visible at this release.

## Tests added in v0.25.0

- 8 discovery shape tests in `crates/core/src/oidc/discovery.rs`:
  - `discovery_does_not_advertise_openid_scope` — pin the
    honest-reset for v0.25.0; this test's expectation flips in
    v0.26.0.
  - `discovery_advertises_oauth2_scopes_only` — pin the exact
    set `["profile", "email", "offline_access"]`.
  - `discovery_response_types_is_code_only`.
  - `discovery_grant_types_match_implementation`.
  - `discovery_code_challenge_methods_is_s256_only`.
  - `discovery_endpoints_anchor_to_issuer`.
  - `discovery_serializes_without_oidc_fields` — wire-shape
    tripwire; rejects accidental re-introduction of the OIDC
    fields without an implementation behind them.
  - `discovery_token_endpoint_auth_methods_match_implementation`.
- 1 integration-style test (covered by manual review for now)
  for the `email_verified` flip on returning-user Magic Link
  verify. Worker-handler tests are mock-heavy; the change is
  small enough that the manual-review path plus the existing
  storage-layer tests cover the behavior. v0.26.0's id_token
  work will add end-to-end RP-visible coverage.

## Operator-visible behavior changes (v0.24.0 → v0.25.0)

- `/.well-known/openid-configuration` now returns a smaller JSON
  document. Existing OIDC RPs that strictly validate the
  discovery doc against OIDC Discovery 1.0 schema will reject
  it as non-OIDC. **This is intentional and honest** — cesauth
  was not actually emitting id_tokens.
- `scope=openid` requests still parse and pass through (the
  authorize/token routes don't gate on it), but no id_token is
  issued, identical to pre-v0.25.0 behavior.
- A user created by an admin via `POST /admin/users` will, on
  their first Magic Link login, have `email_verified=true`
  written. Pre-v0.25.0, the column stayed false; the audit log
  records the UPDATE.

## Re-audit cadence

This audit re-runs:

- When a new path is added that creates or modifies `users` rows
  with email column set.
- When the OIDC id_token issuance (v0.26.0) lands — the per-path
  table needs to be re-verified to confirm the column flows
  through the id_token claim correctly.
- At each major release boundary (v0.x.0 → v1.0.0).

## See also

- [`docs/src/expert/oidc-tokens.md`](./oidc-tokens.md) — token
  issuance flow.
- [`docs/src/expert/oidc-internals.md`](./oidc-internals.md) —
  OIDC implementation notes.
- ADR-007 (HTTP security headers) — the parallel security track
  that v0.24.0/v0.25.0 are part of.
- ADR-008 (id_token issuance, drafted in v0.25.0, implemented in
  v0.26.0) — the design that closes the gap surfaced by this
  audit.
