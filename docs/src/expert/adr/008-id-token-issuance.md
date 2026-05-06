# ADR-008: OIDC `id_token` issuance

**Status**: Draft (v0.25.0). Will graduate to `Accepted` in
v0.26.0 when the implementation lands.

**Context**: as discovered during the v0.25.0 email verification
audit (see `docs/src/expert/email-verification-audit.md`),
cesauth advertises itself as an OIDC OP through the
`/.well-known/openid-configuration` route but has never issued
an `id_token`. The `IdTokenClaims` struct is defined; the
`TokenResponse.id_token` field exists; but `exchange_code` and
`rotate_refresh` both return `id_token: None`. v0.25.0 took the
honest-reset path: discovery doc rewritten to advertise OAuth
2.0 metadata only (RFC 8414), `openid` scope dropped from
`scopes_supported`. v0.26.0 (this ADR) implements id_token
issuance and restores OIDC posture.

## Q1 — When is the id_token issued?

**Question**: which token-endpoint flows return an `id_token`?

**Decision**:

- **`authorization_code` grant** with `openid` in the requested
  scope → id_token returned.
- **`authorization_code` grant** without `openid` → no id_token
  (pure OAuth 2.0 access + refresh response).
- **`refresh_token` grant** with `openid` in the carried scope →
  id_token returned (refreshed; the refresh family carries the
  scopes from the original authorize step).
- **`refresh_token` grant** without `openid` → no id_token.

This matches OpenID Connect Core 1.0 §3.1.3 and §12: the
`openid` scope is the canonical signal that the client wants
OIDC behavior. Other scopes alone (`profile`, `email`) do NOT
trigger id_token issuance — they're advisory, not gating.

## Q2 — Which claims go in the id_token?

**Question**: what's the minimum required + scoped set?

**Decision**: required claims always; scoped claims by `scope`.

**Required (always present)**:
- `iss` — issuer URL.
- `sub` — user_id (the cesauth `users.id`).
- `aud` — client_id.
- `exp` — same TTL as access token (`access_ttl_secs` from
  config).
- `iat` — issuance time.
- `auth_time` — when the user authenticated against cesauth.
  Sourced from `ActiveSession.created_at` if available, else
  from the AuthCode challenge's creation time.

**Conditional**:
- `nonce` — present iff the AuthCode challenge carried a
  `nonce` value (which it does iff the original `/authorize`
  request had `nonce=...`).

**Scope-driven**:
- `email` and `email_verified` — present iff `email` is in the
  granted scopes AND `users.email` is non-null.
- `name` — present iff `profile` is in the granted scopes AND
  `users.display_name` is non-null.

This matches the `IdTokenClaims` struct already defined in
`cesauth_core::jwt::claims`. The struct does not need to
change.

## Q3 — How does claims construction get user data?

**Question**: `service::token::exchange_code` doesn't currently
take a `UserRepository`. How does it source `email`,
`email_verified`, `name`?

**Decision**: add `UserRepository` to the function signature.
The trait is already in `cesauth_core::ports::repo`. The change
is a generic-parameter addition:

```rust
pub async fn exchange_code<CR, AS, FS, GR, UR>(
    clients:  &CR, codes: &AS, families: &FS, grants: &GR,
    users:    &UR,                        // NEW
    signer:   &JwtSigner,
    access_ttl_secs:  i64, refresh_ttl_secs: i64,
    input:    &ExchangeCodeInput<'_>,
) -> CoreResult<TokenResponse>
where
    CR: ClientRepository, AS: AuthChallengeStore,
    FS: RefreshTokenFamilyStore, GR: GrantRepository,
    UR: UserRepository,                   // NEW
{
    // ... existing flow ...
    if scopes.contains("openid") {
        let user = users.find_by_id(&user_id).await?
            .ok_or(CoreError::Internal)?;
        let id_claims = build_id_token_claims(
            &client, &user, &scopes, nonce, auth_time, now, access_ttl_secs);
        let id_token = signer.sign(&id_claims)?;
        // attach to TokenResponse
    }
}
```

A user-not-found at this point is `CoreError::Internal` — the
authorize step that issued the code already validated the
user existed; if it's gone now, something is corrupt.

## Q4 — How is `auth_time` sourced?

**Question**: cesauth doesn't currently track when the user
authenticated; the access token's `iat` is the issuance time
of the access token, not the authentication event. OIDC
`auth_time` should be the latter.

**Decision**: pass `auth_time` through the `AuthCode`
challenge. The challenge is created by `/authorize` after the
session is established; capturing `session.issued_at` (or
falling back to challenge creation time if the session was
already long-established) gives the right value.

The `Challenge::AuthCode` variant gains a new `auth_time: i64`
field. v0.26.0's schema migration adds this to the
serialization shape (the challenge is stored as JSON in the
DO, so the migration is "new field with default"; existing
in-flight challenges from a pre-v0.26.0 worker continue to
work — they get `auth_time: 0` which any RP consumer should
treat as "timestamp unknown" rather than a hard error, but
strict RPs may reject. Acceptable since auth codes have a
short TTL; in-flight ones drain within ~1 minute of deploy).

For the refresh-token path, `auth_time` lives in the
`RefreshTokenFamily` DO state (added v0.26.0).

## Q5 — Which claims ARE NOT in the id_token?

Explicitly out of scope for v0.26.0:

- `acr` (authentication context class). cesauth doesn't
  distinguish authentication strengths today. A future release
  with TOTP (planned v0.26.0 - v0.27.0 in the security track)
  could reasonably add `acr` values once there are multiple
  contexts to distinguish.
- `amr` (authentication methods reference). Same reasoning.
  When TOTP lands, `amr: ["mfa", "otp"]` etc. become possible.
- `azp` (authorized party). Only meaningful in multi-audience
  id_tokens, which cesauth doesn't issue.
- Custom claims. cesauth doesn't have a story for client-
  configurable custom claims; that's a much later release if
  ever.

## Q6 — Does the discovery doc reflect the truth?

**Decision**: yes, fully restored to OIDC Discovery 1.0 + RFC
8414 metadata.

In v0.26.0 the discovery doc gains:
- `subject_types_supported: ["public"]`
- `id_token_signing_alg_values_supported: ["EdDSA"]`
- `claims_supported: ["sub", "iss", "aud", "exp", "iat",
  "auth_time", "nonce", "email", "email_verified", "name"]`
- `openid` returned to `scopes_supported`.

Tests pin the change. The eight v0.25.0 discovery tests get
flipped/extended:
- `discovery_does_not_advertise_openid_scope` → renamed and
  inverted; pin that `openid` IS present.
- `discovery_serializes_without_oidc_fields` → renamed and
  inverted; pin that the OIDC fields ARE present.
- `discovery_advertises_oauth2_scopes_only` → expanded to
  include `openid`.
- New: `discovery_advertises_id_token_signing_alg_values`,
  `discovery_advertises_subject_types`,
  `discovery_advertises_claims_supported`.

## Q7 — Test plan for v0.26.0

End-to-end:
1. Authorize with `scope=openid email`, complete login,
   exchange code at `/token`.
2. Decode the returned id_token. Assert:
   - `iss` matches issuer.
   - `sub` matches the authenticated user_id.
   - `aud` matches the client_id.
   - `exp` is `iat + access_ttl_secs`.
   - `auth_time <= iat`.
   - `nonce` matches what was sent at `/authorize`.
   - `email` matches `users.email`.
   - `email_verified` matches `users.email_verified`.
3. Repeat with `scope=openid` only — assert `email`/`name` are
   absent.
4. Repeat with `scope=email profile` (no `openid`) — assert NO
   id_token is returned.
5. Refresh-token rotation with carried `openid` scope returns a
   fresh id_token.
6. `email_verified` flip path (the v0.25.0 fix): admin creates
   user with `email_verified=false`, user logs in via Magic
   Link, refresh-token rotation should now return id_token with
   `email_verified=true`.

Unit:
- `build_id_token_claims` is a pure function. ~10 unit tests
  covering scope-driven population, missing-email handling,
  display_name handling, nonce passthrough, auth_time sourcing.

## Q8 — Migration and rollout

`SCHEMA_VERSION` does not change. The challenge JSON shape adds
a field but JSON is forward-compatible (older shapes deserialize
with default for new field; newer shapes deserialize on older
workers ignoring unknown fields).

`RefreshTokenFamily` DO state adds `auth_time`. Existing DO
instances need a migration on first read (set to issuance time
as a fallback). This is detailed in v0.26.0's release notes.

**Backward compatibility**: RPs that requested `scope=openid`
against v0.25.0 and earlier got `id_token: null`. Against
v0.26.0 they get a real id_token. **This is the desired
break** — the whole point of v0.26.0 is to make this work.

## Decision summary

| Question | Decision |
|---|---|
| Q1 — when issued | `authorization_code` and `refresh_token` grants iff `openid` in granted scope |
| Q2 — claims | iss/sub/aud/exp/iat/auth_time always; nonce conditional; email + email_verified iff `email` scope; name iff `profile` scope |
| Q3 — sourcing | Add `UserRepository` to `service::token` signature |
| Q4 — auth_time | Carry through `AuthCode.auth_time` (new field) and `RefreshTokenFamily.auth_time` |
| Q5 — out of scope | acr, amr, azp, custom claims (deferred indefinitely) |
| Q6 — discovery | Restored to full OIDC Discovery 1.0 in v0.26.0; tests updated |
| Q7 — tests | End-to-end + unit, ~10 new tests |
| Q8 — migration | No SCHEMA_VERSION bump; challenge JSON shape gains a default field; DO state gains a default field |

## Acceptance criteria for v0.26.0

- ADR graduates from `Draft` to `Accepted`.
- All v0.25.0 discovery tests are inverted/extended to the OIDC
  shape.
- New unit tests for `build_id_token_claims`.
- New integration test for end-to-end id_token round-trip
  through `exchange_code`.
- New integration test for `rotate_refresh` carrying the
  `openid` scope.
- The email_verification audit doc updates to note the gap is
  closed.
- Discovery doc shape change is the only operator-visible
  break; CHANGELOG calls it out.
