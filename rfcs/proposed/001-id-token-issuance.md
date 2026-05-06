# RFC 001: OIDC `id_token` issuance

**Status**: Proposed
**ROADMAP**: `## Planned (0.x) / Later` — "OIDC `id_token` issuance"
**ADR**: [ADR-008](../docs/src/expert/adr/008-id-token-issuance.md) (Draft, all eleven design questions resolved)
**Estimated scope**: Medium — ~600 LOC across 4 files + test additions, one schema migration, one wire change

## Background

cesauth advertises itself as an OIDC OP through
`/.well-known/openid-configuration`, but `exchange_code` and
`rotate_refresh` have always returned `id_token: None`. The
v0.25.0 email-verification audit surfaced this gap; v0.25.0
took the **honest reset** path — discovery was reduced to
RFC 8414 OAuth 2.0 metadata only. ADR-008 (drafted v0.25.0)
settles the design for restoring OIDC posture. This RFC is
the engineering spec for landing it.

ADR-008 has eleven Resolved decisions covering when id_token
is issued, which claims are emitted, signing algorithm, key
rotation behavior, `auth_time` sourcing, `nonce` flow,
`email_verified` semantics, error responses, discovery doc
restoration, refresh-flow id_token regeneration, and
backward compatibility. **The design is settled**; this RFC
focuses on the implementation order, surface changes, and
test plan.

## Requirements

### Functional

1. `POST /token` with `grant_type=authorization_code` and
   `openid` in the carried scope MUST return a signed
   id_token alongside the access_token + refresh_token.
2. `POST /token` with `grant_type=refresh_token` and
   `openid` in the carried scope MUST return a freshly-
   minted id_token (new `iat`, `exp`, possibly different
   `auth_time` if reauthentication occurred).
3. Both grants without `openid` MUST NOT include id_token
   (RFC 6749 OAuth 2.0 response shape).
4. id_token MUST carry the required claims (`iss`, `sub`,
   `aud`, `exp`, `iat`, `auth_time`) and the conditional /
   scoped claims per ADR-008 §Q2.
5. Discovery doc at `/.well-known/openid-configuration`
   MUST advertise OIDC posture: `openid` in
   `scopes_supported`, `id_token_signing_alg_values_supported:
   ["EdDSA"]`, `subject_types_supported: ["public"]`,
   `claims_supported: [...]` per ADR-008 §Q9.
6. id_token signing MUST use the same Ed25519 key the
   access token uses (key rotation handled by the same
   multi-key path v0.41.0 introduced).

### Non-functional

7. The change MUST NOT require a wire-incompatible client
   update for clients that didn't previously request the
   `openid` scope. Existing OAuth-only callers see no
   change.
8. The change MUST NOT regress any existing test in the
   `service::token` or `oidc::discovery` test suites
   beyond the deliberate inversions covered by the test
   plan.
9. The implementation MUST keep id_token claim assembly
   pure (testable without a full worker harness) — same
   pure-service pattern as v0.40+ work.

### Schema

10. `Challenge::AuthCode` and the `RefreshTokenFamily` DO
    state MUST gain an `auth_time: i64` field. Migration
    plan covered in §Design.

## Design

### Surface changes

#### Wire — id_token in `TokenResponse`

`cesauth_core::oidc::token_response::TokenResponse.id_token`
already exists as `Option<String>`; populate it on the
`openid`-scope path. No struct change.

#### Wire — discovery doc restored to OIDC

`cesauth_core::oidc::discovery::DiscoveryDoc` gains:

- `id_token_signing_alg_values_supported: vec!["EdDSA"]`
- `subject_types_supported: vec!["public"]`
- `claims_supported: Vec<&'static str>` listing every claim
  cesauth may emit (per ADR-008 §Q9):
  `["iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "email", "email_verified", "name"]`

`scopes_supported` regains `"openid"` (currently
`["profile", "email", "offline_access"]`).

#### Schema — `auth_time` on `Challenge::AuthCode`

```rust
pub struct AuthCodeChallenge {
    pub code:       String,
    pub user_id:    String,
    pub client_id:  String,
    pub redirect_uri: String,
    pub scopes:     Vec<String>,
    pub nonce:      Option<String>,
    pub expires_at: i64,
    pub created_at: i64,
    pub auth_time:  i64,    // ← new (ADR-008 §Q4)
}
```

`auth_time` is set at AuthCode-mint time in
`post_auth::complete_auth_post_gate`. Its value is the
moment the user completed the user-presence step against
cesauth (Magic Link verify, WebAuthn verify, TOTP verify).
The auth method's verify time is the canonical
`auth_time` per OIDC Core §2.

`#[serde(default)]` on the field; pre-v0.51.0 challenges
deserialize with `auth_time: 0`. The id_token claim builder
treats `auth_time == 0` as "missing" and falls back to
`created_at`. This keeps in-flight challenges across the
deploy boundary functional.

#### Schema — `auth_time` on `RefreshTokenFamily` DO

Same field, same `#[serde(default)]` discipline. Existing
DOs deserialize with `auth_time: 0`; the refresh path
detects the missing value and sets it to the family's
`created_at` on first read (one-time fix-up; idempotent).

### Module layout

```
crates/core/src/
  oidc/
    id_token.rs                  ← new pure module
    id_token/tests.rs
  service/
    token.rs                     ← existing; extended
```

`id_token.rs` exports two pure functions:

```rust
pub fn build_id_token_claims(
    iss:        &str,
    user:       &User,
    client_id:  &str,
    scopes:     &[String],
    nonce:      Option<&str>,
    auth_time:  i64,
    iat:        i64,
    exp:        i64,
) -> IdTokenClaims;

pub fn sign_id_token(
    claims:    &IdTokenClaims,
    key:       &Ed25519SigningKey,
    kid:       &str,
) -> CoreResult<String>;
```

Both pure; no I/O. The first composes claims from inputs,
applying scope-driven population (`email` scope →
`email`/`email_verified` claims; `profile` scope → `name`).
The second is a thin wrapper over the existing JWS Compact
serializer from `crates/core/src/jwt/signer.rs`.

### Service integration

`service::token::exchange_code` and
`service::token::rotate_refresh` gain a generic parameter
`U: UserRepository` and an `iss: &str` parameter, which
they use to look up the user and build the id_token claims
when `scopes.contains("openid")`. The construction order:

1. Existing access-token mint.
2. Existing refresh-token rotation.
3. **NEW**: if `scopes.contains("openid")`, look up user
   by id, build claims, sign, populate
   `TokenResponse.id_token`.
4. Existing wire-out.

If the user lookup fails (deleted between authorize and
token exchange — should be rare; AuthCode TTL is short),
**fail closed** with `unauthorized_client`. The discovery
of a deleted user mid-flow is an integrity violation; we
prefer surfacing it over emitting an id_token with a
stale `sub`.

### Refresh-flow id_token regeneration

ADR-008 §Q10 settled this: every refresh that carries
`openid` mints a fresh id_token. New `iat`, `exp`. The
`auth_time` is the family's `auth_time` value — NOT the
refresh moment — because OIDC Core §2 defines `auth_time`
as the moment the user authenticated, not the moment a
token was minted.

This means a refresh after a long-running idle session
will return an id_token whose `auth_time` is far in the
past. RP-side max_age comparisons remain meaningful.

### Worker-glue changes

`crates/worker/src/routes/oidc/token.rs` reads `iss` from
config (already present), passes through. Adds the
`UserRepository` adapter from
`crates/adapter-cloudflare`. No new env var.

### Backward compatibility

ADR-008 §Q11 settled: existing OAuth-only callers see
**zero change**. The only callers affected are those that
explicitly pass `openid` scope through `/authorize` — and
those callers were already getting a discovery doc that
*didn't* advertise OIDC, so they were already on
non-spec territory. Restoring the discovery doc to OIDC
posture and shipping id_token brings them back to spec.

## Test plan

### Unit (pure, in `cesauth-core`)

`crates/core/src/oidc/id_token/tests.rs`:

1. `build_claims_required_only` — no scopes beyond
   `openid`; assert claims = required-set exactly. No
   `email`, no `name`.
2. `build_claims_with_email_scope_emits_email_claims`.
3. `build_claims_with_profile_scope_emits_name_claim`.
4. `build_claims_with_both_scopes_emits_all_scoped_claims`.
5. `build_claims_email_verified_reflects_user_state`
   (true / false / unset → field absent).
6. `build_claims_nonce_present_when_authorize_carried_one`.
7. `build_claims_nonce_absent_when_authorize_did_not`.
8. `build_claims_auth_time_zero_falls_back_to_created_at`
   — pin the migration-compatibility behavior.
9. `sign_id_token_uses_supplied_kid_in_header`.
10. `sign_id_token_emits_eddsa_alg_header`.
11. `sign_id_token_round_trip_verifies_against_supplied_pub_key`.
12. `id_token_does_not_emit_unknown_scope_claims` — passing
    a phantom scope `"frobnicate"` doesn't add anything.

### Integration (against in-memory adapters)

`crates/core/src/service/token/tests.rs` (extending the
existing file):

13. `exchange_code_with_openid_scope_returns_id_token`.
14. `exchange_code_without_openid_scope_does_not_return_id_token`.
15. `exchange_code_id_token_aud_equals_client_id`.
16. `exchange_code_id_token_sub_equals_user_id`.
17. `exchange_code_id_token_auth_time_matches_authcode_auth_time`.
18. `exchange_code_id_token_nonce_matches_authorize_nonce`.
19. `rotate_refresh_with_openid_scope_returns_fresh_id_token`
    (assert `iat` differs across two consecutive rotations).
20. `rotate_refresh_id_token_auth_time_preserves_family_auth_time`
    (NOT the rotation moment).
21. `rotate_refresh_without_openid_does_not_return_id_token`.
22. `exchange_code_user_deleted_between_authorize_and_exchange_returns_unauthorized_client`.

### Discovery doc (existing test file inversion)

`crates/core/src/oidc/discovery/tests.rs` — the eight
v0.25.0 tests that asserted OAuth-only posture get
**inverted** here. New posture:

23. `discovery_advertises_openid_scope`.
24. `discovery_advertises_eddsa_signing_alg`.
25. `discovery_advertises_public_subject_type`.
26. `discovery_advertises_claims_supported`.
27. `discovery_claims_supported_lists_every_claim_id_token_emits`
    — pin the no-drift between the doc and `build_claims`.

### Pin tests (no-regression)

28. `id_token_signing_uses_same_key_as_access_token`.
29. `id_token_kid_header_matches_signing_key_kid`.
30. `id_token_kid_appears_in_jwks` (cross-cutting; pin
    the multi-key v0.41.0 invariant survives the new
    code path).

Net: ~30 new tests. Existing `service::token` and
`oidc::discovery` test counts will increase; the existing
v0.25.0 wire tests will be inverted in place (no count
change).

## Security considerations

**Claim correctness drift**. The single most plausible
production bug here is `claims_supported` in the discovery
doc drifting from what `build_claims` actually emits — an
RP might rely on `claims_supported` to decide whether to
ask for `email` scope, and a missing claim would surface
as a confusing audit-log absence. Test 27 pins this: the
discovery test re-derives the `claims_supported` list from
`build_claims`'s scope-x-output matrix, so a future change
that adds a claim without updating the doc fails the test.

**Stale `auth_time` after deploy**. The
`#[serde(default)]` migration leaves in-flight challenges
with `auth_time: 0`. Test 8 pins the fall-back behavior;
the production exposure window is bounded by AuthCode TTL
(short — single-digit minutes). Refresh families with
`auth_time: 0` get one-time fix-up to `created_at` on
first read after the upgrade — also safe because
`created_at` is the worst-case approximation of
`auth_time` (the family was created when the original
authorize flow completed, which is at most milliseconds
after the user finished verifying).

**Forgery via key-rotation race**. A refresh occurring
during key-rotation could in principle sign with the new
key while the JWKS hasn't propagated. The existing
v0.41.0 multi-key infrastructure handles this for access
tokens (overlap window with old + new keys both
verifiable). id_token rides on the same `kid` selection
path — this is structural, not new threat surface.

**`auth_time` precision**. `auth_time` is unix-seconds.
RPs that compare against `max_age` apply RFC 6749 leeway
implicitly; cesauth doesn't need to add fuzz. Test 17
pins the byte-equal value across the chain.

**Denial via deleted user**. The fail-closed behavior on
mid-flow user deletion (test 22) prevents emitting an
id_token with a `sub` referring to a no-longer-existent
user. Surfaced as `unauthorized_client` per RFC 6749 — the
RP retries through `/authorize`, which itself rejects the
deleted user with the existing path. No new gap.

## Open questions

None remaining. ADR-008 settled all eleven. If
implementation surfaces a new question, append it to
ADR-008's Open questions section as `Q12` etc., not to
this RFC.

## Implementation order

Suggested branch progression for review-ability:

1. `id_token.rs` pure module + 12 unit tests. Compiles
   stand-alone. No service/discovery wiring yet. Reviewable
   as one PR.
2. `Challenge::AuthCode.auth_time` field +
   `RefreshTokenFamily.auth_time` field with `#[serde(default)]`.
   Service code reads/writes the new field. Existing tests
   pass with `auth_time: 0` defaults. One PR.
3. `service::token::exchange_code` and `rotate_refresh`
   integration + 10 service-layer tests. One PR.
4. Discovery doc restoration + 5 inversions/extensions.
   One PR.
5. CHANGELOG, ROADMAP `✅`, ADR-008 `Status: Accepted`,
   versioning bump. Final PR.

Total: 5 PRs, each independently mergeable in a
clean-tree state.
