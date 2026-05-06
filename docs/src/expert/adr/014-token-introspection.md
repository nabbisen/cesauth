# ADR-014: RFC 7662 OAuth 2.0 Token Introspection

**Status**: **Accepted (v0.38.0)**.

**Context**: cesauth has supported the issuance and rotation
of OAuth 2.0 access + refresh tokens since v0.4. Resource
servers consuming those tokens have had two paths to verify
them:

1. **Local verification of access tokens** via the
   `/jwks.json` public key set. Works for unrevoked tokens,
   but a resource server that only verifies signatures locally
   misses revocations between issuance and access-token expiry
   (cesauth's default access-token TTL is 60 minutes; refresh
   rotation revocation cascades aren't observable to a
   sig-only verifier until the access token expires).
2. **Trust the bearer**, refresh on every request. Wasteful
   and not actually safer because cesauth doesn't currently
   refresh-on-resource-access patterns.

What was missing: a server-side "is this token currently
active?" query. Refresh tokens in particular are completely
opaque to bearers — only cesauth can tell whether a presented
refresh token is the family's `current_jti` vs a retired jti vs
from a revoked family. A resource server that needs to validate
a refresh token presented to it (e.g., for a token-exchange
flow, or for offline access verification) had no way to ask.

RFC 7662 specifies the standard introspection endpoint that
fills this gap. v0.38.0 implements it.

## Audit findings (pre-v0.38.0 baseline)

What was already in place:

- **`/jwks.json`** advertises the active public signing keys
  (v0.4 / ADR-008). Resource servers can verify access-token
  JWTs locally.
- **`SigningKeyRepository::list_active`** returns the keys
  with `public_key_b64`. The introspection access-token
  path can reuse this to verify JWTs the same way clients
  would.
- **`RefreshTokenFamilyStore::peek`** is the read-only DO
  query (added in v0.34.0 alongside the reuse-detection
  forensics work). The introspection refresh path uses it
  without consuming or modifying state.
- **`ClientRepository::client_secret_hash`** returns the
  stored hash — added in v0.4 alongside the schema. Until
  v0.38.0, **no code in cesauth actually consulted this**:
  the `/token` endpoint accepts public clients (PKCE-only)
  and didn't verify confidential-client secrets. This was a
  separate latent issue, surfaced by the introspection
  audit. v0.38.0 adds the verification helper that
  introspection uses; future work may extend it to `/token`
  for confidential-client paths.

What was missing:

- No `/introspect` endpoint.
- No client credential verification helper.
- No HTTP Basic auth parser (cesauth's existing flows use
  form-body credentials only).
- `DiscoveryDocument` did not advertise an introspection
  endpoint (so spec-compliant discovery clients couldn't
  even know to ask).

## Decision

### Endpoint at `POST /introspect`

Path is conventional but not spec-mandated. cesauth uses
`/introspect` (matching the discovery field name) for
maximal client-library compatibility.

### Authentication: `client_secret_basic` preferred, `client_secret_post` accepted

RFC 7662 §2.1 requires client authentication on the
introspection endpoint. cesauth accepts the two RFC 6749
§2.3.1 methods:

- `client_secret_basic`: HTTP `Authorization: Basic
  base64(client_id:client_secret)`. **Recommended for
  resource servers** because it keeps secrets out of
  request bodies (which proxies sometimes log).
- `client_secret_post`: form-body `client_id` +
  `client_secret`. Fallback for clients that can't easily
  set headers.

The extractor (`crate::client_auth::extract`) prefers Basic
when an `Authorization` header is present, falling back to
the form body **only when no Authorization header is
present at all**. A malformed Basic header does NOT fall
through to form — a malformed-header-then-form-bypass would
be a client-confusion attack surface.

The `none` method (PKCE-only public clients) is **not
accepted** at this endpoint — RFC 7662 §2.1 mandates
authentication, and a public client with no secret has no
way to satisfy it. `DiscoveryDocument::introspection_endpoint_auth_methods_supported`
advertises only `client_secret_basic` + `client_secret_post`
to make this explicit to spec-aware clients.

### Privacy: type-level invariant on inactive responses

RFC 7662 §2.2: "If the introspection call is properly
authorized but the token is not active, ... the response
MUST be a JSON object with only the top-level member
`active` set to the value `false`".

Enforcing this at the type level: `IntrospectionResponse::inactive()`
is the only public constructor that produces an `active =
false` shape, and it accepts no claim arguments. The handler
literally **cannot** accidentally leak — there's no code path
to put a claim into an inactive response.

The `serde` definition uses `skip_serializing_if =
"Option::is_none"` on every claim field, so the wire output
of the inactive response is exactly `{"active":false}`.
The test
`inactive_response_serializes_with_only_active_field`
pins this byte-exact.

### Read-only by design

Introspection NEVER triggers reuse detection. A retired jti
is reported `active = false` without consuming the family.

This is the spec-conformant choice but also the security-
conformant one: a malicious resource server with valid
introspection credentials must NOT be able to revoke
families on demand. Calling introspection has zero side
effects on token state.

### Hint is advisory

RFC 7662 §2.1 lets the client send `token_type_hint` to
help the AS pick which type to check first. The AS may
ignore the hint, which is exactly what the test
`hint_access_with_actually_refresh_token_falls_through_to_refresh_check`
pins: even when the client says "this is an access token"
but it's actually a refresh, introspection succeeds.

cesauth's order:
- No hint, or `access_token` hint → try access first
  (cheaper — no DO round-trip on the negative path), fall
  through to refresh.
- `refresh_token` hint → try refresh first, fall through
  to access.

### Audit

New event kind `EventKind::TokenIntrospected`. Payload:

```json
{
  "introspecter_client_id": "rs_demo",
  "token_type":             "access_token" | "refresh_token" | "none",
  "active":                 true | false
}
```

The token itself is **deliberately not in the payload** —
including it would defeat the inactive-privacy invariant
(an audit row with the token would let anyone with audit
access deduce whether the token was valid at the time,
which is exactly what the inactive response is supposed to
hide). Operators monitoring for unusual introspection
patterns (e.g., a single resource-server hammering the
endpoint) can alert on volume + introspecter_client_id;
they don't need the token to do that.

`token_type` is `"none"` when `active = false` — cesauth
doesn't expose to the audit log whether the inactive
result was reached via the access-path or the refresh-path
(another privacy property: an attacker with audit access
can't distinguish "we received a JWT signature mismatch"
from "we received a retired refresh jti").

### Discovery

`DiscoveryDocument` gains:

- `introspection_endpoint: String` —
  `format!("{issuer}/introspect")`.
- `introspection_endpoint_auth_methods_supported: &'static
  [&'static str]` — `["client_secret_basic",
  "client_secret_post"]`. Excludes `"none"`.

Test `discovery_introspection_endpoint_requires_authentication`
pins both invariants.

### Client credential verification

A new helper `cesauth_core::service::client_auth::verify_client_credentials`
takes `(client_id, client_secret)`, looks up the stored
SHA-256 hash via `ClientRepository::client_secret_hash`,
and does constant-time hex comparison. Failure modes
(unknown client, no secret on file, mismatched hash) all
return the same `CoreError::InvalidClient` to avoid the
enumeration side-channel.

cesauth uses SHA-256-of-secret rather than Argon2/scrypt
because:
- `client_secret` is a server-minted high-entropy random
  string (32+ bytes from the admin console provisioning
  flow), not a user-chosen password.
- For high-entropy secrets, salted password hashes provide
  no additional protection — there's nothing to brute-
  force from the hash.

If a future ADR allows user-chosen client secrets (we do
not, today), this helper MUST be revisited.

## Wire compatibility

No breaking changes for existing OAuth/OIDC clients.
`/introspect` is a new endpoint; existing clients ignore
its existence.

The discovery document grows two fields. Spec-conformant
parsers tolerate unknown fields, so existing consumers
aren't affected. Strict-mode parsers may need a config
flag added (their problem, not ours).

## Tests

839 → 867 (+28).

- core: 320 → 342 (+22)
  - 8 in `service::client_auth::tests`: correct/wrong
    secret, unknown client, public client (no secret on
    file), empty secret, SHA-256 vector + length, constant-
    time helper.
  - 13 in `service::introspect::tests`: active refresh
    returns full claims, retired jti is inactive +
    privacy-invariant pin (no leak), revoked family
    inactive, unknown family inactive, malformed token
    inactive (not 400), empty token inactive, hint-
    fallback, hint-parser. Plus 4 type-level invariant
    pins (inactive constructor, byte-exact wire form,
    access has Bearer, refresh omits Bearer).
  - 1 in `oidc::discovery::tests`:
    `discovery_introspection_endpoint_requires_authentication`.
- worker: 165 → 171 (+6) in `client_auth::tests`:
  percent-decode passthrough, escape, plus-to-space,
  truncated, invalid hex, hex-digit lookup table.
- ui, adapter-test, do, migrate, adapter-cloudflare:
  unchanged.

## Open questions

- **Q1**: Resource-server-typed clients. Today any
  registered confidential client can introspect any token
  — there's no audience-scoping ("client_X may only
  introspect tokens issued for resource_R"). For
  multi-tenant deployments where one cesauth issues for
  many resource servers, this is a privilege-escalation
  concern. v0.38.0 ships unscoped; a future iteration
  adds a `resource_server_audience` column to
  `oidc_clients` and a check in `introspect_token` that
  the requesting client's audience matches the token's
  audience. Not blocking v0.38.0 because cesauth's
  current deployments all run with one resource server
  per tenant.
- **Q2**: ~~Per-resource-server rate limiting.~~
  **Resolved in v0.43.0.** The introspection endpoint
  now hits a per-client rate-limit gate after
  authentication and before any DO lookup or JWT
  verify. Bucket key shape is `introspect:<client_id>`
  — the authenticated client_id is the natural
  rate-limit unit (RFC 7662 introspection requires
  authentication, so we always have a stable
  identifier to limit against). Default threshold:
  600/window, default window: 60s — sized for
  resource servers that may introspect on every
  request. `INTROSPECTION_RATE_LIMIT_THRESHOLD = 0`
  disables the gate (operator opt-out for
  deployments that have a rate limit upstream at a
  load balancer or whose RSes legitimately need
  extreme rates). Per-client isolation pinned by
  test: a chatty RS_A's saturated bucket does not
  affect RS_B. Wire response: HTTP 429 with
  `Retry-After: <secs>` header (RFC 7231 §6.6 +
  §7.1.3); body code `invalid_request` (RFC 6749
  §5.2 catch-all since neither RFC 7662 nor RFC 7009
  define a rate-limit error code; matches v0.37.0's
  `/token` rate-limit precedent). New audit kind
  `EventKind::IntrospectionRateLimited` (snake_case
  `introspection_rate_limited`) emitted on denial
  with payload `{client_id, threshold, window_secs,
  retry_after_secs}`. Distinct from the v0.37.0
  `RefreshRateLimited` because they're different
  surfaces with different operational semantics — a
  spike in `introspection_rate_limited` indicates
  resource-server polling pathology, while
  `refresh_rate_limited` indicates token-replay
  probing on `/token`.
- **Q3**: Audit retention. Every introspection call
  emits an audit row. For a chatty resource server,
  this could fill the audit log quickly. Operators may
  want a separate retention policy for
  `token_introspected` rows (shorter than other events).
  Defer to operator demand; v0.38.0 emits but doesn't
  expire.
- **Q4**: ~~Multi-key access-token verification.~~
  **Resolved in v0.41.0.** The access-token verify
  path now does kid-directed lookup with a try-each
  fallback. The JWT's `kid` header is extracted via
  `cesauth_core::jwt::signer::extract_kid` (no signature
  verification at this stage; kid is untrusted). If the
  kid matches one of the active keys, that key is
  tried first — the fast path, one crypto verify call.
  If the kid doesn't match anything, isn't present, or
  the kid-matched key fails to verify (defensive),
  every active key is tried in turn. Returns active
  on first success; inactive if all fail. The
  cryptographic check remains the gate; an attacker
  who forges a kid pointing at a key they don't
  control still has to produce a valid signature with
  that key, which they can't. **Side-finding**: the
  multi-key work surfaced a P0 latent bug from v0.38.0:
  jsonwebtoken-10's `CryptoProvider::install_default`
  requirement wasn't met by the workspace's bare
  `ed25519-dalek` opt-dep, and the first real
  introspection request would have panicked the
  worker. v0.41.0 fixes this by enabling the
  `rust_crypto` feature (accepting transitive `rsa` as
  unused-but-linked dead code, with a follow-up to
  swap to `josekit` + direct ed25519-dalek tracked).
  See v0.41.0 CHANGELOG.

## Considered alternatives (rejected)

- **Make `/introspect` a public endpoint.** Rejected —
  RFC 7662 §2.1 explicitly requires authentication, and
  a public introspection endpoint would let anyone with a
  guessed token learn its claims (or, on inactive
  response, learn that the token isn't currently
  active — which is information the bearer shouldn't have).
- **Always include all claims even on inactive
  response.** Rejected — RFC 7662 §2.2 MUST and the
  privacy concern is real (see "Read-only by design"
  above).
- **Trigger reuse detection on a retired-jti
  introspection.** Rejected — would let a malicious
  resource server revoke families on demand. Read-only
  semantics are correct.
- **Argon2 for `client_secret_hash`.** Rejected — see
  "Client credential verification" above.

## See also

- RFC 7662 — the spec.
- [ADR-008: ID token issuance](008-id-token-issuance.md)
  — the related "what claims do we expose" thread.
- [ADR-011: Refresh token reuse hardening](011-refresh-token-reuse-hardening.md)
  — the v0.34.0 work that introduced
  `RefreshTokenFamilyStore::peek`, which introspection
  reuses.
- [ADR-013: Internationalization](013-i18n.md) — the
  immediately-prior release; v0.38.0 doesn't touch
  i18n surfaces because `/introspect` returns
  machine-readable JSON only.
