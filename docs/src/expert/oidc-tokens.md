# Token issuance & refresh rotation

> **v0.25.0 status note**: cesauth currently issues access tokens
> and refresh tokens but **does not issue OIDC `id_token`s**. The
> `TokenResponse.id_token` field is always `null`. ID token
> issuance is designed in [ADR-008](./adr/008-id-token-issuance.md)
> and will land in v0.26.0 — at which point this document and the
> code flow below pick up id_token signing for `openid`-scoped
> requests. See [`email-verification-audit.md`](./email-verification-audit.md)
> for the discovery and motivation.

## `/token` endpoint

Two grant types, both at `POST /token`:

- `grant_type=authorization_code` — exchange a code for tokens
- `grant_type=refresh_token` — rotate to a fresh refresh token

Client auth per the client's `token_auth_method`:

- `none` — PKCE-only public clients (the tutorial uses this)
- `client_secret_basic` — HTTP Basic header
- `client_secret_post` — `client_id` + `client_secret` in the form

## Authorization code exchange

```
POST /token
    │
    ├── parse form, classify grant_type → TokenGrant::AuthorizationCode
    │
    ├── call token_service::exchange_code(…):
    │     ├── take(code) from AuthChallengeStore   (single-use)
    │     ├── verify client_id matches the parked code
    │     ├── verify redirect_uri matches the parked code
    │     ├── verify code_verifier (SHA-256, base64url) == parked code_challenge
    │     ├── init RefreshTokenFamily DO with a fresh family_id, first jti
    │     ├── write Grant row to D1 (grant history)
    │     └── sign access_token (JWT EdDSA)
    │         (v0.26.0 will additionally sign id_token here when
    │          `openid` is in granted scope; see ADR-008)
    │
    └── return TokenResponse JSON:
            { access_token, token_type: "Bearer", expires_in,
              refresh_token, scope, id_token: null }
            (v0.26.0: id_token field is populated when scope
             includes `openid`)
```

## Refresh rotation

```
POST /token grant_type=refresh_token
    │
    ├── parse form, classify → TokenGrant::RefreshToken
    │
    ├── call token_service::rotate_refresh(…):
    │     ├── parse presented jti
    │     ├── RefreshTokenFamily.rotate(presented_jti, new_jti, now):
    │     │     ├── if presented_jti is the current active jti:
    │     │     │     rotate: mark it retired, set new one active, return Ok
    │     │     ├── if presented_jti is already retired:
    │     │     │     burn the whole family, return ReusedAndRevoked
    │     │     └── if family is already revoked:
    │     │           return AlreadyRevoked
    │     └── on Ok, sign fresh access token, return
    │         (v0.26.0 will additionally sign a fresh id_token
    │          when `openid` was in the family's carried scope)
    │
    └── return new TokenResponse (or 400 invalid_grant on reuse)
```

**The reuse-burns-family rule is RFC 9700 §4.14.2.** If a retired
refresh token reappears, cesauth cannot distinguish an attacker who
replayed an intercepted token from a legitimate client that did not
notice the rotation succeeded. The safe response is to revoke the
whole family immediately.

This rule is the reason `RefreshTokenFamily` is a Durable Object and
not a D1 row. The rotation has to be serialized per family, and D1
does not guarantee that.

## Access token claims

```json
{
  "iss":   "https://auth.example.com",
  "sub":   "<user_id>",
  "aud":   "<client_id>",
  "iat":   1715712445,
  "exp":   1715713045,
  "jti":   "<uuid>",
  "scope": "openid profile email",
  "cid":   "<client_id>"
}
```

The `cid` claim is a non-standard convenience for resource servers
that want to key on client without re-parsing `aud`. Standard
claims follow RFC 9068.

## ID token claims

```json
{
  "iss":    "https://auth.example.com",
  "sub":    "<user_id>",
  "aud":    "<client_id>",
  "iat":    1715712445,
  "exp":    1715713045,
  "nonce":  "<the nonce from /authorize>",
  "auth_time": 1715712400
}
```

Additional claims come from the requested scopes:

- `profile` scope → `preferred_username`, `name`, `updated_at`
- `email` scope → `email`, `email_verified`

## Revocation

`POST /revoke` accepts a `token` parameter and returns 200 regardless
of whether the token existed (RFC 7009, to block existence probing).

Behind the scenes:

- **Refresh token** → `RefreshTokenFamilyStore::revoke(family_id)`.
  The whole family is burned; every subsequent rotation on it gets
  `AlreadyRevoked`.
- **Access token** → no state to update. cesauth does not
  cross-reference access tokens against a revocation list because
  their lifetime is short (10 minutes) and their `jti` is not
  written to a store. Clients that need instant access-token
  revocation should lower `access_token_ttl_secs`.

## TTLs

All configurable via `wrangler.toml` `[vars]`:

| Var                          | Default        | Applies to                   |
|------------------------------|----------------|------------------------------|
| `ACCESS_TOKEN_TTL_SECS`      | `600` (10 min) | JWT `exp`                    |
| `REFRESH_TOKEN_TTL_SECS`     | `2592000` (30 days) | Refresh family     |
| `MAGIC_LINK_TTL_SECS`        | `600` (10 min) | OTP validity                 |
| `SESSION_TTL_SECS`           | `2592000` (30 days) | Session cookie     |
| `PENDING_AUTHORIZE_TTL_SECS` | `300` (5 min)  | `/authorize` cold-path park  |
| `AUTH_CODE_TTL_SECS`         | `300` (5 min)  | Issued auth codes            |

The short `AUTH_CODE_TTL_SECS` is why the beginner tutorial
sometimes gets `invalid_grant` — the staged code expired mid-typing.
