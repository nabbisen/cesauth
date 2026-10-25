# Integrating an application

**RFC 141.** This chapter is for the people on the other side of cesauth:
whoever is wiring *their* application to sign users in through it. If you
are working on cesauth itself, see [Admin operations
guide](./expert/admin-operations.md) and [OIDC
internals](./expert/oidc-internals.md) instead.

## 1. Discovery

```
GET /.well-known/openid-configuration
```

returns an RFC 8414 metadata document: `authorization_endpoint`,
`token_endpoint`, `jwks_uri`, `revocation_endpoint`, `introspection_endpoint`,
`userinfo_endpoint`, and the `scopes_supported` / `response_types_supported` /
`code_challenge_methods_supported` lists below. Fetch it rather than
hardcoding these paths — they are stable, but the document is still the
single source your client library should read them from.

## 2. Scopes and claims

**Scopes cesauth issues** (`scopes_supported`, and the only values
`allowed_scopes` may register — RFC 141 §4.3):

| Scope | Effect |
|---|---|
| `openid` | Request an `id_token` alongside the access token |
| `profile` | `name` claim on the `id_token`; `/userinfo` returns name fields |
| `email` | `email`, `email_verified` claims; `/userinfo` returns them |
| `offline_access` | A refresh token is issued (without it, `/token` returns an access token only) |

**Claims an `id_token` may carry** (`claims_supported`): `iss`, `sub`, `aud`,
`exp`, `iat`, `auth_time`, `nonce`, `email`, `email_verified`, `name`.
Signing is Ed25519 (`alg: EdDSA`) only.

## 3. Registering a client

Through `POST /admin/console/clients` (a system-admin bearer call — see
[Admin operations guide](./expert/admin-operations.md) for how to obtain
one). No SQL, ever (RFC 141 — this replaces a hand-written `INSERT INTO
oidc_clients` that earlier versions of this chapter, and
`deployment/production.md`, used to ask for).

```sh
curl -s -X POST "$CESAUTH_URL/admin/console/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "my-app",
    "name": "My Application",
    "client_type": "confidential",
    "redirect_uris": ["https://my-app.example.com/callback"],
    "allowed_scopes": ["openid", "profile", "email"],
    "token_auth_method": "client_secret_basic",
    "audience": null
  }'
```

returns:

```json
{
  "client": { "id": "my-app", "name": "My Application", "client_type": "confidential", "...": "..." },
  "client_secret": "the-plaintext-secret-shown-exactly-once"
}
```

**`client_secret` is returned exactly once, in this response (and in
`rotate-secret`'s). Copy it now — cesauth stores only its hash and will
never show it to you, or to anyone, again.** If you lose it, rotate:
`POST /admin/console/clients/:id/rotate-secret` mints a new one and
invalidates the old one immediately.

| Field | Meaning |
|---|---|
| `id` | Your client's `client_id`. Operator-chosen; non-empty, ASCII-graphic, ≤128 bytes |
| `name` | Display label only — not part of any protocol exchange |
| `client_type` | `"public"` (a browser SPA or CLI with nothing to keep secret — see the next section) or `"confidential"` (a server that can hold a secret) |
| `redirect_uris` | See §4 below. At least one, each a well-formed absolute URI |
| `allowed_scopes` | A subset of §2's list. At least one |
| `token_auth_method` | How your app authenticates at `/token`. `"none"` (only valid for `client_type: "public"` — no secret exists), `"client_secret_basic"` (HTTP `Authorization: Basic`), or `"client_secret_post"` (`client_secret` in the form body). **`/token` enforces whichever you registered** (RFC 141 §4.4): presenting credentials a different way than you registered, or presenting any secret at all for a `"none"`-registered client, is `invalid_client` |
| `audience` | Optional. Scopes which tokens your client may `/introspect` (ADR-014). Leave `null` unless you know you need this |

`require_pkce` is not a field you set: PKCE (S256) is mandatory for every
client, always.

**`client_type` cannot be changed after creation; `token_auth_method` can.**
`POST /admin/console/clients/:id` updates `name`, `redirect_uris`,
`allowed_scopes`, `audience`, and — between `"client_secret_basic"` and
`"client_secret_post"` only — `token_auth_method` (omit the field to leave
it unchanged). It cannot be set to `"none"` for a confidential client, or
to either secret-bearing method for a public one — the same §4.3 coupling
`create` enforces, enforced again here. To change `client_type` itself,
delete the client (`POST /admin/console/clients/:id/delete`) and register
again with a new secret.

> **Upgrading from before 0.85.0?** `token_auth_method` existed in the
> schema the whole time but was never read anywhere before this release. A
> confidential client you registered by hand and never explicitly set it
> on is `"none"` in storage, and as of 0.85.0 `/token` enforces it: that
> client's otherwise-correct requests will start failing with
> `401 invalid_client`, rejected before your secret is even compared. The
> fix is one call — `POST /admin/console/clients/:id` with the
> `token_auth_method` your integration actually presents credentials
> with (`"client_secret_basic"` for `Authorization: Basic`,
> `"client_secret_post"` for `client_secret` in the form body) — not a
> re-registration, and not a lost secret.

**Deletion is immediate and irreversible, and does not revoke outstanding
access.** Refresh stops working at once (every rotation looks the client up
first). Access tokens already issued remain valid until they expire —
self-contained signed JWTs, not something cesauth can recall — which with
the default `ACCESS_TOKEN_TTL_SECS` is up to 10 minutes.

## 4. Redirect URI rules

Each registered `redirect_uris` entry must be a well-formed absolute URI
(`scheme://host…`) with no `#` fragment. At `/authorize`, cesauth checks the
request's `redirect_uri` against your registered list by **exact string
match** — no normalization, no partial match, no wildcard. Register the
*exact* string your application will send, including trailing slash or
absence of one.

## 5. Token lifetimes to assume

The reference deployment's defaults (`wrangler.toml`; an operator may have
changed these — check `/​.well-known/openid-configuration` doesn't carry
them, so ask your operator if you need the exact values for a production
instance):

| Token | Default lifetime |
|---|---|
| Access token | 600 seconds (10 minutes) |
| Refresh token family, absolute cap | 2,592,000 seconds (30 days) |
| Refresh token family, idle timeout | 1,209,600 seconds (14 days) — a family that goes this long without a rotation expires even inside the 30-day cap |

Treat the access token as short-lived always; do not cache it beyond its
`exp`. A refresh token is single-use per rotation (RFC 9700 §4.14.2): each
`/token` refresh call both consumes the one you presented and issues a new
one — store the new one and discard the old immediately, or your next
refresh will look like reuse and revoke the whole family.

## 6. What `/token` errors mean for your code

| `error` | HTTP | What it means for you |
|---|---|---|
| `invalid_request` | 400 | A required parameter is missing or malformed. Check your request shape, not your credentials |
| `invalid_client` | 401 | Client authentication failed: wrong `client_id`/`client_secret`, or — RFC 141 §4.4 — you presented credentials via a transport (Basic vs. the form body) other than what you registered, or presented a secret at all for a `"none"`-registered public client |
| `invalid_grant` | 400 | The authorization code or refresh token is unknown, expired, already used, or was issued to a different client / redirect URI. **Also returned for refresh-token reuse** (presenting a token already rotated past) — deliberately indistinguishable on the wire from "just expired", so an attacker probing a stolen token learns nothing. If you see this on a refresh you didn't expect to be stale, stop retrying it: the family may have been revoked |
| `invalid_scope` | 400 | A requested scope is not one your client is `allowed_scopes`-registered for |
| `unsupported_grant_type` | 400 | Only `authorization_code` and `refresh_token` are implemented |
| `invalid_request` (429) | 429 | Rate-limited; respect the `Retry-After` header before retrying |
| `server_error` | 500 | Something failed on cesauth's side, not yours |

Every `/token` error response carries `cache-control: no-store` and no
other detail — the error code above, and nothing else. Do not try to
distinguish sub-cases cesauth has deliberately merged (see `invalid_grant`
above); doing so would reopen the side channel the merge exists to close.
