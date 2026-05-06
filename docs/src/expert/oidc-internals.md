# OIDC internals

> **v0.25.0 status note**: cesauth implements the OAuth 2.0
> Authorization Code flow with PKCE today. OpenID Connect Core
> 1.0 conformance requires `id_token` issuance, which is **not yet
> implemented** — see [ADR-008](./adr/008-id-token-issuance.md)
> for the v0.26.0 plan and
> [`email-verification-audit.md`](./email-verification-audit.md)
> for how this gap was discovered. The current discovery document
> is RFC 8414 (OAuth 2.0 metadata), not OIDC Discovery 1.0.

cesauth implements OAuth 2.0 with the Authorization Code flow
plus PKCE, plus partial OIDC scaffolding (`/authorize` accepts
`openid` scope, `nonce`, and `prompt` parameters; the JWT
infrastructure issues EdDSA-signed access tokens). The remaining
OIDC-required pieces — `id_token` issuance with claims sourcing
from the user record — land in v0.26.0.

The three deep-dive pages below cover the flow,
the token lifecycle, and the `prompt` / `max_age` handling.

- [Authorization Code + PKCE](./oidc-authorization.md)
- [Token issuance & refresh rotation](./oidc-tokens.md)
- [`prompt` & `max_age` handling](./oidc-prompt-max-age.md)

## Endpoints at a glance

| Method | Path                                  | Purpose                          |
|--------|---------------------------------------|----------------------------------|
| GET    | `/.well-known/openid-configuration`   | Discovery document               |
| GET    | `/jwks.json`                          | Public key set                   |
| GET    | `/authorize`                          | Authorization Code + PKCE start  |
| POST   | `/token`                              | Code exchange + refresh rotation |
| POST   | `/revoke`                             | Token revocation (RFC 7009)      |

## What cesauth implements

- **Flow**: Authorization Code with PKCE S256. `plain` is not
  supported; `code_challenge_method=plain` is rejected with
  `invalid_request`.
- **Client auth**: `none` (public PKCE-only clients),
  `client_secret_basic`, and `client_secret_post`.
- **Scopes**: `profile`, `email`, plus any others the
  `oidc_clients.allowed_scopes` whitelist permits. Pre-v0.25.0
  also advertised `openid`; that's been removed pending id_token
  issuance (see ADR-008, planned v0.26.0). The route accepts
  `openid` in incoming requests for forward-compat with future
  v0.26.0 RPs but doesn't emit anything that depends on it yet.
- **Response types**: `code` only. `token` and `id_token` response
  types (the implicit flow) are not supported. Note: this is the
  *response_type* parameter; cesauth's id_token issuance gap
  (no `id_token` *body field* in `/token` responses) is a
  separate matter, designed in ADR-008 for v0.26.0.
- **Response modes**: query. `fragment` and `form_post` are rejected.
- **Signing**: EdDSA (Ed25519). The `kid` header rotates with the
  signing-key table; old `kid`s remain in JWKS until their grace
  window expires.
- **Prompt**: `none` and `login`. `consent` and `select_account`
  are rejected at validation with `invalid_request`.
- **`max_age`**: supported. Sessions older than `max_age` force
  re-authentication.

## What is out of scope

- SAML, OAuth 1.0, WS-Federation.
- Implicit flow, hybrid flow.
- Dynamic client registration (RFC 7591).
- Device Authorization Grant (RFC 8628).
- Request objects (`request` / `request_uri` parameters).
- Federation (OpenID Connect Federation).

Any addition to this list should ship as a new route module that
depends on a new set of ports; the core/adapter split means such
additions are localized.
