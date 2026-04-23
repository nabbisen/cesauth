# OIDC internals

cesauth implements OpenID Connect Core 1.0 with the Authorization
Code flow and PKCE. The three deep-dive pages below cover the flow,
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
- **Scopes**: `openid`, `profile`, `email`, plus any others the
  `oidc_clients.allowed_scopes` whitelist permits.
- **Response types**: `code` only. `token` and `id_token` response
  types (the implicit flow) are not supported.
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
