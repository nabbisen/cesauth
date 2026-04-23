# Error codes

cesauth surfaces two classes of error to clients:

1. **OIDC/OAuth2 standard error codes** — carried in the `error`
   field of a JSON body or redirect query string.
2. **HTTP status codes** — the transport-level signal.

## OIDC / OAuth2 error codes

Per RFC 6749, 6750, 7009, and OpenID Connect Core:

| Code                       | Meaning                                             | Typical cause               |
|----------------------------|-----------------------------------------------------|------------------------------|
| `invalid_request`          | Malformed or missing parameter                      | Missing `code`, bad JSON     |
| `invalid_client`           | Client auth failed / client unknown                 | Wrong `client_secret`        |
| `invalid_grant`            | Grant invalid, expired, revoked, or reused          | Expired auth code, reused refresh |
| `unauthorized_client`      | Client not allowed to use this grant type           | `token_auth_method` mismatch |
| `unsupported_grant_type`   | Grant type not implemented                          | e.g. `password`              |
| `invalid_scope`            | Scope outside client whitelist                      | Client's `allowed_scopes` does not contain the requested |
| `unsupported_response_type`| `response_type` ≠ `code`                            | Implicit/hybrid flow request |
| `login_required`           | `prompt=none` but session is stale                  | SSO silent check             |
| `interaction_required`     | Server cannot complete without user interaction     | Paired with `prompt=none`    |
| `account_selection_required`| User must select an account                        | (not currently emitted)      |
| `consent_required`         | Missing / stale consent                             | (not currently emitted)      |

## HTTP status codes

| Status | When                                                      |
|--------|-----------------------------------------------------------|
| `200`  | Success; or `/revoke` regardless (RFC 7009)               |
| `204`  | Admin success with no body (`DELETE /admin/sessions/:id`) |
| `302`  | Successful redirect (`/authorize` → `redirect_uri`, `/magic-link/verify` → `/` or redirect_uri) |
| `400`  | `invalid_request`, `invalid_grant`, bad form body         |
| `401`  | Missing or bad credentials on `/admin/*`                  |
| `403`  | CSRF failure; admin key disabled                          |
| `404`  | Unknown path; or `/__dev/*` with `WRANGLER_LOCAL≠"1"`     |
| `409`  | `Conflict` from admin user creation (email already used)  |
| `429`  | Rate limit exceeded                                       |
| `500`  | Internal error. Check `wrangler tail` for the structured log |

## 500 debugging cheat sheet

Every `/token` 500 now emits a structured log on the way out. The
three most common forms:

```
{"lvl":"error","cat":"config","msg":"load_signing_key failed: …"}
    → JWT_SIGNING_KEY secret is missing from .dev.vars / production secrets

{"lvl":"error","cat":"crypto","msg":"JwtSigner::from_pem failed: …"}
    → PEM is malformed (interrupted genpkey, truncated copy,
      missing BEGIN/END markers)

{"lvl":"warn","cat":"auth","msg":"exchange_code failed: <CoreError>"}
    → Not actually a 500; this is a 400 invalid_grant with a
      specific reason. CoreError::PreconditionFailed("…") is the
      most detailed breadcrumb.
```

See [Troubleshooting](../beginner/troubleshooting.md) for the same
symptoms in walkthrough form.

## `PortError` → HTTP mapping

| `PortError`                         | `CoreError` mapping           | HTTP status + OAuth code |
|-------------------------------------|-------------------------------|--------------------------|
| `NotFound`                          | `NotFound`                    | 404                      |
| `Conflict`                          | `Conflict`                    | 409                      |
| `PreconditionFailed("…")`           | Context-specific              | 400 `invalid_grant` typically |
| `Unavailable`                       | `Internal`                    | 500                      |
| `Serialization`                     | `Serialization`               | 500                      |

The context-specific mapping for `PreconditionFailed` happens in
`core::service::*`, not in the port layer. A port never speaks
HTTP.
