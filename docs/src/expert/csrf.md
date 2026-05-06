# CSRF model

cesauth applies CSRF defense by route, choosing one of four
mechanisms based on the route's authentication and content type.
The detailed per-route audit lives in [`csrf-audit.md`](./csrf-audit.md);
this chapter is the design overview.

## Defense mechanisms

| Mechanism | When it applies | What stops the attacker |
|---|---|---|
| **CSRF token** | Browser-cookie-authenticated form POSTs | Attacker page can't read the `__Host-cesauth-csrf` cookie (HttpOnly + `__Host-` prefix prevents cross-origin Set-Cookie). Without the cookie's value, the attacker can't echo it in the form field. |
| **Origin/Referer check** | State-clearing routes with no UI form (e.g. `/logout`) | Attacker page's request carries the attacker's `Origin` (or `Referer`), not cesauth's. |
| **CORS preflight** | JSON-only POSTs | Cross-origin `application/json` triggers a preflight that cesauth doesn't grant. |
| **`Authorization: Bearer`** | Bearer-token-authenticated routes | Browsers can't auto-send `Authorization` from a cross-origin form; only same-origin JS can set it, and same-origin JS isn't a CSRF vector. |

## Protected endpoints

| Endpoint                                  | Mechanism                              |
|-------------------------------------------|----------------------------------------|
| `GET  /authorize`                         | Read-only; sets the CSRF cookie        |
| `POST /magic-link/request`                | CSRF token (form) / CORS preflight (JSON) |
| `POST /magic-link/verify`                 | CSRF token (form, added v0.24.0) / CORS preflight (JSON) |
| `POST /webauthn/register/finish`          | JSON-only — CORS preflight             |
| `POST /webauthn/authenticate/finish`      | JSON-only — CORS preflight             |
| `POST /api/v1/anonymous/promote`          | JSON-only — CORS preflight             |
| `POST /admin/console/*`                   | `Authorization: Bearer` (admin token)  |
| `POST /admin/tenancy/*`                   | `Authorization: Bearer` (admin token)  |
| `POST /admin/t/<slug>/*`                  | `Authorization: Bearer` (user-as-bearer per ADR-002) |
| `POST /api/v1/...`                        | `Authorization: Bearer` (admin token)  |
| `POST /oauth/token`                       | OAuth client_secret + grant secret     |
| `POST /oauth/revoke`                      | OAuth client_secret                    |
| `POST /logout`                            | Origin/Referer check                   |

## The pattern

1. Client loads a page that renders a form. The server sets
   `__Host-cesauth-csrf=<random>` as `HttpOnly; Secure;
   SameSite=Strict; Path=/`.
2. The form includes a hidden field `<input name="csrf"
   value="<random>">` with the same value.
3. On POST, the handler compares the cookie to the form field.
   Equal (constant-time) and non-empty → accept. Otherwise reject
   with 403.

Cookie is `HttpOnly` because the form template renders the token
into the HTML directly — client-side JavaScript never reads the
cookie. This protects against XSS stealing the token.

## Why `SameSite=Strict`

The CSRF cookie is `Strict` (the session cookie is `Lax`). `Strict`
prevents the cookie from being sent on *any* cross-site navigation
— including the link a phishing site might construct. `Lax` would
suffice against the canonical CSRF attack, but `Strict` costs
nothing here because the token is only ever checked during a
same-site form POST.

## Why JSON bypasses

Cross-origin `application/json` POSTs trigger a CORS preflight.
Without explicit `Access-Control-Allow-Origin` on cesauth's side
(which we do not grant to arbitrary origins), the browser refuses
to send the request. So a cross-site attacker cannot construct a
JSON POST from the victim's browser at all. A simple request —
`application/x-www-form-urlencoded`, `multipart/form-data`, or
`text/plain` — can be made cross-origin without preflight, which is
why those paths get CSRF'd.

The implementation gates on `content-type`:

```rust
fn requires_csrf(req: &Request) -> bool {
    match req.content_type() {
        Some(ct) if ct.starts_with("application/x-www-form-urlencoded") => true,
        Some(ct) if ct.starts_with("multipart/form-data")               => true,
        Some(ct) if ct.starts_with("text/plain")                        => true,
        _ => false,  // application/json and everything else
    }
}
```

## Constant-time compare

Token compare uses a constant-time loop:

```rust
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
```

Same helper is used for admin bearer token comparison. The
compiler could in theory rewrite this, but the `#[inline]`
attribute is deliberately omitted to reduce that risk, and the
pattern matches what mainstream crypto libraries do.

## Cookie name rationale

`__Host-cesauth-csrf` uses the `-` separator (not `_`) to match the
hyphenated form used by the rest of cesauth's cookies. The `__Host-`
prefix requires `Secure`, `Path=/`, and no `Domain` — same
constraints as the session cookie.
