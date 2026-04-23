# Session cookies

cesauth issues a signed session cookie on every successful
authentication. This chapter covers the format, signing, and
revocation model.

## Cookie

```
__Host-cesauth_session = <b64url(json-payload)>.<b64url(hmac-sha256)>

Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000
```

The `__Host-` prefix requires (per CHIPS-adjacent rules):

- `Secure` attribute set
- `Path=/`
- No `Domain` attribute

All three are enforced by the issuing code.

## Payload

```json
{
  "sid":              "<session_id, uuid>",
  "uid":              "<user_id>",
  "iat":              1715712445,
  "exp":              1718304445,
  "authenticated_at": 1715712400,
  "auth_method":      "magic_link" | "webauthn"
}
```

`iat` / `exp` are cookie-level. `authenticated_at` is the moment the
user last proved identity (updated on each `post_auth::complete_auth`
call), used by the `max_age` check in `/authorize`.

## Why HMAC-SHA256, not JWT

A session cookie does not need to be readable by a third party,
round-trippable through other systems, or support algorithm
negotiation. It needs:

1. Integrity against forgery.
2. A small, fixed wire format.
3. A straightforward rotation story.

HMAC-SHA256 with a dedicated secret (`SESSION_COOKIE_KEY`) covers
all three in a fraction of the complexity of JWT. If you rotate the
signing key, old sessions become invalid on the next `/authorize`
hit — which also happens to be the intended behavior of a key
rotation.

The `SESSION_COOKIE_KEY` is a distinct secret from
`JWT_SIGNING_KEY`. Leaking one does not compromise the other; the
two blast radii are disjoint.

## Verification

Every route that reads the session does:

```rust
let cookie   = extract_cookie("__Host-cesauth_session")?;
let (payload, sig) = split_at_dot(cookie)?;
let expected_sig = hmac_sha256(&SESSION_COOKIE_KEY, payload);
if !constant_time_eq(sig, &expected_sig) {
    return Err(SessionInvalid);
}
let s: SessionPayload = serde_json::from_slice(&b64_decode(payload))?;
if s.exp < now { return Err(SessionExpired); }
```

Signature first, then body parsing. A forged body never reaches
serde.

## Revocation

The cookie carries `sid`. The authoritative revocation check is
`ActiveSessionStore::status(sid)`, which returns one of:

- `Active(state)` — ok to proceed
- `Revoked(state)` — session was revoked; the cookie is dead
- `NotStarted` — `sid` never existed; treat as forgery

`/authorize` calls `status(sid)` on every hit. A revoked session
means `/authorize` goes to the cold path (login page), regardless
of cookie presence.

`POST /logout` calls `ActiveSessionStore::revoke(sid)` and clears the
cookie by setting `Max-Age=0`. The admin surface has `DELETE
/admin/sessions/:id` for operator-initiated revocation (phone
stolen).

## Why an unsigned pending cookie is OK

`__Host-cesauth_pending` carries a single UUID — a handle into the
`AuthChallenge` DO. No identity claims. Forging the cookie at worst
points to a handle that does not exist (or belongs to another user),
and the DO rejects the `take` because the bound IP + UA hash does
not match. Signing it would be belt-and-suspenders.

## Cookie lifecycle

| Event                              | Session cookie              | Pending cookie       |
|------------------------------------|-----------------------------|----------------------|
| Fresh browser hits `/authorize`    | —                           | Set (pending handle) |
| User authenticates                 | Set (signed, Max-Age=30d)   | Cleared              |
| Return visit, valid session        | Untouched                   | —                    |
| Return visit, revoked session      | Ignored, pending set        | Set                  |
| `POST /logout`                     | Cleared                     | Cleared              |
| Admin revokes session              | Still in browser, but `/authorize` treats as invalid | — |
