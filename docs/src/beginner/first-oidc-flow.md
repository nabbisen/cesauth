# Your first OIDC flow with curl

This chapter walks through a complete authentication and authorization
run using nothing but `curl` and `jq`. By the end you will have:

1. Created a user via the admin API.
2. Issued a Magic Link and read its OTP from the dev audit log.
3. Verified the OTP and received a signed session cookie.
4. Run the OIDC Authorization Code + PKCE flow against the same user.
5. Used the refresh token to rotate, then revoked the grant.

Everything happens on `http://localhost:8787` while `wrangler dev` is
running. Use two terminals — one for the Worker, one for curl.

> **Magic Link "dev delivery".** `routes::magic_link::request` does
> not send real email in this build. It writes the plaintext OTP into
> the audit log as `reason = "dev-delivery handle=… code=…"`. That is
> convenient locally and **must be removed before any production
> deploy**. The tutorial reads the OTP out of the audit log on
> purpose.

## Step 1 — Create a user

```sh
USER_ID=$(curl -s -X POST http://localhost:8787/admin/users \
  -H 'authorization: Bearer dev-admin-secret-change-me' \
  -H 'content-type: application/json' \
  -d '{"email":"bob@example.com","display_name":"Bob"}' | jq -r .id)
echo "USER_ID=$USER_ID"
```

If you get `409 email already in use`, the row is there from a
previous run. Either reset (see [Resetting](./resetting.md)) or drop
the row:

```sh
wrangler d1 execute cesauth --local --command \
  "DELETE FROM users WHERE email='bob@example.com';"
```

## Step 2 — Request a Magic Link

```sh
curl -s -X POST http://localhost:8787/magic-link/request \
  -H 'content-type: application/json' \
  -d '{"email":"bob@example.com"}' \
  -D /tmp/ml-headers.txt -o /tmp/ml-body.html

head -3 /tmp/ml-headers.txt
# HTTP/1.1 200 OK
```

> **CSRF aside.** `application/json` POSTs bypass CSRF validation —
> browsers cannot forge them cross-origin without a CORS preflight.
> The form-based login page DOES require the `__Host-cesauth-csrf`
> cookie plus a matching `csrf` form field. See the [CSRF
> model](../expert/csrf.md) chapter for why.

The response body is the "check your inbox" HTML page. In production
the plaintext OTP goes in an email; here it is in the audit log:

```sh
AUDIT=$(curl -s 'http://localhost:8787/__dev/audit?body=1' |
        jq '[.keys[].body | select(.kind=="magic_link_issued")] | .[-1]')
echo "$AUDIT" | jq .
```

Expected (trimmed):

```json
{
  "ts":      1715712345,
  "kind":    "magic_link_issued",
  "subject": "bob@example.com",
  "reason":  "dev-delivery handle=…uuid… code=AB2CDE34"
}
```

Extract handle and code:

```sh
HANDLE=$(echo "$AUDIT" | jq -r '.reason | capture("handle=(?<h>[^ ]+) code=").h')
CODE=$(echo "$AUDIT"   | jq -r '.reason | capture("code=(?<c>[A-Z0-9]+)").c')
echo "HANDLE=$HANDLE  CODE=$CODE"
```

## Step 3 — Verify the Magic Link

```sh
curl -s -X POST http://localhost:8787/magic-link/verify \
  -H 'content-type: application/json' \
  -d "{\"handle\":\"$HANDLE\",\"code\":\"$CODE\"}" \
  -D /tmp/verify-headers.txt -o /tmp/verify.html -w 'status=%{http_code}\n'
# status=302
```

`302` is the success signal. `post_auth::complete_auth` has two
branches: if `/authorize` parked a pending request first (via the
`__Host-cesauth_pending` cookie), it mints an `AuthCode` and 302s to
`redirect_uri?code=…&state=…`. Otherwise it 302s to `/`. Either way a
signed `__Host-cesauth_session` cookie is attached.

```sh
grep -i '^location\|^set-cookie' /tmp/verify-headers.txt
# location: /
# set-cookie: __Host-cesauth_session=<b64>.<b64>; Max-Age=...; Secure; HttpOnly; SameSite=Lax
# set-cookie: __Host-cesauth_pending=; Max-Age=0; ...
```

Confirm `magic_link_verified` landed in the audit log:

```sh
curl -s 'http://localhost:8787/__dev/audit?body=1' |
  jq '[.keys[].body | select(.kind=="magic_link_verified")] | .[-1]'
```

Bob is now authenticated. In a real browser flow `/authorize` would
have parked a pending request first and Step 4b below would happen
automatically. To keep this tutorial curl-only, we use a dev-only
helper instead.

## Step 4 — OIDC Authorization Code + PKCE

### 4a. Build the PKCE pair

```sh
CODE_VERIFIER=$(openssl rand -base64 40 | tr -d '=+/\n' | head -c 64)
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" | openssl dgst -binary -sha256 |
                 base64 | tr '+/' '-_' | tr -d '=\n')
echo "VERIFIER=$CODE_VERIFIER"
echo "CHALLENGE=$CODE_CHALLENGE"
```

### 4b. Begin the flow

```sh
curl -s -D - -o /dev/null -G http://localhost:8787/authorize \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=demo-cli' \
  --data-urlencode 'redirect_uri=http://localhost:8787/callback' \
  --data-urlencode 'scope=openid profile email' \
  --data-urlencode 'state=abc123' \
  --data-urlencode 'nonce=xyz789' \
  --data-urlencode "code_challenge=$CODE_CHALLENGE" \
  --data-urlencode 'code_challenge_method=S256' \
  | head -5
# HTTP/1.1 200 OK
# content-type: text/html; charset=utf-8
```

A real browser would render the login page here, authenticate, and
be redirected to `redirect_uri?code=…&state=abc123`. That path is
implemented end-to-end; `post_auth::complete_auth` reads the
`__Host-cesauth_pending` cookie set by `/authorize`, pulls the parked
`Challenge::PendingAuthorize` out of the `AuthChallenge` DO, and
mints the code.

To exercise `/token` without a cookie jar, cesauth ships a dev-only
helper endpoint, `POST /__dev/stage-auth-code/:handle`. It writes a
raw `AuthCode` challenge directly to the `AuthChallenge` DO. Like
`/__dev/audit`, it is gated on `WRANGLER_LOCAL="1"`.

Stage a code for Bob:

```sh
CODE_HANDLE=$(uuidgen | tr 'A-Z' 'a-z')
NOW=$(date +%s)
EXP=$((NOW + 300))

jq -n --arg u "$USER_ID" --arg c "$CODE_CHALLENGE" \
      --argjson n "$NOW" --argjson e "$EXP" '
  {
    kind:                   "auth_code",
    client_id:              "demo-cli",
    redirect_uri:           "http://localhost:8787/callback",
    user_id:                $u,
    scopes:                 ["openid","profile","email"],
    nonce:                  "xyz789",
    code_challenge:         $c,
    code_challenge_method:  "S256",
    issued_at:              $n,
    expires_at:             $e
  }' \
| curl -s -X POST "http://localhost:8787/__dev/stage-auth-code/$CODE_HANDLE" \
    -H 'content-type: application/json' \
    --data-binary @- -w '\nstatus=%{http_code}\n'
# staged
# status=200
```

> `scopes` is a bare JSON array, not an object. In Rust, `Scopes` is a
> tuple struct (`pub struct Scopes(pub Vec<String>)`) — serde
> (de)serializes it as `["openid","profile","email"]`. `{"0": [...]}`
> is rejected with `invalid type: map, expected a sequence`.

### 4c. Exchange the code for tokens

```sh
curl -s -X POST http://localhost:8787/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE_HANDLE" \
  --data-urlencode "redirect_uri=http://localhost:8787/callback" \
  --data-urlencode "client_id=demo-cli" \
  --data-urlencode "code_verifier=$CODE_VERIFIER" | tee /tmp/tokens.json | jq .
```

> **If `400 Bad Request` with `{"error":"invalid_grant"}`**: the staged
> code is gone. Causes are TTL expired (5 min), already redeemed
> (codes are single-use), or the worker restarted and the DO lost the
> entry. Re-run 4b with a fresh `$CODE_HANDLE`.

Expected:

```json
{
  "access_token":  "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImNlc2F1dGgtMjAyNi0wMSJ9.…",
  "token_type":    "Bearer",
  "expires_in":    600,
  "refresh_token": "…base64url…",
  "scope":         "openid profile email"
}
```

Save both:

```sh
ACCESS_TOKEN=$(jq -r .access_token  /tmp/tokens.json)
REFRESH_TOKEN=$(jq -r .refresh_token /tmp/tokens.json)
```

### 4d. Inspect the access token

```sh
echo "$ACCESS_TOKEN" | cut -d. -f2 |
  tr '_-' '/+' | base64 -d 2>/dev/null | jq .
```

Expected claims:

```json
{
  "iss":   "https://auth.example.com",
  "sub":   "…$USER_ID…",
  "aud":   "demo-cli",
  "exp":   1715713045,
  "iat":   1715712445,
  "jti":   "…uuid…",
  "scope": "openid profile email",
  "cid":   "demo-cli"
}
```

### 4e. Verify the signature via JWKS

```sh
curl -s http://localhost:8787/jwks.json | jq .
```

Any JWT library can verify the token against this JWKS. Example in
Node with `jose`:

```js
import { createRemoteJWKSet, jwtVerify } from "jose";
const JWKS = createRemoteJWKSet(new URL("http://localhost:8787/jwks.json"));
const { payload } = await jwtVerify(accessToken, JWKS, {
  issuer:   "https://auth.example.com",
  audience: "demo-cli",
});
```

## Step 5 — Rotate the refresh token

```sh
curl -s -X POST http://localhost:8787/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN" \
  --data-urlencode "client_id=demo-cli" | tee /tmp/tokens2.json | jq .
```

You get a fresh access + refresh token. **The old refresh token is
now retired.** If anything tries to use it again, cesauth burns the
entire family per RFC 9700 §4.14.2 (reuse detection). Try it:

```sh
curl -s -X POST http://localhost:8787/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN" \
  --data-urlencode "client_id=demo-cli" | jq .
# { "error": "invalid_grant" }
```

And now the *new* refresh token no longer works either — detecting
the reuse revoked the whole family:

```sh
NEW_REFRESH=$(jq -r .refresh_token /tmp/tokens2.json)
curl -s -X POST http://localhost:8787/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$NEW_REFRESH" \
  --data-urlencode "client_id=demo-cli" | jq .
# { "error": "invalid_grant" }
```

This reuse-burns-family property is why `RefreshTokenFamily` lives
in a Durable Object and not in D1. The [Token issuance & refresh
rotation](../expert/oidc-tokens.md) chapter explains.

## Step 6 — Explicit revocation

For the normal log-out case, use the revocation endpoint:

```sh
# Start fresh: re-run Step 4 to get a new refresh token. Then:
curl -s -X POST http://localhost:8787/revoke \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$REFRESH_TOKEN" \
  --data-urlencode "client_id=demo-cli" \
  -w 'status=%{http_code}\n' -o /dev/null
# status=200
```

Per RFC 7009, `/revoke` returns 200 on well-formed input regardless
of whether the token actually existed — this prevents
token-existence probing.

## Step 7 — Admin: revoke a session

The admin API exposes per-session revocation for events like "phone
was stolen". Sessions are keyed by id:

```sh
curl -s -X DELETE http://localhost:8787/admin/sessions/some-session-id \
  -H 'authorization: Bearer dev-admin-secret-change-me' \
  -w 'status=%{http_code}\n' -o /dev/null
# status=204
```

## What next?

- [Inspecting state](./inspecting-state.md) — peek into D1, the audit
  log, and live operational logs.
- [Troubleshooting](./troubleshooting.md) — common failure modes from
  this tutorial, consolidated.
- [OIDC internals](../expert/oidc-internals.md) — the expert-side
  explanation of what each endpoint just did.
