# Security response headers

cesauth attaches a fixed set of HTTP response headers to every
response, configured per ADR-007. This chapter explains what
headers ship by default, how to override them, and when an
operator might want to.

## What's there by default

Every response (HTML, JSON, error 404/500, anything) carries:

- `X-Content-Type-Options: nosniff` — disables MIME sniffing.
- `Referrer-Policy: strict-origin-when-cross-origin` — sends
  full URL on same-origin requests, origin-only on cross-origin
  HTTPS, nothing on cross-origin HTTP.
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
  — 2 years, applies to all subdomains. **No `preload` by
  default** (see below if you want it).
- `Permissions-Policy: ...` — disables camera, microphone,
  geolocation, payment, USB, magnetometer, gyroscope,
  accelerometer, MIDI, serial, bluetooth, fullscreen, and
  picture-in-picture for the cesauth origin and any frames it
  embeds.

Additionally, HTML responses (`Content-Type: text/html`) carry:

- `Content-Security-Policy: ...` — defense against XSS. The
  default policy is restrictive (`default-src 'none'`), but
  cesauth's existing HTML routes (login page, OIDC authorize
  page, admin console) **set their own CSP** because their
  templates use inline `<style>` and `<script>` blocks. Those
  per-route policies use `'unsafe-inline'` and are visible in
  the response headers. A future release will migrate to a
  nonce-based CSP that doesn't need `'unsafe-inline'`.
- `X-Frame-Options: DENY` — clickjacking defense. Belt-and-
  suspenders with `frame-ancestors 'none'` in CSP.

## Opting into HSTS preload

If you want your domain in browsers' preload list (so first-
visit users are HTTPS-only without prior contact):

1. Confirm your deployment is HTTPS-only with no fallback to
   HTTP. The preload list is **hard to leave** — your domain
   becomes browser-baked-in.
2. Set the env var:
   ```toml
   [vars]
   SECURITY_HEADERS_STS = "max-age=63072000; includeSubDomains; preload"
   ```
3. Submit your domain to <https://hstspreload.org>.

The default `max-age=63072000; includeSubDomains` (without
`preload`) is the right value for any deployment that's not
sure they want preload. Don't set `preload` casually.

## Overriding the CSP

The `SECURITY_HEADERS_CSP` env var sets the **fallback** CSP —
the policy applied to HTML responses that don't carry their
own. cesauth's existing routes (login, authorize, admin console)
override this anyway, so this knob mostly affects future routes
and any custom routes added by a fork.

If you have a legitimate need for a different default CSP — for
example, you're embedding cesauth's pages inside a known partner
frame — set:

```toml
[vars]
SECURITY_HEADERS_CSP = "default-src 'self'; frame-ancestors https://partner.example"
```

This won't override the per-route CSPs; those would need to be
patched separately.

## Disabling HTML-only headers (debugging)

For local development or debugging, you can disable CSP and
X-Frame-Options entirely:

```toml
[vars]
SECURITY_HEADERS_DISABLE_HTML_ONLY = "true"
```

The match is **strict** — only the exact string `"true"`
(case-insensitive) disables. Typos like `"yes"`, `"1"`, `"True!"`
do nothing. This is intentional: a one-character typo in your
config should not silently disable security headers.

**Do not set this in production.** The deployment-guide
production checklist (`docs/src/deployment/preflight.md`)
includes verifying this knob is unset.

The universal headers (`X-Content-Type-Options`,
`Strict-Transport-Security`, `Referrer-Policy`,
`Permissions-Policy`) **cannot** be disabled via this knob.
They're cheap and apply to every response type. To disable
them, you'd have to fork the worker.

## Verifying in production

```sh
curl -sI https://<your-cesauth-host>/login | grep -iE \
  'content-security|x-frame|x-content|referrer|strict-transport|permissions'
```

You should see all six headers. If any are missing, check:

1. Is the `cesauth-worker` build at v0.23.0 or newer?
2. Did the deploy use the latest wrangler.toml?
3. Are you hitting the right origin (not Cloudflare's edge
   cache returning a stale response)? Cache should not affect
   this — security headers are added per-response by the
   worker, but a misconfigured cache rule could in theory
   strip them. Check `Cache-Control` on the response.

## Verifying for a JSON endpoint

```sh
curl -sI https://<your-cesauth-host>/.well-known/openid-configuration | grep -iE \
  'content-security|x-frame|x-content|referrer|strict-transport|permissions'
```

For a JSON endpoint you should see four headers (the universal
set), not six. **No CSP**, **no X-Frame-Options** — those are
HTML-only.

## Routes with custom CSPs (v0.23.0)

These three routes set their own `Content-Security-Policy`
because their templates use inline `<style>`/`<script>`:

- `GET /login`
- `GET /authorize`
- `GET /admin/console/*`

Each of these uses `'unsafe-inline'` for `style-src` and (for
login + authorize) `script-src`. A planned future release will
migrate to nonces; until then, this is a known limitation
documented in ADR-007 §Q3.

When a request lands on one of these routes, the middleware
detects the route's CSP via the response's existing
`Content-Security-Policy` header and does **not** apply the
fallback. The other security headers (universal + X-Frame-Options)
still apply.

## See also

- [ADR-007](../expert/adr/007-security-response-headers.md)
  — design rationale and decision summary.
- [SECURITY.md](../../../.github/SECURITY.md) — vulnerability
  disclosure policy and security contact.
- [CSRF audit (v0.24.0)](../expert/csrf-audit.md) — the
  parallel-track audit done alongside this header rollout.
- Mozilla Observatory: <https://observatory.mozilla.org/> —
  external automated check of your deployment's headers.
