# ADR-007: HTTP security response headers

**Status**: Accepted (v0.23.0)

**Context**: cesauth serves HTML (`/login`, `/admin/console/*`,
`/admin/tenancy/*`, `/admin/t/*`, OAuth `/authorize` consent
pages) and JSON (`/api/v1/*`, `/oauth/token`, `/.well-known/*`).
Until v0.22.0, responses carried no security-related headers
beyond `Content-Type` and CORS. This is a real gap for an IDaaS
— the HTML surface is precisely what attackers want to clickjack
or XSS.

This ADR settles the response-header policy. Implementation
ships with this release (v0.23.0).

**A note on ADR numbering**: ADR-006 was drafted for an
"account lockout" feature in an earlier v0.23.0 attempt, then
withdrawn before the release graduated to canonical status —
the withdrawal happened because cesauth has no password
authentication path, making per-account lockout's primary
threat model inapplicable. The ADR-006 number is not reused;
this ADR is 007. The withdrawn artifact remains in the
release archive (`cesauth-0.23.0-account-lockout-withdrawn.tar.gz`)
for historical reference; see CHANGELOG for the full context.

## Q1 — Middleware vs per-route

**Question**: do handlers add security headers individually, or
does a single middleware add them to every response?

**Decision**: middleware. Per-route additions create silent
gaps — a future handler that forgets to add a header is a
regression that won't fail any test. A single
post-processor that runs against every Worker response is the
audit-friendly answer: one site to read, one site to test, no
gaps possible from omission.

## Q2 — Header set per content type

**Question**: do all responses get all headers, or are some
gated by content type?

**Decision**: split into "universal" and "HTML-only" sets.

**Universal** (every response):
- `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing.
  Defense against polyglot attacks where the same byte stream
  is interpreted differently by browser and server.
- `Referrer-Policy: strict-origin-when-cross-origin` — full URL
  to same-origin, origin only to cross-origin HTTPS, nothing
  to cross-origin HTTP. Common safe default.
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
  — 2 years (Mozilla's recommended duration). Forces HTTPS
  on subsequent visits.
- `Permissions-Policy: ...` — disables features cesauth pages
  have no business using. Specific list in §Q5.

**HTML-only** (`Content-Type: text/html`):
- `Content-Security-Policy: ...` — gated by content type
  because CSP semantics don't apply to JSON. Specific policy
  in §Q3.
- `X-Frame-Options: DENY` — prevents framing. Belt-and-
  suspenders with CSP `frame-ancestors`. Older browsers honor
  XFO before they look at CSP.

The detection looks at the response's `Content-Type` header
exactly. A response without `Content-Type` (an unusual case;
Worker handlers should always set one) gets the universal set
and is treated as non-HTML — safer default.

## Q3 — CSP shape

**Question**: report-only or enforcing? What directives?

**Decision**: **enforcing CSP, but `'unsafe-inline'` is retained
for `script-src` and `style-src` in v0.23.0** as a known
limitation of the current template architecture.

cesauth's HTML templates (in `crates/ui/src/templates.rs` as of
v0.22.0) embed CSS and JavaScript inline:

- `<style>{BASE_CSS}</style>` is inlined into every page
  (one `<style>` per page).
- `<script defer>` blocks live on the login page and
  authorize page for the WebAuthn passkey attempt and form
  validation logic.
- Cloudflare Turnstile loads externally from
  `https://challenges.cloudflare.com/turnstile/v0/api.js` on
  pages that use it.

A CSP without `'unsafe-inline'` would block these inline
blocks. Two paths exist for removing the `'unsafe-inline'`:

1. **Extract** — move CSS to an `<link rel="stylesheet">` and
   scripts to `<script src="...">`, both same-origin. This is
   a templates refactor that touches every render path.
2. **Nonces** — generate a per-request nonce, attach it to
   every inline block, and use `script-src 'nonce-XYZ'`
   instead of `'unsafe-inline'`. This is the modern best
   practice but requires (a) a nonce generator wired to
   `BASE_CSS` rendering and every inline `<script>` site,
   (b) test updates to compare against nonced output.

Either path is real refactor work — too large for v0.23.0,
which is scoped to "deploy security headers as a unified
middleware". The path forward:

- v0.23.0: keep the existing per-route CSPs verbatim (which
  contain `'unsafe-inline'` for both scripts and styles).
  The middleware adds the **other** universal headers (STS,
  Permissions-Policy, the existing X-Content-Type-Options /
  Referrer-Policy / X-Frame-Options now consolidated into
  one site).
- A later release (planned in ROADMAP) does the nonce
  migration, making the CSPs `'unsafe-inline'`-free.

The other CSP directives are unchanged from this ADR's
original draft: `default-src 'none'`, `frame-ancestors 'none'`,
`base-uri 'none'`, `connect-src 'self'`, `form-action 'self'`,
`img-src 'self' data:`. These are already in place per-route
and stay there.

**No `unsafe-eval`** in any current CSP — that one is a hard
bar. A future maintainer adding `'unsafe-eval'` to any CSP
must amend the ADR explicitly.

**WebAuthn**: `navigator.credentials.create/get` is not gated
by CSP at all (it's an internal browser API, not a fetch).
No carve-out needed.

**Magic Link callback**: the callback link arrives via email,
gets clicked, lands on cesauth's HTML page. No CSP issue —
the page is same-origin to itself.

## Q4 — STS posture

**Question**: include `preload`?

**Decision**: no, default to `max-age=63072000; includeSubDomains`.
`preload` requires registration with hstspreload.org and
commits the operator's domain to all-HTTPS for years; that's
a deployment policy decision, not a library default.

The deployment guide documents how to upgrade to `preload` if
the operator wants it. The middleware accepts an
operator-supplied STS string via `wrangler.toml` env var,
falling back to the safe default. This way, an operator who
*does* want `preload` can supply their own value without
forking cesauth.

`max-age=63072000` (2 years) matches Mozilla and Google's
current recommendations. Operators in early rollout phase
who want a shorter window can supply a smaller value via the
env var.

## Q5 — Permissions-Policy

**Question**: which features to disable?

**Decision**: disable everything cesauth pages don't use. The
list:

```
camera=(), microphone=(), geolocation=(), payment=(),
usb=(), magnetometer=(), gyroscope=(), accelerometer=(),
midi=(), serial=(), bluetooth=(),
fullscreen=(), picture-in-picture=()
```

`()` (empty allowlist) means "this feature is disabled for
this origin and all framed contexts". The list is whitelist-
by-omission for features cesauth doesn't disable — currently
none beyond what `default-src 'none'` already covers.

If a future feature needs one of these (e.g., camera for a
WebAuthn platform authenticator with face recognition — not a
thing today), the policy is updated and the directive is
re-listed with the appropriate allowlist.

## Q6 — Per-tenant override

**Question**: should tenants be able to override the policy?

**Decision**: no, deployment-wide single policy. cesauth's
HTML pages are deployment-rendered, not tenant-customizable
(a tenant doesn't get to inject CSS into the login page).
Per-tenant CSP would only be useful if cesauth supported
embedded HTML widgets in partner sites, which it does not.

If a future feature surfaces tenant-themed login pages, a
per-tenant `style-src` carve-out can be added then.

## Q7 — Operator escape hatch

**Question**: what if a deployment legitimately needs a
different policy (e.g., embedding cesauth login pages inside a
known partner frame)?

**Decision**: `wrangler.toml` env vars. Three knobs:

- `SECURITY_HEADERS_CSP` — overrides the default CSP string.
- `SECURITY_HEADERS_STS` — overrides the default STS string.
- `SECURITY_HEADERS_DISABLE_HTML_ONLY` — boolean, when true
  disables CSP and X-Frame-Options entirely. Use for debugging
  only; the deployment guide warns about this loudly.

The env vars are read at request time (cheap — Workers env
access is constant-time), not at build time, so a deployment
can change them via `wrangler secret` without redeployment.

These are operator-level decisions; the library should not
prevent legitimate use cases. The library's job is to apply
sensible defaults that 99% of deployments won't need to
touch.

## Q8 — Test surface

**Question**: how is correctness verified?

**Decision**: three layers.

1. **Unit tests for the header-construction function**
   (`apply_security_headers(response, content_type, env)`):
   pure function input-to-output, easy to exercise.
2. **Integration tests at the Worker handler level**: a small
   set of representative routes (`/login`, `/api/v1/users`,
   `/oauth/token`) get full request-response cycle tests
   asserting the headers are present in the actual Worker
   output.
3. **A regression test** that picks a route from each
   "category" (HTML, JSON, OAuth) and asserts the universal
   headers are always there. Catches future routes that bypass
   the middleware (the middleware should be unmissable, but
   the test pins the contract).

## Decision summary

| Question | Decision |
|---|---|
| Q1 — placement | Single middleware wrapping every Worker response; existing `harden_headers` is the seed |
| Q2 — header set | Universal set always; HTML-only set (X-Frame-Options) gated by `Content-Type: text/html` |
| Q3 — CSP shape | Per-route CSPs, kept as-is (with `'unsafe-inline'`); a later release does the nonce migration |
| Q4 — STS | `max-age=63072000; includeSubDomains`; `preload` is operator opt-in |
| Q5 — Permissions-Policy | Disable camera/microphone/geolocation/payment/usb/etc. |
| Q6 — per-tenant | No, single deployment-wide policy |
| Q7 — operator override | `SECURITY_HEADERS_CSP`/`STS`/`DISABLE_HTML_ONLY` env vars (CSP override applies only to routes that don't set their own) |
| Q8 — testing | Unit (pure function) + integration (route handler) + regression (category coverage) |

## Implementation notes

The middleware lives in `crates/worker/src/security_headers.rs`
as a thin wrapper around `cesauth_core::security_headers::headers_for_response`.
The pure function is in `crates/core/src/security_headers.rs`
so adapters and tests can exercise it without spinning up a
Worker.

The wrapping happens in `crates/worker/src/lib.rs`'s top-level
`fetch` handler — the existing `harden_headers` shim is replaced
by the new middleware. So even error responses (404, 500) carry
the headers. This is critical: error responses on `/login` are
still HTML, and a 5xx without `X-Frame-Options` is the
clickjacking surface we're trying to close.

**CSP middleware behavior**: the middleware looks at whether
the response already has a `Content-Security-Policy` header
set (from a per-route handler). If so, the middleware does
NOT overwrite — the route's CSP wins. If not, and the
response is HTML, the middleware applies `config.csp` (which
defaults to a strict policy without `'unsafe-inline'` —
suitable for HTML pages that don't have inline content).
This way, the existing per-route CSPs continue to apply on
the routes that need them; new HTML routes that don't need
inline content automatically get the strict default.

**Existing `harden_headers` consolidation**: as of v0.22.0,
`harden_headers` set four headers: `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy: no-referrer`, and
`Cache-Control: no-store`. The v0.23.0 middleware:

- Keeps `X-Content-Type-Options: nosniff` (universal).
- Keeps `X-Frame-Options: DENY` but gates it to HTML responses
  (the JSON API doesn't need it; X-Frame-Options on JSON is
  semantically meaningless anyway, browsers ignore it).
- Changes `Referrer-Policy` from `no-referrer` to
  `strict-origin-when-cross-origin`. The old value was
  *stricter* (zero referrer info ever); the new value sends
  origin-only on cross-origin HTTPS. The change is a
  deliberate UX vs. privacy tradeoff: external monitoring
  tools that aggregate by referrer (a deployment's own
  analytics) work better with origin-only than with
  no-referrer-at-all, and the privacy delta from
  origin-only-on-HTTPS is small.
- Drops `Cache-Control: no-store` from the universal set —
  not all responses need to be uncacheable, and routes that
  do (auth-bearing endpoints) set `Cache-Control` themselves
  already. The middleware would clobber legitimate cache
  control. Per-route handlers retain control.

A `Referrer-Policy` regression test pins the new value so a
future maintainer who sees the old comment thread doesn't
silently revert.

## Forward compatibility

When TOTP, refresh-token-rotation enforcement, or other
new HTML surfaces ship in later releases, they automatically
inherit the security headers — no per-feature work needed.

When the audit log hash chain (planned) emits HTML status
pages, those pages get the same CSP. When admin operations
v0.25.0 surfaces sessions/authenticators UIs, same.
