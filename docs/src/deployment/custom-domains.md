# Custom domains & DNS

cesauth issues OAuth/OIDC tokens whose `iss` claim must exactly
match the URL clients use to reach the service. That puts the
custom-domain configuration on the critical path for production:
get this wrong and every token cesauth issues will fail
validation at the relying party.

This chapter covers the Cloudflare-side wiring. DNS-side and
cert-side advice is generic; the cesauth-specific bits are the
`ISSUER` consistency rule, the WebAuthn origin coupling, and the
"Custom Domain vs Route" decision.

## Custom Domain vs Route — pick Custom Domain

Cloudflare offers two ways to attach a hostname to a Worker:

- **Workers Routes** (`example.com/*` → Worker) — the legacy
  pattern. Routes share TLS with the underlying zone and don't
  add a hostname-level identity to the Worker.
- **Custom Domains** (the Worker "owns" `auth.example.com`) —
  the modern pattern. The Worker is the origin for that
  hostname; Cloudflare manages the edge cert directly attached
  to the Worker, not to a zone-level proxy.

**Use Custom Domains for cesauth.** The reasons:

1. **Clean origin separation.** WebAuthn's RP ID and origin
   checks are strict. With Routes, the Worker shares an origin
   with whatever else lives on the zone; a passkey registered
   for `example.com` will not authenticate at `auth.example.com`,
   and vice versa. Custom Domains let cesauth be the sole
   resident of `auth.example.com`.
2. **Cert lifecycle is independent.** The cert for the cesauth
   custom domain is provisioned, renewed, and revoked
   independently of the zone's other certs. If you need to
   rotate cesauth's cert (or the zone's TLS configuration
   changes for unrelated reasons), the blast radius is bounded.
3. **`ISSUER` matching is mechanical.** The custom domain IS
   `auth.example.com`. There's no "Route pattern + zone +
   subpath" arithmetic to get wrong. Whatever you put in
   `ISSUER` matches the dashboard.
4. **Wrangler tooling treats Custom Domains as first-class.**
   `wrangler deploy` shows the bound custom domains; the
   dashboard groups invocations by the domain that received
   the request.

## Configuration

### Step 1 — Reserve the hostname in DNS

In Cloudflare DNS for the zone `example.com`:

```
Type    Name    Content              Proxy   TTL
CNAME   auth    auth.example.com     Proxied Auto
```

The CNAME target can be any value Cloudflare can resolve to its
edge — `auth.example.com` itself is fine; the proxy makes the
record functional. The orange-cloud (proxied) status is
**required** — Custom Domains do not work on grey-cloud
records.

### Step 2 — Attach the Custom Domain

Cloudflare dashboard → Workers & Pages → cesauth → **Triggers**
→ scroll to **Custom Domains** (NOT **Routes**) → Add Custom
Domain → enter `auth.example.com`.

Cloudflare provisions an edge certificate for the hostname
within ~1–5 minutes. Until provisioning completes, the
hostname returns a TLS error. Verify with:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' https://auth.example.com/
```

A `404` is correct (cesauth has no `/` route); a TLS error means
the cert is still provisioning or DNS hasn't propagated.

### Step 3 — Set `ISSUER` to match

In `wrangler.toml`:

```toml
[vars]
ISSUER = "https://auth.example.com"
```

The `ISSUER` value:

- **Must include the scheme** (`https://`).
- **Must NOT have a trailing slash.** OIDC discovery doc
  consumers vary on trailing-slash tolerance; the `iss` claim
  is byte-equal compared by every client we know of.
- **Must NOT include a path.** cesauth roots its routes at `/`;
  serving cesauth at `auth.example.com/auth` is technically
  possible but breaks WebAuthn's origin checks and is not
  supported.

Then `wrangler deploy`.

### Step 4 — Set WebAuthn-related vars consistently

```toml
WEBAUTHN_RP_ID     = "auth.example.com"
WEBAUTHN_RP_NAME   = "cesauth"        # cosmetic, shown to users
WEBAUTHN_RP_ORIGIN = "https://auth.example.com"
```

`WEBAUTHN_RP_ID` is the **registrable domain** (no scheme, no
port, no path) at which passkeys are bound. `WEBAUTHN_RP_ORIGIN`
is the full origin of pages that perform WebAuthn ceremonies.
For cesauth they're the same hostname.

If cesauth is served at `auth.example.com` but you want
passkeys to also work at `example.com`, set `WEBAUTHN_RP_ID =
"example.com"` (the parent registrable domain). This is the
only legal RP ID relaxation; every other variation breaks
authenticator compatibility.

### Step 5 — Verify

```sh
# Discovery doc resolves and `issuer` matches.
curl -sS https://auth.example.com/.well-known/openid-configuration \
  | jq -r .issuer
# -> https://auth.example.com  (exactly)

# JWKS reachable.
curl -sS https://auth.example.com/jwks.json | jq -r '.keys[].kid'
# -> the kid from $JWT_KID in [vars]

# Issued tokens have iss = ISSUER.
# (Run an /authorize → /token round trip and decode the access_token.)
```

## Common mistakes

### `ISSUER` set to the workers.dev hostname

When you `wrangler deploy` without a Custom Domain, Cloudflare
gives the Worker a `cesauth.<account>.workers.dev` URL. It works
for ad-hoc testing, but if you set `ISSUER` to that URL, every
client validates `iss` against the workers.dev hostname, and
later attaching a Custom Domain makes every issued token fail
validation overnight.

**Production deploy: set `ISSUER` to the Custom Domain BEFORE
shipping clients.** The transition path from a workers.dev
issuer to a custom-domain issuer is tedious — you need to
double-publish JWKS at both URLs through a grace window.

### Trailing slash in `ISSUER`

`https://auth.example.com/` and `https://auth.example.com` are
not the same value to most JWT libraries. Pick one (cesauth
uses no trailing slash, matching most OIDC providers) and stay
consistent.

### Custom Domain attached, but DNS still grey-cloud

The Custom Domain configuration shows green and the cert is
provisioned, but actual requests bypass Cloudflare and hit
nothing. Re-check the DNS row's proxy status — must be orange
cloud (proxied).

### `WEBAUTHN_RP_ORIGIN` mismatched with `ISSUER`

`ISSUER = https://auth.example.com` but
`WEBAUTHN_RP_ORIGIN = https://example.com`. Token issuance
works; passkey registration fails with origin-mismatch errors.
Keep them aligned.

## Multi-tenant DNS

Multi-tenant cesauth deployments may want per-tenant subdomains
(e.g. `acme.auth.example.com`). cesauth as of 0.5.x serves a
**single hostname per Worker** — multi-tenancy is in the URL
path (`/admin/t/<slug>/*`) and the JWT `tenant_id` claim, not
in DNS.

If you genuinely need DNS-level isolation per tenant, the
options are:

1. **One Worker per tenant.** Each tenant gets its own
   `wrangler.toml`, its own Worker name, its own Custom Domain.
   D1 / R2 are sharded per Worker. Heavy operationally; only
   reasonable for very small N.
2. **Wildcard Custom Domain + path-level dispatch.** Put
   `*.auth.example.com` on one Worker and dispatch on the
   `Host` header at request time. cesauth doesn't ship this
   today; the route handlers expect a fixed `ISSUER`. If you
   want this, file a feature request.
3. **CNAME the tenant's own domain to the cesauth Worker.**
   `auth.acme.com → cesauth.<account>.workers.dev`. The
   tenant's cert goes through Cloudflare for SaaS (a separate
   product). Out of scope for this chapter.

## DNS records cesauth doesn't need

- **MX** — cesauth doesn't receive mail. The Magic Link
  delivery path is outbound only.
- **TXT for SPF/DKIM/DMARC** — your mail provider handles
  these; cesauth doesn't.
- **CAA** — Cloudflare's Universal SSL handles its own CAA
  validation. If you set CAA on the zone, allow Cloudflare's
  issuing CAs (`letsencrypt.org`, `digicert.com`, depending on
  your account tier).

## See also

- [Pre-flight checklist § G](./preflight.md#g---custom-domain--tls)
- [WebAuthn implementation](../expert/webauthn.md) — the RP ID
  and origin requirements at the protocol level.
- Cloudflare docs: *Workers → Configuration → Triggers →
  Custom Domains*.
