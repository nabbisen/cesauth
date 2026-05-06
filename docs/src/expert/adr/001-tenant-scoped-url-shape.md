# ADR-001: URL shape for the tenant-scoped admin surface

**Status**: Accepted (v0.11.0)
**Decision**: Path-based: `/admin/t/<slug>/...`
**Rejected**: Subdomain-based (`<slug>.cesauth.example`)

## Context

The v0.8.0-0.10.0 SaaS console at `/admin/saas/*` serves the cesauth
deployment's operator staff — one console, every tenant. v0.12.0+
introduces a *tenant-scoped* admin surface where tenant admins
administer their own tenant rather than every tenant. The surface
is reachable from a tenant-side login, gated through user-as-bearer
plus `check_permission`, and filtered to the caller's tenant.

Where this surface lives in URL space is the question. Two
alternatives:

1. **Path-based**: `/admin/t/<slug>/...` (e.g.,
   `/admin/t/acme/organizations`). One domain, one cert, one cookie
   jar. Tenant identity is encoded in the URL.

2. **Subdomain-based**: `<slug>.cesauth.example/admin/...` (e.g.,
   `acme.cesauth.example/admin/organizations`). Each tenant gets
   what looks like its own deployment.

## Decision

Path-based: `/admin/t/<slug>/...`.

## Consequences

### What this gives us

- **Single cert, single domain.** No wildcard cert provisioning,
  no per-tenant DNS records, no Cloudflare Workers custom-domain
  configuration that scales with tenant count. Subdomain at scale
  on Cloudflare requires either a wildcard cert (which Cloudflare
  Workers handles, but introduces operational coupling — a cert
  rotation issue affects every tenant simultaneously) or
  per-tenant Custom Hostnames (which has setup-and-quota friction
  per tenant).
- **Same-origin everything.** Cookies, fetch, redirects all behave
  the same as the existing `/admin/saas/*`. ADR-002 picks
  `Authorization`-bearer auth which is origin-scoped; keeping one
  origin keeps the auth model simple.
- **Tenant identity is visible.** A path-based URL like
  `/admin/t/acme/users` is unambiguous — there's no question of
  whether the caller's session is the right tenant. Subdomain-
  based would have looked like a normal browser session against a
  different "site" but is actually the same Worker; the indirection
  is more confusing than helpful.
- **Routing is straightforward.** The Worker matches `/admin/t/:slug`
  as a path pattern. With subdomains, the router would need to
  inspect the `Host` header *and* match a path; introducing two
  resolution surfaces multiplies the failure modes.

### What this costs us

- **The URL doesn't feel like "their own deployment."** A tenant
  admin looking at `/admin/t/acme/users` sees `cesauth.example`
  in the address bar. For a B2B IDaaS this is fine — the platform
  brand IS the brand. For a white-label situation it would not be
  fine; cesauth is not currently positioned as white-label.
- **Tenant slug is in the URL space forever.** Renaming a tenant
  slug breaks bookmarks. Slugs are already `UNIQUE` in the
  schema (v0.5.0) and the `tenants.slug` column is documented as
  immutable; this just makes the immutability promise more
  visible.

### What we explicitly didn't decide

- Whether we'll *also* expose subdomains as an alternate path in
  the future (e.g., for white-label customers). That's a
  not-now decision; the path-based URL doesn't preclude it.
- Whether `<slug>` is the tenant slug or the tenant id. We pick
  the slug because it's the operator-visible identifier and
  matches how `/admin/saas/tenants/:tid` already works (`:tid` is
  the id, but the user types the slug). The 0.12.0 router resolves
  slug → id at request time.

## Alternatives considered

### Subdomain (`<slug>.cesauth.example/admin/...`)

Rejected primarily for the operational cost. Cloudflare Workers
*can* handle wildcard subdomains via Custom Hostnames, but each
hostname is a separate config record. The benefit (own-deployment
feel) doesn't justify the cost for a B2B IDaaS at this stage.

The "feels like own deployment" benefit does become real for
white-label customers — but we don't have white-label customers
yet, and this ADR doesn't preclude introducing subdomain support
later as an *additional* path for those customers specifically.

### Per-tenant query string (`/admin/t?slug=acme`)

Not considered seriously. Query strings are awkward for routing,
break the "URL identifies the resource" expectation, and would
fight with the existing `?user_id=` query string used elsewhere.

## See also

- ADR-002: User-as-bearer mechanism (depends on this URL choice)
- ADR-003: System-admin from inside the tenant view (depends on
  this URL choice)
