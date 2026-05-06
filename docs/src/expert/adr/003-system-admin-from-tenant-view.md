# ADR-003: System-admin operations from inside the tenant view

**Status**: Accepted (v0.11.0)
**Decision**: Complete URL-prefix separation — no in-page mode
switch. `/admin/saas/*` is system-admin; `/admin/t/<slug>/*` is
tenant-admin; the two surfaces never interleave.
**Rejected**: In-page "switch to operator mode" affordance with
re-authentication.

## Context

The v0.12.0+ tenant-scoped admin surface needs to handle the
case where a system-admin (the cesauth deployment's operator
staff) is administering a tenant. Two natural ways to express
this:

1. **A "switch mode" affordance.** While inside the tenant-
   scoped view (`/admin/t/acme/...`), a system-admin sees a
   button that says "Switch to operator mode" or "View as
   operator." Clicking it elevates them — possibly with a
   re-authentication prompt — and grants access to system-
   level operations on this tenant (e.g., suspend the whole
   tenant, change its plan, change its status) without leaving
   the page.
2. **Complete URL-prefix separation.** `/admin/saas/*` is the
   system-admin surface (everything cesauth has built since
   v0.8.0). `/admin/t/<slug>/*` is the tenant-admin surface.
   No mode switch. To do system-admin work, you visit
   `/admin/saas/...`. Done.

## Decision

Option 2: complete URL-prefix separation.

A system-admin who wants to administer a tenant has two clear
choices:

- Use the system-admin console at `/admin/saas/tenants/:tid` —
  the existing v0.8.0-0.10.0 surface. Has access to every
  tenant via the existing role-gate.
- Use the tenant-admin console at `/admin/t/<slug>/...` *as that
  tenant's admin* — which requires a user-as-bearer token whose
  `users.tenant_id` matches the tenant.

These surfaces share no code paths, no view components, and no
URL prefix. They are physically separate.

## Consequences

### What this gives us

- **Tenant-boundary leakage is structurally impossible.** A bug
  that accidentally renders cross-tenant data in the tenant-
  admin view *cannot* expose system-level views, because there
  is no view-layer code that conditions on "what mode am I in?"
  Each route has one purpose. Reviewers can verify
  `/admin/t/<slug>/...` handlers without needing to know the
  state of any "mode" flag.

- **Auth model stays simple.** ADR-002's `AdminPrincipal`
  carries `user_id: Option<String>`. The system-admin surface
  ignores `user_id`; the tenant-admin surface requires it
  *and* requires it to match the URL slug. There's no third
  state ("user-as-bearer but escalated"), no additional flags
  on the principal, no re-auth grace window to track.

- **Audit trails are unambiguous.** The audit log already
  includes the actor's `principal.id`. Adding a "via=tenant-
  admin-console" marker (paralleling the existing "via=saas-
  console" from v0.9.0) gives clean post-hoc separation: which
  surface was used to perform the action. With a mode switch,
  the same `principal.id` would alternate between meanings
  depending on a transient flag we'd have to capture in audit.

- **Routing is straightforward.** `/admin/saas/*` and
  `/admin/t/:slug/*` are distinct path patterns. The router
  matches them independently. No ambiguity, no precedence
  rules.

### What this costs us

- **The system-admin who wants to suspend a tenant has to
  navigate to a different URL.** From inside `/admin/t/acme/`,
  the link to "suspend this tenant" leads them out to
  `/admin/saas/tenants/:tid/status`. This is one extra click
  (or one bookmark, or one terminal tab). Not a real cost.

- **No future evolution for an "embedded operator banner."**
  If we later decide we *want* a "you are administering
  tenant X as system-admin Y" indicator inside the tenant
  view, we'd need to revisit this decision. The cost of doing
  so is low — we'd replace the URL-prefix split with a guarded
  mode flag — but it would be a real revision, not a layered
  addition.

- **A user with both system and tenant roles needs two
  tokens.** A cesauth employee who is also a tenant member
  (which is unlikely but possible — e.g., dogfooding) would
  use their system token at `/admin/saas/*` and a separate
  user-as-bearer token at `/admin/t/<their-tenant>/*`. We
  expect this to be rare; the alternative (one token, two
  surfaces) introduces the leak risk we're avoiding.

### What we explicitly didn't decide

- **Whether `/admin/saas/*` will ever be reachable by a
  user-as-bearer principal.** Answer in spirit: no. A user-
  bearer-token's `role` is whatever was issued, but the
  `/admin/saas/*` surface checks `AdminAction::ManageTenancy`
  *and* doesn't read `user_id` — so a tenant admin with a
  user-bearer token and `Operations` role would technically
  pass the role check. Whether the resolution layer should
  *additionally* refuse user-bearer tokens on `/admin/saas/*`
  is a 0.12.0 implementation detail. Conservatively, yes —
  user-bearer tokens are scoped to their tenant view.
- **How tenant admins discover system-admin contact.** A
  tenant admin who needs system intervention has to email/
  ticket the cesauth operator team out-of-band. We don't
  build a "request system intervention" affordance. Not a
  product cesauth wants to grow into right now.

## Alternatives considered

### Mode switch with re-authentication (rejected)

The strongest case for this is operator ergonomics: looking at
a tenant's organizations list and noticing something wrong, the
operator wants to fix it without leaving the page. Asking them
to navigate elsewhere feels backwards.

We rejected it because:

1. The complexity isn't local to the UI. A mode flag on the
   principal means every route handler that touches tenancy
   data has to think about which mode it's in. That's the
   exact failure mode this ADR is trying to prevent.
2. The "ergonomic" win is small for cesauth's actual operator
   workflow. System-admin work happens in batches, not in the
   middle of a tenant-admin session.
3. Re-auth prompts in the middle of a flow are themselves a
   security smell — operators learn to click through them, and
   then a real elevation prompt looks the same as a routine
   re-auth.

### Single console with role-conditional rendering (rejected)

Don't separate the surfaces at all — render
`/admin/saas/tenants/:tid` for everyone, and conditionally
render mutation buttons based on whether the caller is
system-admin or tenant-admin.

We rejected it because:

1. It requires every read page to think about "is this caller a
   system-admin or a tenant-admin?" That's not the model the
   v0.8.0-0.10.0 console was built around — its pages assume
   "every tenant is visible." Retrofitting tenant filtering
   throughout would be a large code change for marginal
   benefit.
2. A bug in the conditional-rendering logic leaks cross-tenant
   data. URL-prefix separation makes such bugs structurally
   impossible.

## Operational implication

The system-admin onboarding doc (currently
`docs/src/expert/tenancy.md`) gets a brief note:

> System-admins administering a tenant continue to use
> `/admin/saas/*`. The tenant-scoped console at
> `/admin/t/<slug>/*` is *not* an alternative entry point for
> them — it's the surface tenant-admins use. The two consoles
> never interleave.

This deters the natural assumption that a v0.12.0 tenant-admin
console would replace, or be a more powerful version of, the
v0.8.0-0.10.0 system-admin console.

## See also

- ADR-001: URL shape — establishes the path-prefix split this
  ADR depends on
- ADR-002: User-as-bearer mechanism — defines the
  `AdminPrincipal::user_id` that this ADR uses to decide
  surface access
