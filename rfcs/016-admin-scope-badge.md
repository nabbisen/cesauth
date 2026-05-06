# RFC 016: Admin scope badge — system vs tenant visible everywhere

**Status**: Ready
**ROADMAP**: External UI/UX design update v0.50.1 — page 8 ("Admin Surfaces")
**ADR**: N/A (small surface change)
**Severity**: **P2 — defense-in-depth UX; not security-critical, but reduces operator-error class**
**Estimated scope**: Small — ~40 LOC across three frame templates + ~80 LOC CSS + ~12 tests

## Background

cesauth ships three distinct admin surfaces:

- `/admin/console/*` — system-scope admin (cost & data safety, alerts, system tokens, all-tenant audit).
- `/admin/tenancy/*` — tenancy-scope console (tenant catalogue, role assignments).
- `/admin/t/<slug>/*` — tenant-scope admin (one specific tenant's users, OIDC clients, group memberships).

Each has its own page chrome
(`crates/ui/src/admin/frame.rs`,
`crates/ui/src/tenancy_console/frame.rs`,
`crates/ui/src/tenant_admin/frame.rs`).
Visually they're distinct already — the tenant
admin uses a dark-blue header, the system admin
uses lighter chrome with a role-badge — but the
distinction is **stylistic, not semantic**. There
is no shared "you are operating in scope X" badge
that an operator (or a screenshot reviewer) reads
in the same place across all three surfaces.

The error class this allows: an operator with
`Role::SystemAdmin` rolling between
`/admin/t/acme/users` and
`/admin/console/audit` may not immediately
register that the URL change is also a scope
change. A typed admin command in the wrong tab is
the result.

The UI/UX deck's page 8 calls out:
"Scope badge | system / tenant" — make scope
visible **as a first-class UI element**, not as
incidental chrome styling.

## Decision / Plan

### Surface

Every admin frame renders a `<span class="scope-badge scope-{system|tenant}">` immediately
next to the brand, before the role badge. Wire
shape:

```
[cesauth admin]  [System scope]  [System Admin · alice]   ← /admin/console/*
[cesauth admin]  [Tenancy scope] [System Admin · alice]   ← /admin/tenancy/*
[cesauth admin]  [Tenant: acme]  [Tenant Admin · alice]   ← /admin/t/acme/*
```

Three concrete scope values:

| Scope | Label EN | Label JA | Color token |
|---|---|---|---|
| System | "System scope" | "システム全体" | `--scope-system` |
| Tenancy | "Tenancy scope" | "テナント運用" | `--scope-tenancy` |
| Tenant | "Tenant: <slug>" | "テナント: <slug>" | `--scope-tenant` |

(Tenancy scope is the cross-tenant operator
console — distinct from system scope, which is
deployment-wide infrastructure. Distinct from
tenant scope, which is one specific tenant.)

### Color tokens

Add to `BASE_CSS` token block:

```css
--scope-system:  #6b3aa0;   /* purple — distinct from danger/warning/info */
--scope-tenancy: #1864ab;   /* same blue family as info */
--scope-tenant:  #1f9d55;   /* same green family as success */

/* dark mode */
--scope-system:  #c084fc;
--scope-tenancy: #60a5fa;
--scope-tenant:  #4ade80;
```

The choice of colors is **intentionally distinct
from the existing semantic tokens** (success,
warning, danger, info) so a "scope" badge can sit
next to a "danger" confirmation without color
confusion. Purple for system is the convention
because system-scope is the rarest privilege
escalation surface; tenancy is a workspace-list-
level scope (blue, navigation-coded); tenant is
the per-tenant scope (green, "scoped, the
narrowest non-trivial scope").

### Pure helper

`cesauth_core::admin::scope::ScopeBadge`:

```rust
pub enum ScopeBadge<'a> {
    System,
    Tenancy,
    Tenant(&'a str),  // slug
}

impl ScopeBadge<'_> {
    pub fn label_for(&self, locale: Locale) -> Cow<'static, str> {
        // delegates to MessageKey
    }
    pub fn css_class(&self) -> &'static str {
        match self {
            Self::System  => "scope-badge scope-system",
            Self::Tenancy => "scope-badge scope-tenancy",
            Self::Tenant(_) => "scope-badge scope-tenant",
        }
    }
}
```

Three `MessageKey` variants:
`AdminScopeSystem`, `AdminScopeTenancy`,
`AdminScopeTenant` (the tenant variant takes the
slug as a `{slug}` substitution, similar to the
existing v0.45.0 `{n}` substitution pattern in
flash messages).

### Frame integration

Each of the three admin frame functions takes a
`scope: ScopeBadge` parameter (default
`ScopeBadge::System` for the existing
`admin_frame`, `ScopeBadge::Tenancy` for
`tenancy_frame`, and `ScopeBadge::Tenant(slug)`
for `tenant_admin_frame`). The emit is a single
`<span class="...">{label}</span>` next to brand.

`<header class="site">` becomes:

```html
<header class="site">
  <span class="brand">cesauth admin</span>
  <span class="scope-badge {scope_class}" aria-label="Operating scope: {scope_aria}">{scope_label}</span>
  <span class="role-badge {role_badge}" aria-label="Current admin role: {role_label}">{role_label}{name_suffix}</span>
</header>
```

`aria-label` carries the full "Operating scope:
..." prose so screen readers get the full
context, not just "Tenant: acme".

### Acceptance — screenshot test

Existing `crates/ui/src/admin/tests.rs`,
`tenancy_console/tests.rs`, `tenant_admin/tests.rs`
each gain three tests:

1. `frame_renders_scope_badge_with_correct_class` — pin the CSS class.
2. `scope_badge_label_localizes` — pin EN + JA.
3. `scope_badge_aria_label_carries_full_prose` — pin a11y.

Plus one shared test:

4. `tenant_scope_badge_shows_slug` — pin the substitution.

## Open questions

**Should the scope badge clickable to switch
scope?** No. Scope is determined by the URL
prefix (`/admin/console/`, `/admin/tenancy/`,
`/admin/t/<slug>/`); making the badge
interactive duplicates URL navigation. Screen
readers already get the URL via standard
navigation. Skip.

**Should the role badge be removed in favor of
just the scope badge?** No. Role and scope are
orthogonal: a System Admin operating in
`/admin/t/acme` is a real operator role still
helpful to display (they retain system-admin
privileges by virtue of role). Both badges stay.

## Notes for the implementer

- This is a **chrome change**, not a behavior
  change. Routes and policies are unchanged. The
  only thing that changes is what the operator
  sees in the page header.
- Coordinate with RFC 015 (request traceability):
  the request_id appears in operator logs; the
  scope badge appears in the operator's UI. Both
  are "make ambient context visible" patterns.
  No code coupling, just consistent design
  intent.
- The color token additions go in `BASE_CSS` —
  the same shared CSS block where the v0.31.0
  `--success`/`--warning`/`--danger`/`--info`
  tokens live. Don't fork into a per-frame CSS.
- Add a small entry to `docs/src/expert/development.md` (the
  dev directive): when adding a new admin route,
  the route handler MUST pass an explicit
  `ScopeBadge` to the frame. A grep test under
  RFC 012's drift-scan catches missing scope
  arguments at PR time.
