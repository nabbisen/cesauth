# RFC 102 — UI route path centralization

**Status**: Implemented | **Tier**: Refactoring | **Size**: Small-Medium | **Target**: v0.66.0

## Problem

**202 hardcoded route paths** appear as string literals in `crates/ui/src/`:

```
7  "/admin/.../users/{uid}/role_assignments"
7  "/admin/.../tenants/{tid}"
6  "/me/.../totp/disable"
6  "/admin/.../tokens"
5  "/admin/.../{tslug}/organizations/{oid}"
5  "/admin/.../tenants/{}"
5  "/admin/.../tenants/new"
5  "/admin/.../tenants"
4  "/me/.../totp/enroll"
... (192 more)
```

When a route is renamed in `crates/worker/src/lib.rs`, the corresponding form
`action="..."` and link `href="..."` strings in UI templates **do not get
automatically updated**. The route-contracts.md script catches some of these
(it parses `lib.rs` and verifies docs), but it does not verify UI link
correctness.

Today's coupling structure:

```
crates/worker/src/lib.rs   ← route table (source of truth)
crates/ui/src/templates.rs ← hardcoded paths   (consumer #1)
crates/ui/src/admin/*.rs   ← hardcoded paths   (consumer #2)
crates/ui/src/tenant_admin/*.rs ← hardcoded paths (consumer #3)
docs/src/expert/route-contracts.md ← docs       (consumer #4)
```

When you rename `/admin/console/audit` → `/admin/console/audit-events`, you
must edit `lib.rs`, ~6 UI files, and `route-contracts.md`. Three of those
won't fail compilation if you forget.

## Proposed solution

Create `crates/core/src/routes.rs` — a const path catalog:

```rust
//! Centralized URL path constants — single source of truth.
//!
//! Worker route registration in `crates/worker/src/lib.rs` and
//! UI form `action=` / link `href=` strings both reference these
//! constants. Renaming a route is now a single-line change.

/// Admin console — security-headed operator surface.
pub mod admin {
    pub const OVERVIEW:    &str = "/admin/console";
    pub const COST:        &str = "/admin/console/cost";
    pub const SAFETY:      &str = "/admin/console/safety";
    pub const AUDIT:       &str = "/admin/console/audit";
    pub const AUDIT_EXPORT:&str = "/admin/console/audit/export";
    pub const AUDIT_CHAIN: &str = "/admin/console/audit/chain";
    pub const CONFIG:      &str = "/admin/console/config";
    pub const ALERTS:      &str = "/admin/console/alerts";
    pub const TOKENS:      &str = "/admin/console/tokens";
    pub const OPERATIONS:  &str = "/admin/console/operations";
}

/// End-user self-service surface.
pub mod me {
    pub const SECURITY:        &str = "/me/security";
    pub const SECURITY_SESSIONS: &str = "/me/security/sessions";
    pub const TOTP_ENROLL:     &str = "/me/security/totp/enroll";
    pub const TOTP_VERIFY:     &str = "/me/security/totp/verify";
    pub const TOTP_DISABLE:    &str = "/me/security/totp/disable";
    pub const TOTP_RECOVER:    &str = "/me/security/totp/recover";
}

/// Routes that include path parameters; functions return the
/// rendered string. Use these instead of `format!("/admin/t/{slug}")`.
pub fn admin_tenant_overview(slug: &str) -> String {
    format!("/admin/t/{slug}")
}
pub fn admin_tenant_organizations(slug: &str) -> String {
    format!("/admin/t/{slug}/organizations")
}
// ... etc
```

### Migration strategy

1. **Phase 1** — Define the catalog. No behavior change.
2. **Phase 2** — Worker `lib.rs` switches to using `routes::admin::AUDIT`
   constants in the route table.
3. **Phase 3** — UI templates switch incrementally; one surface
   (admin / tenant_admin / tenancy_console / me) per commit.
4. **Phase 4** — Add a compile-time guard: `route-contracts-check.sh` parses
   `routes.rs` instead of `lib.rs`.

## Acceptance

- `crates/core/src/routes.rs` exists with all 165 route paths as constants
  (static paths) or functions (parameterized paths).
- `crates/worker/src/lib.rs` route table uses the constants.
- All UI files that previously hardcoded paths use the constants/functions.
- A rename of `routes::admin::AUDIT` produces compile errors at every consumer.

## Risk

- Parameterized routes require `format!()` calls, which allocate. For form
  `action=` attributes this is acceptable (one allocation per render); for
  hot-path routes it might matter. Profiling will tell.
- The exception list (genuinely external URLs like `https://...`) should
  be limited and clearly marked.

## Out of scope

- JS-side route construction (none in this codebase as of v0.65.0).
- Reverse routing from URL → handler (Rust doesn't have a need for this).
