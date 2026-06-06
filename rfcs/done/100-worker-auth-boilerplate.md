# RFC 100 — Worker route auth boilerplate consolidation

**Status**: Implemented | **Tier**: Refactoring | **Size**: Small | **Target**: v0.66.0

## Problem

**59 worker route handlers** start with the exact same 5-line preamble:

```rust
pub async fn handler<D>(req: Request, ctx: RouteContext<D>) -> worker::Result<Response> {
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, AdminAction::ViewConsole) {
        return Ok(r);
    }
    // ...actual handler logic
}
```

Some 67 route handlers additionally have the tenant-admin variant
(`tenant_admin_gate::resolve_or_respond` + `check_action`).

This boilerplate is uniform across the codebase, doesn't carry meaningful
variation per route, and visually crowds the actual route logic. New routes
copy-paste it and occasionally drift (e.g. using `ensure_role_allows` for an
action that should use `check_action`).

## Proposed solution

### Option A — declarative macros (preferred)

Add `crates/worker/src/auth/macros.rs`:

```rust
/// Resolves principal + enforces system-admin action. Returns
/// `Result<(AdminPrincipal, RouteContext<D>)>` for the handler body
/// to destructure.
///
/// Usage:
/// ```ignore
/// pub async fn list_tokens<D>(req: Request, ctx: RouteContext<D>) -> worker::Result<Response> {
///     let (principal, ctx) = require_system_admin!(req, ctx, AdminAction::ViewConsole);
///     // ... rest of handler
/// }
/// ```
macro_rules! require_system_admin {
    ($req:expr, $ctx:expr, $action:expr) => {{
        let principal = match crate::routes::admin::auth::resolve_or_respond(&$req, &$ctx.env).await? {
            Ok(p)  => p,
            Err(r) => return Ok(r),
        };
        if let Err(r) = crate::routes::admin::auth::ensure_role_allows(&principal, $action) {
            return Ok(r);
        }
        (principal, $ctx)
    }};
}

macro_rules! require_tenant_admin {
    ($req:expr, $ctx:expr, $permission:expr) => {{
        let principal = match crate::routes::admin::auth::resolve_or_respond(&$req, &$ctx.env).await? {
            Ok(p)  => p,
            Err(r) => return Ok(r),
        };
        let ctx_ta = match crate::routes::admin::tenant_admin::gate::resolve_or_respond(principal, &$ctx).await? {
            Ok(c)  => c,
            Err(r) => return Ok(r),
        };
        if let Err(r) = crate::routes::admin::tenant_admin::gate::check_read(&ctx_ta, $permission, &$ctx).await? {
            return Ok(r);
        }
        (ctx_ta, $ctx)
    }};
}
```

### Option B — functional combinator

```rust
pub async fn with_system_admin<D, F, Fut>(
    req: Request,
    ctx: RouteContext<D>,
    action: AdminAction,
    body: F,
) -> worker::Result<Response>
where
    F: FnOnce(AdminPrincipal, RouteContext<D>) -> Fut,
    Fut: std::future::Future<Output = worker::Result<Response>>,
{
    let principal = match auth::resolve_or_respond(&req, &ctx.env).await? {
        Ok(p)  => p,
        Err(r) => return Ok(r),
    };
    if let Err(r) = auth::ensure_role_allows(&principal, action) {
        return Ok(r);
    }
    body(principal, ctx).await
}
```

Macros are preferred because they preserve the per-route compiler diagnostics
(macro_rules expansion stays in the source span) and avoid the lifetime
gymnastics of async closures.

## Migration plan

Implement macros in **one commit**. Migrate existing routes **incrementally**
(one PR per route directory: `admin/console/`, `admin/tenant_admin/`,
`admin/tenancy_console/`, etc.) so the change is reviewable.

## Acceptance

- 59 handlers (system-admin variant) and 67 handlers (tenant-admin variant)
  switch to the macros.
- Average handler line count drops by ~5 lines.
- Test suite still passes.
- New routes added after this RFC use the macros.

## Risk

Macros that expand to `return` statements have a subtle gotcha: they only work
inside functions that return `worker::Result<Response>`. This is documented in
the macro's rustdoc; the compiler error if misused is clear ("return outside of
function" or "mismatched types").
