# RFC 034 — /introspect handler wired to find_auth_view

**Status**: Implemented  
**Priority**: P1 (RFC 026 hot path not connected)  
**Size**: Small (~40 LOC change)  
**Depends on**: RFC 026 (already merged)

## Problem

RFC 026 added `ClientAuthView`, `find_auth_view`, and
`check_client_credentials_from_view` to core and both adapters. However
`worker/src/routes/oidc/introspect.rs` still uses the old two-read pattern:

1. `verify_client_credentials(&clients, ...)` → D1 read #1
2. `clients.find(...)` → D1 read #2

The TOCTOU window and extra D1 read remain in production.

## Decision

Replace the two-read pattern with:

```rust
let view = clients.find_auth_view(&creds.client_id).await
    .map_err(|_| oauth_error_response("server_error", ...))?
    .ok_or_else(|| oauth_error_response("invalid_client", ...))?;

let outcome = check_client_credentials_from_view(&view, &creds.client_secret);
// ... gate on outcome ...

let audience = view.audience.as_deref();
// use audience for aud gate
```

Single D1 read. TOCTOU window closed.
