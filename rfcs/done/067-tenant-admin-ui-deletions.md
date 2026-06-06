# RFC 067 — Tenant admin UI: deletion requests page

**Status**: Implemented  
**Size**: Medium

Add `deletion_requests_page(principal, tenant, requests)` to
`cesauth-ui::tenant_admin`. Shows pending deletions with cancel/execute actions.
Also add self-service "Delete my account" section to /me/security page.
