# RFC 052 — Authorization service hardening

**Status**: Implemented  
**Priority**: P1 (SaaS guide §6.6 — "権限判定の一元化")  
**Size**: Medium

The current authz module has PermissionCatalog and role/permission definitions but lacks:
- A `check_permission(user_id, tenant_id, action)` pure service function
- Tests covering cross-tenant rejection, role inheritance, system_admin superset invariant
- Role-assignment validation (scope enforcement at service layer)
