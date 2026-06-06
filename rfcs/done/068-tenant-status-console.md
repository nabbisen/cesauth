# RFC 068 — Tenancy console: tenant suspend/restore

**Status**: Implemented  
**Size**: Medium

Expose `suspend_tenant` / `restore_tenant` from the tenancy console.
Routes: POST /admin/tenancy/tenants/:id/suspend and /restore.
This completes §16.8: "テナント単位での停止・復帰が可能である".
