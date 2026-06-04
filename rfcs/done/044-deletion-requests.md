# RFC 044 — User deletion requests (GDPR / account deletion)

**Status**: Implemented  
**Priority**: P1 (SaaS guide §4.4: required for GDPR Article 17 "right to erasure")  
**Size**: Medium (~150 LOC core + 80 LOC migration + 100 LOC worker)  
**Depends on**: RFC 021 (ON DELETE CASCADE), RFC 020

## Problem

Users have no self-service way to request account deletion. GDPR Article 17
("right to erasure") requires that users can request deletion and receive
confirmation. Operators need a review queue before data is physically deleted.

RFC 021's `ON DELETE CASCADE` on `users(id)` means physical deletion is safe
at the DB level, but the business flow (request → review → execute → confirm)
is missing.

## Decision

Add `deletion_requests` table + two-stage deletion flow:

### Schema (migration 0019)
```sql
CREATE TABLE deletion_requests (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id),
    tenant_id    TEXT NOT NULL REFERENCES tenants(id),
    requested_at INTEGER NOT NULL,
    requested_by TEXT NOT NULL,        -- user_id (self) or admin_id
    reason       TEXT,
    scheduled_at INTEGER NOT NULL,     -- requested_at + grace_period (default 30d)
    executed_at  INTEGER,
    executed_by  TEXT,
    cancelled_at INTEGER,
    cancelled_by TEXT,
    status       TEXT NOT NULL CHECK (status IN ('pending','executed','cancelled'))
                 DEFAULT 'pending'
);
CREATE INDEX idx_deletion_requests_pending
    ON deletion_requests(scheduled_at)
    WHERE status = 'pending';
```

### Core service
- `schedule_deletion(user_id, tenant_id, requested_by, grace_secs, now)` → `DeletionRequest`
- `execute_deletion(request_id, executed_by, now, user_repo)` — calls `user_repo.delete_by_id`
- `cancel_deletion(request_id, cancelled_by, now)` → update status
- Cron: `sweep_pending_deletions(now)` — executes past `scheduled_at` requests

### Wire
- `POST /me/security/delete-account` — user self-service request (grace 30d)
- `GET /admin/t/:slug/deletion-requests` — tenant admin queue
- `POST /admin/t/:slug/deletion-requests/:id/execute` — immediate admin-triggered delete
- `POST /admin/t/:slug/deletion-requests/:id/cancel`

### Audit
- `DeletionRequested`, `DeletionExecuted`, `DeletionCancelled` EventKind
