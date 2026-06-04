-- ----------------------------------------------------------------------------
-- 0019_deletion_requests.sql
-- ----------------------------------------------------------------------------
-- RFC 044: User deletion request queue for GDPR Article 17 "right to erasure".
--
-- Flow:
--   1. User (self) or admin submits a deletion request → status = 'pending'.
--   2. The cron sweep checks for requests where scheduled_at <= now
--      and executes them (calls DELETE on users; ON DELETE CASCADE from
--      RFC 021 cleans all related rows).
--   3. Admin can cancel a pending request before scheduled_at.
--
-- Grace period: configurable (default 30 days), gives the operator time
-- to hold for legal/compliance review before physical deletion.
--
-- Note: physical deletion is irreversible. The row in deletion_requests
-- is preserved as an audit trail even after execution (executed_at is set).
-- The user row and all FK-cascaded data are gone; the deletion_request row
-- itself remains for compliance evidence.
-- ----------------------------------------------------------------------------

CREATE TABLE deletion_requests (
    id              TEXT    PRIMARY KEY,              -- UUID v4
    user_id         TEXT    NOT NULL,                 -- NOT REFERENCES users(id): user will be deleted
    tenant_id       TEXT    NOT NULL REFERENCES tenants(id),
    requested_at    INTEGER NOT NULL,
    requested_by    TEXT    NOT NULL,                 -- user_id (self) or admin user_id
    reason          TEXT,                             -- optional operator/user note
    scheduled_at    INTEGER NOT NULL,                 -- physical delete happens at/after this time
    executed_at     INTEGER,                          -- NULL until sweep runs
    executed_by     TEXT,                             -- sweep worker id or admin user_id
    cancelled_at    INTEGER,
    cancelled_by    TEXT,
    status          TEXT    NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'executed', 'cancelled'))
);

-- Partial index: efficient sweep query.
CREATE INDEX idx_deletion_requests_pending
    ON deletion_requests(scheduled_at)
    WHERE status = 'pending';

-- One pending request per user at a time.
CREATE UNIQUE INDEX idx_deletion_requests_user_pending
    ON deletion_requests(user_id)
    WHERE status = 'pending';

-- SCHEMA_VERSION 19.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '19');
