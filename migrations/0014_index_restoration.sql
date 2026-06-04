-- ----------------------------------------------------------------------------
-- 0014_index_restoration.sql
-- ----------------------------------------------------------------------------
-- RFC 024: Restores indexes lost at the 0004 users-table rebuild and adds
-- new partial indexes for cron-scan query paths.
--
-- Lost indexes (0001 → 0004 regression):
--   idx_users_status     ON users(status)         — global; dropped at 0004
--   idx_users_created_at ON users(created_at)     — global; dropped at 0004
--
-- New partial indexes for cron paths:
--   idx_users_anonymous_expired    — anonymous-user retention sweep
--   idx_user_sessions_active_created — session-index audit cron + repair cron
--
-- Index shape rationale:
--   * Tenant-scoped composite (tenant_id, status) serves the tenant-admin
--     user-listing query; the plain single-column forms from 0001 are
--     superseded by composite forms that match current query patterns.
--   * Partial indexes on narrow predicates keep the index size proportional
--     to the active / anonymous population rather than the total table size.
-- ----------------------------------------------------------------------------

-- ============================================================================
-- users — restore and tune
-- ============================================================================

-- Tenant-scoped status index (admin console user lists, suspension checks).
CREATE INDEX IF NOT EXISTS idx_users_tenant_status
    ON users(tenant_id, status);

-- General created_at index (admin search by registration window, reports).
CREATE INDEX IF NOT EXISTS idx_users_created_at
    ON users(created_at);

-- Partial index for the anonymous-user retention sweep:
--   SELECT id FROM users
--    WHERE account_type = 'anonymous' AND email IS NULL AND created_at < ?
-- Only anonymous email-less rows are indexed; all other rows are excluded.
CREATE INDEX IF NOT EXISTS idx_users_anonymous_expired
    ON users(created_at)
    WHERE account_type = 'anonymous' AND email IS NULL;

-- ============================================================================
-- user_sessions — partial index for cron scan
-- ============================================================================

-- Partial index for the session-index audit cron and repair cron:
--   SELECT ... FROM user_sessions
--    WHERE revoked_at IS NULL ORDER BY created_at ASC LIMIT ?
-- Only active (non-revoked) sessions are indexed; once a session is revoked
-- the row leaves the index and no longer contributes to index size.
CREATE INDEX IF NOT EXISTS idx_user_sessions_active_created
    ON user_sessions(created_at)
    WHERE revoked_at IS NULL;

-- SCHEMA_VERSION 14.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '14');
