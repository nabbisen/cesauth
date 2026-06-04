-- ----------------------------------------------------------------------------
-- 0015_audit_request_id.sql
-- ----------------------------------------------------------------------------
-- RFC 015: Adds a nullable `request_id` column to `audit_events` so that
-- audit rows can be cross-linked to the log lines from the same request.
--
-- The value is sourced from the `cf-ray` header on inbound requests and
-- written into every audit event emitted during that request.  For cron
-- and background operations the column is NULL (no inbound request).
--
-- The column is intentionally nullable (not NOT NULL): existing rows
-- and cron-path rows legitimately have no request_id.  A NULL here means
-- "emitted outside a request context", not "unknown request".
--
-- There is NO index on this column by default.  The expected query pattern
-- is "find the audit rows for request X" — a point-lookup over a short
-- time window.  Operators can add a covering index if needed via D1
-- `CREATE INDEX`.
-- ----------------------------------------------------------------------------

ALTER TABLE audit_events ADD COLUMN request_id TEXT;

-- SCHEMA_VERSION 15.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '15');
