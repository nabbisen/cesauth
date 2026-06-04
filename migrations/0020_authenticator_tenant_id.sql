-- ----------------------------------------------------------------------------
-- 0020_authenticator_tenant_id.sql
-- ----------------------------------------------------------------------------
-- RFC 051: Add tenant_id to the authenticators table.
--
-- Why: The data structure review (P2) noted that authenticators, consent,
-- and grants have no tenant_id, forcing multi-hop JOINs for tenant-scoped
-- export/import and preventing direct tenant boundary validation at the
-- schema layer.
--
-- This migration addresses authenticators first — the most critical table
-- for WebAuthn credential management. consent and grants are already
-- indirectly tenant-scoped via oidc_clients; authenticators are only
-- linked via users(tenant_id), making them the most ambiguous.
--
-- Approach:
--   1. Add nullable tenant_id column.
--   2. Backfill from users table.
--   3. Enforce NOT NULL after backfill.
--      Note: SQLite does not support altering column nullability after
--      table creation, so we use the rebuild pattern.
--   4. Add FK and index.
--
-- The column is backfilled with 'tenant-default' for authenticators whose
-- user_id is not found (should not happen in a healthy DB, but defensive).
-- ----------------------------------------------------------------------------

PRAGMA foreign_keys = OFF;

-- Step 1: Add nullable tenant_id to existing table for backfill
ALTER TABLE authenticators ADD COLUMN tenant_id TEXT;

-- Step 2: Backfill from users table
UPDATE authenticators
SET tenant_id = (
    SELECT u.tenant_id FROM users u WHERE u.id = authenticators.user_id
)
WHERE tenant_id IS NULL;

-- Default for any orphaned rows (defence-in-depth)
UPDATE authenticators SET tenant_id = 'tenant-default' WHERE tenant_id IS NULL;

-- Step 3: Rebuild with NOT NULL enforcement and FK
ALTER TABLE authenticators RENAME TO authenticators_pre_0020;

CREATE TABLE authenticators (
    id                TEXT    PRIMARY KEY,
    user_id           TEXT    NOT NULL,
    tenant_id         TEXT    NOT NULL REFERENCES tenants(id),
    credential_id     TEXT    NOT NULL UNIQUE,
    public_key        BLOB    NOT NULL,
    sign_count        INTEGER NOT NULL DEFAULT 0,
    transports        TEXT,
    aaguid            TEXT,
    backup_eligible   INTEGER NOT NULL DEFAULT 0,
    backup_state      INTEGER NOT NULL DEFAULT 0,
    name              TEXT,
    created_at        INTEGER NOT NULL,
    last_used_at      INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO authenticators SELECT * FROM authenticators_pre_0020;
DROP TABLE authenticators_pre_0020;

CREATE INDEX IF NOT EXISTS idx_authenticators_user   ON authenticators(user_id);
CREATE INDEX IF NOT EXISTS idx_authenticators_tenant ON authenticators(tenant_id);

PRAGMA foreign_key_check;
PRAGMA foreign_keys = ON;

-- SCHEMA_VERSION 20.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '20');
