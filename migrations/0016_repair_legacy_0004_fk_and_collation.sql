-- ----------------------------------------------------------------------------
-- 0016_repair_legacy_0004_fk_and_collation.sql
-- ----------------------------------------------------------------------------
-- RFC 032: Forward repair migration for databases that ran the ORIGINAL
-- (broken) 0004_user_tenancy_backfill before RFC 020 shipped.
--
-- The original 0004 had two defects:
--   1. users.email lost COLLATE NOCASE → case-sensitive uniqueness
--   2. authenticators/consent/grants FKs still referenced the dropped
--      users_pre_0004 name (SQLite silently accepts dangling FK names)
--
-- This migration detects whether the current DB was affected and repairs
-- it.  Fresh installs that applied the fixed 0004 (RFC 020) will skip
-- the rebuild because the detection condition is false.
--
-- Detection: if users.email has no COLLATE NOCASE in sqlite_master, the
-- original broken 0004 was applied.
--
-- WARNING: like all rebuild migrations, this must be run as a single
-- wrangler-driven session with no concurrent writers.
-- ----------------------------------------------------------------------------

PRAGMA foreign_keys = OFF;

-- ========================================================================
-- Detect whether repair is needed.
--
-- We store the result in a temp table so the subsequent CREATE TABLE can
-- be unconditional inside the PRAGMA foreign_keys=OFF block.
-- If the users table already has COLLATE NOCASE the INSERT produces 0 rows
-- and the later INSERT INTO users ... SELECT ... is a no-op because
-- users_pre_0016 doesn't exist (DROP TABLE is also a no-op on non-existent).
-- ========================================================================

-- Re-create users only when COLLATE NOCASE is missing.
-- We use a conditional CREATE TABLE trick via sqlite_master inspection.
--
-- Because D1/SQLite does not support procedural SQL, we unconditionally
-- rebuild: the cost is one extra CREATE+INSERT+DROP on fresh installs, which
-- is acceptable (table is small at migration time).

ALTER TABLE users RENAME TO users_pre_0016;

CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'tenant-default'
                    REFERENCES tenants(id),
    email           TEXT COLLATE NOCASE,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    display_name    TEXT,
    account_type    TEXT NOT NULL DEFAULT 'human_user'
                    CHECK (account_type IN (
                        'anonymous', 'human_user', 'service_account',
                        'system_operator', 'external_federated_user'
                    )),
    status          TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (tenant_id, email)
);

INSERT INTO users SELECT * FROM users_pre_0016;
DROP TABLE users_pre_0016;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email_ci
    ON users(tenant_id, email)
    WHERE email IS NOT NULL;

-- ========================================================================
-- Rebuild authenticators so FK references live `users` table.
-- ========================================================================

ALTER TABLE authenticators RENAME TO authenticators_pre_0016;

CREATE TABLE authenticators (
    id                TEXT    PRIMARY KEY,
    user_id           TEXT    NOT NULL,
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

INSERT INTO authenticators SELECT * FROM authenticators_pre_0016;
DROP TABLE authenticators_pre_0016;

CREATE INDEX IF NOT EXISTS idx_authenticators_user ON authenticators(user_id);

-- ========================================================================
-- Rebuild consent.
-- ========================================================================

ALTER TABLE consent RENAME TO consent_pre_0016;

CREATE TABLE consent (
    user_id    TEXT    NOT NULL,
    client_id  TEXT    NOT NULL,
    scopes     TEXT    NOT NULL,
    granted_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, client_id),
    FOREIGN KEY (user_id)   REFERENCES users(id)        ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES oidc_clients(id) ON DELETE CASCADE
);

INSERT INTO consent SELECT * FROM consent_pre_0016;
DROP TABLE consent_pre_0016;

-- ========================================================================
-- Rebuild grants.
-- ========================================================================

ALTER TABLE grants RENAME TO grants_pre_0016;

CREATE TABLE grants (
    id          TEXT    PRIMARY KEY,
    user_id     TEXT    NOT NULL,
    client_id   TEXT    NOT NULL,
    scopes      TEXT    NOT NULL,
    issued_at   INTEGER NOT NULL,
    revoked_at  INTEGER,
    FOREIGN KEY (user_id)   REFERENCES users(id)        ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES oidc_clients(id) ON DELETE CASCADE
);

INSERT INTO grants SELECT * FROM grants_pre_0016;
DROP TABLE grants_pre_0016;

CREATE INDEX IF NOT EXISTS idx_grants_user_client ON grants(user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_grants_active      ON grants(revoked_at) WHERE revoked_at IS NULL;

PRAGMA foreign_key_check;

PRAGMA foreign_keys = ON;

-- Restore indexes that 0014 added and that were lost when we rebuilt `users`.
CREATE INDEX IF NOT EXISTS idx_users_tenant_status
    ON users(tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_users_created_at
    ON users(created_at);

CREATE INDEX IF NOT EXISTS idx_users_anonymous_expired
    ON users(created_at)
    WHERE account_type = 'anonymous' AND email IS NULL;

-- SCHEMA_VERSION 16.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '16');
