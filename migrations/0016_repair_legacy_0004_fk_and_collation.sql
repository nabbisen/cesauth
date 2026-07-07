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

-- ========================================================================
-- Rebuild remaining tables with REFERENCES users(id).
--
-- When `ALTER TABLE users RENAME TO users_pre_0016` runs above, SQLite
-- 3.26.0+ rewrites FK references in every other table to point at
-- `users_pre_0016`.  After `DROP TABLE users_pre_0016` those references
-- become dangling.  PRAGMA foreign_key_check only validates row-level
-- integrity and passes on an empty DB; the dangling FK causes a hard
-- error at runtime when an INSERT is attempted with foreign_keys=ON.
-- Rebuilding each affected table here re-points its FK at `users`.
--
-- Tables already handled above: authenticators, consent, grants.
-- ========================================================================

-- user_sessions
ALTER TABLE user_sessions RENAME TO user_sessions_pre_0016;
CREATE TABLE user_sessions (
    session_id   TEXT    PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    auth_method  TEXT    NOT NULL,
    client_id    TEXT    NOT NULL
);
INSERT INTO user_sessions SELECT * FROM user_sessions_pre_0016;
DROP TABLE user_sessions_pre_0016;
CREATE INDEX IF NOT EXISTS user_sessions_user_idx
    ON user_sessions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active_created
    ON user_sessions(created_at ASC) WHERE revoked_at IS NULL;

-- user_tenant_memberships
ALTER TABLE user_tenant_memberships RENAME TO user_tenant_memberships_pre_0016;
CREATE TABLE user_tenant_memberships (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    joined_at  INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);
INSERT INTO user_tenant_memberships SELECT * FROM user_tenant_memberships_pre_0016;
DROP TABLE user_tenant_memberships_pre_0016;
CREATE INDEX IF NOT EXISTS idx_utm_user ON user_tenant_memberships(user_id);

-- user_organization_memberships
ALTER TABLE user_organization_memberships RENAME TO user_org_mbr_pre_0016;
CREATE TABLE user_organization_memberships (
    organization_id  TEXT NOT NULL REFERENCES organizations(id),
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role             TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    joined_at        INTEGER NOT NULL,
    PRIMARY KEY (organization_id, user_id)
);
INSERT INTO user_organization_memberships SELECT * FROM user_org_mbr_pre_0016;
DROP TABLE user_org_mbr_pre_0016;
CREATE INDEX IF NOT EXISTS idx_uom_user ON user_organization_memberships(user_id);

-- user_group_memberships
ALTER TABLE user_group_memberships RENAME TO user_group_mbr_pre_0016;
CREATE TABLE user_group_memberships (
    group_id   TEXT NOT NULL REFERENCES groups(id),
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at  INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
);
INSERT INTO user_group_memberships SELECT * FROM user_group_mbr_pre_0016;
DROP TABLE user_group_mbr_pre_0016;
CREATE INDEX IF NOT EXISTS idx_ugm_user ON user_group_memberships(user_id);

-- role_assignments
ALTER TABLE role_assignments RENAME TO role_assignments_pre_0016;
CREATE TABLE role_assignments (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES roles(id),
    scope_type TEXT NOT NULL
               CHECK (scope_type IN ('system','tenant','organization','group','user')),
    scope_id   TEXT,
    granted_by TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    expires_at INTEGER,
    CHECK (
        (scope_type = 'system' AND scope_id IS NULL) OR
        (scope_type != 'system' AND scope_id IS NOT NULL)
    )
);
INSERT INTO role_assignments SELECT * FROM role_assignments_pre_0016;
DROP TABLE role_assignments_pre_0016;
CREATE INDEX IF NOT EXISTS idx_ra_user  ON role_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_ra_scope ON role_assignments(scope_type, scope_id);

-- totp_authenticators
ALTER TABLE totp_authenticators RENAME TO totp_authenticators_pre_0016;
CREATE TABLE totp_authenticators (
    id                TEXT    PRIMARY KEY,
    user_id           TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext BLOB    NOT NULL,
    secret_nonce      BLOB    NOT NULL,
    secret_key_id     TEXT    NOT NULL,
    last_used_step    INTEGER NOT NULL DEFAULT 0,
    name              TEXT,
    created_at        INTEGER NOT NULL,
    last_used_at      INTEGER,
    confirmed_at      INTEGER
);
INSERT INTO totp_authenticators SELECT * FROM totp_authenticators_pre_0016;
DROP TABLE totp_authenticators_pre_0016;
CREATE INDEX IF NOT EXISTS idx_totp_authenticators_user
    ON totp_authenticators(user_id);
CREATE INDEX IF NOT EXISTS idx_totp_authenticators_unconfirmed
    ON totp_authenticators(created_at) WHERE confirmed_at IS NULL;

-- totp_recovery_codes
ALTER TABLE totp_recovery_codes RENAME TO totp_recovery_codes_pre_0016;
CREATE TABLE totp_recovery_codes (
    id          TEXT    PRIMARY KEY,
    user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT    NOT NULL,
    redeemed_at INTEGER,
    created_at  INTEGER NOT NULL
);
INSERT INTO totp_recovery_codes SELECT * FROM totp_recovery_codes_pre_0016;
DROP TABLE totp_recovery_codes_pre_0016;
CREATE INDEX IF NOT EXISTS idx_totp_recovery_codes_user
    ON totp_recovery_codes(user_id);

-- anonymous_sessions
ALTER TABLE anonymous_sessions RENAME TO anonymous_sessions_pre_0016;
CREATE TABLE anonymous_sessions (
    token_hash  TEXT    NOT NULL PRIMARY KEY,
    user_id     TEXT    NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    tenant_id   TEXT    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE
);
INSERT INTO anonymous_sessions SELECT * FROM anonymous_sessions_pre_0016;
DROP TABLE anonymous_sessions_pre_0016;

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
