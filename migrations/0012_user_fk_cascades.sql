-- ----------------------------------------------------------------------------
-- 0012_user_fk_cascades.sql
-- ----------------------------------------------------------------------------
-- RFC 021: Adds ON DELETE CASCADE foreign keys from user-scoped tables to
-- `users(id)` so that deleting a user row also cleans up all user-scoped
-- data (TOTP secrets, sessions, memberships, role assignments).
--
-- Prior to this migration, code comments and sweep.rs referred to
-- "FK ON DELETE CASCADE handles cleanup" but the schema lacked the actual
-- constraints for most tables, leaving two failure modes:
--   1. Encrypted TOTP secrets survived user deletion (privacy / GDPR risk).
--   2. role_assignments rows granting deleted users roles survived, creating
--      potential authorization residue.
--
-- Implementation uses the SQLite "rename, recreate, copy, drop" pattern.
-- ----------------------------------------------------------------------------

PRAGMA foreign_keys = OFF;

-- ============================================================================
-- 1. user_tenant_memberships
-- ============================================================================

ALTER TABLE user_tenant_memberships RENAME TO user_tenant_memberships_pre_0012;

CREATE TABLE user_tenant_memberships (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    user_id    TEXT NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    joined_at  INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);

INSERT INTO user_tenant_memberships SELECT * FROM user_tenant_memberships_pre_0012;
DROP TABLE user_tenant_memberships_pre_0012;

CREATE INDEX IF NOT EXISTS idx_utm_user ON user_tenant_memberships(user_id);

-- ============================================================================
-- 2. user_organization_memberships
-- ============================================================================

ALTER TABLE user_organization_memberships RENAME TO user_org_memberships_pre_0012;

CREATE TABLE user_organization_memberships (
    organization_id  TEXT NOT NULL REFERENCES organizations(id),
    user_id          TEXT NOT NULL REFERENCES users(id)          ON DELETE CASCADE,
    role             TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    joined_at        INTEGER NOT NULL,
    PRIMARY KEY (organization_id, user_id)
);

INSERT INTO user_organization_memberships SELECT * FROM user_org_memberships_pre_0012;
DROP TABLE user_org_memberships_pre_0012;

CREATE INDEX IF NOT EXISTS idx_uom_user ON user_organization_memberships(user_id);

-- ============================================================================
-- 3. user_group_memberships
-- ============================================================================

ALTER TABLE user_group_memberships RENAME TO user_group_memberships_pre_0012;

CREATE TABLE user_group_memberships (
    group_id   TEXT NOT NULL REFERENCES groups(id),
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at  INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

INSERT INTO user_group_memberships SELECT * FROM user_group_memberships_pre_0012;
DROP TABLE user_group_memberships_pre_0012;

CREATE INDEX IF NOT EXISTS idx_ugm_user ON user_group_memberships(user_id);

-- ============================================================================
-- 4. role_assignments
--    user_id carries cascade; deleting a role does NOT cascade.
-- ============================================================================

ALTER TABLE role_assignments RENAME TO role_assignments_pre_0012;

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

INSERT INTO role_assignments SELECT * FROM role_assignments_pre_0012;
DROP TABLE role_assignments_pre_0012;

CREATE INDEX IF NOT EXISTS idx_ra_user  ON role_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_ra_scope ON role_assignments(scope_type, scope_id);

-- ============================================================================
-- 5. totp_authenticators  (10 columns; preserve exact shape from 0007)
-- ============================================================================

ALTER TABLE totp_authenticators RENAME TO totp_authenticators_pre_0012;

CREATE TABLE totp_authenticators (
    id               TEXT    PRIMARY KEY,
    user_id          TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext BLOB   NOT NULL,
    secret_nonce     BLOB    NOT NULL,
    secret_key_id    TEXT    NOT NULL,
    last_used_step   INTEGER NOT NULL DEFAULT 0,
    name             TEXT,
    created_at       INTEGER NOT NULL,
    last_used_at     INTEGER,
    confirmed_at     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_totp_authenticators_user
    ON totp_authenticators(user_id);
CREATE INDEX IF NOT EXISTS idx_totp_authenticators_unconfirmed
    ON totp_authenticators(created_at)
    WHERE confirmed_at IS NULL;

INSERT INTO totp_authenticators SELECT * FROM totp_authenticators_pre_0012;
DROP TABLE totp_authenticators_pre_0012;

-- ============================================================================
-- 6. totp_recovery_codes
-- ============================================================================

ALTER TABLE totp_recovery_codes RENAME TO totp_recovery_codes_pre_0012;

CREATE TABLE totp_recovery_codes (
    id          TEXT    PRIMARY KEY,
    user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT    NOT NULL,
    redeemed_at INTEGER,
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_totp_recovery_codes_user
    ON totp_recovery_codes(user_id);

INSERT INTO totp_recovery_codes SELECT * FROM totp_recovery_codes_pre_0012;
DROP TABLE totp_recovery_codes_pre_0012;

-- ============================================================================
-- 7. user_sessions
-- ============================================================================

ALTER TABLE user_sessions RENAME TO user_sessions_pre_0012;

CREATE TABLE user_sessions (
    session_id   TEXT    PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    auth_method  TEXT    NOT NULL,
    client_id    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS user_sessions_user_idx
    ON user_sessions(user_id, created_at DESC);

INSERT INTO user_sessions SELECT * FROM user_sessions_pre_0012;
DROP TABLE user_sessions_pre_0012;

-- Defense-in-depth: abort if any FK dangles.
PRAGMA foreign_key_check;

PRAGMA foreign_keys = ON;

-- SCHEMA_VERSION 12.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '12');
