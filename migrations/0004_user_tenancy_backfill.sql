-- ------------------------------------------------------------------------
-- cesauth :: 0004_user_tenancy_backfill.sql
--
-- Adds `tenant_id` to every existing user row by associating it with
-- the bootstrap tenant that 0003 seeded. After this migration runs,
-- every row in `users` belongs to exactly one tenant — there are no
-- "tenant-less" users, which simplifies authz reasoning.
--
-- D1 (SQLite) cannot ADD COLUMN with a foreign key constraint and a
-- DEFAULT in one step against an existing table — we use the
-- "rename, recreate, copy" pattern.  Per the SQLite documentation at
-- https://www.sqlite.org/lang_altertable.html#otheralter this pattern
-- requires that every child table holding a FK to the renamed table is
-- also rebuilt in the same PRAGMA foreign_keys=OFF block; otherwise the
-- child-table FKs reference the now-dropped "users_pre_0004" name.
--
-- Concurrency note: this migration is NOT safe to run against a live
-- writer. The standard practice is wrangler-driven, single-session.
--
-- RFC 020 (v0.53.x): repaired to (a) rebuild authenticators / consent /
-- grants so their FKs point at the live `users` table, (b) restore
-- COLLATE NOCASE on `email` (lost in the original 0004), and (c) add
-- a PRAGMA foreign_key_check at the end as defense-in-depth.
-- ------------------------------------------------------------------------

PRAGMA foreign_keys = OFF;

-- ========================================================================
-- 1. users
-- ========================================================================

ALTER TABLE users RENAME TO users_pre_0004;

CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'tenant-default'
                    REFERENCES tenants(id),
    -- email is COLLATE NOCASE so that uniqueness is case-insensitive,
    -- matching the UserRepository contract.  The 0001 definition had
    -- this; it was accidentally dropped in the original 0004.
    email           TEXT COLLATE NOCASE,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    display_name    TEXT,
    -- Account type per spec §5.
    account_type    TEXT NOT NULL DEFAULT 'human_user'
                    CHECK (account_type IN (
                        'anonymous', 'human_user', 'service_account',
                        'system_operator', 'external_federated_user'
                    )),
    status          TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    -- Composite uniqueness: one email address per tenant (case-insensitive
    -- via the column's COLLATE NOCASE).
    UNIQUE (tenant_id, email)
);

INSERT INTO users
    (id, tenant_id, email, email_verified, display_name,
     account_type, status, created_at, updated_at)
SELECT
    id,
    'tenant-default',
    email, email_verified, display_name,
    'human_user',
    status, created_at, updated_at
FROM users_pre_0004;

-- Partial unique index for non-anonymous users.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email_ci
    ON users(tenant_id, email)
    WHERE email IS NOT NULL;

DROP TABLE users_pre_0004;

-- ========================================================================
-- 2. authenticators — rebuild so FK points at live `users`
-- ========================================================================

ALTER TABLE authenticators RENAME TO authenticators_pre_0004;

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

INSERT INTO authenticators SELECT * FROM authenticators_pre_0004;
DROP TABLE authenticators_pre_0004;

CREATE INDEX IF NOT EXISTS idx_authenticators_user ON authenticators(user_id);

-- ========================================================================
-- 3. consent — rebuild so FK points at live `users`
-- ========================================================================

ALTER TABLE consent RENAME TO consent_pre_0004;

CREATE TABLE consent (
    user_id    TEXT    NOT NULL,
    client_id  TEXT    NOT NULL,
    scopes     TEXT    NOT NULL,
    granted_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, client_id),
    FOREIGN KEY (user_id)   REFERENCES users(id)        ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES oidc_clients(id) ON DELETE CASCADE
);

INSERT INTO consent SELECT * FROM consent_pre_0004;
DROP TABLE consent_pre_0004;

-- ========================================================================
-- 4. grants — rebuild so FK points at live `users`
-- ========================================================================

ALTER TABLE grants RENAME TO grants_pre_0004;

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

INSERT INTO grants SELECT * FROM grants_pre_0004;
DROP TABLE grants_pre_0004;

CREATE INDEX IF NOT EXISTS idx_grants_user_client ON grants(user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_grants_active      ON grants(revoked_at) WHERE revoked_at IS NULL;

-- ========================================================================
-- 5. Bootstrap-tenant memberships
-- ========================================================================

INSERT OR IGNORE INTO user_tenant_memberships
    (tenant_id, user_id, role, joined_at)
SELECT
    'tenant-default', id, 'member', created_at
FROM users;

-- Defense-in-depth: abort if any FK dangles.
PRAGMA foreign_key_check;

PRAGMA foreign_keys = ON;

-- SCHEMA_VERSION 4.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '4');
