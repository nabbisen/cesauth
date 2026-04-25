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
-- "rename, recreate, copy" pattern. This is safe because every
-- INSERT into `users` in 0001 / 0002 / 0003 wrote a fresh row; we
-- are not dropping data.
--
-- Concurrency note: this migration is NOT safe to run against a live
-- writer. The standard practice is wrangler-driven, single-session.
-- The pre-existing 0001 migration carries the same caveat.
-- ------------------------------------------------------------------------

PRAGMA foreign_keys = OFF;

-- ------------------------------------------------------------------------
-- 1. users
-- ------------------------------------------------------------------------

ALTER TABLE users RENAME TO users_pre_0004;

CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'tenant-default'
                    REFERENCES tenants(id),
    -- Note the change in semantics: email is now unique PER TENANT,
    -- not globally. Two tenants may both have an alice@example.com.
    email           TEXT,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    display_name    TEXT,
    -- Account type per spec §5. Existing users default to human_user;
    -- service accounts and others must be re-tagged out-of-band by
    -- the operator (no automatic detection is possible).
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

INSERT INTO users
    (id, tenant_id, email, email_verified, display_name,
     account_type, status, created_at, updated_at)
SELECT
    id,
    'tenant-default',         -- backfill: every pre-0004 user joins the bootstrap tenant
    email, email_verified, display_name,
    'human_user',             -- pre-0004 had no account-type column; assume human
    status, created_at, updated_at
FROM users_pre_0004;

-- Re-create indexes that 0001 had (`idx_users_email` was the only one
-- the schema explicitly defined). Because email is now scoped per
-- tenant we adjust the index shape too.
CREATE INDEX IF NOT EXISTS idx_users_tenant_email
    ON users(tenant_id, email) WHERE email IS NOT NULL;

DROP TABLE users_pre_0004;

-- ------------------------------------------------------------------------
-- 2. Bootstrap-tenant memberships
--    Every existing user is auto-added to `tenant-default` with the
--    `member` role. Owners / admins must be re-graded out-of-band
--    (which is unavoidable: pre-0004 there was no tenancy concept,
--    so every user looks the same to the migration).
-- ------------------------------------------------------------------------

INSERT OR IGNORE INTO user_tenant_memberships
    (tenant_id, user_id, role, joined_at)
SELECT
    'tenant-default', id, 'member', created_at
FROM users;

PRAGMA foreign_keys = ON;
