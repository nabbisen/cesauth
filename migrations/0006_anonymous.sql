-- ============================================================================
-- 0006_anonymous.sql
-- ----------------------------------------------------------------------------
-- v0.16.0 foundation work for the anonymous-trial promotion flow (ADR-004).
--
-- Adds the `anonymous_sessions` table — a thin auth-surface for the
-- "visitor without an account" case. The visitor's user row lives in
-- `users` like any other (with `account_type='anonymous'`,
-- `email IS NULL`); this table holds the bearer token that
-- authenticates requests on behalf of that anonymous user.
--
-- Why a separate table from `admin_tokens` (introduced in 0005):
--   * admin_tokens carries permission-bearing principals — every row
--     has a `Role` (Super / Operations / Security / ReadOnly) that
--     gates the entire `/admin/*` surface. An anonymous visitor has
--     no admin role and should not be able to acquire one through
--     this token.
--   * The lifecycle is different: anonymous tokens are not refreshable
--     (24h TTL, then re-call /anonymous/begin), not user-mintable
--     (server issues exactly one per /begin call), and not revocable
--     in the same way (revocation happens implicitly via the daily
--     retention sweep or the promotion-time rotation).
--
-- Semantics (post-0.16.0):
--   Each row pins one anonymous bearer token to one user_id. The
--   token's plaintext is shown once at creation; cesauth stores only
--   the SHA-256 hash. Lookup at request time: hash the presented
--   bearer, look it up here, find the user_id, then load the user
--   row and check `account_type='anonymous'` and not expired.
--
-- This migration is foundation-only. v0.16.0 ships the schema, the
-- AnonymousSession type, and the repository port. The HTTP routes
-- (`/api/v1/anonymous/begin`, `/api/v1/anonymous/promote`) ship in
-- v0.17.0; the daily retention sweep ships in v0.6.05.
-- ============================================================================

CREATE TABLE IF NOT EXISTS anonymous_sessions (
    -- The token's hash. SHA-256 of the plaintext bearer, hex-encoded.
    -- Primary key both for lookup and to enforce uniqueness across
    -- collisions (which won't happen in practice but the DB should
    -- not be the layer that lets one through).
    token_hash      TEXT     NOT NULL PRIMARY KEY,

    -- The user_id this token authenticates as. Foreign key to
    -- `users.id`; ON DELETE CASCADE so the daily sweep that drops
    -- expired anonymous user rows automatically removes their tokens.
    user_id         TEXT     NOT NULL,

    -- Issued-at timestamp. Unix seconds.
    created_at      INTEGER  NOT NULL,

    -- Expires-at timestamp. Unix seconds. Default 24h post-creation
    -- per ADR-004 §Q2; the application enforces, the DB stores.
    expires_at      INTEGER  NOT NULL,

    -- Tenant of the anonymous user, denormalized here for fast IP-
    -- based rate-limit lookups that don't want to join `users`.
    tenant_id       TEXT     NOT NULL,

    FOREIGN KEY (user_id)   REFERENCES users(id)       ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)     ON DELETE CASCADE
);

-- Index for the retention sweep: find every session whose row's
-- created_at < now - 7d. The sweep handler does
-- `DELETE FROM users WHERE account_type='anonymous' AND email IS NULL
--   AND created_at < ?` and the cascade cleans up here. This index
-- supports the "list expired tokens" diagnostic path operators may
-- run before the sweep.
CREATE INDEX IF NOT EXISTS idx_anonymous_sessions_created
    ON anonymous_sessions (created_at);

-- Index for finding sessions by user_id. Used by the promotion path
-- to revoke an anonymous user's token at promotion time (rotate
-- through to a regular session) and by diagnostics ("how many open
-- sessions does this user have"; in the v0.16.0 design the answer
-- is always 0 or 1, but the index is cheap insurance).
CREATE INDEX IF NOT EXISTS idx_anonymous_sessions_user
    ON anonymous_sessions (user_id);
