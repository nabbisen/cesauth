-- ------------------------------------------------------------------------
-- cesauth :: 0001_initial.sql
--
-- D1 holds only long-lived relational data. Anything transactional -
-- auth codes, refresh rotations, active sessions, rate limits - lives in
-- Durable Objects and is NOT represented here.
--
-- Conventions
--   * All timestamps are unix seconds (INTEGER). Workers has no reliable
--     clock-skew guarantee across calls, so we store raw seconds rather
--     than TEXT timestamps and let the `time` crate format on read.
--   * IDs are stored as TEXT (UUIDv4 serialized) so they're stable across
--     dumps and easy to diff in the audit log.
--   * No ON UPDATE CURRENT_TIMESTAMP. SQLite honors that only with a
--     trigger; we set `updated_at` explicitly from the core crate.
-- ------------------------------------------------------------------------

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------------
-- users
-- A user can exist with no email at all (username-less passkey first).
-- `email` is therefore nullable; when present it is unique and lowercased.
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              TEXT    PRIMARY KEY,
    email           TEXT    UNIQUE COLLATE NOCASE,
    email_verified  INTEGER NOT NULL DEFAULT 0,  -- 0/1
    display_name    TEXT,
    status          TEXT    NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled', 'deleted')),
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_status     ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- ------------------------------------------------------------------------
-- authenticators
-- One row per WebAuthn credential. `credential_id` is the raw bytes as
-- base64url (no padding), which is what the browser ships to us, so we
-- avoid a round-trip through BLOB.
--
-- sign_count is updated on each successful assertion. A non-monotonic
-- counter is a cloning indicator per the WebAuthn spec - the verification
-- code enforces that.
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authenticators (
    id                TEXT    PRIMARY KEY,
    user_id           TEXT    NOT NULL,
    credential_id     TEXT    NOT NULL UNIQUE,          -- base64url
    public_key        BLOB    NOT NULL,                 -- COSE key
    sign_count        INTEGER NOT NULL DEFAULT 0,
    transports        TEXT,                             -- JSON array, nullable
    aaguid            TEXT,                             -- 16-byte hex
    backup_eligible   INTEGER NOT NULL DEFAULT 0,
    backup_state      INTEGER NOT NULL DEFAULT 0,
    name              TEXT,                             -- user-supplied label
    created_at        INTEGER NOT NULL,
    last_used_at      INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_authenticators_user ON authenticators(user_id);

-- ------------------------------------------------------------------------
-- oidc_clients
-- `client_secret_hash` is NULL for public (PKCE-only) clients.
-- `redirect_uris` is a JSON array stored as TEXT; we validate on read.
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oidc_clients (
    id                 TEXT    PRIMARY KEY,             -- client_id
    name               TEXT    NOT NULL,
    client_type        TEXT    NOT NULL
                       CHECK (client_type IN ('public', 'confidential')),
    client_secret_hash TEXT,                             -- sha256_hex(secret) or NULL (RFC 002, v0.51.0: SHA-256 correct for server-minted 256-bit secrets)
    redirect_uris      TEXT    NOT NULL,                 -- JSON array
    allowed_scopes     TEXT    NOT NULL,                 -- JSON array
    token_auth_method  TEXT    NOT NULL DEFAULT 'none'
                       CHECK (token_auth_method IN (
                           'none',
                           'client_secret_basic',
                           'client_secret_post'
                       )),
    require_pkce       INTEGER NOT NULL DEFAULT 1,       -- spec says PKCE always
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);

-- ------------------------------------------------------------------------
-- consent
-- User-granted scopes per (user, client). We store the *latest* consent
-- snapshot; historical records go to the audit log in R2.
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS consent (
    user_id    TEXT    NOT NULL,
    client_id  TEXT    NOT NULL,
    scopes     TEXT    NOT NULL,                         -- JSON array
    granted_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, client_id),
    FOREIGN KEY (user_id)   REFERENCES users(id)        ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES oidc_clients(id) ON DELETE CASCADE
);

-- ------------------------------------------------------------------------
-- grants
-- A durable record of "this refresh-token family was issued to this
-- (user, client) pair". The *state* of the family (current token, rotation
-- counter, etc.) lives in a Durable Object. This table exists so that
-- admin operations like "revoke everything client X issued to user Y"
-- can enumerate families without scanning every DO.
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS grants (
    id          TEXT    PRIMARY KEY,                    -- family id
    user_id     TEXT    NOT NULL,
    client_id   TEXT    NOT NULL,
    scopes      TEXT    NOT NULL,                       -- JSON array
    issued_at   INTEGER NOT NULL,
    revoked_at  INTEGER,                                -- NULL = active
    FOREIGN KEY (user_id)   REFERENCES users(id)        ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES oidc_clients(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_grants_user_client ON grants(user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_grants_active      ON grants(revoked_at) WHERE revoked_at IS NULL;

-- ------------------------------------------------------------------------
-- jwt_signing_keys
-- Records which `kid`s have existed. The secret material itself lives in
-- Workers Secrets; this table is just a registry so JWKS can list
-- recently-rotated-out public keys during the grace window.
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jwt_signing_keys (
    kid        TEXT    PRIMARY KEY,
    public_key TEXT    NOT NULL,                        -- base64url(raw 32 bytes)
    alg        TEXT    NOT NULL DEFAULT 'EdDSA',
    created_at INTEGER NOT NULL,
    retired_at INTEGER                                   -- NULL = current
);

CREATE INDEX IF NOT EXISTS idx_jwt_signing_keys_active
    ON jwt_signing_keys(retired_at) WHERE retired_at IS NULL;
