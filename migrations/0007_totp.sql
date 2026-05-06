-- ============================================================================
-- 0007_totp.sql
-- ----------------------------------------------------------------------------
-- v0.26.0 foundation work for TOTP (RFC 6238) as a second factor (ADR-009).
--
-- Adds two new tables: `totp_authenticators` for per-user TOTP secrets at
-- rest (encrypted with AES-GCM, see ADR-009 §Q5), and `totp_recovery_codes`
-- for the rescue path when a user loses their authenticator device
-- (ADR-009 §Q6).
--
-- Per ADR-009 §Q4, TOTP gets its own table rather than being shoehorned
-- into the existing `authenticators` table (which is WebAuthn-specific:
-- credential_id, COSE public_key, sign_count, AAGUID — none apply to
-- TOTP). A separate table is clean.
--
-- This migration is purely additive. No existing column or table is
-- changed. Both new tables are empty on first deploy. Operators may
-- choose not to enroll TOTP at all, in which case the tables remain
-- empty.
--
-- Tooling check: SCHEMA_VERSION constant in cesauth_core::migrate goes
-- 6 → 7. The schema_version_matches_migration_count test pins the
-- invariant.
--
-- Per ADR-009 §Q11, cesauth-migrate's MIGRATION_TABLE_ORDER list
-- gains both tables. The prod→staging redaction profile drops both
-- entirely (TOTP secrets must not survive redaction even hashed —
-- a staging deployment with real user TOTP secrets would let any
-- staging operator authenticate as that user).
-- ============================================================================

-- ----- totp_authenticators ---------------------------------------------------
-- Per-user TOTP secret. One row per (user, authenticator app) pair —
-- a user with multiple TOTP authenticators (e.g., phone + tablet)
-- gets multiple rows.
--
-- `secret_ciphertext` + `secret_nonce` together let the worker
-- decrypt the secret on verify. AES-GCM-256:
--
--   AES-GCM(plaintext_secret, key, nonce, aad="totp:" + id) → ciphertext
--
-- The AAD ("additional authenticated data") binds ciphertext to the
-- row's primary key, so an attacker who reads a D1 backup cannot
-- swap one row's ciphertext into another row's slot.
--
-- `secret_key_id` is the human-readable identifier of which
-- deployment key encrypted this row. Rotation: mint new key, deploy
-- with new id, new writes use the new key, old reads still find the
-- old key by id. Re-encryption from old to new is a separate operator
-- job, not on the hot path.
--
-- `last_used_step` is the latest TOTP step that successfully verified
-- against this secret. Replay protection (ADR-009 §Q3): a verify with
-- step ≤ last_used_step fails. Default 0 because no real TOTP step
-- can equal 0 (step 0 = unix epoch, beaten by ≥ 50 years on any real
-- verification).
--
-- `confirmed_at` is the enrollment-completion marker. NULL during
-- enrollment (the user has scanned the QR code but not yet typed a
-- verifying code). The first successful verify flips it to `now`.
-- Pre-confirmation rows older than 24h are pruned by the daily cron
-- (extended in v0.27.0; see ADR-009 §Q9).
CREATE TABLE IF NOT EXISTS totp_authenticators (
    id                       TEXT    PRIMARY KEY,
    user_id                  TEXT    NOT NULL,
    secret_ciphertext        BLOB    NOT NULL,
    secret_nonce             BLOB    NOT NULL,
    secret_key_id            TEXT    NOT NULL,
    last_used_step           INTEGER NOT NULL DEFAULT 0,
    name                     TEXT,
    created_at               INTEGER NOT NULL,
    last_used_at             INTEGER,
    confirmed_at             INTEGER
);

CREATE INDEX IF NOT EXISTS idx_totp_authenticators_user
  ON totp_authenticators(user_id);

-- Partial index for the cron sweep that prunes unconfirmed
-- enrollments. The typical case is a fully-confirmed
-- authenticator (`confirmed_at` set), and the index size is
-- minimized by being partial.
CREATE INDEX IF NOT EXISTS idx_totp_authenticators_unconfirmed
  ON totp_authenticators(created_at)
  WHERE confirmed_at IS NULL;

-- ----- totp_recovery_codes ---------------------------------------------------
-- Per-user single-use recovery codes for when the user loses their
-- TOTP authenticator. Generated at the user's first TOTP enrollment
-- and shown to the user once in plaintext. Stored hashed (SHA-256),
-- following cesauth's existing pattern for high-entropy
-- server-issued bearer secrets (admin_tokens.token_hash,
-- magic_link::hash). Argon2 would be the right choice for
-- user-chosen passwords, but recovery codes are CSPRNG-generated
-- with ~50 bits of entropy already — password-stretching would add
-- CPU cost without security gain.
--
-- 10 codes per user (ADR-009 §Q6). Each ≈ 50 bits of entropy
-- (10 base32 characters formatted XXXXX-XXXXX for human readability).
-- Single-use: `redeemed_at` set on first successful redemption.
--
-- Recovery does NOT advance the matched TOTP authenticator's
-- `last_used_step` (the recovery path bypasses TOTP, doesn't use it).
CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id                TEXT    PRIMARY KEY,
    user_id           TEXT    NOT NULL,
    code_hash         TEXT    NOT NULL,
    redeemed_at       INTEGER,
    created_at        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_totp_recovery_codes_user
  ON totp_recovery_codes(user_id);
