-- ============================================================================
-- 0009_user_session_index.sql
-- ----------------------------------------------------------------------------
-- v0.35.0: Per-user session enumeration index (ADR-012, "Sessions track").
--
-- Background: sessions live one-per-DO at `ActiveSession` keyed by session_id.
-- That layout is great for the hot path (lookup by id is O(1) and revoke is
-- atomic) but provides no way to answer "show me all sessions for user X" —
-- which is exactly what the v0.35.0 `/me/security/sessions` page needs.
--
-- We considered three alternatives during ADR-012 design:
--
--   1. **Add a second `UserSessionIndex` DO** keyed by user_id, holding a
--      list of session_ids. Pros: same single-store shape as the existing
--      session DO. Cons: doubles the number of DO classes (currently three:
--      RefreshTokenFamily, ActiveSession, MagicLinkChallenge); each new
--      session has to write to TWO DOs at start time, multiplying failure
--      modes.
--
--   2. **Iterate the DO storage at the namespace level**. Cloudflare DOs
--      don't support cross-DO iteration. Rejected outright.
--
--   3. **D1 secondary index.** This file. session_id PRIMARY KEY, user_id
--      indexed. The DO remains the source of truth for individual session
--      state (touch / revoke / status); the D1 row is a denormalized index
--      whose only job is "given a user_id, what session_ids exist".
--      Eventually-consistent updates from the DO are fine here — at most
--      the user-facing list shows a session_id whose state has changed
--      since the index was written, and the per-row DO peek catches that
--      when rendering.
--
-- Choice was option 3 because it adds a small DDL change rather than
-- doubling the DO count, and the `audit_events` table already established
-- the precedent of D1-as-secondary-store-for-DO-data.
--
-- Schema:
--
--   user_sessions
--     session_id TEXT PRIMARY KEY      -- matches ActiveSession DO key
--     user_id    TEXT NOT NULL         -- the index column
--     created_at INTEGER NOT NULL      -- mirror; for ordering newest-first
--     revoked_at INTEGER NULL          -- mirror; updated on revoke
--     auth_method TEXT NOT NULL        -- mirror; surfaced in the user UI
--     client_id  TEXT NOT NULL         -- mirror; surfaced in the user UI
--
-- Index:
--
--   user_sessions_user_idx ON (user_id, created_at DESC) — supports the
--   common query (newest-first list for one user).
--
-- The mirror columns mean the user-facing list page can render a row
-- without consulting the DO at all. The DO is only consulted when the
-- user clicks "revoke" or when the session's authority is needed for an
-- authenticated request.
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_sessions (
  session_id   TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  revoked_at   INTEGER,
  auth_method  TEXT NOT NULL,
  client_id    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS user_sessions_user_idx
  ON user_sessions (user_id, created_at DESC);

-- v0.35.0 SCHEMA_VERSION 8 -> 9.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '9');
