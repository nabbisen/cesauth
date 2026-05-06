-- ============================================================================
-- 0005_admin_token_user_link.sql
-- ----------------------------------------------------------------------------
-- v0.11.0 foundation work for the tenant-scoped admin surface (0.12.0+).
--
-- Adds a nullable `user_id` column to `admin_tokens` so that a token can be
-- linked to a specific row in `users`. This is the path we picked in
-- ADR-002 ("user-as-bearer mechanism"): rather than introduce session
-- cookies or short-lived JWTs as a brand-new auth path, we extend the
-- existing admin-token mechanism with an optional user identity.
--
-- Semantics (post-0.12.0):
--   * `user_id IS NULL` — the token is a "system-admin token" (the kind
--     that 0.3.x and 0.4.x have always issued). Resolves to an
--     `AdminPrincipal { user_id: None, .. }`. Has access to
--     `/admin/console/*` and `/admin/saas/*`.
--   * `user_id IS NOT NULL` — the token is a "user-as-bearer" token.
--     The token still resolves to an `AdminPrincipal` (so the existing
--     `Role`-based authorization still works), but the `user_id` field
--     is populated. The principal can additionally hit
--     `/admin/t/<slug>/*` if their `users.tenant_id` matches `<slug>`.
--
-- This migration is foundation-only: it creates the column and the
-- supporting index. No code in v0.11.0 reads or writes the column yet.
-- v0.12.0 adds the resolution path and the route surface.
--
-- Why we did this in 0.11.0 even though no code uses it yet:
--   * Schema migrations are easier to review in isolation.
--   * 0.12.0 will be code-only (no schema), keeping the diff small and
--     each phase reviewable on its own.
--
-- See also: docs/src/expert/adr/{001,002,003}.md
-- ============================================================================

-- SQLite/D1 doesn't allow adding a column with a foreign-key constraint
-- via ALTER TABLE. We add the column without the FK reference; the
-- application layer enforces the linkage. This matches how the original
-- 0002 schema handled foreign-key-like relations (no inline REFERENCES;
-- the type system + service layer enforce instead).
ALTER TABLE admin_tokens ADD COLUMN user_id TEXT;

CREATE INDEX IF NOT EXISTS idx_admin_tokens_user_id
    ON admin_tokens(user_id)
    WHERE user_id IS NOT NULL;
