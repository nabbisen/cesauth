-- ----------------------------------------------------------------------------
-- 0018_invitation_tokens.sql
-- ----------------------------------------------------------------------------
-- RFC 043: Invitation token system for tenant self-service onboarding.
--
-- An invitation links a pending email address to a tenant and an initial role.
-- The invite is issued by a tenant admin, sent via the MagicLinkMailer port,
-- and consumed when the invitee completes registration (passkey or magic link).
--
-- States:
--   pending   - issued, not yet accepted, not expired
--   accepted  - invitee completed registration (accepted_at IS NOT NULL)
--   revoked   - manually revoked by issuer (revoked_at IS NOT NULL)
--   expired   - pending AND now > expires_at (not a column; checked at query time)
--
-- Uniqueness: one pending invitation per (tenant_id, email) at a time.
-- A new invite for the same email in the same tenant is only allowed after
-- the previous one is accepted, revoked, or expired.
-- ----------------------------------------------------------------------------

CREATE TABLE invitation_tokens (
    id           TEXT    PRIMARY KEY,              -- UUID v4
    tenant_id    TEXT    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email        TEXT    NOT NULL COLLATE NOCASE,  -- recipient email (COLLATE NOCASE per RFC 020)
    role         TEXT    NOT NULL,                 -- initial role on accept (e.g. "tenant_member")
    issued_by    TEXT    NOT NULL,                 -- admin user_id who created the invite
    issued_at    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,                 -- issued_at + grace period (default 72h)
    accepted_at  INTEGER,                          -- NULL = not yet accepted
    accepted_by  TEXT,                             -- user_id of the account that accepted
    revoked_at   INTEGER,
    revoked_by   TEXT                              -- user_id who revoked
);

-- Efficient lookup for the accept flow: by invite id + email.
CREATE INDEX idx_invitation_tokens_pending
    ON invitation_tokens(tenant_id, email, expires_at)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- One-pending-per-email-per-tenant constraint.
-- (Enforced here; the service layer also checks before issuing.)
CREATE UNIQUE INDEX idx_invitation_tokens_email_tenant_active
    ON invitation_tokens(tenant_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- SCHEMA_VERSION 18.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '18');
