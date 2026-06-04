# RFC 043 — Invitation tokens

**Status**: Implemented  
**Priority**: P1 (SaaS guide §4.4: required for tenant self-service onboarding)  
**Size**: Large (~200 LOC core + 100 LOC migration + 150 LOC worker)  
**Depends on**: RFC 001 (sessions), RFC 020 (migration chain)

## Problem

Users can only join a tenant through admin-direct creation or anonymous promote.
There is no mechanism for a tenant admin to invite someone by email and have
them complete registration themselves — a requirement for SaaS onboarding.

## Decision

Add `invitation_tokens` table + invitation flow:

### Schema (migration 0018)
```sql
CREATE TABLE invitation_tokens (
    id           TEXT PRIMARY KEY,     -- UUID
    tenant_id    TEXT NOT NULL REFERENCES tenants(id),
    email        TEXT NOT NULL COLLATE NOCASE,
    role         TEXT NOT NULL,        -- initial role on accept
    issued_by    TEXT NOT NULL,        -- admin user_id
    issued_at    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,     -- issued_at + 72h
    accepted_at  INTEGER,              -- NULL = pending
    accepted_by  TEXT,                 -- user_id on accept
    revoked_at   INTEGER,
    revoked_by   TEXT
);
CREATE INDEX idx_invitations_tenant ON invitation_tokens(tenant_id, accepted_at)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX idx_invitations_email_tenant_pending
    ON invitation_tokens(tenant_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
```

### Core service
- `cesauth_core::invitation` module
- `issue_invitation(tenant_id, email, role, issued_by, now)` → `Invitation`
- `verify_invitation(token_id, email, now)` → `InvitationVerifyOutcome`
  - Expired / Revoked / AlreadyAccepted / Valid
- Pure functions; I/O via `InvitationRepository` port

### Wire flow
1. `POST /admin/t/:slug/invitations` — tenant admin issues invitation; mailer sends link
2. `GET /accept-invite?id=...&email=...` — renders accept page (passkey or magic link)
3. `POST /accept-invite` — verifies token, creates/links user, grants role, redirects
