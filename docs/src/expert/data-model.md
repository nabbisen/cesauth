# Data Model

cesauth's D1 (SQLite) schema as of **SCHEMA_VERSION 20**.

## Entity Relationships

```
tenants (SCHEMA_VERSION 1+)
│   id, slug, display_name, status, created_at, updated_at
│
├── users
│   │   id, tenant_id, email (COLLATE NOCASE), email_verified
│   │   account_type, status, display_name, created_at, updated_at
│   │
│   ├── authenticators (WebAuthn credentials)
│   │       id, user_id, tenant_id *, credential_id (UNIQUE),
│   │       public_key (BLOB), sign_count, transports, aaguid,
│   │       backup_eligible, backup_state, name, created_at, last_used_at
│   │       * tenant_id added in migration 0020
│   │
│   ├── totp_authenticators
│   │       id, user_id, secret_ciphertext, secret_nonce,
│   │       secret_key_id, last_used_step, confirmed_at, …
│   │
│   ├── totp_recovery_codes
│   │       id, user_id, code_hash (SHA-256), redeemed_at
│   │
│   ├── user_sessions  (D1 index; authoritative state in DO)
│   │       session_id, user_id, tenant_id, auth_time, …
│   │
│   ├── consent
│   │       id, user_id, client_id, scopes, granted_at
│   │
│   └── grants
│           id, user_id, client_id, scopes, issued_at, revoked_at
│
├── organizations
│   │   id, tenant_id, slug, display_name, status, created_at, updated_at
│   │
│   └── groups
│           id, tenant_id, parent (org_id or tenant_id), slug,
│           display_name, status, created_at, updated_at
│
├── user_tenant_memberships
│       tenant_id, user_id, role, joined_at
│
├── user_organization_memberships
│       organization_id, user_id, role, joined_at
│
├── user_group_memberships
│       group_id, user_id, joined_at
│
├── roles
│       id, slug, tenant_id (NULL = system role), display_name, …
│
├── permissions          (seed: PermissionCatalog::ALL)
│       id, slug, display_name, …
│
├── role_permissions
│       role_id, permission_id
│
├── role_assignments
│       id, user_id, role_id, scope_type, scope_id,
│       granted_by, granted_at, expires_at
│
├── subscriptions        (one per tenant)
│       id, tenant_id, plan_id, lifecycle (trial|paid|grace),
│       status, started_at, current_period_end, trial_ends_at, …
│
├── subscription_history
│       id, subscription_id, tenant_id, event,
│       from_plan_id, to_plan_id, actor, occurred_at
│
├── invitation_tokens    (migration 0018)
│       id, tenant_id, email, role, issued_by,
│       issued_at, expires_at, accepted_at, accepted_by,
│       revoked_at, revoked_by
│
└── deletion_requests    (migration 0019)
        id, user_id, tenant_id, requested_at, requested_by,
        reason, scheduled_at, executed_at, executed_by,
        cancelled_at, cancelled_by, status (pending|executed|cancelled)

plans (global, not tenant-scoped)
    id, slug, display_name, active,
    features (comma-separated), quotas (name=value,…)

oidc_clients (not tenant-scoped in schema; linked by audience)
    id, client_secret_hash, redirect_uris, allowed_scopes,
    client_type, require_pkce, audience, …

jwt_signing_keys
    kid, public_key, private_key_encrypted, created_at,
    expires_at, retired_at

audit_events (append-only, hash-chained)
    id, kind, actor, subject, scope, detail,
    timestamp, prev_hash, hash

admin_tokens
admin_thresholds
bucket_safety_state
cost_snapshots
schema_meta
```

## Durable Objects (ephemeral / strong-consistency state)

The following state lives in **Cloudflare Durable Objects**, not D1:

| DO class | Purpose |
|---|---|
| `AuthChallengeStore` | Authorization code challenges (single-use, short TTL) |
| `RefreshTokenFamilyStore` | Refresh token family state, rotation, reuse detection |
| `SessionDO` | Active session state (touch, idle timeout, revocation) |
| `RateLimitStore` | Per-family and per-client rate limit counters |

## Scope types for role_assignments

| `scope_type` | `scope_id` references |
|---|---|
| `system` | *(none — global scope)* |
| `tenant` | `tenants.id` |
| `organization` | `organizations.id` |
| `group` | `groups.id` |
| `user` | `users.id` |

## Key invariants

- `users.email` uses `COLLATE NOCASE` — case-insensitive uniqueness per tenant.
- `invitation_tokens`: unique index on `(tenant_id, email)` where pending (accepted_at IS NULL AND revoked_at IS NULL).
- `deletion_requests`: unique index on `user_id` where pending.
- `authenticators.tenant_id` (migration 0020): backfilled from `users.tenant_id`.
- `audit_events` is append-only; rows are never updated or deleted.
- Physical deletion of a user triggers `ON DELETE CASCADE` on authenticators, totp, consent, grants, memberships, role_assignments.

## Migration history

| Migration | Version | Change |
|---|---|---|
| 0001_initial.sql | 1 | Core tables: users, authenticators, consent, grants, oidc_clients |
| 0003_tenancy.sql | 3 | tenants, orgs, groups, memberships, roles, subscriptions, plans |
| 0007_totp.sql | 7 | totp_authenticators, totp_recovery_codes |
| 0009_user_session_index.sql | 9 | user_sessions index table |
| 0010_admin.sql | 10 | admin_tokens, admin_thresholds, bucket_safety_state, cost_snapshots |
| 0011_schema_meta.sql | 11 | schema_meta table (required by migrate-test) |
| 0012–0016 | 12–16 | Tenant boundary FKs, permission catalog, cascade fixes, audit hash chain |
| 0017_csp_nonces.sql | 17 | CSP nonce infrastructure |
| 0018_invitation_tokens.sql | 18 | Invitation token system (RFC 043) |
| 0019_deletion_requests.sql | 19 | User deletion requests / GDPR Article 17 (RFC 044) |
| 0020_authenticator_tenant_id.sql | 20 | `tenant_id` on authenticators (RFC 051) |
