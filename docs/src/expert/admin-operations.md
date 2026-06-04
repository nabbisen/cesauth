# Admin Operations Guide

Operations performed by cesauth system administrators.

## Tenant lifecycle

### Provision a new tenant

```http
POST /api/v1/tenants
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "slug": "acme-corp",
  "display_name": "Acme Corporation",
  "owner_user_id": "u-...",
  "owner_role": "Owner"
}
```

Returns the new `Tenant` object. A `TenantCreated` audit event is emitted.

### Suspend a tenant

```http
POST /api/v1/tenants/:id/status
{ "status": "Suspended" }
```

Suspends the tenant. All active sessions for users in this tenant
remain valid until they expire or are explicitly revoked; new sessions
cannot be created for suspended tenants.

### Delete a tenant (soft)

```http
POST /api/v1/tenants/:id/status
{ "status": "Deleted" }
```

Soft-delete. The tenant row persists for audit trail. A `TenantStatusChanged`
audit event is emitted.

---

## Invitation management

### Issue an invitation

```http
POST /admin/t/:slug/invitations
Content-Type: application/x-www-form-urlencoded

email=alice@example.com&role=tenant_member&csrf_token=...
```

Sends an invitation email to `email`. The invitation link is valid for
**72 hours** (configurable via `DEFAULT_INVITE_TTL_SECS`).

### Revoke a pending invitation

Not yet exposed via the admin console UI. Directly via the service layer:

```rust
invitation::revoke_invitation(&repo, &invite_id, &admin_user_id, now).await
```

---

## Deletion request management

### Admin queue

```http
GET /admin/t/:slug/deletion-requests
```

Shows all pending deletion requests for the tenant.

### Cancel a deletion request

```http
POST /admin/t/:slug/deletion-requests/:id/cancel
```

Cancels a pending request before `scheduled_at`. Emits `DeletionCancelled`.

### Execute immediately (bypass grace period)

```http
POST /admin/t/:slug/deletion-requests/:id/execute
```

Physically deletes the user. **Irreversible.** Emits `DeletionExecuted`.
ON DELETE CASCADE removes all child data (authenticators, sessions, etc.).

---

## Session management

### Revoke all sessions for a user

```http
POST /me/security/sessions/revoke-others
```

(Self-service; for admin-initiated revocation use the admin console.)

### Force-expire idle sessions

The daily cron trigger calls `sweep.rs::run(env)` which:
1. Finds anonymous sessions past their retention window.
2. Finds unconfirmed TOTP enrollments past their confirmation window.
3. (RFC 047) Executes pending deletion requests past `scheduled_at`.

---

## Audit log investigation

Audit events are stored in `audit_events` (D1) with a SHA-256 hash chain.
Each row includes:

| Field | Content |
|---|---|
| `kind` | Event type string (see `audit.rs::EventKind::as_str()`) |
| `actor` | User ID or `null` for system events |
| `subject` | Affected resource ID |
| `scope` | Tenant slug or `"system"` |
| `detail` | JSON payload (operation-specific) |
| `timestamp` | Unix seconds |
| `prev_hash` | SHA-256 of the previous row |
| `hash` | SHA-256 of this row + prev_hash |

To verify chain integrity, compute `sha256(row_canonical_json + prev_hash)`
for each row in insertion order and compare with the stored `hash`.

---

## Plan management

### Change a tenant's subscription plan

```rust
cesauth_core::billing::change_plan(
    &subs_repo, &plan_repo, &history_repo,
    tenant_id, to_plan_id, actor, now,
).await
```

Records a `SubscriptionHistoryEntry` with `event = "plan_changed"`.
No HTTP route is yet exposed; this is called from operator tooling.

---

## Key rotation

JWT signing keys are managed via the `jwt_signing_keys` D1 table.
A new key pair is generated with `JwtSigner::new_key()` and inserted
via `SigningKeyRepository::create()`. The old key is retired
(`retired_at` set) after all tokens signed with it have expired.

See `docs/src/expert/adr/` for design decisions on key lifetimes.
