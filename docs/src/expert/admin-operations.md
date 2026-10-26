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

**RFC 147.** RFC 044/047 shipped this queue non-functional: all three
routes below audited an outcome and redirected as if it had happened,
without a repository wired behind any of them, and the daily cron never
called the function that was supposed to execute them. Cycle 1 (0.85.1)
stopped the false claims (`501`, no audit event). Cycle 2 (0.86.0) wires
all three to `cesauth_core::deletion` for real, and wires the cron. This
completes RFC 047, two years of releases after it shipped.

### Admin queue

```http
GET /admin/t/:slug/deletion-requests
```

Shows all pending deletion requests for the tenant, server-rendered with a
CSRF token that matches the double-submit cookie (the template's token was
a hardcoded empty string before 0.86.0 — no form on this page could pass
CSRF).

### Cancel a deletion request

```http
POST /admin/t/:slug/deletion-requests/:id/cancel
```

Cancels a pending request via `cesauth_core::deletion::cancel_deletion`. A
`deletion_cancelled` audit event is emitted with `subject` = the affected
user (not the cancelling admin); the row's own `cancelled_by` column
records the acting admin. The `:id` is validated against the caller's
tenant before anything else — a request belonging to another tenant, or
that does not exist, is a `404` with no audit event.

### Execute immediately (bypass grace period)

```http
POST /admin/t/:slug/deletion-requests/:id/execute
```

Executes a pending request immediately via
`cesauth_core::deletion::execute_deletion`, bypassing the grace period.
Physically deletes the user row; `ON DELETE CASCADE` removes every child
table that references `users(id)` (authenticators, sessions, TOTP state,
tenancy memberships and role assignments — 28 tables in all). **One
exception: `invitation_tokens` is not removed.** It carries no foreign key
to `users(id)` — only a plain-text `email` plus `issued_by` / `accepted_by`
/ `revoked_by` user ids — so a deleted user's invitation history for this
tenant survives the deletion. Whether to purge or scrub it is a separate
design question, out of this cycle's scope (RFC 147 §14).

A `deletion_executed` audit event is emitted with `subject` = the deleted
user; the row's `executed_by` column distinguishes an admin-triggered
execution (the admin's principal id) from the daily sweep (`"sweep"`) —
no new audit event kind was added for this. The `:id` is validated against
the caller's tenant the same way `cancel` is.

This is irreversible. Nothing in cesauth makes deletion reversible or
recoverable, and this chapter does not claim GDPR compliance is achieved
by this pipeline existing — only that the three routes above now do what
they say.

---

## Session management

### Revoke all sessions for a user

```http
POST /me/security/sessions/revoke-others
```

(Self-service; for admin-initiated revocation use the admin console.)

### Force-expire idle sessions

The daily cron trigger calls `sweep.rs::run(env)`, which:
1. Finds anonymous sessions past their retention window.
2. Finds unconfirmed TOTP enrollments past their confirmation window.

Independently, the same cron tick also calls `sweep.rs::sweep_pending_deletions(env)`
(RFC 147 cycle 2), which executes every pending deletion request past its
`scheduled_at`. It is a separate function on the same schedule, not a third
step inside `run` — before 0.86.0 it existed and was correct but nothing
called it, so no self-requested or admin-scheduled deletion had ever
executed via the cron.

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
