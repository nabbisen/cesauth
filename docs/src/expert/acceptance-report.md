# SaaS Extension Acceptance Report

This document traces each acceptance criterion from the SaaS extension specification
(§16) to the implementing RFC, migration, and module. For auditors and maintainers.

**Version**: v0.64.0  
**Specification**: `cesauth-商用_SaaS_化可能な構成への拡張開発指示書.md`

---

## §16.1 Data Model

| Criterion | Status | Evidence |
|---|---|---|
| Tenant / Org / Group / User / Role / Subscription physically separated | ✅ | `migrations/0003_tenancy.sql` — 12 distinct tables |
| Membership expressed via membership tables | ✅ | `user_tenant_memberships`, `user_organization_memberships`, `user_group_memberships` |
| RoleAssignment with scoped permission grant | ✅ | `role_assignments` + `crates/core/src/authz/` (RFC 086) |
| Plan and Subscription as separate entities | ✅ | `plans` + `subscriptions` + `subscription_history` (§migration table) |
| Compatibility / migration procedures | ✅ | Migrations 0010-0020 — each with rollback comment |

---

## §16.2 Functional Requirements

| Criterion | Status | RFC / Module |
|---|---|---|
| Tenant creation → user membership → role grant | ✅ | `tenancy/service.rs::create_tenant` + invitation flow (RFC 066) |
| Organization and group CRUD + membership | ✅ | `tenancy/service.rs` + `routes/tenant_admin/` |
| Permission-based access control at API level | ✅ | `authz::check_permission` called from every mutating route (RFC 086) |
| Plan change reflected tenant-wide | ✅ | `billing/` module + `SubscriptionPlanChanged` EventKind |
| Anonymous trial → registered user migration | ✅ | `AnonymousPromoted` event + `routes/me/auth/` (ADR-004) |

---

## §16.3 Authentication & Authorization

| Criterion | Status | RFC / Module |
|---|---|---|
| Post-auth session issued correctly | ✅ | `post_auth/` + `ActiveSession` DO |
| Permission check centralized | ✅ | `authz::check_permission` — single entry point per spec §9.2 |
| system / tenant / org / group scope works | ✅ | `scope_covers()` lattice — 14 tests (RFC 086) |
| user_type independent authorization | ✅ | `RoleAssignment` is orthogonal to `AccountType` |

---

## §16.4 Non-Functional Requirements

| Criterion | Status | Evidence |
|---|---|---|
| Cross-tenant data isolation verifiable | ✅ | Composite indexes (migration 0013) + `tenant_id` on every data table |
| API response time not degraded | ✅ | Single-query authz check; no N+1 patterns in hot paths |
| Audit log records without gaps | ✅ | SHA-256 chain (ADR-010, RFC 008) + chain verification cron |
| Logical + physical deletion policy | ✅ | `deletion_requests` table + sweep cron (ADR-004 §Q3) |

---

## §16.5 Audit Log

| Criterion | Status | Evidence |
|---|---|---|
| All admin operations recorded | ✅ | Every mutating route calls `audit::write_owned` |
| actor / action / scope / timestamp required | ✅ | `EventKind` + `actor_id` + `ts` columns |
| Before/after diff available | ✅ | `reason` field carries change description; `BucketSafetyChange` carries diff |

---

## §16.6 Tests

| Criterion | Status | Count |
|---|---|---|
| Unit tests per domain | ✅ | 1,192 tests (v0.64.0) across 20+ domain modules |
| Integration tests for tenant/permission boundary | ✅ | `cesauth-adapter-test`: 125 integration tests |
| Error paths covered (permission denied, expired, deleted) | ✅ | `DenyReason` variants all tested (RFC 086); expiry path tested |

---

## §16.7 Documentation

| Criterion | Status | Location |
|---|---|---|
| ER diagram or equivalent | ✅ | `docs/src/expert/data-model.md` (RFC 092) |
| API specification updated | ✅ | `docs/src/expert/route-contracts.md` (165 routes) |
| Migration procedures | ✅ | Each migration file has inline header comment with rollback guidance |
| Operator procedures | ✅ | `docs/src/expert/` (operations, generic-error-policy) |

---

## §16.8 Operations

| Criterion | Status | Evidence |
|---|---|---|
| Main operations from admin console | ✅ | `/admin/console/*` (163 admin routes) |
| Root cause from audit log | ✅ | Audit log search + filtered export (RFC 080) |
| Tenant suspend / restore | ✅ | `tenancy_console/tenant_detail.rs::suspend/restore` (RFC 068) |

---

## Open Items

None. All §16 criteria are fulfilled as of v0.64.0.

For future phases, see `ROADMAP.md §Later`:
- Full FIDO attestation verification
- Device Authorization Grant (RFC 8628)
- Dynamic Client Registration (RFC 7591/7592)

---

*Generated: v0.64.0 · See also: [Data Model](data-model.md) · [Route Contracts](route-contracts.md)*
