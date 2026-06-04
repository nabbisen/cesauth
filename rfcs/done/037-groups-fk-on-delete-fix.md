# RFC 037 — Groups composite FK ON DELETE semantics fix

**Status**: Implemented  
**Priority**: P2 (schema correctness)  
**Size**: Small (1 migration)  
**Depends on**: RFC 023

## Problem

`0013_tenant_composite_keys.sql` sets `ON DELETE SET NULL` on the composite FK
`groups(tenant_id, organization_id) → organizations(tenant_id, id)`.
When `organization_id` is SET NULL, SQLite attempts to also NULL `tenant_id`
(which is NOT NULL) → constraint error on any organization hard delete.

## Decision

`0017_groups_fk_restrict.sql`: rebuild `groups` table replacing `ON DELETE SET NULL`
with `ON DELETE RESTRICT` (hard deletes of referenced orgs/groups are refused;
soft delete via `status='deleted'` is the intended path per the domain model).

Soft delete already prevents hard deletes in normal operation; RESTRICT makes
the schema enforce what the service layer already assumes.
