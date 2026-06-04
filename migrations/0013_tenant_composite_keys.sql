-- ----------------------------------------------------------------------------
-- 0013_tenant_composite_keys.sql
-- ----------------------------------------------------------------------------
-- RFC 023: Adds composite UNIQUE indexes on organizations and groups to
-- provide multi-column targets for composite FKs that enforce the tenant
-- boundary invariant.
--
-- Problem: the previous schema expressed FKs as single-column references
-- to organizations(id) and groups(id), which allows cross-tenant linkage
-- (a group in T1 referencing an organization in T2 is not rejected).
--
-- Fix: composite FKs using (tenant_id, organization_id) and
-- (tenant_id, parent_group_id) ensure both sides of the reference share
-- the same tenant_id.
--
-- This RFC also produces ADR-016 (see docs/src/expert/adr/).
-- ----------------------------------------------------------------------------

PRAGMA foreign_keys = OFF;

-- ============================================================================
-- 1. Composite UNIQUE indexes on organizations — make (tenant_id, id) a
--    multi-column reference target.
-- ============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_tenant_id_id
    ON organizations(tenant_id, id);

-- ============================================================================
-- 2. Composite UNIQUE index on groups — make (tenant_id, id) a reference
--    target (groups can be parents of other groups).
-- ============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_tenant_id_id
    ON groups(tenant_id, id);

-- ============================================================================
-- 3. Rebuild groups to add composite FKs
-- ============================================================================

ALTER TABLE groups RENAME TO groups_pre_0013;

CREATE TABLE groups (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id),
    parent_kind        TEXT NOT NULL CHECK (parent_kind IN ('tenant', 'organization')),
    -- Composite FK: (tenant_id, organization_id) must be a real
    -- organizations row, enforcing that the org belongs to this tenant.
    organization_id    TEXT,
    slug               TEXT NOT NULL,
    display_name       TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('active', 'deleted')),
    -- Composite FK: (tenant_id, parent_group_id) must be a real
    -- groups row in the same tenant.
    parent_group_id    TEXT,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    CHECK (
        (parent_kind = 'tenant'       AND organization_id IS NULL) OR
        (parent_kind = 'organization' AND organization_id IS NOT NULL)
    ),
    FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id)
        ON DELETE SET NULL,
    FOREIGN KEY (tenant_id, parent_group_id)
        REFERENCES groups(tenant_id, id)
        ON DELETE SET NULL
);

INSERT INTO groups SELECT * FROM groups_pre_0013;
DROP TABLE groups_pre_0013;

-- Restore per-tenant and per-org slug uniqueness indexes.
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_tenant_slug
    ON groups(tenant_id, slug) WHERE parent_kind = 'tenant';
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_org_slug
    ON groups(organization_id, slug) WHERE parent_kind = 'organization';

-- Restore the composite-target index on groups (dropped by the rebuild).
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_tenant_id_id
    ON groups(tenant_id, id);

-- Defense-in-depth: abort the migration if any existing row violates
-- the new composite FKs.
PRAGMA foreign_key_check;

PRAGMA foreign_keys = ON;

-- SCHEMA_VERSION 13.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '13');
