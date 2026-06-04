-- ----------------------------------------------------------------------------
-- 0017_groups_fk_restrict.sql
-- ----------------------------------------------------------------------------
-- RFC 037: Replace ON DELETE SET NULL on groups composite FKs with
-- ON DELETE RESTRICT, fixing a schema defect introduced in RFC 023.
--
-- The defect: ON DELETE SET NULL on composite FK
--   (tenant_id, organization_id) → organizations(tenant_id, id)
-- would attempt to NULL both tenant_id and organization_id when the
-- referenced organization is hard-deleted. Since tenant_id is NOT NULL,
-- this causes a constraint error instead of the intended "null out the
-- organization reference".
--
-- The domain model already prevents hard deletes via soft-delete
-- (status='deleted'). RESTRICT makes the schema enforce what the
-- service layer already assumes: if code tries to hard-delete a
-- referenced organization or parent group, it fails explicitly rather
-- than corrupting data silently.
-- ----------------------------------------------------------------------------

PRAGMA foreign_keys = OFF;

ALTER TABLE groups RENAME TO groups_pre_0017;

CREATE TABLE groups (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id),
    parent_kind        TEXT NOT NULL CHECK (parent_kind IN ('tenant', 'organization')),
    organization_id    TEXT,
    slug               TEXT NOT NULL,
    display_name       TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('active', 'deleted')),
    parent_group_id    TEXT,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    CHECK (
        (parent_kind = 'tenant'       AND organization_id IS NULL) OR
        (parent_kind = 'organization' AND organization_id IS NOT NULL)
    ),
    -- RFC 037: RESTRICT instead of SET NULL — hard deletes of referenced
    -- orgs/groups are refused; soft delete (status='deleted') is the path.
    FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, parent_group_id)
        REFERENCES groups(tenant_id, id)
        ON DELETE RESTRICT
);

INSERT INTO groups SELECT * FROM groups_pre_0017;
DROP TABLE groups_pre_0017;

-- Restore indexes.
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_tenant_slug
    ON groups(tenant_id, slug) WHERE parent_kind = 'tenant';
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_org_slug
    ON groups(organization_id, slug) WHERE parent_kind = 'organization';
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_tenant_id_id
    ON groups(tenant_id, id);

PRAGMA foreign_key_check;

PRAGMA foreign_keys = ON;

-- SCHEMA_VERSION 17.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '17');
