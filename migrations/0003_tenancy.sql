-- ------------------------------------------------------------------------
-- cesauth :: 0003_tenancy.sql
--
-- Tenancy-service foundation. Adds the tables for:
--
--   * tenants / organizations / groups               (tenancy boundary)
--   * user_*_memberships                              (relations, §2.4)
--   * permissions / roles / role_assignments          (authz, §3.5)
--   * plans / subscriptions / subscription_history    (billing, §3.6)
--
-- None of this is hot-path for authentication. Per §11 the priority
-- order is data model first, routes and UI later; this migration
-- lays the full data model so the service layer in `cesauth-core`
-- has somewhere to read from.
--
-- Backwards compatibility: existing rows in `users`, `sessions`, etc.
-- remain untouched. A sentinel row is seeded in `tenants` with the id
-- `tenant-default` so that any follow-up migration that needs to
-- backfill tenant_id on existing tables has a target.
-- ------------------------------------------------------------------------

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------------
-- Tenants
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id            TEXT PRIMARY KEY,
    slug          TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    status        TEXT NOT NULL
                  CHECK (status IN ('pending', 'active', 'suspended', 'deleted')),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);

-- Sentinel bootstrap tenant. Matches `crate::tenancy::DEFAULT_TENANT_ID`.
INSERT OR IGNORE INTO tenants (id, slug, display_name, status, created_at, updated_at)
VALUES ('tenant-default', 'default', 'Default Tenant', 'active',
        strftime('%s','now'), strftime('%s','now'));

-- ------------------------------------------------------------------------
-- Organizations
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organizations (
    id                       TEXT PRIMARY KEY,
    tenant_id                TEXT NOT NULL REFERENCES tenants(id),
    slug                     TEXT NOT NULL,
    display_name             TEXT NOT NULL,
    status                   TEXT NOT NULL
                             CHECK (status IN ('active', 'suspended', 'deleted')),
    parent_organization_id   TEXT REFERENCES organizations(id),
    created_at               INTEGER NOT NULL,
    updated_at               INTEGER NOT NULL,
    UNIQUE (tenant_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_orgs_tenant ON organizations(tenant_id, status);

-- ------------------------------------------------------------------------
-- Groups
-- ------------------------------------------------------------------------
-- `parent_kind` + one of (tenant_id, organization_id) encodes the
-- GroupParent enum. The CHECK enforces exactly one parent flavor.
CREATE TABLE IF NOT EXISTS groups (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id),
    parent_kind        TEXT NOT NULL CHECK (parent_kind IN ('tenant', 'organization')),
    organization_id    TEXT REFERENCES organizations(id),
    slug               TEXT NOT NULL,
    display_name       TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('active', 'deleted')),
    parent_group_id    TEXT REFERENCES groups(id),
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    CHECK (
        (parent_kind = 'tenant'       AND organization_id IS NULL) OR
        (parent_kind = 'organization' AND organization_id IS NOT NULL)
    )
);

-- Uniqueness per tenant for tenant-scoped groups, per org for org-scoped.
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_tenant_slug
    ON groups(tenant_id, slug) WHERE parent_kind = 'tenant';
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_org_slug
    ON groups(organization_id, slug) WHERE parent_kind = 'organization';

-- ------------------------------------------------------------------------
-- Memberships
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_tenant_memberships (
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    user_id     TEXT NOT NULL,     -- REFERENCES users(id) — omit FK for migration order flexibility
    role        TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    joined_at   INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_utm_user ON user_tenant_memberships(user_id);

CREATE TABLE IF NOT EXISTS user_organization_memberships (
    organization_id  TEXT NOT NULL REFERENCES organizations(id),
    user_id          TEXT NOT NULL,
    role             TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    joined_at        INTEGER NOT NULL,
    PRIMARY KEY (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_uom_user ON user_organization_memberships(user_id);

CREATE TABLE IF NOT EXISTS user_group_memberships (
    group_id   TEXT NOT NULL REFERENCES groups(id),
    user_id    TEXT NOT NULL,
    joined_at  INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_ugm_user ON user_group_memberships(user_id);

-- ------------------------------------------------------------------------
-- Permissions catalog (§3.5)
-- ------------------------------------------------------------------------
-- Stored as rows rather than an enum so operators can add their own
-- permission strings for custom workflows without a Rust release.
CREATE TABLE IF NOT EXISTS permissions (
    name        TEXT PRIMARY KEY,
    description TEXT,
    created_at  INTEGER NOT NULL
);

-- Seed the catalog. Matches `cesauth_core::authz::PermissionCatalog::ALL`.
INSERT OR IGNORE INTO permissions (name, description, created_at) VALUES
    ('tenant:read',    'View tenant metadata',                strftime('%s','now')),
    ('tenant:update',  'Edit tenant metadata',                strftime('%s','now')),
    ('tenant:suspend', 'Suspend tenant access',               strftime('%s','now')),
    ('tenant:delete',  'Soft-delete a tenant',                strftime('%s','now')),
    ('organization:create',          'Create an organization',             strftime('%s','now')),
    ('organization:read',            'List / view organizations',          strftime('%s','now')),
    ('organization:update',          'Edit organization metadata',         strftime('%s','now')),
    ('organization:delete',          'Soft-delete an organization',        strftime('%s','now')),
    ('organization:member:add',      'Add user to an organization',        strftime('%s','now')),
    ('organization:member:remove',   'Remove user from an organization',   strftime('%s','now')),
    ('group:create',                 'Create a group',                     strftime('%s','now')),
    ('group:read',                   'List / view groups',                 strftime('%s','now')),
    ('group:update',                 'Edit group metadata',                strftime('%s','now')),
    ('group:delete',                 'Soft-delete a group',                strftime('%s','now')),
    ('group:member:add',             'Add user to a group',                strftime('%s','now')),
    ('group:member:remove',          'Remove user from a group',           strftime('%s','now')),
    ('user:read',                    'List / view users',                  strftime('%s','now')),
    ('user:invite',                  'Invite a new user',                  strftime('%s','now')),
    ('user:disable',                 'Disable a user account',             strftime('%s','now')),
    ('user:delete',                  'Soft-delete a user',                 strftime('%s','now')),
    ('role:assign',                  'Grant a role to a user',             strftime('%s','now')),
    ('role:unassign',                'Revoke a role grant',                strftime('%s','now')),
    ('subscription:read',            'View subscription state',            strftime('%s','now')),
    ('subscription:update',          'Change plan / subscription state',   strftime('%s','now')),
    ('audit:read',                   'Search the audit log',               strftime('%s','now'));

-- ------------------------------------------------------------------------
-- Roles
-- ------------------------------------------------------------------------
-- `tenant_id IS NULL` means "system role" — shipped by cesauth or
-- defined by the operator, usable across all tenants. A concrete
-- tenant_id means a tenant-local role.
CREATE TABLE IF NOT EXISTS roles (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT REFERENCES tenants(id),
    slug          TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    -- permissions stored as a comma-separated list in one TEXT column to
    -- keep this simple; the authz service parses it on read. D1 has no
    -- JSON1 extension, so we go text. Newlines disallowed in slugs so a
    -- comma-delimited list is safe.
    permissions   TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_scope_slug_system
    ON roles(slug) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_scope_slug_tenant
    ON roles(tenant_id, slug) WHERE tenant_id IS NOT NULL;

-- Seed system roles. The permissions column lists comma-separated
-- entries from the `permissions` table above.
INSERT OR IGNORE INTO roles (id, tenant_id, slug, display_name, permissions, created_at, updated_at) VALUES
    ('role-system-admin',          NULL, 'system_admin',
     'System admin',
     'tenant:read,tenant:update,tenant:suspend,tenant:delete,organization:create,organization:read,organization:update,organization:delete,organization:member:add,organization:member:remove,group:create,group:read,group:update,group:delete,group:member:add,group:member:remove,user:read,user:invite,user:disable,user:delete,role:assign,role:unassign,subscription:read,subscription:update,audit:read',
     strftime('%s','now'), strftime('%s','now')),

    ('role-system-readonly',       NULL, 'system_readonly',
     'System readonly',
     'tenant:read,organization:read,group:read,user:read,subscription:read,audit:read',
     strftime('%s','now'), strftime('%s','now')),

    ('role-tenant-admin',          NULL, 'tenant_admin',
     'Tenant admin',
     'tenant:read,tenant:update,organization:create,organization:read,organization:update,organization:delete,organization:member:add,organization:member:remove,group:create,group:read,group:update,group:delete,group:member:add,group:member:remove,user:read,user:invite,user:disable,role:assign,role:unassign,subscription:read,audit:read',
     strftime('%s','now'), strftime('%s','now')),

    ('role-tenant-readonly',       NULL, 'tenant_readonly',
     'Tenant readonly',
     'tenant:read,organization:read,group:read,user:read,subscription:read',
     strftime('%s','now'), strftime('%s','now')),

    ('role-organization-admin',    NULL, 'organization_admin',
     'Organization admin',
     'organization:read,organization:update,organization:member:add,organization:member:remove,group:create,group:read,group:update,group:delete,group:member:add,group:member:remove,user:read',
     strftime('%s','now'), strftime('%s','now')),

    ('role-organization-member',   NULL, 'organization_member',
     'Organization member',
     'organization:read,group:read,user:read',
     strftime('%s','now'), strftime('%s','now'));

-- ------------------------------------------------------------------------
-- Role assignments
-- ------------------------------------------------------------------------
-- scope is (scope_type, scope_id). scope_type ∈ {system, tenant,
-- organization, group, user}. scope_id is NULL only when scope_type
-- is 'system'; the CHECK encodes that invariant.
CREATE TABLE IF NOT EXISTS role_assignments (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    role_id      TEXT NOT NULL REFERENCES roles(id),
    scope_type   TEXT NOT NULL
                 CHECK (scope_type IN ('system','tenant','organization','group','user')),
    scope_id     TEXT,
    granted_by   TEXT NOT NULL,
    granted_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    CHECK (
        (scope_type = 'system' AND scope_id IS NULL) OR
        (scope_type != 'system' AND scope_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_ra_user   ON role_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_ra_scope  ON role_assignments(scope_type, scope_id);

-- ------------------------------------------------------------------------
-- Plans
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS plans (
    id                 TEXT PRIMARY KEY,
    slug               TEXT NOT NULL UNIQUE,
    display_name       TEXT NOT NULL,
    active             INTEGER NOT NULL DEFAULT 1,
    features           TEXT NOT NULL DEFAULT '',  -- comma-separated FeatureFlag list
    quotas             TEXT NOT NULL DEFAULT '',  -- "name=value,name=value" encoding
    price_description  TEXT,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);

-- Seed the four built-in plans. Quotas encode as name=value,... with
-- -1 meaning unlimited (matches `Quota::UNLIMITED`).
INSERT OR IGNORE INTO plans (id, slug, display_name, active, features, quotas, price_description, created_at, updated_at) VALUES
    ('plan-free',       'free',       'Free',       1, 'core',
     'max_users=5,max_organizations=1,max_groups=10',
     'Free tier',               strftime('%s','now'), strftime('%s','now')),
    ('plan-trial',      'trial',      'Trial',      1, 'core,pro_features',
     'max_users=50,max_organizations=5,max_groups=50',
     '14-day trial',            strftime('%s','now'), strftime('%s','now')),
    ('plan-pro',        'pro',        'Pro',        1, 'core,pro_features',
     'max_users=100,max_organizations=10,max_groups=100',
     'Paid',                    strftime('%s','now'), strftime('%s','now')),
    ('plan-enterprise', 'enterprise', 'Enterprise', 1, 'core,pro_features,enterprise_features',
     'max_users=-1,max_organizations=-1,max_groups=-1',
     'Contact sales',           strftime('%s','now'), strftime('%s','now'));

-- ------------------------------------------------------------------------
-- Subscriptions + history
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS subscriptions (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL UNIQUE REFERENCES tenants(id),
    plan_id              TEXT NOT NULL REFERENCES plans(id),
    lifecycle            TEXT NOT NULL CHECK (lifecycle IN ('trial', 'paid', 'grace')),
    status               TEXT NOT NULL
                         CHECK (status IN ('active', 'past_due', 'cancelled', 'expired')),
    started_at           INTEGER NOT NULL,
    current_period_end   INTEGER,
    trial_ends_at        INTEGER,
    status_changed_at    INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS subscription_history (
    id                TEXT PRIMARY KEY,
    subscription_id   TEXT NOT NULL REFERENCES subscriptions(id),
    tenant_id         TEXT NOT NULL REFERENCES tenants(id),
    event             TEXT NOT NULL,
    from_plan_id      TEXT,
    to_plan_id        TEXT,
    from_status       TEXT,
    to_status         TEXT,
    actor             TEXT NOT NULL,
    occurred_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subhist_sub  ON subscription_history(subscription_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_subhist_tenant ON subscription_history(tenant_id, occurred_at DESC);
