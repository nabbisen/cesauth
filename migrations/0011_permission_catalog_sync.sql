-- ----------------------------------------------------------------------------
-- 0011_permission_catalog_sync.sql
-- ----------------------------------------------------------------------------
-- RFC 022: Adds tenant:member:add and tenant:member:remove to the permissions
-- table seed, which were declared in cesauth_core::authz::PermissionCatalog
-- but absent from the 0003 seed.  Also grants them to tenant_admin and
-- system_admin roles so the documented tenant-admin membership-management
-- capability actually works.
--
-- Live consequence before this migration on a fresh deployment:
--   1. Operator promotes a user to `tenant_admin`.
--   2. The user opens /admin/t/acme/users and tries to add a member.
--   3. check_permission returns Denied (tenant:member:add not in the role).
--   4. The action is rejected with 403 Forbidden despite being documented.
--
-- The UPDATE statements use instr() to avoid double-appending if this
-- migration is applied more than once.  `INSERT OR IGNORE` on the
-- permissions rows is idempotent by definition.
-- ----------------------------------------------------------------------------

INSERT OR IGNORE INTO permissions (name, description, created_at) VALUES
    ('tenant:member:add',    'Add user to a tenant',      strftime('%s','now')),
    ('tenant:member:remove', 'Remove user from a tenant', strftime('%s','now'));

-- Grant to system_admin (must be a superset of all built-in roles).
UPDATE roles
   SET permissions = permissions || ',tenant:member:add'
 WHERE id = 'role-system-admin'
   AND instr(permissions, 'tenant:member:add') = 0;

UPDATE roles
   SET permissions = permissions || ',tenant:member:remove'
 WHERE id = 'role-system-admin'
   AND instr(permissions, 'tenant:member:remove') = 0;

-- Grant to tenant_admin (the role that performs member management).
UPDATE roles
   SET permissions = permissions || ',tenant:member:add'
 WHERE id = 'role-tenant-admin'
   AND instr(permissions, 'tenant:member:add') = 0;

UPDATE roles
   SET permissions = permissions || ',tenant:member:remove'
 WHERE id = 'role-tenant-admin'
   AND instr(permissions, 'tenant:member:remove') = 0;

-- SCHEMA_VERSION 11.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '11');
