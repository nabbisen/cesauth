//! cesauth schema topology — the order tables must be exported in
//! and imported in to satisfy foreign-key constraints.
//!
//! This is curated by hand because the FK graph is small (low
//! tens of tables) and changes only on schema migration. Each
//! schema migration that adds a table appends its name in
//! correct topological position. A test pins the list against
//! the actual D1 `sqlite_master` table contents at build time
//! (in v0.21.0+ alongside import) — for now (v0.20.0), the list
//! is operator-trusted.
//!
//! Order rationale (from the migrations under `migrations/`):
//!
//! ```text
//! tenants
//!  ├── organizations          (FK tenants)
//!  │    └── groups            (FK tenants, organizations)
//!  ├── users                  (FK tenants)
//!  │    ├── authenticators    (FK users)
//!  │    └── consent           (FK users, oidc_clients)
//!  ├── oidc_clients           (no tenant FK at this stage)
//!  ├── grants                 (FK users, oidc_clients)
//!  ├── jwt_signing_keys       (no FKs)
//!  ├── admin_tokens           (FK users, optional)
//!  ├── plans                  (no FKs)
//!  ├── subscriptions          (FK tenants, plans)
//!  │    └── subscription_history (FK subscriptions)
//!  ├── permissions            (no FKs)
//!  ├── roles                  (FK tenants, optional)
//!  ├── role_assignments       (FK roles, users)
//!  ├── *_memberships          (FK users, tenants/orgs/groups)
//!  └── anonymous_sessions     (FK users, tenants)
//! ```
//!
//! Audit-side state (`bucket_safety_state`, `cost_snapshots`,
//! `admin_thresholds`) is operator-state, not principal data;
//! ADR-005 §Q1 puts it out of migration scope. It's omitted
//! from this list deliberately. Operators recreate audit-state
//! at the destination from defaults.

/// All cesauth tables that participate in migration, in
/// topological order. The exporter visits them in this order
/// and the importer writes them in this order.
pub const MIGRATION_TABLE_ORDER: &[&str] = &[
    // Top of the FK graph.
    "tenants",

    // Tenant-scoped containers.
    "organizations",
    "groups",

    // Tenant-scoped principals.
    "users",

    // User-scoped credentials.
    "authenticators",

    // OIDC server-side.
    "oidc_clients",
    "consent",
    "grants",
    "jwt_signing_keys",

    // Admin layer.
    "admin_tokens",

    // Billing.
    "plans",
    "subscriptions",
    "subscription_history",

    // Authz.
    "permissions",
    "roles",
    "role_assignments",

    // Memberships — must come after users / tenants /
    // organizations / groups.
    "user_tenant_memberships",
    "user_organization_memberships",
    "user_group_memberships",

    // Anonymous trial — separate cleanup lifecycle (ADR-004).
    "anonymous_sessions",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn no_duplicate_tables() {
        // A duplicate would cause the exporter to push the same
        // table twice; the importer would reject the second
        // appearance as an unknown row.
        let mut seen = HashSet::new();
        for t in MIGRATION_TABLE_ORDER {
            assert!(seen.insert(*t), "duplicate table: {t}");
        }
    }

    #[test]
    fn topology_invariants_hold() {
        // Pin a small set of must-hold orderings. These
        // catch a future re-shuffle that breaks FK direction.
        let pos = |name: &str| MIGRATION_TABLE_ORDER.iter()
            .position(|t| *t == name)
            .unwrap_or_else(|| panic!("table missing: {name}"));

        // Tenants are the root.
        assert!(pos("tenants") < pos("organizations"));
        assert!(pos("tenants") < pos("users"));
        assert!(pos("tenants") < pos("subscriptions"));

        // Organizations before groups (groups can reference
        // organizations).
        assert!(pos("organizations") < pos("groups"));

        // Users before their dependents.
        assert!(pos("users") < pos("authenticators"));
        assert!(pos("users") < pos("consent"));
        assert!(pos("users") < pos("grants"));
        assert!(pos("users") < pos("admin_tokens"));
        assert!(pos("users") < pos("anonymous_sessions"));

        // Memberships come after every principal/container.
        assert!(pos("users")          < pos("user_tenant_memberships"));
        assert!(pos("organizations")  < pos("user_organization_memberships"));
        assert!(pos("groups")         < pos("user_group_memberships"));

        // Roles before role_assignments.
        assert!(pos("roles") < pos("role_assignments"));
        assert!(pos("users") < pos("role_assignments"));

        // Subscriptions and their history.
        assert!(pos("subscriptions") < pos("subscription_history"));
        assert!(pos("plans")         < pos("subscriptions"));
    }
}
