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

    // TOTP authenticators + recovery codes (ADR-009 Q11).
    // Both are user-scoped via FK to `users.id` but the tables
    // themselves don't carry a `tenant_id` column — same shape as
    // `authenticators` (WebAuthn). Treated as `Global` for the
    // SQL-level WHERE clause; the FK graph constrains
    // tenant-filtered exports indirectly through `users`.
    //
    // The `prod-to-staging` redaction profile drops both of these
    // entirely (drop_tables) — TOTP secrets must NOT survive
    // redaction, even hashed. See ADR-009 §Q5 / §Q11.
    "totp_authenticators",
    "totp_recovery_codes",

    // v0.32.0: audit log moved from R2 to D1 with a hash chain
    // (ADR-010, Phase 1). The chain is deployment-scoped — a
    // chain row covers the entire deployment, not a single
    // tenant — so for tenant-scoped exports this table is
    // treated as Global and exported in full. A `--tenant`
    // export of audit_events still includes events from other
    // tenants, which is acceptable: an audit log import would
    // re-establish the chain anyway, and operators running
    // tenant-scoped exports for migration scenarios have other
    // tools to filter audit data after the fact if they need
    // to. The default redaction profiles preserve audit
    // payloads (no PII redaction); the field-level redaction
    // path can address that if needed.
    "audit_events",
];

// ---------------------------------------------------------------------
// Tenant-filter metadata (v0.22.0)
// ---------------------------------------------------------------------

/// How a table participates in tenant-scoped exports.
///
/// `--tenant <slug>` exports just one tenant's worth of data.
/// The exporter has to know which tables to filter and how —
/// this enum captures both pieces. A table that's
/// `TenantScope::Global` is exported in full regardless of
/// `--tenant`; that's correct for `plans`, `permissions`,
/// `oidc_clients` (today — see note below), `jwt_signing_keys`.
///
/// **A note on `oidc_clients`**: in cesauth 0.x the table has
/// no `tenant_id` column. OIDC clients are deployment-global.
/// A future schema migration that adds tenant scoping to OIDC
/// clients will flip this to `TenantScope::OwnColumn`.
///
/// **A note on tenant-scoped indirection**: `authenticators`
/// references `users`, and `users` is tenant-scoped, but
/// `authenticators` itself has no `tenant_id` column. We treat
/// it as `Global` for the SQL-level WHERE clause and rely on
/// the FK graph: a tenant-filtered export of `users` rows
/// constrains which `authenticators` rows the importer's
/// invariant checks would accept downstream. For v0.22.0,
/// indirection through users is **not** filtered at export time
/// — every authenticator ships in a `--tenant` export. That's
/// acceptable for the current threat model (operator running
/// the export trusts the source side); future sharper scoping
/// is tracked in the ROADMAP under post-1.0 polish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantScope {
    /// Table has no tenant association; export in full.
    Global,
    /// Table has its own `tenant_id`-shaped column. Filter on
    /// `WHERE <column> = ?`. The column name is usually
    /// `tenant_id`, but `tenants` itself uses `id`.
    OwnColumn(&'static str),
}

/// Tenant-scope metadata for every table in `MIGRATION_TABLE_ORDER`.
/// Same length, same order — accessed by index. A test pins the
/// invariant.
pub const TENANT_SCOPES: &[TenantScope] = &[
    TenantScope::OwnColumn("id"),                 // tenants
    TenantScope::OwnColumn("tenant_id"),          // organizations
    TenantScope::OwnColumn("tenant_id"),          // groups
    TenantScope::OwnColumn("tenant_id"),          // users
    TenantScope::Global,                          // authenticators (FK users; see module note)
    TenantScope::Global,                          // oidc_clients (deployment-global today)
    TenantScope::Global,                          // consent (FK users + oidc_clients)
    TenantScope::Global,                          // grants (FK users + oidc_clients)
    TenantScope::Global,                          // jwt_signing_keys (deployment-global)
    TenantScope::Global,                          // admin_tokens (FK users; see module note)
    TenantScope::Global,                          // plans (deployment-global)
    TenantScope::OwnColumn("tenant_id"),          // subscriptions
    TenantScope::Global,                          // subscription_history (FK subscriptions)
    TenantScope::Global,                          // permissions (deployment-global)
    TenantScope::OwnColumn("tenant_id"),          // roles
    TenantScope::Global,                          // role_assignments (FK roles+users)
    TenantScope::OwnColumn("tenant_id"),          // user_tenant_memberships
    TenantScope::Global,                          // user_organization_memberships (FK orgs)
    TenantScope::Global,                          // user_group_memberships (FK groups)
    TenantScope::OwnColumn("tenant_id"),          // anonymous_sessions
    TenantScope::Global,                          // totp_authenticators (FK users; see authenticators note)
    TenantScope::Global,                          // totp_recovery_codes (FK users; see authenticators note)
    TenantScope::Global,                          // audit_events (deployment-scoped chain; see MIGRATION_TABLE_ORDER note)
];

/// Look up the tenant scope for a table. Returns `None` for
/// tables not in `MIGRATION_TABLE_ORDER` — caller should bail
/// rather than guess.
pub fn tenant_scope_for(table: &str) -> Option<TenantScope> {
    MIGRATION_TABLE_ORDER.iter()
        .position(|t| *t == table)
        .map(|i| TENANT_SCOPES[i])
}

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

    #[test]
    fn tenant_scopes_aligns_with_table_order() {
        // Length and order must match. A new table added to
        // MIGRATION_TABLE_ORDER without a corresponding
        // TENANT_SCOPES entry would silently mis-attribute
        // scopes; pin the invariant.
        assert_eq!(MIGRATION_TABLE_ORDER.len(), TENANT_SCOPES.len(),
            "MIGRATION_TABLE_ORDER and TENANT_SCOPES must be the same length");
    }

    #[test]
    fn tenant_scope_for_known_tables() {
        // tenants is tenant-scoped on its own id.
        assert_eq!(tenant_scope_for("tenants"),
            Some(TenantScope::OwnColumn("id")));
        // users is tenant-scoped on tenant_id.
        assert_eq!(tenant_scope_for("users"),
            Some(TenantScope::OwnColumn("tenant_id")));
        // plans is global.
        assert_eq!(tenant_scope_for("plans"), Some(TenantScope::Global));
        // jwt_signing_keys is global.
        assert_eq!(tenant_scope_for("jwt_signing_keys"),
            Some(TenantScope::Global));
        // anonymous_sessions is tenant-scoped.
        assert_eq!(tenant_scope_for("anonymous_sessions"),
            Some(TenantScope::OwnColumn("tenant_id")));
    }

    #[test]
    fn tenant_scope_for_unknown_table_is_none() {
        // Defensive — typos surface as None, caller bails.
        assert!(tenant_scope_for("does_not_exist").is_none());
        assert!(tenant_scope_for("").is_none());
    }
}
