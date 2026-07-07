// Migration chain integration tests.
//
// These tests apply every migration in `migrations/` to a fresh
// in-memory SQLite database and assert structural invariants that would
// otherwise go undetected until a real D1 deployment.
//
// Run with:
//   cargo-1.91 test -p cesauth-migrate-test
//
// v0.77.0 split the original 881-line file into sibling submodules
// under `migration_chain/`. Each group is scoped to a release or RFC
// milestone. Integration-test module resolution in cargo's
// `tests/` directory requires explicit `#[path]` attributes for
// subdirectory submodules; that's the only difference between this
// layout and the src/ splits in v0.75.0-v0.76.0.

#[path = "migration_chain/common.rs"]
mod common;
#[path = "migration_chain/foundation.rs"]
mod foundation;
#[path = "migration_chain/rfc_023_cross_tenant.rs"]
mod rfc_023_cross_tenant;
#[path = "migration_chain/rfc_024_indexes.rs"]
mod rfc_024_indexes;
#[path = "migration_chain/repair_and_fks.rs"]
mod repair_and_fks;
#[path = "migration_chain/rfc_050_sql.rs"]
mod rfc_050_sql;
#[path = "migration_chain/rfc_051_authenticators.rs"]
mod rfc_051_authenticators;
