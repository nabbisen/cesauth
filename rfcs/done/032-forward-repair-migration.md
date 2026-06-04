# RFC 032 — Forward repair migration for existing DBs

**Status**: Implemented  
**Priority**: P0/P1 (existing production DB integrity)  
**Size**: Small (~40 LOC SQL)  
**Depends on**: RFC 020 (schema_meta already in place)

## Problem

The rewritten `0004_user_tenancy_backfill.sql` (RFC 020) repairs the
migration chain for **fresh installs only**. Databases that applied the
original broken `0004` still have:

1. `users.email` without `COLLATE NOCASE` → case-sensitive uniqueness
2. `authenticators`, `consent`, `grants` FKs pointing at `users_pre_0004`
   (dropped table name) — SQLite silently accepts these as dangling references

The remediation must be a **new forward migration** (`0016`) applied to all
deployments, not a rewrite of old files.

## Decision

Add `0016_repair_legacy_0004_fk_and_collation.sql`:

1. Detect whether the `users` table lacks `COLLATE NOCASE` via
   `sqlite_master` inspection.
2. If broken: rebuild `users` + three child tables inside
   `PRAGMA foreign_keys = OFF`, restoring `COLLATE NOCASE` and valid FKs.
3. If already correct (fresh install via fixed 0004): skip (idempotent).
4. `PRAGMA foreign_key_check` at end.

## Operator runbook entry

Update `docs/src/deployment/runbook.md` with a "upgrading from v0.52.x to
v0.54.x" section explaining this migration.
