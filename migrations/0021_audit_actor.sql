-- ----------------------------------------------------------------------------
-- 0021_audit_actor.sql
-- ----------------------------------------------------------------------------
-- RFC 187: adds a nullable `actor` column to `audit_events`, distinct from
-- `subject`. `subject` holds who the event CONCERNS; for most event kinds
-- that is the acting principal, but for cron-emitted kinds (e.g.
-- AnonymousExpired) and admin-on-behalf kinds (e.g. DeletionExecuted,
-- DeletionCancelled) it is the AFFECTED user while the actor is someone or
-- something else. Before this column, that distinction survived only as
-- free text inside `reason` (RFC 187 §3.1-§3.4).
--
-- No backfill, ever (RFC 187 D2). `actor IS NULL` means UNKNOWN for rows
-- written before this migration (seq below the point this migration ran)
-- and NO PRINCIPAL ACTED for rows written after it (cron/system paths that
-- explicitly pass no actor). The two are distinguished by `seq` relative
-- to the migration point, never by a sentinel value — a sentinel is a
-- value that looks like data, and this column has none.
--
-- `actor` is added to `core::ports::audit::AuditEventRow` and to the
-- `Event` struct that becomes `payload` (crates/backend/src/audit.rs) in
-- the SAME cut that adds this column (RFC 187 D1). The column is an
-- INDEX; the payload is the EVIDENCE — `compute_payload_hash` covers the
-- serialized `Event`, so a column without the matching payload field
-- would be the one audit field editable without detection. See
-- crates/backend/src/audit.rs and crates/core/src/audit/chain.rs for the
-- verification this column does NOT change (compute_chain_hash never
-- reads `actor`, by design — see this migration's own sibling commit's
-- report for the independent re-verification).
--
-- Nullable, same reasoning as 0015's `request_id`: existing rows and the
-- "no principal acted" rows both legitimately have no actor. Indexed the
-- same way `subject` is (0008) — a partial index, because `actor` is
-- frequently NULL (116 of this cut's 127 call sites take the write_owned
-- default of `actor = subject`, and the 11 explicit-treatment sites split
-- 8 real actors / 3 explicit NULLs) — and for the same query shape:
-- `actor_contains`, the audit viewer's filter, parallels `subject_contains`
-- exactly (RFC 187 D4, T5).
-- ----------------------------------------------------------------------------

ALTER TABLE audit_events ADD COLUMN actor TEXT;

CREATE INDEX idx_audit_events_actor ON audit_events(actor)
    WHERE actor IS NOT NULL;

-- SCHEMA_VERSION 21.
INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '21');
