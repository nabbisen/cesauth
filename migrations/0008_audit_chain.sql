-- ============================================================================
-- 0008_audit_chain.sql
-- ----------------------------------------------------------------------------
-- v0.32.0: Audit log moves from R2 to D1, with hash chain integrity
-- (ADR-010, Phase 1).
--
-- Before this migration, audit events lived as one-NDJSON-object-per-event
-- in the R2 `AUDIT` bucket. There was no ordering, no integrity check, and
-- no efficient way to query by subject or time range. This migration
-- introduces a D1 table with a SHA-256 hash chain over its rows, making
-- audit writes atomic, queryable, and tamper-evident.
--
-- Each row's `chain_hash` covers the previous row's `chain_hash` along
-- with the row's own payload, sequence, timestamp, kind, and id. Mutating
-- any past row would invalidate every subsequent `chain_hash`; an attacker
-- who tampers with the table must rewrite the chain from the tampered
-- point to the head, a workload that grows linearly with the number of
-- intervening events. See ADR-010 for the full rationale and the threat
-- model the chain protects against.
--
-- Phase 2 (v0.33.0) will add the verification cron and the admin
-- "chain valid through row N" UI. This Phase 1 migration only establishes
-- the storage shape and the genesis row.
--
-- R2 deprecation: The R2 `AUDIT` bucket is no longer written to by
-- cesauth. The bucket binding is removed from `wrangler.toml`. Operators
-- with historical R2 audit data may export it with their own tooling
-- before deploying v0.32.0; cesauth itself does not migrate it.
-- ============================================================================

-- audit_events
-- ----------------------------------------------------------------------------
-- The chain ledger and the canonical store of audit events.
--
-- Per-field columns (subject, client_id, ip, user_agent, reason) duplicate
-- top-level fields from the JSON `payload`. The duplication is deliberate:
-- the indexed columns let admin search and per-user audit views run as
-- normal D1 SELECTs, while the `payload` blob is the canonical record that
-- participates in the hash chain. A future schema change adding a new
-- field can update the `payload` JSON shape without altering the indexed
-- columns or the chain semantics.
CREATE TABLE audit_events (
    -- Monotonic sequence within this deployment. Source of "previous row"
    -- ordering; the chain follows seq order. AUTOINCREMENT (not just
    -- the SQLite default rowid behavior) so a deletion + re-insert never
    -- reuses a value.
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Public event identifier (UUID v4). Used for log correlation,
    -- referenced by Workers logging, and shown in admin search.
    id            TEXT    NOT NULL UNIQUE,

    -- Unix timestamp seconds, captured at write time (not row creation,
    -- though they coincide here).
    ts            INTEGER NOT NULL,

    -- EventKind from cesauth_worker::audit::EventKind, snake_cased.
    -- Indexed for kind+ts queries used by the admin search.
    kind          TEXT    NOT NULL,

    -- Optional indexed metadata. NULLs are common and benign — many
    -- event kinds (e.g. failed-but-unidentifiable login) have no
    -- meaningful subject.
    subject       TEXT,
    client_id     TEXT,
    ip            TEXT,
    user_agent    TEXT,
    reason        TEXT,

    -- Canonical event payload (JSON), serialized exactly once at write
    -- time and never re-encoded. The byte sequence stored here is what
    -- `payload_hash` covers — any later "pretty print" or whitespace
    -- normalization would invalidate the chain.
    payload       TEXT    NOT NULL,

    -- SHA-256 (64-char hex) of `payload` bytes. Defense in depth: even
    -- if an attacker rewrites the chain past this row's `chain_hash`,
    -- they still need to produce a payload that hashes to the same
    -- value as the original.
    payload_hash  TEXT    NOT NULL,

    -- Previous row's `chain_hash`. The genesis row uses 64 zeros.
    previous_hash TEXT    NOT NULL,

    -- SHA-256 (64-char hex) over the chain input — see `cesauth_core::
    -- audit::chain::compute_chain_hash` for the canonical layout.
    chain_hash    TEXT    NOT NULL,

    -- Wall-clock at row insert. Same as `ts` for normal writes; kept
    -- as a separate column to preserve the distinction if `ts` ever
    -- comes from outside the writer.
    created_at    INTEGER NOT NULL
);

-- Time-range queries (admin search defaults to "last N events").
CREATE INDEX idx_audit_events_ts ON audit_events(ts);

-- Kind+time queries (e.g. "show me login failures over the past hour").
CREATE INDEX idx_audit_events_kind_ts ON audit_events(kind, ts);

-- Subject queries (e.g. "everything user X did last week"). Partial
-- index because subject is frequently NULL.
CREATE INDEX idx_audit_events_subject ON audit_events(subject)
    WHERE subject IS NOT NULL;

-- Genesis row. Marks the chain origin: every real event chains from
-- here. The all-zero hashes are sentinel values; the chain verifier
-- treats seq=1 as the start condition. The payload `{}` is the empty
-- object — the genesis carries no event semantics, only the chain
-- anchor.
INSERT INTO audit_events (
    seq, id, ts, kind,
    subject, client_id, ip, user_agent, reason,
    payload, payload_hash, previous_hash, chain_hash, created_at
) VALUES (
    1,
    'genesis-' || strftime('%s', 'now'),
    strftime('%s', 'now'),
    'ChainGenesis',
    NULL, NULL, NULL, NULL, NULL,
    '{}',
    -- payload_hash = SHA-256("{}") = 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
    '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
    -- previous_hash and chain_hash for the genesis: all zeros.
    '0000000000000000000000000000000000000000000000000000000000000000',
    '0000000000000000000000000000000000000000000000000000000000000000',
    strftime('%s', 'now')
);
