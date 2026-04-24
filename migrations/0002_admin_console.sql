-- ------------------------------------------------------------------------
-- cesauth :: 0002_admin_console.sql
--
-- Adds the state backing the Cost & Data Safety Admin Console
-- introduced in v0.3.0:
--
--   * admin_tokens          : principals for the admin surface.
--                             Provisional per TERMS_OF_USE §14 (revisited
--                             when tenant boundaries land).
--   * bucket_safety_state   : operator-attested R2 bucket safety config.
--                             Workers has no direct read API for R2
--                             "is bucket public?" / CORS / lifecycle;
--                             we record operator attestation here and
--                             alert on staleness.
--   * admin_thresholds      : configurable limits for cost/safety alerts.
--   * cost_snapshots        : daily-ish snapshots of cost-proxy numbers
--                             (D1 row counts, R2 object counts, R2 bytes,
--                             KV entry counts). The dashboard reads
--                             consecutive snapshots to show trend.
--
-- Conventions match 0001_initial.sql (unix seconds, TEXT ids, explicit
-- updated_at from Rust).
-- ------------------------------------------------------------------------

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------------
-- admin_tokens
-- The token's plaintext never lands here; we store `token_hash` = SHA-256
-- of the token text as 64-char lower hex. Comparison on the admin-auth
-- fast path is hash-vs-hash (still constant-time, out of abundance).
--
-- `role` is the authorization role; the four values are defined in
-- core::admin::types::Role. Role upgrade/downgrade is UPDATE-in-place;
-- issuance of a fresh token is a new row. Disabling a token sets
-- `disabled_at` - the row stays for audit continuity.
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_tokens (
    id            TEXT    PRIMARY KEY,
    token_hash    TEXT    NOT NULL UNIQUE,          -- SHA-256(token), lower hex
    role          TEXT    NOT NULL
                  CHECK (role IN ('read_only','security','operations','super')),
    name          TEXT,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER,
    disabled_at   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_admin_tokens_role     ON admin_tokens(role);
CREATE INDEX IF NOT EXISTS idx_admin_tokens_disabled ON admin_tokens(disabled_at);

-- ------------------------------------------------------------------------
-- bucket_safety_state
-- One row per R2 bucket cesauth knows about. Typically two:
-- the AUDIT bucket and the ASSETS bucket.
--
-- The 0/1 flags record the *attested* state; they are not a live
-- reflection of CF's control plane. Operators run
-- `wrangler r2 bucket cors get`, `wrangler r2 bucket lifecycle get`, etc.,
-- confirm the values match this row, and hit "Re-verify" to stamp
-- `last_verified_at`. A stale attestation produces a safety alert.
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bucket_safety_state (
    bucket                TEXT    PRIMARY KEY,
    public                INTEGER NOT NULL DEFAULT 0,
    cors_configured       INTEGER NOT NULL DEFAULT 0,
    bucket_lock           INTEGER NOT NULL DEFAULT 0,
    lifecycle_configured  INTEGER NOT NULL DEFAULT 0,
    event_notifications   INTEGER NOT NULL DEFAULT 0,
    notes                 TEXT,
    last_verified_at      INTEGER,
    last_verified_by      TEXT,                    -- admin token name / id
    updated_at            INTEGER NOT NULL
);

-- ------------------------------------------------------------------------
-- admin_thresholds
-- key/value configuration for alerting. Default rows are seeded at
-- first boot by core::admin::service::ensure_default_thresholds.
--
-- Threshold naming convention (dotted):
--   cost.d1.row_count.warn
--   cost.r2.object_count.warn
--   cost.r2.bytes.warn
--   safety.bucket.verification_staleness_days
--   audit.write_failure_ratio.warn
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_thresholds (
    name         TEXT    PRIMARY KEY,
    value        INTEGER NOT NULL,
    unit         TEXT    NOT NULL,                 -- "count"/"bytes"/"days"/"permille"
    description  TEXT,
    updated_at   INTEGER NOT NULL
);

-- ------------------------------------------------------------------------
-- cost_snapshots
-- Time-series of cost-proxy numbers. Written at most once per hour by the
-- Cost Dashboard view (idempotent per bucket of UTC hour).
--
-- The `service` is a coarse grouping:
--   "d1"        - D1 row counts (per-table breakdown in `metrics` JSON)
--   "r2.audit"  - audit bucket listing totals
--   "r2.assets" - assets bucket listing totals
--   "kv"        - KV (approximated by key count over relevant prefixes)
--   "workers"   - self-maintained request counter
--   "turnstile" - self-maintained siteverify counter
--
-- `metrics` is a JSON object - keeps the schema flexible while keeping
-- the row count bounded (one row per service per hour).
-- ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cost_snapshots (
    id          TEXT    PRIMARY KEY,
    taken_at    INTEGER NOT NULL,
    service     TEXT    NOT NULL,
    metrics     TEXT    NOT NULL                   -- JSON object
);

CREATE INDEX IF NOT EXISTS idx_cost_snapshots_service_time
    ON cost_snapshots(service, taken_at);

-- ------------------------------------------------------------------------
-- Default thresholds (seed data). These are conservative starting points;
-- operators tune via `UPDATE admin_thresholds SET value = ?`.
-- ------------------------------------------------------------------------
INSERT OR IGNORE INTO admin_thresholds (name, value, unit, description, updated_at) VALUES
    ('cost.d1.row_count.warn',                    1000000, 'count',
        'Warn when any D1 table exceeds this row count.',
        strftime('%s','now')),
    ('cost.r2.object_count.warn',                  500000, 'count',
        'Warn when audit bucket exceeds this object count.',
        strftime('%s','now')),
    ('cost.r2.bytes.warn',                       10737418240, 'bytes',
        'Warn when audit bucket exceeds 10 GiB.',
        strftime('%s','now')),
    ('safety.bucket.verification_staleness_days',      30, 'days',
        'Warn when a bucket has not been re-verified within N days.',
        strftime('%s','now')),
    ('audit.write_failure_ratio.warn',                 50, 'permille',
        'Warn when audit-write failures exceed 5% (50/1000).',
        strftime('%s','now'));

-- ------------------------------------------------------------------------
-- Default bucket rows. We track the two buckets cesauth owns; operators
-- flip the attested values to match reality on first login.
-- ------------------------------------------------------------------------
INSERT OR IGNORE INTO bucket_safety_state
    (bucket, public, cors_configured, bucket_lock, lifecycle_configured,
     event_notifications, notes, last_verified_at, last_verified_by, updated_at)
VALUES
    ('AUDIT',  0, 0, 0, 0, 0,
     'Security audit log. MUST NOT be public. Lifecycle recommended.',
     NULL, NULL, strftime('%s','now')),
    ('ASSETS', 0, 0, 0, 0, 0,
     'Static assets served through the Worker. Public egress fine but verify.',
     NULL, NULL, strftime('%s','now'));
