# Audit log hash chain

> v0.32.0 introduced this chapter alongside the chain mechanism
> itself. It explains the audit log from an operator's
> perspective: where it lives, how to read it, what the chain
> guarantees, and what to do with historical R2 audit data.
> The architectural rationale is in [ADR-010](./adr/010-audit-log-hash-chain.md).

## What's in the audit log

Every authentication event, admin action, and tenancy mutation
that cesauth performs writes a row to the `audit_events` D1
table. The exact list of event kinds lives in
`crates/worker/src/audit.rs::EventKind` (snake-cased into the
`kind` column). Examples: `magic_link_issued`,
`webauthn_verified`, `token_issued`, `admin_user_created`,
`tenant_status_changed`, `anonymous_promoted`.

Each row carries:

- The standard fields (`ts`, `id`, `kind`, `subject`,
  `client_id`, `ip`, `user_agent`, `reason`).
- A canonical JSON `payload` — the same bytes the v0.31.x R2
  NDJSON file used to contain.
- Three chain fields: `payload_hash`, `previous_hash`,
  `chain_hash`.
- An autoincrement `seq` and an opaque `id` (UUID v4).

## Reading the log

```bash
# Most recent 10 events:
wrangler d1 execute cesauth-prod --remote \
  --command "SELECT seq, ts, kind, subject FROM audit_events
             ORDER BY seq DESC LIMIT 10"

# Everything one user did in the past day:
wrangler d1 execute cesauth-prod --remote \
  --command "SELECT seq, ts, kind, reason FROM audit_events
             WHERE subject = 'usr_abc123'
               AND ts > strftime('%s', 'now', '-1 day')
             ORDER BY seq DESC"

# Full row including chain metadata:
wrangler d1 execute cesauth-prod --remote \
  --command "SELECT * FROM audit_events WHERE seq = 12345"
```

The admin console's audit search (under `/admin/console/audit`)
queries the same table through the
`CloudflareAuditQuerySource` adapter — operators who prefer a
GUI to a SQL prompt land on the same data. Search filters
exposed there: kind (exact), subject (exact), date range, limit.

## Chain semantics

Each row's `chain_hash` covers the previous row's `chain_hash`,
the row's own `payload_hash`, plus its `seq`, `ts`, `kind`, and
`id`. Modifying any past row would force its `chain_hash` to
change, which would invalidate the next row's `previous_hash`
binding — the chain breaks at the tampered row.

The exact byte layout is documented at
`crates/core/src/audit/chain.rs::compute_chain_hash`. It's
pinned by tests; changing it is a chain version bump (Phase 2+
work).

The chain protects against a tamper that:

- Modifies the contents of a past row (the row's
  `payload_hash` no longer matches the actual `payload`, OR the
  row's `chain_hash` no longer matches the recomputed hash).
- Deletes a past row (the next row's `previous_hash` no longer
  matches the predecessor's `chain_hash`).
- Reorders rows (sequence numbers no longer match the chain
  ordering).

The chain does NOT protect against:

- A tamper that consistently rewrites every row from the
  tampered point to the head, plus rewrites the recorded
  chain head if there is one (Phase 2 will record chain heads
  to a separate location to defend against this).
- Loss of D1 itself (whole-database deletion). This is a
  durability concern, not an integrity one — backup the D1
  database to address it.
- Insertion of fake events that aren't actually committed by
  cesauth, if the attacker has direct D1 write access. The
  chain still verifies internally; the events just shouldn't
  be there. Defense: restrict D1 write access to cesauth itself
  via Cloudflare API tokens with narrow scopes.

## The genesis row

Migration `0008_audit_chain.sql` inserts a single row at
`seq=1` with `kind='ChainGenesis'`. This is the chain anchor:
every real event chains from here. The genesis row carries:

- `previous_hash` and `chain_hash` set to 64 zeros (the
  `GENESIS_HASH` sentinel).
- `payload` `{}`.
- `payload_hash` `44136fa3...8a` (SHA-256 of the literal `{}`).

The chain verifier (Phase 2) walks ascending and stops at
`seq=1`. Reading the genesis row gives operators a way to
confirm the migration completed cleanly:

```bash
wrangler d1 execute cesauth-prod --remote \
  --command "SELECT seq, kind, chain_hash FROM audit_events WHERE seq = 1"
# Expected: 1 | ChainGenesis | 0000000000000000000000000000000000000000000000000000000000000000
```

## Old R2 audit data

cesauth v0.31.x and earlier wrote audit events to the R2
`AUDIT` bucket. v0.32.0 removed that binding entirely.
Operators upgrading from v0.31.x:

- Existing R2 audit objects remain on your Cloudflare account.
  cesauth does not read or write them.
- The R2 bucket can be retained for historical lookup, archived
  to cold storage, or deleted — operator's choice.
- There is no automated migration of R2 data into the D1
  `audit_events` table. The chain starts fresh at the genesis
  row inserted by migration 0008. If you need continuity over
  the cutover, export R2 events with your own tooling before
  deploying v0.32.0.

The `wrangler.toml` `[[r2_buckets]] binding = "AUDIT"` entry
has been removed from the example. Existing deployments where
operators left the binding in their own `wrangler.toml` will
keep it bound (cesauth simply doesn't reference it any more);
removing the entry yourself is a one-line cleanup.

## Failure modes

Audit writes are best-effort at the worker layer: a D1 INSERT
failure is logged via the platform-level Workers logging and
the request that triggered it continues. The chain itself
cannot tolerate gaps in `seq`, so a "best-effort" failure means
the event is dropped entirely rather than written into a
half-baked row. The next event continues the chain from the
last-good tail; the missing event simply isn't there to verify.

This is the same trade-off v0.31.x made (R2 write failures
also dropped events silently). The difference is that with
the chain, you can detect that nothing was tampered with — the
chain remains internally consistent across the gap, you just
have one fewer event in the record.

If audit writes start failing systematically (every event
fails), the most likely causes are:

- The `audit_events` table doesn't exist (migration 0008 not
  applied). Run `cesauth-migrate plan` to confirm; apply with
  `wrangler d1 migrations apply`.
- D1 quota exhausted (free tier is 500 MB; paid tier is much
  higher but still finite). `wrangler d1 info` shows current
  size.
- Persistent UNIQUE collisions on `seq` (extremely high write
  contention exhausting the 3-attempt retry budget). Indicates
  a malformed traffic shape; investigate the workload.

The Phase 2 verification cron will surface chain-integrity
failures separately from write-availability failures, so this
chapter will get a section on tamper-detection diagnostics
once that ships.

## Verification (Phase 2, v0.33.0)

ADR-010 Phase 2 ships the verification surface in v0.33.0. The
chain is no longer a passive integrity hint — it's actively
walked, cross-checked against a checkpoint stored in a
separate KV namespace, and reported in the admin console.

### What runs and when

A daily cron at 04:00 UTC piggybacks on the existing sweep
schedule. The worker's `scheduled` event handler invokes both
`sweep::run` (anonymous-trial retention sweep, ADR-004) and
`audit_chain_cron::run` (chain verification, this ADR)
independently. A failure in one doesn't block the other.

The cron runs an **incremental** verification: it reads the
last-recorded checkpoint from KV, walks rows above it via
`AuditEventRepository::fetch_after_seq`, verifies every link,
and writes a fresh checkpoint on success. Cold-start runs
(no prior checkpoint) walk from the genesis row.

### What "verification" checks

For each row past the resume point:

1. **`payload_hash` integrity.** SHA-256 of the row's
   `payload` bytes must equal `payload_hash`. Catches
   in-place edits to the payload column.
2. **`chain_hash` integrity.** Recomputed
   `compute_chain_hash(previous_hash, payload_hash, seq, ts,
   kind, id)` must equal `chain_hash`. Catches in-place
   edits to any chain-input field.
3. **Chain linkage.** The row's `previous_hash` must equal
   the actual predecessor row's `chain_hash`. Catches
   deletion of intermediate rows and reordering.
4. **Genesis sentinel.** Row at seq=1 must have
   `kind='ChainGenesis'` and both `previous_hash` and
   `chain_hash` set to the GENESIS_HASH sentinel (64 zero
   characters).

On runs WITH a prior checkpoint the verifier additionally
**cross-checks `checkpoint.chain_hash` against the current
row at `checkpoint.last_verified_seq`**. A mismatch indicates
the chain has been rewritten BEFORE the checkpoint —
wholesale-rewrite tampering, the attack the chain mechanism
alone can't catch.

### Where the checkpoint lives

Workers KV in the existing `CACHE` namespace under the
reserved `chain:` prefix:

| Key                  | Contents                                  |
|----------------------|-------------------------------------------|
| `chain:checkpoint`   | JSON `AuditChainCheckpoint` (last verified seq + chain_hash + verified_at) |
| `chain:last_result`  | JSON `AuditVerificationResult` (the most-recent run's outcome) |

No TTL on either — these are operational records, not cache
values. Only the verifier writes to them; KV holds them
indefinitely.

The defense the dual-store buys is asymmetric: an attacker who
compromises D1 still has to compromise KV synchronously to
evade detection. ADR-010 §"Open questions Q1" documents the
choice in detail.

### Reading the status

The admin console at **`/admin/console/audit/chain`** renders:

- Current chain length (= MAX(seq) at read time, including the
  genesis row).
- Status badge: ✓ chain valid / ⛔ tamper detected at seq=N /
  ⛔ chain history mismatch / no runs yet.
- Last verification timestamp + how many rows the verifier
  walked in that run.
- Checkpoint metadata: last verified seq, recorded chain_hash,
  when. Plus a consistency badge for the checkpoint
  cross-check.
- "Growth since checkpoint" hint if rows have been appended
  between the last verification and now.

### Triggering a full re-verify

The same page has a CSRF-guarded POST form
(`/admin/console/audit/chain/verify`) that runs an immediate
full re-walk from the genesis row. Use after a deploy or
whenever you want fresh confirmation. The full re-verify
ignores the existing checkpoint (so its `checkpoint_consistent`
field is `null`) and replaces the checkpoint with the new
head on success.

The verify-now endpoint is gated on `AdminAction::ViewConsole`
(any admin role) — re-verification is a non-destructive read
operation that produces a fresher status; an attacker who
triggers it gains nothing the chain isn't already saying.

### When a tamper alarm fires

- The cron writes the failing result to `chain:last_result`.
  The admin console picks it up on the next status read.
- Workers logs carry a `console_error!` line: `audit chain
  TAMPER DETECTED: first_mismatch_seq=N, checkpoint_consistent=
  ..., chain_length=...`
- The checkpoint is **not advanced** — the next cron run will
  re-attempt from the same point. This is intentional: the
  operator's job is to investigate the alarm before the chain
  advances past the suspect rows.
- **cesauth keeps writing audit events.** The chain is for
  forensic value, not runtime gating. Refusing to write would
  let an attacker who forged a mismatch take the audit log
  offline. Per ADR-010 §"Open questions Q3".

Investigation steps:

1. SELECT the suspect row and its predecessor:
   ```bash
   wrangler d1 execute cesauth-prod --remote \
     --command "SELECT seq, ts, kind, id, payload_hash,
                       previous_hash, chain_hash
                FROM audit_events
                WHERE seq IN (?, ?)
                ORDER BY seq"
   ```
   (substituting the reported `first_mismatch_seq` and that
   minus one).

2. Reconstruct the expected chain_hash by hand using the
   recipe at the bottom of this chapter (§Diagnostic queries).
   If your manual recompute matches the row's `chain_hash`,
   the chain mechanism's view is internally consistent and the
   alarm came from the checkpoint cross-check —
   wholesale-rewrite scenario; investigate KV access and any
   D1 access logs from outside cesauth.

3. If your manual recompute disagrees with the row's
   `chain_hash`, the row itself was edited in place. Inspect
   what changed: most likely the `payload` column. Cross-
   reference Workers logs around the row's `created_at` to
   identify what wrote it, and check D1 access logs for any
   write that didn't come from cesauth.

4. Once investigation is done, decide whether to:
   - Mark the result as triaged and trigger a fresh full
     re-verify (the verifier's checkpoint will advance past
     the investigation point ONLY if the chain re-verifies as
     valid — which it won't if the tamper is real).
   - Restore from a backup. (cesauth has no built-in audit
     restore; the operator's backup story applies.)

### Inspecting the KV checkpoint directly

```bash
# Read the latest checkpoint:
wrangler kv:key get --binding=CACHE chain:checkpoint

# Read the latest verification result:
wrangler kv:key get --binding=CACHE chain:last_result

# (NEVER hand-write to these keys; doing so would either
#  hide a real tamper alarm or fabricate a fake one.)
```

ADR-010 graduated to **Accepted** in v0.33.0 once Phase 2
shipped and the tamper-detection scenarios were exercised
against deliberately-tampered test data
(`cesauth_adapter_test::audit_chain::tests`, 10 cases).

## Diagnostic queries

```bash
# Chain length:
wrangler d1 execute cesauth-prod --remote \
  --command "SELECT MAX(seq) AS chain_length FROM audit_events"

# Most active subjects in the past 24h:
wrangler d1 execute cesauth-prod --remote \
  --command "SELECT subject, COUNT(*) AS n FROM audit_events
             WHERE ts > strftime('%s', 'now', '-1 day')
               AND subject IS NOT NULL
             GROUP BY subject ORDER BY n DESC LIMIT 20"

# Distribution of event kinds in the past hour:
wrangler d1 execute cesauth-prod --remote \
  --command "SELECT kind, COUNT(*) AS n FROM audit_events
             WHERE ts > strftime('%s', 'now', '-1 hour')
             GROUP BY kind ORDER BY n DESC"

# Verify a single row's chain_hash by hand:
# 1. SELECT the row and its predecessor.
# 2. Reconstruct: SHA-256(prev.chain_hash || ":" ||
#    row.payload_hash || ":" || row.seq || ":" || row.ts ||
#    ":" || row.kind || ":" || row.id)
# 3. Compare to row.chain_hash.
# (For automated whole-chain verification, the v0.33.0 admin
# UI at /admin/console/audit/chain runs a full re-walk on
# demand; the daily cron handles incremental verification
# automatically.)
```

## See also

- [ADR-010: Audit log hash chain](./adr/010-audit-log-hash-chain.md)
  — the architectural decision and the rationale.
- [Storage](./storage.md) — overview of cesauth's storage
  surfaces.
- [Cookie inventory](./cookies.md) — sibling integrity-and-
  visibility document for cesauth's cookies.
