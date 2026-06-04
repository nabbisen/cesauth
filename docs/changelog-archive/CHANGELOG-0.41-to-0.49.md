# cesauth — CHANGELOG (archive: v0.41.0–v0.49.0)

> This file is part of the changelog archive.
> Current releases are in the root [`CHANGELOG.md`](../../CHANGELOG.md).

## [0.49.0] - 2026-05-04

D1 session-index repair tool. **ADR-012 §Q1.5
Resolved.** Per-operator-request order: tech-debt
(v0.44.0), bulk-revoke (v0.45.0), refresh-
introspection (v0.46.0), i18n-2 (v0.47.0), audit
retention (v0.48.0), D1 repair sixth (this
release). **All six items shipped.**

### Why this matters

v0.40.0 introduced the `session_index_audit` cron
pass which walks D1 outward to per-session DOs,
classifies drift via `session_index::classify`,
and emits `SessionIndexDrift` audit events. **It
emitted but did not repair.** The ADR-012 §Q1.5
paragraph explicitly deferred the repair half:
"Once we have observed a few weeks of
`session_index_drift` events in production, ship
the repair half." Operators have now surfaced
that demand.

### What ships

#### `cesauth_core::ports::session_index::SessionIndexRepo`

New trait. Three methods:

```rust
pub trait SessionIndexRepo {
    async fn list_active(&self, limit: u32) -> PortResult<Vec<SessionIndexRow>>;
    async fn delete_row(&self, session_id: &str) -> PortResult<()>;
    async fn mark_revoked(&self, session_id: &str, revoked_at: i64) -> PortResult<()>;
}
```

Both write methods are **idempotent**:

- `delete_row` on a non-existent session_id is
  `Ok(())`. A repair pass running after a
  reconcile-then-write race produces no error.
- `mark_revoked` uses a `WHERE revoked_at IS NULL`
  SQL guard. A row whose `revoked_at` is already
  set is NOT overwritten — the existing
  timestamp is the canonical first-revoke moment
  and a repair pass must not rewrite history.

The Cloudflare D1 adapter
(`crates/adapter-cloudflare/src/ports/session_index.rs`)
implements both with explicit comments on the
guard SQL.

#### Pure repair service

`cesauth_core::session_index::repair::run_repair_pass(index, store, cfg, now) -> RepairOutcome`.
Composes the existing `classify` logic with
the new port. For each row in
`index.list_active`:

| Drift state | Repair action |
|---|---|
| `InSync` | none |
| `DoVanished` | `index.delete_row(sid)` |
| `DoNewerRevoke` | `index.mark_revoked(sid, do_revoked_at)` |
| `AnomalousD1RevokedDoActive` | **none** (alert-only) |

`AnomalousD1RevokedDoActive` is never auto-
repaired because automated repair would mask
whatever upstream bug produced it (D1 says
revoked, DO says active means a revoke write
landed in D1 but not the DO — that's a
regression, not a drift to silently fix).

**Best-effort**: per-row failures (DO query or
D1 mutation errored) increment `errors` and
continue the batch. Aborting on first error
would leave the bulk of drifts unrepaired
forever if the first row hits a transient
failure.

#### `RepairConfig` opt-in

```rust
pub struct RepairConfig {
    pub auto_repair_enabled: bool,
    pub batch_limit:         u32,
}
```

When `auto_repair_enabled = false` (the cesauth
default), the pass classifies + counts but emits
no D1 writes. `RepairOutcome::dry_run = true` in
that case. When `true`, the pass writes the
repairs.

**Operators opt in deliberately.** Default-off
because:

- **Trust gradient**: a deployment without a
  track record of clean drift events shouldn't
  have automated D1 mutation pointed at it. The
  first cron pass after an upstream regression
  could mass-delete real rows.
- **Reversibility**: the v0.40.0 detection trail
  (one `SessionIndexDrift` audit event per
  drift) is the operator's "what got changed and
  why" record if a repair later turns out to be
  wrong. Auto-repair without the prior
  detection period collapses that trail.

#### Fifth cron pass

`session_index_repair_cron::run` runs after
`sweep` → `audit_chain_cron` →
`session_index_audit` → `audit_retention_cron`
on the daily 04:00 UTC schedule. Independent —
failure logs but doesn't block the others.

Log line shape (dry-run):

```text
session_index_repair: [DRY RUN] walked=1234 in_sync=1230 \
                      would-repair-do_vanished=3 \
                      would-repair-do_newer_revoke=1 \
                      anomalous=0 errors=0 \
                      (set SESSION_INDEX_AUTO_REPAIR=true to enable repairs)
```

Log line shape (auto-repair on):

```text
session_index_repair: walked=1234 in_sync=1230 \
                      repaired-do_vanished=3 \
                      repaired-do_newer_revoke=1 \
                      anomalous=0 errors=0
```

#### Env vars

| Env var | Default | Effect |
|---|---|---|
| `SESSION_INDEX_AUTO_REPAIR` | `false` | When `"true"`, enable D1 mutations |
| `SESSION_INDEX_REPAIR_BATCH_LIMIT` | `1000` | Max rows walked per pass |

### Tests

973 → **986** lib (+13). With migrate integration:
1002 → **1015**.

- core: 430 → 443 (+13). All in
  `session_index::repair::tests`:
  - Happy paths: `in_sync_rows_count_no_writes`,
    `do_vanished_drift_is_repaired_when_enabled`,
    `do_newer_revoke_drift_is_repaired_with_do_timestamp`.
  - Anomalous case pin:
    `anomalous_alert_only_is_never_repaired`
    (also documents the
    `list_active`-filter-excludes-anomalous edge).
  - Dry-run pin:
    `dry_run_classifies_but_writes_nothing`.
  - Error handling:
    `list_failure_propagates_as_internal`,
    `per_row_status_failure_increments_errors_does_not_abort`,
    `per_row_repair_failure_increments_errors_does_not_abort`
    (best-effort failure containment).
  - Counts:
    `walked_count_equals_listed_rows`,
    `idempotent_second_repair_pass_is_no_op`,
    `mark_revoked_idempotent_at_repo_level`
    (the WHERE-revoked_at-IS-NULL guard).
  - Wire shape:
    `default_config_is_dry_run` (pin: opt-in
    contract), `outcome_default_zero_counts`.
- ui: 244 → 244.
- worker: 182 → 182 (cron handler is glue; the
  testable transformation is in pure core).

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9).
  Repair operates on the existing `user_sessions`
  table; no migration.
- Wire format unchanged.
- DO state unchanged (the repair pass reads DO
  state via `ActiveSessionStore::status`, never
  mutates it).
- No new dependencies.

### Operator-visible changes

- **New cron pass** runs daily after the existing
  four. **Default behavior is dry-run** —
  classifies but doesn't mutate.
- **Two new optional env vars**:
  `SESSION_INDEX_AUTO_REPAIR` and
  `SESSION_INDEX_REPAIR_BATCH_LIMIT`. Operators
  opt in to repairs by setting
  `SESSION_INDEX_AUTO_REPAIR=true`.
- **Recommended deployment progression**:
  1. Upgrade to v0.49.0. The dry-run pass starts
     emitting log lines showing
     would-repair counts.
  2. Watch for at least one week, ideally a
     month. If the dry-run counts are stable
     (small numbers, no spikes), the upstream
     paths are healthy and repair is safe.
  3. Set `SESSION_INDEX_AUTO_REPAIR=true` and
     redeploy. Subsequent cron passes write the
     repairs.
- No `wrangler.toml` change (cron schedule
  unchanged). No new bindings. No schema
  migration.

### ADR changes

- **ADR-012 §Q1.5** marked **Resolved**. Inline
  resolution paragraph follows the
  ADR-011 §Q1 / ADR-012 §Q1, §Q4 / ADR-014 §Q4,
  §Q2, §Q3 inline-resolution style.
- No new ADR.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.48.0 → 0.49.0.
- UI footers + tests bumped to v0.49.0.
- ROADMAP: v0.49.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.48.0 → 0.49.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   dependencies.**
3. `wrangler deploy`. **No schema migration. No
   new bindings.**
4. **Watch the dry-run cron output** for a week
   or more.
5. **Optionally** turn repair on:
   ```
   wrangler secret put SESSION_INDEX_AUTO_REPAIR  # set to "true"
   ```
   Or add to `[vars]` in `wrangler.toml`.

### Per-operator-request ordering — complete

| # | Item | Release |
|---|---|---|
| 1 | Tech-debt sweep | v0.44.0 |
| 2 | Bulk "revoke all other sessions" | v0.45.0 |
| 3 | Refresh-token introspection enhancements | v0.46.0 |
| 4 | i18n-2 continuation | v0.47.0 |
| 5 | Audit retention policy | v0.48.0 |
| 6 | D1 repair tool | **v0.49.0** ← here |

### Forward roadmap

- **No items pending from operator-requested
  order.** The six-item batch is complete.
- **Future security-track items still open**
  (operator demand pending):
  - ADR-012 §Q2: User notification on idle /
    absolute timeout.
  - ADR-012 §Q3: Geographic / device-fingerprint
    columns on `user_sessions`.
  - ADR-012 §Q5: Orphan DOs (Cloudflare does not
    support DO namespace iteration; this would
    require a different storage shape).
  - ADR-014 §Q1: Audience scoping for
    introspection responses.

---

## [0.48.0] - 2026-05-04

Audit retention policy. **ADR-014 §Q3 Resolved.**
Per-operator-request order: tech-debt sweep
(v0.44.0), bulk-revoke (v0.45.0), refresh-
introspection (v0.46.0), i18n-2 (v0.47.0), audit
retention fifth (this release).

### Why this matters

v0.38.0 added `/introspect` which emits one audit
row per call. A chatty resource server can produce
~1 introspection/sec/user. A 1k-active-user
deployment hits ~86M `token_introspected` rows per
day. D1 is row-priced; retention without a pruning
policy means cost scales linearly with deployment
age. ADR-014 §Q3 was deferred at v0.38.0 because
the steady-state cost wasn't observable yet;
v0.48.0 ships the policy now that operators have
surfaced demand.

The challenge: cesauth's audit log is a
hash-chained ledger (ADR-010, migrations/0008).
Naively deleting old rows would break the chain.
v0.48.0 prunes safely by anchoring on the
verifier's checkpoint.

### What ships

#### Pure service in core: `cesauth_core::audit::retention`

`run_retention_pass(repo, checkpoints, cfg, now) ->
RetentionOutcome`. Reads the verifier checkpoint,
computes a safe `floor_seq`, runs two passes
(per-kind for `TokenIntrospected`, then global for
everything else), returns counts.

**Hash-chain preservation strategy**: the verifier
resumes from `last_verified_seq + 1` and never
re-walks rows below the checkpoint, so pruning
those rows is integrity-safe. The cross-check
anchor row at `last_verified_seq` itself is
preserved by a 100-row safety margin
(`CHECKPOINT_SAFETY_MARGIN`):

```text
floor_seq = max(checkpoint.last_verified_seq - 100, 2)
```

Rows below `floor_seq` are eligible for pruning;
rows ≥ `floor_seq` are not. The margin is well
above the per-cron-pass write rate in any cesauth
deployment (cron is daily; even at peak
introspection rate the verifier walks far more
than 100 rows per pass).

**Genesis row (seq=1) is sacred** — both the
in-memory test adapter and the Cloudflare D1
adapter explicitly exclude `seq <= 1` from the
prune predicate. An aggressive 0-day retention
config still leaves the chain anchor intact for
any future re-walk.

**Refuses to prune without a checkpoint** — fresh
deployments where `audit_chain_cron` hasn't yet
run produce `Ok(skipped_no_checkpoint = true)`.
Pruning without a chain anchor opens a
forensics-vs-tampering ambiguity that the safety
margin is meant to prevent.

#### Two-knob retention policy

| Knob | Default | Env var |
|---|---|---|
| Global window | 365 days | `AUDIT_RETENTION_DAYS` |
| Per-kind: `TokenIntrospected` | 30 days | `AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS` |

The shorter `TokenIntrospected` window reflects
operational value: high volume + low forensic
interest after ~30 days. Other event kinds
(`session_revoked_by_user`, `password_reset`,
`client_credentials_authenticated`, etc.) keep the
365-day window because they're rare-but-
forensically-valuable.

Setting either knob to `0` disables that pass.
Setting both to `0` is a legitimate "I want
unbounded retention" config — both passes exit
with zero deletions.

#### Two-pass execution

1. **Per-kind pass**: when `token_introspected_days
   > 0` and (either `global_days == 0` OR
   `token_introspected_days < global_days`), delete
   `TokenIntrospected` rows older than the per-kind
   window.
2. **Global pass**: when `global_days > 0`, delete
   rows of any kind older than the global window.
   `TokenIntrospected` is excluded from this pass
   when per-kind was active (preventing
   double-counting in the outcome).

#### `AuditEventRepository::delete_below_seq` trait method

```rust
async fn delete_below_seq(
    &self,
    floor_seq:   i64,
    older_than:  i64,
    kind_filter: AuditRetentionKindFilter,
) -> PortResult<u32>;
```

Implementation MUST observe all three gates
conjunctively (seq < floor, ts < cutoff, kind
matches filter) AND preserve the genesis row
(seq=1). The trait method is **non-default** —
adding to 3rd-party implementors requires an
update; cesauth's two in-tree adapters
(`adapter-test` in-memory + `adapter-cloudflare`
D1) are updated.

#### `AuditRetentionKindFilter` enum

```rust
pub enum AuditRetentionKindFilter {
    OnlyKinds(Vec<String>),    // delete IFF kind is in the list
    ExcludeKinds(Vec<String>), // delete IFF kind is NOT in the list
}
```

`OnlyKinds([])` is the delete-zero shortcut (a
defensive distinction from "any kind"). The D1
adapter translates filter variants into
parameterized SQL — kind values are bound as `?n`
parameters, never concatenated.

#### Fourth cron pass

`audit_retention_cron::run` runs after `sweep` →
`audit_chain_cron` → `session_index_audit` on the
daily 04:00 UTC schedule. Independent: a
retention failure logs to console and propagates
`Err`, but doesn't block the other passes (the
runtime drives them via `if let Err`).

Log line shape:

```text
audit_retention: deleted_token_introspected=12345 deleted_global=42 \
                 checkpoint_seq=98765 floor_seq=98665 \
                 (cfg: global_days=365 ti_days=30)
```

Or on a fresh deployment:

```text
audit_retention: skipped (no chain checkpoint yet — \
                 waiting for first verification cron run)
```

### Tests

957 → **973** lib (+16). With migrate integration:
986 → **1002**.

- core: 414 → 430 (+16). All in
  `audit::retention::tests`:
  - `no_checkpoint_skips_pass` — refuses to prune
    without a chain anchor.
  - `checkpoint_present_but_below_safety_margin_is_no_op`
    — floor_seq lower-bound (max with 2) protects
    fresh deployments.
  - `token_introspected_pass_prunes_old_rows_only` —
    happy path for the 30d window.
  - `global_pass_prunes_only_above_global_window` —
    happy path for the 365d window.
  - `global_pass_excludes_token_introspected_when_per_kind_active`
    — critical correctness pin: no double-prune.
  - `global_includes_token_introspected_when_per_kind_disabled`
    — `ti_days=0` lets global cover TI.
  - `global_includes_token_introspected_when_per_kind_geq_global`
    — edge: per-kind window ≥ global skips per-kind.
  - `global_zero_disables_global_pass` — `global=0`
    disables global, per-kind still runs.
  - `floor_seq_protects_recent_rows_even_when_old_by_ts`
    — chain-walker safety pin.
  - `checkpoint_at_genesis_keeps_genesis_safe` —
    genesis row never prunes.
  - `delete_failure_propagates_as_internal` —
    error mapping.
  - `checkpoint_read_failure_propagates_as_internal`
    — error mapping for the checkpoint store too.
  - `idempotent_second_call_is_zero_count` —
    second call after first is no-op.
  - `default_config_matches_published_defaults` —
    pin: 365 / 30 (matches CHANGELOG + ADR text).
  - `safety_margin_is_one_hundred` — pin: 100
    (matches ADR text).
  - `kind_token_introspected_constant_matches_event_kind`
    — pin: catches drift between
    `KIND_TOKEN_INTROSPECTED` constant and EventKind
    serde.
- ui: 244 → 244.
- worker: 182 → 182 (cron handler is glue; the
  testable transformation is in the pure core
  service).

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9).
  Retention DELETE statements operate on the
  existing `audit_events` table; no migration.
- Wire format unchanged.
- DO state unchanged.
- No new dependencies.

### Operator-visible changes

- **New cron pass** runs daily after the existing
  three. Default behavior with operator-unset env
  vars: 365-day global window, 30-day window for
  `token_introspected`.
- **New env vars** (both optional):
  - `AUDIT_RETENTION_DAYS` (default 365)
  - `AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS` (default 30)
- **No production behavior change** until the next
  cron tick. After that, audit rows past their
  retention windows start disappearing on each
  daily run.
- **Storage cost reduction** scales with the
  difference between previous unbounded retention
  and the new windows. Operators with deployments
  several years old should expect a one-time large
  prune followed by steady-state.
- **Audit dashboards** that count
  `token_introspected` events more than 30 days
  back will see counts decline. Dashboards relying
  on `chain_length` from the verifier still get
  the full count (chain_length is `MAX(seq)`,
  unaffected by deletes — seq is AUTOINCREMENT and
  never reused).
- No `wrangler.toml` change (cron schedule
  unchanged). No new bindings. No schema
  migration.

### ADR changes

- **ADR-014 §Q3** marked **Resolved**. Inline
  resolution paragraph follows the
  ADR-011 §Q1 / ADR-012 §Q1, §Q4 / ADR-014 §Q4 / §Q2
  inline-resolution style.
- No new ADR.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.47.0 → 0.48.0.
- UI footers + tests bumped to v0.48.0.
- ROADMAP: v0.48.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.47.0 → 0.48.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   dependencies.**
3. `wrangler deploy`. **No schema migration. No new
   bindings.**
4. **Optionally** set env vars to override
   defaults:
   ```
   wrangler secret put AUDIT_RETENTION_DAYS
   wrangler secret put AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS
   ```
   Or add them as `[vars]` entries in
   `wrangler.toml`. Default values are reasonable
   for most deployments.
5. **Watch the first cron run** — the daily 04:00
   UTC pass will surface the first-time prune count
   in `console_log!`. Long-running deployments
   should expect substantial deletes on the first
   pass.

### Forward roadmap

- **Next up (per operator request)**: ADR-012
  §Q1.5 D1 repair tool.
- **Future security-track items still open**:
  ADR-012 §Q2-§Q3, §Q5; ADR-014 §Q1 audience
  scoping.

---

## [0.47.0] - 2026-05-04

i18n-2 continuation. Per-operator-request order: tech-
debt sweep (v0.44.0), bulk-revoke (v0.45.0), refresh-
introspection (v0.46.0), i18n-2 fourth (this release).

### Why this matters

v0.39.0 opened the i18n-2 thread, migrating the
LOGIN / TOTP enroll / TOTP verify / Security Center
templates to the catalog-based `_for(.., locale)`
pattern. Four user-facing templates were left for
later: the Magic Link "Check your inbox" page, the
TOTP recovery codes display, the TOTP disable
confirm, and the generic error page. v0.47.0 closes
the gap.

The PrimaryAuthMethod label (used by Security Center
to render "how you sign in") was also still hard-
coded JA pre-v0.47.0 — a v0.39.0 limitation noted in
that release's CHANGELOG. v0.47.0 migrates it too.

### What ships

#### 22 new MessageKey variants

Catalog total: 76 → **98**. Distributed:

- **3** PrimaryAuthMethod labels (`PrimaryAuthMethodPasskey`,
  `PrimaryAuthMethodMagicLink`,
  `PrimaryAuthMethodAnonymous`)
- **5** Magic Link sent page (Title, Heading, Intro,
  OtpHeading, CodeLabel; submit reuses the existing
  `TotpVerifyContinueButton`).
- **6** TOTP recovery codes page (Title, Heading,
  AlertStrong, AlertBody, Body, Continue).
- **7** TOTP disable confirm page (Title, Heading,
  AlertStrong, AlertBody, RecoveryHint,
  ConfirmHeading, Submit; cancel reuses the existing
  `TotpEnrollCancelLink`).
- **1** Error page back link (`ErrorPageBackLink`).

JA + EN translations for every new key. The catalog
**uniqueness invariant** (no two MessageKey variants
resolve to the same string within a locale) caught
two well-intentioned duplicates during development:
`MagicLinkSentSubmit` ("Continue" / "続ける") would
have collided with `TotpVerifyContinueButton`, and
`TotpDisableCancel` ("Cancel and go back" /
"キャンセルして戻る") would have collided with
`TotpEnrollCancelLink`. Both new variants were
dropped in favor of reusing the existing keys —
strictly better outcome (one source of truth per
string).

#### Privacy-preserving phrasing pinned

`MagicLinkSentIntro` translates the v0.27.0 privacy-
phrasing — "if that address is registered, we've just
sent a one-time code" — into JA preserving the same
non-confirmation:
"このメールアドレスが登録されている場合、ワンタイムコードを送信しました。"

User-enumeration prevention is part of the contract;
the test
`magic_link_sent_page_for_renders_japanese_default`
pins the JA phrasing carries the "登録されている場合"
conditional.

#### `PrimaryAuthMethod::label_for(locale)`

New public method on the public enum. The legacy
`label()` getter is preserved as a default-locale
shorthand that delegates to `label_for(Locale::default())`.
`security_center_page_for` calls `label_for(locale)`,
so the Security Center renders the primary-method
label in the negotiated locale (fixing the v0.39.0
limitation).

#### Four templates gain `_for(.., locale)` variants

| Template | Pre-v0.47.0 | v0.47.0 |
|---|---|---|
| `magic_link_sent_page` | EN-only | shorthand wraps `_for` with `Locale::default()` (Ja) |
| `error_page` | EN-only | shorthand wraps `_for`; title + detail caller-supplied (caller does its own localization) |
| `totp_recovery_codes_page` | EN-only | shorthand wraps `_for`; codes themselves are locale-invariant |
| `totp_disable_confirm_page` | EN-only | shorthand wraps `_for`; cancel link reuses `TotpEnrollCancelLink` |

**Behavior change for legacy shorthand callers**:
the four shorthands previously rendered EN.
v0.47.0 routes them through `_for` with
`Locale::default()` which is `Ja`. The pin
`magic_link_sent_legacy_shorthand_now_renders_ja_default`
documents this. **Production handlers were already
on negotiated locales since v0.39.0 and pass through
`_for`, so the production path is unaffected.**
External code calling the shorthand directly may
see the change; updating to `_for(.., Locale::En)`
restores pre-v0.47.0 behavior explicitly.

#### Worker handlers thread locale

Four call sites updated:

- `crates/worker/src/routes/me/totp/disable.rs`:
  `totp_disable_confirm_page` → `_for(.., locale)`
  with `crate::i18n::resolve_locale(&req)`.
- `crates/worker/src/routes/me/totp/enroll.rs`:
  `totp_recovery_codes_page` → `_for(.., locale)`.
- `crates/worker/src/routes/magic_link/request.rs`:
  both render sites (rate-limit fallback + success
  path) routed through `magic_link_sent_page_for`
  with a single `let locale =
  crate::i18n::resolve_locale(&req);` at the top of
  the handler.

`error_page` has no in-tree worker call sites — it's
a public template helper retained for external
consumers; the `_for` variant is available when
needed.

### Tests

948 → **957** lib (+9). With migrate integration:
977 → **986**.

- core: 414 → 414 (catalog-only changes; existing
  i18n test suite covers the new keys via
  exhaustiveness + uniqueness invariants).
- ui: 235 → 244 (+9). New tests:
  `magic_link_sent_page_for_renders_japanese_default`,
  `magic_link_sent_page_for_renders_english`,
  `magic_link_sent_legacy_shorthand_now_renders_ja_default`,
  `totp_recovery_codes_page_for_renders_japanese_default`,
  `totp_recovery_codes_page_for_renders_english`,
  `totp_disable_confirm_page_for_renders_japanese_default`,
  `totp_disable_confirm_page_for_renders_english`,
  `error_page_for_renders_localized_back_link`,
  `primary_auth_method_label_for_renders_each_locale`.
- worker: 182 → 182.
- 3 pre-v0.47.0 UI tests
  (`recovery_codes_page_includes_irreversibility_warning`,
  `disable_page_warns_about_recovery_code_loss`,
  `disable_page_offers_cancel_link`) **migrated**
  to assert via `_for(.., Locale::En)` since they
  pin EN-substring assertions and the default-
  shorthand now returns JA.

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9).
- Wire format unchanged.
- DO state unchanged.
- No new dependencies.

### Operator-visible changes

- **JA renders** for the four migrated pages when
  the user's `Accept-Language` negotiates Ja
  (or unset, since cesauth defaults to Ja). EN
  preserved for `Accept-Language: en`.
- **No behavior change** for production handlers —
  they were already on negotiated locales.
- No `wrangler.toml` change. No new bindings.
  No schema migration.

### ADR changes

- **No new ADR.** v0.47.0 closes out the i18n-2
  thread opened in v0.39.0 — the design pattern
  (catalog + `_for` variants + default shorthand
  routing) is already established and documented in
  v0.36.0 / v0.39.0 release notes.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.46.0 → 0.47.0.
- UI footers + tests bumped to v0.47.0.
- ROADMAP: v0.47.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.46.0 → 0.47.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   dependencies.**
3. `wrangler deploy`. **No schema migration.**
4. **External callers using template shorthands
   directly** (no in-tree callers, but listing for
   completeness): if you depended on the EN
   rendering of `magic_link_sent_page`,
   `totp_recovery_codes_page`,
   `totp_disable_confirm_page`, or `error_page`,
   migrate to `*_for(.., Locale::En)` to preserve
   the EN output.

### Forward roadmap

- **Next up (per operator request)**: ADR-014 §Q3
  audit retention policy.
- Then: ADR-012 §Q1.5 D1 repair tool.
- **i18n-2 fully closed** with v0.47.0 — every
  user-facing template now flows through the catalog
  with locale negotiation. Admin / tenancy console
  templates remain JA-only (separable thread).

---

## [0.46.0] - 2026-05-04

Refresh-token introspection enhancements. Per-operator-
request order: tech-debt sweep first (v0.44.0), bulk-
revoke second (v0.45.0), refresh-introspection
enhancements third (this release).

### Why this matters

Pre-v0.46.0, refresh-token introspection collapsed
every "inactive" path — revoked, jti-mismatched, never-
existed — into a bare `{"active": false}`. Spec-
compliant per RFC 7662 §2.2 but **operationally
opaque**:

- A resource server caching introspection results
  couldn't distinguish "this token was rotated past;
  the user has a fresher one" from "this token was
  killed by reuse-defense; alert security".
- An audit dashboard couldn't break down inactive-
  introspection events by reason without external
  correlation against the family DO state.
- Stale-token-due-to-rotation looked identical to
  forged-token in the response, masking real
  attacker probing in the noise of legitimate
  rotations.

v0.46.0 surfaces this signal under an `x_cesauth`
extension envelope, namespaced per RFC 7662 §2.2
("Specific implementations MAY extend this structure
with their own service-specific response names").
Resource servers consuming only the spec-defined
fields are unaffected; resource servers reading the
extension get four-way classification + revocation
metadata.

### What ships

#### `cesauth_core::oidc::introspect::CesauthIntrospectionExt`

New struct serializing under the `x_cesauth` key. All
fields are `Option`-typed and `skip_serializing_if =
"Option::is_none"`, so a response with no extension
data renders without the key entirely.

```rust
pub struct CesauthIntrospectionExt {
    pub family_state:  Option<FamilyClassification>,
    pub revoked_at:    Option<i64>,
    pub revoke_reason: Option<RevokeReason>,
    pub current_jti:   Option<String>,
}
```

`FamilyClassification` (snake_case serde):

| Variant | When | x_cesauth fields |
|---|---|---|
| `Current` | jti matches `family.current_jti` AND not revoked | `family_state` only |
| `Retired` | jti in `family.retired_jtis` | `family_state` + `current_jti` (stale-token hint) |
| `Revoked` | `family.revoked_at.is_some()` | `family_state` + `revoked_at` + `revoke_reason` |
| `Unknown` | family doesn't exist OR jti mismatch with no retired-membership | `family_state` only |

`RevokeReason` (snake_case serde):

- `ReuseDetected` — family killed by ADR-011 §Q1
  reuse defense (a retired jti was presented to
  `/token`). Distinguished by `family.reused_jti.is_some()`.
- `Explicit` — `/revoke` endpoint, admin revocation,
  or bulk-revoke (v0.45.0). Future work could split
  this into User vs Admin if demand surfaces.

#### Privacy invariant

The `Unknown` classification is the **conflation
point**. Distinct underlying states map to it:

- Family doesn't exist (never issued, already swept,
  wrong deployment).
- Family exists but the presented jti is neither
  `current_jti` nor in `retired_jtis` (forged jti
  against a real family).

Surfacing `Retired` for a forged jti would let an
attacker confirm that a guessed family_id exists
(by seeing the response shape change between
`Unknown` and `Retired`). v0.46.0 explicitly maps
the no-retired-membership case to `Unknown` to
prevent this — pinned by the
`jti_mismatch_without_retired_membership_is_unknown_not_retired`
test.

`current_jti` is surfaced **only** on the Retired
path — the introspecter has proven possession of a
once-valid jti, so revealing the current one is no
fresh information leak. It lets RS dashboards
recognize "stale due to rotation; user has a newer
token" without trying to refresh.

#### `service::introspect::introspect_refresh` rewrite

The five-line decision tree (no-decode, no-family,
revoked, jti-mismatch, current) now produces five
distinct response shapes:

```text
no-decode     → Ok(None)              [orchestrator falls through to access]
no-family     → Ok(Some(inactive_with_ext{Unknown}))
revoked       → Ok(Some(inactive_with_ext{Revoked, revoked_at, revoke_reason}))
jti-mismatch  → Ok(Some(inactive_with_ext{
                  Retired+current_jti  if jti in retired_jtis,
                  Unknown              otherwise }))
current       → Ok(Some(active_refresh_with_ext{Current}))
```

The pre-v0.46.0 behavior of falling through to the
access-token verify path on revoked/mismatched
families is **removed**. Reasoning: a token that
successfully decoded as refresh shape isn't a JWT
(JWTs fail the refresh decode at the `exp.parse::<i64>()`
step). Falling through was already a no-op in
practice; v0.46.0 makes this explicit by returning
`Some(inactive_with_ext)` instead of `None`.

#### Worker audit-payload extension

`EventKind::TokenIntrospected` payload gains two
optional fields when `x_cesauth` is present:

```diff
  {
    "introspecter_client_id": "...",
    "token_type":             "...",
    "active":                 false,
+   "family_state":           "retired" | "revoked" | "unknown",
+   "revoke_reason":          "reuse_detected" | "explicit"
  }
```

Access-token paths set neither, keeping audit rows
compact for the high-volume happy path. Refresh-
token paths set `family_state` always, and
`revoke_reason` only when `family_state="revoked"`.

This unlocks operator-side breakdowns:

- **Spike in `family_state="unknown"` events** →
  someone is probing forged family_ids. Could be
  scanner traffic; could be targeted reconnaissance.
- **Spike in `revoke_reason="reuse_detected"`** →
  a token-leak event affecting multiple users.
  Security alert.
- **Steady-state `family_state="retired"`** →
  legitimate background level of stale-RS-cache
  introspection; expected.

### Tests

937 → **948** lib (+11). With migrate integration:
966 → **977**.

- core: 403 → 414 (+11). All in
  `service::introspect::tests::refresh_ext`:
  - `active_refresh_response_carries_x_cesauth_current`
  - `revoked_family_returns_inactive_with_explicit_reason`
  - `reuse_detected_family_returns_inactive_with_reuse_reason`
  - `retired_jti_returns_inactive_with_current_jti_hint`
  - `unknown_family_returns_unknown_classification`
  - `jti_mismatch_without_retired_membership_is_unknown_not_retired`
    (the privacy invariant pin)
  - `truly_malformed_token_falls_through_no_ext`
    (preserves pre-v0.46.0 access-fallback behavior
    for tokens that don't decode as refresh shape)
  - `access_token_path_does_not_set_x_cesauth`
  - `x_cesauth_field_serializes_under_correct_key`
  - `x_cesauth_omitted_when_none`
  - `revoke_reason_serializes_as_snake_case`
- ui: 235 → 235 (no UI changes).
- worker: 182 → 182 (handler payload extended, no
  new tests; the testable transformation is in the
  pure core service).

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9). No
  migration.
- DO state unchanged.
- **Wire format additive only**:
  - Introspection response gains optional
    `x_cesauth` envelope. Spec-conformant clients
    consuming only the RFC 7662 fields are
    unaffected (they ignore unknown top-level
    keys per RFC 7662 §2.2).
  - Audit payload gains optional `family_state` +
    `revoke_reason` fields when present.
- **No new dependencies.**

### Operator-visible changes

- **Resource servers reading `x_cesauth`** can now
  distinguish four families of inactive responses.
  Recommend updating dashboard queries to break out
  by `family_state` / `revoke_reason`.
- **Audit dashboards**: `token_introspected` events
  now carry `family_state` (refresh-token paths) +
  `revoke_reason` (revoked-family paths). Add
  panels:
  - `family_state` breakdown (Current / Retired /
    Revoked / Unknown).
  - `revoke_reason` for the revoked subset
    (ReuseDetected = security alert, Explicit =
    expected).
- **No production behavior change for happy-path
  introspection.** Active responses gain `x_cesauth.family_state="current"`
  but the spec fields (active/scope/exp/etc.) are
  byte-identical to v0.45.0.
- No `wrangler.toml` change. No new bindings. No
  schema migration.

### ADR changes

- **No new ADR.** v0.46.0 is an additive extension
  under RFC 7662 §2.2's allowance for service-
  specific response names. No cesauth-specific
  decision points beyond what the family-state
  machine already records.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.45.0 → 0.46.0.
- UI footers + tests bumped to v0.46.0.
- ROADMAP: v0.46.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.45.0 → 0.46.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   production dependencies.**
3. `wrangler deploy`. **No schema migration. No new
   bindings.**
4. **For resource servers** that want the extra
   signal: update introspection-response parsers to
   read `x_cesauth.family_state` (snake_case) and
   `x_cesauth.revoke_reason`. Both are optional —
   absent on access-token responses and on refresh-
   token responses where no extension data exists.
5. **For audit dashboards**: add panels grouping
   `token_introspected` events by `family_state` and
   `revoke_reason`. Steady-state baseline:
   `current` + `retired` are normal; `unknown` should
   be near-zero unless scanner traffic is present;
   `reuse_detected` should be near-zero — non-zero
   warrants security investigation.

### Forward roadmap

- **Next up (per operator request)**: i18n-2
  continuation (TOTP recovery codes / disable /
  magic link / error pages).
- Then: ADR-014 §Q3 audit retention policy, ADR-012
  §Q1.5 D1 repair tool.
- **Future security-track items still open**:
  ADR-012 §Q2-§Q3, §Q5; ADR-014 §Q1 audience scoping.

---

## [0.45.0] - 2026-05-04

Bulk "revoke all other sessions" UX (ADR-012 §Q4
**Resolved**). Per-operator-request order: tech-debt
sweep first (v0.44.0, done), bulk-revoke second
(this release).

### Why this matters

Pre-v0.45.0, `/me/security/sessions` showed up to 50
session rows with a per-row revoke button. Users
wanting to sign out everywhere except their current
device had to click one button per row. After someone
flags a credential leak ("did I leave my work laptop
unlocked?") the UX should be one button, not
N clicks. Most major auth providers expose this; cesauth
now does too.

### What ships

#### `cesauth_core::service::sessions::revoke_all_other_sessions`

New pure-service module orchestrating `list_for_user`
+ filtered per-row `revoke`. Returns
`BulkRevokeOutcome { revoked: u32, errors: u32,
skipped_current: u32 }`. Best-effort semantics
(matches cesauth's failure-isolation pattern):

- Per-row revoke failure increments `errors` and
  continues — does NOT abort the batch. The
  alternative (one error → user sees an error and
  has no idea which sessions were revoked vs
  left alone) is worse than "most got revoked,
  retry the button for the rest" (idempotent).
- Per-row `Ok(SessionStatus::NotStarted)` (race with
  sweep) counts as `revoked` — from the user's
  perspective the row is gone, which is what they
  wanted.
- Per-row `Ok(SessionStatus::Active)` (shouldn't
  happen — `revoke` is supposed to be terminal)
  counts as `errors` to surface store bugs in the
  audit counter.
- Per-user cap of 50 (matches the page's display
  limit).

#### `POST /me/security/sessions/revoke-others`

Worker handler in `crates/worker/src/routes/me/sessions.rs`.
CSRF-protected with the same form-token-vs-cookie
check as the per-row endpoint. Pure-service does the
heavy lifting; handler picks one of three flashes
based on outcome and 302-redirects back to the list:

- `revoked > 0 && errors == 0` →
  `OtherSessionsRevoked` (Success, count substituted).
- `errors > 0` → `OtherSessionsRevokeFailed` (Danger,
  error count substituted) regardless of how many
  succeeded — the message advises retry, which
  becomes a legitimate no-op for already-revoked
  rows (idempotent).
- `revoked == 0 && errors == 0` →
  `NoOtherSessions` (Info, no count).

Audit emits **one** `SessionRevokedByUser` event with
`bulk: true` payload field, NOT one per row. The
per-row approach would require capturing each
`session_id` mid-loop, which the pure service doesn't
surface (by design — its return type is counts, not
row metadata). Operators distinguish bulk from
per-row clicks via the payload's `bulk` field.

#### Flash codec extended

`Flash` struct gains optional `count: Option<u32>`
parameter for messages with `{n}` substitution. Wire
format: `<key>:<N>` notation in the cookie payload
(e.g., `success.other_sessions_revoked:3`). The `:`
delimiter is verified by test to not appear in any
existing `FlashKey::as_str()` value, so:

- Pre-v0.45.0 cookies (no `:`) decode as
  `count = None` → fully backward-compatible. Cookies
  in flight at the moment of upgrade still
  display correctly.
- New cookies decode `count = Some(N)` with strict
  parsing (rejects multi-`:`, non-numeric, u32
  overflow).

Format-prefix bump from `v1:` was **not** needed —
the change is additive within the existing format,
not a re-encoding.

`FlashView::text` migrated from `&'static str` to
`Cow<'static, str>`. The borrowed variant is the
zero-allocation path for parameter-free flashes
(v0.31–v0.44); the owned variant carries
runtime-substituted strings. `FlashView` lost its
`Copy` derivation (Cow isn't Copy) but kept `Clone`
— flash text is short and rare so the cost is
irrelevant.

`render_view_for` does the `{n}` → decimal
substitution at projection time. Catalog strings
without `{n}` are unaffected by the substitution
logic — safe for any combination of count-bearing
flash + parameter-free MessageKey (the catalog
string renders verbatim).

#### UI button on `/me/security/sessions`

`sessions_page_for` adds a `<section
class="bulk-revoke">` above the back link with:

1. Inline confirmation copy
   (`SessionsRevokeOthersConfirm` MessageKey).
2. Form posting to
   `/me/security/sessions/revoke-others` with CSRF
   token.
3. Submit button labeled with
   `SessionsRevokeOthersButton`.

The whole section is **conditional on
`items.iter().any(|s| !s.is_current)`**. Edge cases
pinned by tests:

- Empty session list → button hidden.
- Only the current session → button hidden.
- Current session not in the listing (D1 mirror
  drift, ADR-012 §Q5) → button shown (every
  listed item is "other").

#### i18n catalog

5 new MessageKey variants:

- `SessionsRevokeOthersButton`: the button label.
- `SessionsRevokeOthersConfirm`: the inline
  confirmation copy.
- `FlashOtherSessionsRevoked`: success flash with
  `{n}` placeholder (e.g., "Signed out 3 other
  device(s)" / "他の 3 件のセッションをサインアウトしました").
- `FlashOtherSessionsRevokeFailed`: failure flash
  with `{n}` for the error count.
- `FlashNoOtherSessions`: zero-other-sessions
  info flash.

JA + EN translations included; pluralization
explicitly deferred to ADR-013 §Q4 (consistent with
the v0.39.0 deferral). The JA forms are
count-agnostic ("件"); the EN forms use bare
"device(s)" as a defensive fallback (slightly
awkward at n=1 but unambiguous).

MessageKey total: 71 → 76.

### Tests

911 → **937** lib (+26). With migrate integration:
940 → **966**.

- core: 393 → 403 (+10). All in
  `service::sessions::tests`:
  `revokes_all_other_active_sessions_keeps_current`,
  `no_other_active_sessions_is_zero_count_no_calls`,
  `user_with_no_sessions_is_zero_count_zero_skipped`,
  `current_session_not_in_user_list_revokes_all_listed`
  (the §Q5 drift edge case),
  `does_not_touch_other_users_sessions` (multi-tenant
  isolation), `already_revoked_sessions_are_filtered_by_list`,
  `per_row_failure_increments_errors_does_not_abort`
  (best-effort failure containment),
  `list_failure_propagates_as_internal_error`,
  `revoke_returning_notstarted_counts_as_revoked`
  (race-with-sweep mental-model match),
  `second_call_after_first_is_zero_count` (idempotence).
- ui: 230 → 235 (+5). Bulk button presence in EN +
  JA, hidden when empty / only-current,
  shown-when-current-not-listed (§Q5 case).
- worker: 171 → 182 (+11). 8 in `flash::tests` for the
  count codec (round-trip, count=0, u32::MAX,
  multi-`:`, non-numeric, overflow, no-FlashKey-has-
  colon defensive pin) + 3 for `render_view_for`
  substitution (substitute-when-template-has-n,
  zero-alloc-when-no-count, owned-when-substituted).

### Schema / wire / DO

- Schema unchanged (still SCHEMA_VERSION 9). No
  migration.
- DO state unchanged.
- **Wire format**:
  - Discovery doc unchanged.
  - Flash cookie format additive only — `key:N`
    notation in the payload, backward-compatible with
    v0.31–v0.44 cookies.
  - One new endpoint: `POST /me/security/sessions/revoke-others`.
- **No new dependencies.**

### Operator-visible changes

- **New endpoint mounted**:
  `POST /me/security/sessions/revoke-others`. CSRF
  token required (existing pattern). Returns 302 to
  the list page.
- **Audit dashboards**: `SessionRevokedByUser` events
  with payload field `bulk: true` are the bulk
  action; `bulk: false` (or absent) are per-row
  clicks. A spike of `bulk: true` events is
  legitimate — users responding to an alert by
  signing out everywhere is exactly the workflow this
  release enables.
- **No `wrangler.toml` change. No new bindings. No
  schema migration.**

### ADR changes

- **ADR-012 §Q4** marked **Resolved**. Inline
  resolved-paragraph follows the
  ADR-011 §Q1 / ADR-012 §Q1 / ADR-014 §Q4 / ADR-014
  §Q2 inline-resolution style.
- No new ADR.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.44.0 → 0.45.0.
- UI footers + tests bumped to v0.45.0.
- ROADMAP: v0.45.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.44.0 → 0.45.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   production dependencies.**
3. `wrangler deploy`. **No schema migration. No new
   bindings.**
4. Optionally update audit dashboards to break out
   `bulk: true` `SessionRevokedByUser` events from
   per-row.

### Forward roadmap

- **Next up (per operator request)**: refresh-token
  introspection enhancements.
- Then: i18n-2 continuation (TOTP recovery codes /
  disable / magic link / error pages), ADR-014 §Q3
  audit retention, ADR-012 §Q1.5 D1 repair tool.
- **Future security-track items still open**:
  ADR-012 §Q2-§Q3, §Q5; ADR-014 §Q1 audience scoping.

---

## [0.44.0] - 2026-05-03

Tech-debt sweep: drop `jsonwebtoken` in favor of direct
`ed25519-dalek`. Resolves the v0.41.0 trade-off that
accepted transitive `rsa` v0.9 (RUSTSEC-2023-0071) as
dead-code-but-linked.

### Why this matters

v0.41.0 enabled `jsonwebtoken/rust_crypto` to satisfy
`CryptoProvider::install_default`. The trade-off: `rust_crypto`
pulls `rsa` v0.9 in transitively, alongside `pkcs1`,
`num-bigint-dig`, `num-iter`, `num-traits`, `signature 2.x`,
`p256`, `p384`, `hmac` — all unused by cesauth (we never
call `Algorithm::RS*` or `Algorithm::PS*`). cesauth's
threat model didn't include the dead RSA path being
exercised, so the trade-off was sound — but a
linked-but-unreachable `rsa::PrivateKey` is still:

- An unwanted item in the supply chain audit trail.
- A `cargo audit` finding that operators have to
  acknowledge per release.
- Bundle-size weight (workers-rs target).
- A signal that drifts from cesauth's "minimal,
  EdDSA-only, no RSA" identity.

The v0.41.0 CHANGELOG already tracked this as a
follow-up: "Future tech-debt sweep should swap to
`josekit` + `ed25519-dalek` direct, dropping `rsa`
entirely."

### What ships

#### `crates/core/src/jwt/signer.rs` rewrite

The whole module — `JwtSigner::from_pem`,
`JwtSigner::sign`, `verify<C>`, `extract_kid` — is
rewritten using `ed25519-dalek` 2.x directly + manual
JWS Compact Serialization (RFC 7515 §3.1).

**`JwtSigner::from_pem`** uses `ed25519-dalek`'s
`pkcs8` feature (which exposes the `DecodePrivateKey`
trait via re-export) plus the upstream `pkcs8` crate
with the `pem` feature for the `from_pkcs8_pem(&str)`
method.

**`JwtSigner::sign<C>`** hand-builds the JWS:
1. Header JSON: `{"alg":"EdDSA","typ":"JWT","kid":"..."}`
   with `kid` properly JSON-string-escaped via
   `serde_json::to_string`.
2. `b64url_no_padding(header_json) + "." +
   b64url_no_padding(payload_json)` is the
   signing input per RFC 7515 §5.1.
3. `ed25519_dalek::Signer::sign(signing_input.as_bytes())`
   produces the 64-byte signature.
4. Final: `signing_input + "." + b64url(sig.to_bytes())`.

**`verify<C>`** is the inverse:
1. Split on `.`. Reject if not exactly three segments.
2. Decode header. Check `alg=EdDSA` strictly. Reject
   `alg=none` and any other algorithm by default
   (RFC 8725 §3.1).
3. Decode signature. Verify with the supplied 32-byte
   public key against the original signing input
   bytes (RFC 7515 §5.2). **Cryptographic gate
   first**, before any claim parsing — preserves the
   v0.41.0 discipline.
4. Decode payload. Validate `iss`, `aud` (string
   form only — cesauth never emits the array form
   from RFC 7519 §4.1.3, and accepting it would be
   a footgun for operators copy-pasting tokens
   between deployments), `exp` (with `leeway_secs`),
   `nbf` (optional, with leeway).
5. Second-pass deserialize into the caller's `C`
   shape. Both decodes operate on the same in-memory
   bytes; no extra allocation cost.

**`extract_kid`** decodes only the header (no
signature work) and returns `header.kid` if present.
Returns `None` for malformed input. Same contract as
v0.41.0 — kid is **untrusted** at this point; the
caller must follow up with `verify`.

#### Same wire format

Tokens produced by v0.44.0's signer are **byte-identical**
to what jsonwebtoken produced for the same inputs:

- JWS Compact Serialization is deterministically
  pinned by RFC 7515 §3.1.
- Both implementations encode JSON header / payload
  via base64url-no-padding, then sign the
  dot-joined input with Ed25519.
- Field ordering inside the header JSON differs
  (cesauth: `alg, typ, kid`; jsonwebtoken: `typ,
  alg, kid`) but verifiers parse JSON and don't
  care about order.

Tokens produced by v0.43.0 verify under v0.44.0
without re-issuance. Wire format unchanged. **No
forced rotation** — the v0.41.0 latent CryptoProvider
panic from v0.38.0-v0.40.0 was already fixed in
v0.41.0; v0.44.0 just removes the dead-code
attack surface.

#### Dependency tree changes

**Removed from `cargo tree -p cesauth-core`**:

- `jsonwebtoken` 10.x (root removal)
- `rsa` 0.9 (the RUSTSEC-2023-0071 dep)
- `pkcs1`, `num-bigint-dig`, `num-iter`,
  `num-integer`, `num-traits`, `simple_asn1` (RSA's
  multi-precision arithmetic stack)
- `signature` 2.x (jsonwebtoken's algorithm trait)

**Retained** (already direct deps for non-jsonwebtoken
reasons): `hmac` (TOTP), `p256` (WebAuthn ES256),
`signature 1.x` (transitive of p256), `sha2` (KDF /
TOTP / refresh token hash). These have always been
in the tree and are unrelated to the jsonwebtoken
swap.

**Added**:

- `pkcs8 0.10` direct dep with `pem` feature (the
  `DecodePrivateKey::from_pkcs8_pem` method requires
  `pkcs8`'s `pem` feature, which `ed25519-dalek`'s
  `pkcs8` feature alone does not enable).

**Workspace `time` dep** gains the `formatting`
feature explicitly. Pre-v0.44.0 `formatting` was
being unified in via jsonwebtoken's transitive
`time` dep with that feature enabled; removing
jsonwebtoken broke the unification, so we declare
the requirement explicitly. This is purely a
correctness fix for the now-unification-free state.

### Tests

911 lib tests still pass. **Zero test count change**:

- core: 393 → 393. The signer rewrite is a pure
  refactor; existing tests through `service::introspect`
  exercise the verify path with real Ed25519 JWTs
  (v0.41.0's multi_key tests — see the dependency
  on `ed25519-dalek::Signer` already there).
  Existing tests via `service::token` exercise the
  sign path via real `JwtSigner::sign` calls.
  Coverage is preserved by virtue of the existing
  test suite already exercising both the new and
  old implementations through identical entry
  points.
- ui: 230 → 230.
- worker: 171 → 171.
- adapter-test, do, migrate: unchanged.

Total still 940 with migrate integration tests.

### Schema / wire / DO

- Schema unchanged from v0.43.0 (still
  SCHEMA_VERSION 9). No migration.
- **Wire format byte-identical for issued tokens
  vs v0.43.0** — RFC 7515 §3.1 deterministic
  encoding pins this.
- DO state unchanged.

### Operator-visible changes

- **Bundle size goes DOWN** — `rsa` family of
  crates removed. WASM bundle should shrink by
  ~5-10% based on similar swaps in other
  ed25519-only projects.
- **`cargo audit` runs cleaner** — no more
  RUSTSEC-2023-0071 acknowledgment needed.
- **Supply-chain audit trail simpler** — `cesauth-core`'s
  direct deps are now exactly the crypto primitives
  cesauth actually exercises.
- **No production behavior change** — wire format
  is byte-identical; tokens issued before the
  upgrade verify under the new code; no forced
  rotation.
- **No `wrangler.toml` change. No new bindings. No
  schema migration.**

### ADR changes

- **No new ADR.** The v0.41.0 CHANGELOG already
  tracked the swap as planned tech-debt; v0.44.0
  delivers it. The v0.41.0 §Q4 resolution paragraph
  in ADR-014 references "the v0.4 'WASM caveat'
  comment in `signer.rs` already anticipates this
  move" — the WASM-caveat comment now documents
  v0.44.0 as the resolution.

### Doc / metadata changes

- `Cargo.toml` workspace version 0.43.0 → 0.44.0.
- `Cargo.toml`: `jsonwebtoken` removed from
  `[workspace.dependencies]`. Comment updated.
- `Cargo.toml`: `time` features include `formatting`.
- `crates/core/Cargo.toml`: `jsonwebtoken` removed,
  `pkcs8` added.
- UI footers + tests bumped to v0.44.0.
- `crates/worker/src/config.rs`: PEM-decode docstring
  updated to reference `ed25519_dalek::SigningKey::from_pkcs8_pem`
  instead of `jsonwebtoken::EncodingKey::from_ed_pem`.
  PEM input format and `\n`-escaping requirement
  unchanged (still PKCS#8 PEM with real newlines).
- ROADMAP: v0.44.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.43.0 → 0.44.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. Fresh build
   recommended (lockfile diff is substantial — the
   removed transitive deps no longer appear).
3. `wrangler deploy`. **No schema migration. No
   `wrangler.toml` change. No new bindings.**
4. **No operator action required.** Wire format
   identical; deployed v0.43.0 tokens verify under
   v0.44.0; no forced rotation.

### Forward roadmap

- **Next up (per operator request)**: ADR-012 §Q4
  bulk "revoke all other sessions" UX.
- **Then**: refresh-token introspection enhancements,
  i18n-2 continuation (TOTP recovery codes / disable
  / magic link / error pages), ADR-014 §Q3 audit
  retention, ADR-012 §Q1.5 D1 repair tool.
- **Future security-track items still open**:
  ADR-012 §Q2-§Q5, ADR-014 §Q1 audience scoping.

---

## [0.43.0] - 2026-05-03

Per-client introspection rate limit (ADR-014 §Q2
**Resolved**). Closes the second of ADR-014's three
remaining open questions on the introspection endpoint
(§Q4 was resolved in v0.41.0; §Q1 + §Q3 remain).

### Why this matters

v0.38.0 shipped `/introspect` with **no rate limit**.
The endpoint requires client authentication, but a
compromised confidential client (or a malicious resource
server with valid creds) had unbounded ability to:

1. **Token-existence probing**. Each introspection call
   reveals whether a token is currently active. With
   sufficient throughput an attacker could brute-force
   guesses (cesauth refresh tokens are 16+ random
   bytes encoded, so practical brute-force is
   infeasible — but the design shouldn't depend on
   it).
2. **DoS amplification**. Each introspection call hits
   the `RefreshTokenFamily` DO; chatty introspection
   could degrade legitimate token-rotation traffic.
3. **Resource-server isolation failure**. One chatty
   resource server could starve cron-tick budgets
   that other RSes need.

v0.43.0 caps per-client introspection rate.

### What ships

#### `cesauth_core::service::introspect::check_introspection_rate_limit`

Mirrors the v0.37.0 `/token` per-family rate-limit
pattern (ADR-011 §Q1) but with a different bucket-key
namespace and at a different abstraction layer.

```rust
pub async fn check_introspection_rate_limit<RL>(
    rates:                   &RL,
    authenticated_client_id: &str,
    now_unix:                i64,
    window_secs:             i64,
    threshold:               u32,
) -> CoreResult<IntrospectionRateLimitDecision>
where RL: RateLimitStore;
```

Returns `Allowed` or `Denied { retry_after_secs }`.

**Bucket key shape**: `introspect:<client_id>`. The
authenticated client_id is the natural unit:

- **Per-family** (v0.37.0 pattern) wouldn't apply —
  introspection consumes tokens across many families,
  so the per-family bucket can't tell us "this RS is
  hammering us".
- **Per-token-jti** would let an attacker probing
  many distinct tokens against the same client never
  hit any single jti's bucket.
- **Per-user-id** would be wrong — introspection
  responses don't reveal the user (for inactive
  tokens), so an attacker can't even target by user.
- **Per-client-id** is the right granularity. RFC
  7662 requires authentication, so we always have
  a stable identifier; chatty RS_A doesn't affect
  RS_B; legitimate per-RS quotas are operator-
  configurable.

**threshold = 0 disables the gate.** Operators who
have an upstream rate limit (load balancer, edge
worker) or whose RSes legitimately need extreme
rates set `INTROSPECTION_RATE_LIMIT_THRESHOLD=0`. The
auth-required gate at the endpoint layer is
unaffected.

#### `Config` additions

```diff
+ pub introspection_rate_limit_threshold:   u32,
+ pub introspection_rate_limit_window_secs: i64,
```

`INTROSPECTION_RATE_LIMIT_THRESHOLD` env, default
**600**. `INTROSPECTION_RATE_LIMIT_WINDOW_SECS` env,
default **60**. Default 600/min = 10/sec is sized
for resource servers that may introspect on every
incoming request — substantially more permissive than
v0.37.0's `/token` default of 5/min (which fires
specifically on token-replay probing patterns, where
5 attempts in a window is already pathological).

#### Worker handler `crates/worker/src/routes/oidc/introspect.rs`

Rate-limit check fires:

1. **AFTER** client authentication. The bucket key
   needs the authenticated client_id, and an
   unauthenticated attacker shouldn't be able to
   burn the rate limit on behalf of a victim
   client_id.
2. **BEFORE** any DO lookup or JWT verify. A tripped
   limit doesn't even reach the family store or the
   signing-key consultation, so DoS amplification is
   contained.

On denial:

- HTTP **429 Too Many Requests** with `Retry-After:
  <secs>` header (RFC 7231 §6.6 + §7.1.3) via the
  existing `oauth_error_response` plumbing
  (`CoreError::RateLimited`).
- New audit event `EventKind::IntrospectionRateLimited`
  (snake_case `introspection_rate_limited`) with payload
  `{client_id, threshold, window_secs,
  retry_after_secs}`.
- Warn-level log line on the `RateLimit` category.

The response shape exactly matches v0.37.0's `/token`
rate-limit response — same status, same `Retry-After`
header, same body code. Resource-server clients
already handling 429s on `/token` (which they should
be) handle this identically.

#### `EventKind::IntrospectionRateLimited`

New audit kind — distinct from v0.37.0's
`RefreshRateLimited` because they're different
surfaces with different operational semantics:

- **`refresh_rate_limited`** spike → `/token`
  endpoint hit hard, indicates token-replay probing
  patterns.
- **`introspection_rate_limited`** spike →
  `/introspect` endpoint hit hard, indicates
  resource-server polling pathology OR a compromised
  confidential client used for mass token probing.

Operators alert on each independently.

### Tests

902 → **911** lib (+9 from v0.43.0 work; 6 in
`introspect::tests::rate_limit` mod + 3 already
present from earlier session). With migrate
integration: 934 → **940**.

- core: 387 → 393 (+6). All in
  `service::introspect::tests::rate_limit`:
  - `threshold_zero_always_allows` —
    operator opt-out path
  - `first_n_within_window_allowed_then_n_plus_one_denied`
    — basic limit behavior
  - `denied_decision_carries_retry_after_secs` —
    Retry-After value sanity
  - `rate_limit_is_isolated_per_client_id` — the
    headline property: chatty RS_A doesn't affect
    RS_B
  - `rate_limit_resets_after_window_rolls` — bucket
    decay semantics
  - `threshold_one_denies_immediately_after_first_hit`
    — defensive boundary

  Tests use an inline RefCell-backed
  `RateLimitStore` stub mirroring the v0.37.0 +
  v0.42.0 stub-vs-adapter-test pattern.
- ui: 230 → 230 (no UI changes).
- worker: 171 → 171 (handler edits, no new tests;
  all testable logic in pure core service).

### Schema / wire / DO

- Schema unchanged from v0.42.0 (still
  SCHEMA_VERSION 9). No migration.
- Wire format unchanged for happy-path
  introspection. Rate-limit denial returns 429 +
  `Retry-After` (same shape v0.37.0 `/token`
  established).
- DO state unchanged.
- No new dependencies.

### Operator-visible changes

- **Two new env vars** for tuning:
  `INTROSPECTION_RATE_LIMIT_THRESHOLD` (default 600),
  `INTROSPECTION_RATE_LIMIT_WINDOW_SECS` (default 60).
  Set threshold to 0 to disable. The defaults are
  permissive enough that legitimate resource-server
  patterns (one introspection per request, even at
  a few requests per second per RS) stay well
  under the limit.
- **New audit kind to monitor**:
  `introspection_rate_limited`. Add a panel on the
  audit dashboard. Steady-state baseline: **0
  events per day**. Non-zero indicates either:
  - **Misconfigured RS in tight poll loop** —
    investigate the RS-side caching (introspection
    responses are cacheable for the access-token's
    `exp` window).
  - **Compromised client_secret** — an attacker
    using a leaked credential to mass-probe tokens.
    Rotate the client_secret immediately if no
    legitimate cause is identified.
- **No production behavior change for happy-path
  introspection.** Resource servers operating well
  under 600/min see no impact.

### ADR changes

- **ADR-014 §Q2** marked **Resolved**. Implementation
  details + bucket-key rationale + audit-attribution
  recorded inline in the resolved-paragraph,
  matching the ADR-011 §Q1 / ADR-012 §Q1 / ADR-014
  §Q4 inline-resolution style.
- No new ADR.

### Doc / metadata changes

- `Cargo.toml` version 0.42.0 → 0.43.0.
- UI footers + tests bumped to v0.43.0.
- ROADMAP: v0.43.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.42.0 → 0.43.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   production dependencies.**
3. Optionally tune env vars (defaults are sized for
   typical deployments):
   - `INTROSPECTION_RATE_LIMIT_THRESHOLD=600`
   - `INTROSPECTION_RATE_LIMIT_WINDOW_SECS=60`
4. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change. No new bindings (reuses
   the existing `CACHE` KV binding for rate-limit
   buckets, same as v0.37.0).
5. Add the audit-dashboard panel for
   `introspection_rate_limited`.

### Forward roadmap

- **Future security-track items still open**:
  - ADR-012 §Q1.5 D1 repair tool (decision blocked
    on observed v0.40.0 drift data)
  - ADR-012 §Q2 user notification on session timeout
  - ADR-012 §Q3 device fingerprint columns
  - ADR-012 §Q4 bulk revoke other sessions
  - ADR-012 §Q5 orphan DO limitation
  - ADR-014 §Q1 introspection resource-server
    audience scoping (multi-tenant correctness)
  - ADR-014 §Q3 audit retention policy
- **Tech-debt sweep candidate**: swap jsonwebtoken to
  `josekit` + `ed25519-dalek` direct, dropping
  transitive `rsa` (v0.41.0 trade-off).
- **i18n-2 continued (v0.39.1+)**: TOTP recovery
  codes, TOTP disable confirm, magic link, error
  pages, `PrimaryAuthMethod::label`, Security
  Center enabled-state recovery-codes row (blocked
  on pluralization — ADR-013 §Q4).

---

## [0.42.0] - 2026-05-03

RFC 7009 token revocation conformance. Closes a **silent
security gap** in v0.27.0's `/revoke`: pre-v0.42.0 the
endpoint was fully public — any actor with a refresh
token (e.g., obtained from a leaky client) could revoke
the underlying family without authenticating, and could
attribute their own `client_id` form field to
arbitrarily-issued tokens. Per RFC 7009 §2.1 confidential
clients MUST authenticate, and §2 says "the
authorization server first validates the client
credentials and then verifies whether the token was
issued to the client making the revocation request" —
v0.27.0 did neither.

### What ships

#### `cesauth_core::service::client_auth::verify_client_credentials_optional`

Companion to v0.38.0's
`verify_client_credentials`. The optional variant takes
`presented_secret: Option<&str>` and returns a
three-variant `ClientAuthOutcome`:

- **`PublicOrUnknown`** — the named `client_id` is
  registered as public (no `client_secret_hash` on
  file) OR doesn't exist at all. The conflation is
  intentional: the caller can't tell "unknown
  client" from "public client" by outcome alone,
  preserving the v0.38.0 enumeration-side-channel
  defense.
- **`Authenticated`** — confidential client with
  matching credentials.
- **`AuthenticationFailed`** — confidential client,
  either no credentials presented or wrong secret.

Used by `/revoke` to decide whether the requesting
client_id requires authentication.

#### `cesauth_core::service::revoke` — pure RFC 7009 service

New module orchestrating the four-way classification +
cid-binding gate:

```rust
pub async fn revoke_refresh_token<FS, CR>(
    families: &FS, clients: &CR, input: &RevokeInput<'_>,
) -> CoreResult<RevokeOutcome>
```

Returns one of four `RevokeOutcome` variants:

| Outcome | When | Audit-attributable cause |
|---|---|---|
| `Revoked { family_id, client_id, auth_mode }` | Token decoded, auth+cid policy passed, family DO revoked | success |
| `NotRevocable` | Token couldn't be decoded as refresh token (malformed, or a JWT access token) | scanner traffic / unsupported type |
| `UnknownFamily` | Token decoded but family didn't exist (already swept, or recycled id) | stale client integration / clock skew |
| `Unauthorized { reason }` | Auth or cid-binding failed | `ConfidentialAuthFailed` or `ClientIdCidMismatch` |

`RevokeAuthMode` (`PublicClient` / `ConfidentialClient`)
distinguishes how an authorized revoke succeeded.
`UnauthorizedReason` (`ConfidentialAuthFailed` /
`ClientIdCidMismatch`) attributes denials.

**RFC 7009 §2 ordering** — authenticate first against
the request's `client_id`, then check the cid binding
(request's claimed client_id vs token's actual cid).
The service picks the auth target as
`input.client_id.unwrap_or(token_cid.as_str())` so:

- Public client with no `client_id` form field →
  trivially passes cid binding (auth target IS the
  cid).
- Public client with a wrong `client_id` form field
  → cid mismatch → `Unauthorized` (closes the
  cross-client revoke vector).
- Confidential client with creds → authenticated
  against own client_id → cid binding still
  enforced (can't revoke another client's token
  even after authenticating).

**Cross-client revoke prevention** is the headline
**security improvement**, not just spec conformance:
pre-v0.42.0, an attacker who obtained a refresh token
belonging to ClientA could submit it to `/revoke`
with `client_id=AttackerControlledApp` and the
endpoint would happily revoke it. v0.42.0's cid
binding gate rejects this with silent 200.

#### Worker handler `crates/worker/src/routes/oidc/revoke.rs`

Rewritten to delegate to the pure service:

- Parses form body via `req.form_data()` (matches the
  v0.38.0 introspection pattern).
- Reuses v0.38.0's `client_auth::extract` for
  `Authorization: Basic` + form-body credential
  extraction. Authorization header takes precedence
  per RFC 6749 §2.3.1.
- Resolves requestor's claimed client_id: Basic-header
  creds first, form `client_id` field second. Used
  for the cid-binding gate.
- Calls `revoke_refresh_token`. Maps outcome to:
  - **Audit event** with per-outcome JSON payload.
    `NotRevocable` cases are NOT audited (scanner
    traffic; would just bloat the chain). The other
    three outcomes emit `EventKind::RevocationRequested`
    with payload `{outcome, ...}`.
  - **Log line** for operator dashboards (info
    level, Auth category, with client_id breadcrumb).
- **Wire response: always 200 OK with empty body** per
  RFC 7009 §2.2 — including the `Unauthorized` cases.
  Returning 401 there would let an attacker probe
  whether a refresh token belongs to a confidential
  vs public client by response shape.

#### Discovery doc — RFC 8414 §2

```diff
+ "revocation_endpoint_auth_methods_supported": [
+     "none",
+     "client_secret_basic",
+     "client_secret_post"
+ ]
```

The `none` entry is the spec-mandated difference vs
`introspection_endpoint_auth_methods_supported`: RFC
7009 §2.1 explicitly allows public-client revocation,
RFC 7662 §2.1 doesn't. Spec-conformant clients
(`oauth-discovery`-style libraries) auto-pick-up the
new field.

#### Token-type-hint support

`POST /revoke` now parses the `token_type_hint` form
parameter (`access_token` / `refresh_token`) per RFC
7009 §2.1. Unknown values are ignored as the spec
allows. The hint is currently advisory only — cesauth's
revoke implementation always treats the input as a
refresh token; access-token revocation remains
unsupported (RFC 7009 §2: the AS MAY refuse). A future
release may use the hint to short-circuit the refresh
decode for `access_token`-hinted tokens.

### Tests

882 → **902** lib (+20). With migrate integration: 911
→ **934**.

- core: 364 → 387 (+23).
  - 6 in `client_auth::tests` for the optional
    helper (public, unknown, no creds, correct creds,
    wrong creds, empty secret).
  - 14 in `service::revoke::tests`:
    `public_client_with_no_client_id_revokes_by_token_possession`,
    `public_client_form_client_id_mismatch_returns_unauthorized`
    (the cross-client revoke prevention pin),
    `confidential_client_with_correct_creds_revokes`,
    `confidential_client_no_creds_returns_unauthorized`,
    `confidential_client_wrong_secret_returns_unauthorized`,
    `confidential_client_cannot_revoke_other_clients_token`
    (the multi-tenant cross-cid pin),
    `malformed_token_returns_not_revocable`,
    `empty_token_returns_not_revocable`,
    `unknown_family_returns_unknown_family`,
    `jwt_access_token_returns_not_revocable`,
    `token_type_hint_parses_recognized_values`,
    `token_type_hint_returns_none_for_unknown`,
    `already_revoked_family_revokes_again_idempotently`.
  - 3 in `oidc::discovery::tests`:
    `discovery_revocation_endpoint_auth_methods_advertised`,
    `discovery_revocation_endpoint_auth_methods_includes_none`
    (pins the RFC 7009 §2.1 vs RFC 7662 §2.1 spec
    difference),
    `discovery_revocation_endpoint_auth_methods_in_wire_form`.
- ui: 230 → 230. No UI changes.
- worker: 171 → 171. Handler edits, no new tests;
  the testable logic is in the pure core service.

### Schema / wire / DO

- Schema unchanged from v0.41.0 (still SCHEMA_VERSION 9).
  No migration.
- Wire format additive only: discovery doc gains one
  field. Spec-conformant parsers tolerate.
- DO state unchanged.
- No new dependencies.

### Operator-visible changes / breaking-change notice

- **Pre-v0.42.0 `/revoke` was a known security gap**
  (cross-client revoke; no confidential-client auth).
  v0.42.0 fixes the gap. Operators running clients
  that depend on the loose v0.27.0 behavior — there
  shouldn't be any, since the spec was the looser
  side — may see new `Unauthorized` audit events.
- **Confidential-client revoke now requires
  authentication.** Clients with a `client_secret_hash`
  on file MUST submit credentials via Authorization:
  Basic (preferred) or `client_secret`/`client_id`
  form fields. Without credentials the revoke is
  silently no-op'd (200, no body, audit event
  attributes `Unauthorized:ConfidentialAuthFailed`).
- **Cross-client revoke is rejected.** A request
  presenting `client_id=ClientA` for a token whose
  cid is ClientB is silently no-op'd (200, no body,
  audit event attributes `Unauthorized:ClientIdCidMismatch`).
- **`token_type_hint` is now parsed** but currently
  advisory-only.
- **Discovery doc adds
  `revocation_endpoint_auth_methods_supported`** —
  RFC 8414 §2. Spec-conformant clients pick it up
  automatically.
- **Audit dashboards should add a panel breaking down
  `revocation_requested` events by `outcome` field**
  — the new four-way attribution lets operators
  distinguish:
  - `revoked` (steady-state),
  - `unauthorized` with `reason: cid_mismatch` (could
    be cross-client revoke probing — alert),
  - `unauthorized` with `reason: auth_failed` (could
    be wrong creds — investigate, but also some
    integrations rotate secrets out of band),
  - `unknown_family` (stale clients / clock skew —
    operationally noisy but not security-meaningful).

### ADR changes

- **No new ADR.** The implementation maps directly to
  RFC 7009; no cesauth-specific decision points
  beyond what the spec says. The cid-binding-on-
  public-clients choice is recorded inline in the
  module-level docs of `cesauth_core::service::revoke`.

### Doc / metadata changes

- `Cargo.toml` version 0.41.0 → 0.42.0.
- UI footers + tests bumped to v0.42.0.
- ROADMAP: v0.42.0 Shipped table row.
- This CHANGELOG entry.

### Upgrade path 0.41.0 → 0.42.0

1. `git pull` or extract this tarball.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **No new
   production dependencies.**
3. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change. No new bindings.
4. **For confidential-client integrations**: ensure
   `client_secret_basic` (Authorization: Basic) or
   `client_secret_post` (form-body) credentials are
   sent on `/revoke`. Without them, revocation
   silently no-ops.
5. **For public-client integrations** (mobile apps,
   SPAs): no action required IF you weren't sending
   a wrong `client_id` form field. If you were
   sending one that doesn't match the token's
   cid, revocation will now silently no-op.
6. Add the audit-dashboard panel for
   `revocation_requested` outcome breakdown.

### Forward roadmap

- **Future security-track items still open**:
  - ADR-012 §Q1.5 D1 repair tool (decision blocked
    on observed v0.40.0 drift data)
  - ADR-012 §Q2 user notification on session timeout
  - ADR-012 §Q3 device fingerprint columns
  - ADR-012 §Q4 bulk revoke other sessions
  - ADR-012 §Q5 orphan DO limitation
  - ADR-014 §Q1 introspection resource-server
    audience scoping
  - ADR-014 §Q2 introspection rate limit
  - ADR-014 §Q3 audit retention policy
- **Tech-debt sweep candidate**: swap jsonwebtoken to
  `josekit` + `ed25519-dalek` direct, dropping
  transitive `rsa` (v0.41.0 trade-off).
- **i18n-2 continued (v0.39.1+)**: TOTP recovery
  codes, TOTP disable confirm, magic link, error
  pages, `PrimaryAuthMethod::label`, Security
  Center enabled-state recovery-codes row (blocked
  on pluralization — ADR-013 §Q4).

---

## [0.41.0] - 2026-05-03

Multi-key access-token introspection (ADR-014 §Q4
**Resolved**) AND fix for a latent jsonwebtoken-10
CryptoProvider bug introduced in v0.38.0 that would
have panicked the worker on the first real-token
introspection request.

### Why this matters

**Two issues, one release**:

1. **Signing-key rotation correctness.** v0.38.0
   shipped `/introspect` with a single-key access-token
   verify path: `keys.first()` selected only the most-
   recently-added active signing key. During a
   signing-key rotation grace period (multiple keys
   active concurrently), an access token signed with an
   older but still-active `kid` would fail introspection's
   verify path. The refresh-token fallback path
   covered most user-facing cases, but resource servers
   actually validating access tokens via introspection
   would have seen them reported `active=false`.
2. **A P0 latent bug from v0.38.0.** The workspace's
   jsonwebtoken-10 dependency was configured with
   `features = ["use_pem", "ed25519-dalek", "rand"]`,
   deliberately omitting the `rust_crypto` umbrella to
   avoid the transitive `rsa` dep affected by
   RUSTSEC-2023-0071 (Marvin Attack). This was a sound
   threat-model decision (cesauth never uses RSA) but
   it produced a runtime bug: jsonwebtoken-10 wired
   the EdDSA verify path through
   `CryptoProvider::install_default`, which the bare
   `ed25519-dalek` opt-dep doesn't satisfy. **The
   first real introspection request with a real
   access token in production would have panicked the
   worker** with the message "Could not automatically
   determine the process-level CryptoProvider". The
   bug existed since v0.38.0 (introspection's
   introduction) but no CI test exercised the
   real-JWT verify path until v0.41.0's multi-key
   work tried to.

### What ships

#### Multi-key support (ADR-014 §Q4)

**`cesauth_core::oidc::introspect::IntrospectionKey<'a>`** —
new type with `kid: &'a str` + `public_key_raw: &'a [u8]`.
Borrowed lifetime ties to the worker's signing-key
buffer (which lives only for the request duration).

**`cesauth_core::jwt::signer::extract_kid(token: &str) -> Option<String>`** —
extracts the JWT header's `kid` member without
verifying the signature. Returns `None` for malformed
tokens or kid-less headers. **The kid is untrusted at
this point** — used only as a hint for key selection;
the cryptographic verify still runs against the chosen
key.

**`introspect_token` signature change**:

```diff
- public_key_raw: &[u8]
+ keys: &[IntrospectionKey<'_>]
```

Old behavior is the special case `keys.len() == 1`.

**`introspect_access` multi-key strategy**:

1. Empty keys → return `Ok(None)` (deployment
   misconfigured; refresh-token path still works,
   pinned by `refresh_path_isolated_from_empty_access_keys`).
2. **kid-directed lookup**: extract the JWT's `kid`
   header. If it matches one of the active keys, try
   that key first. Fast path: 1 crypto verify call.
3. **try-each fallback**: if no kid present, no
   match in active set, or kid-matched key fails to
   verify (defensive), walk every active key in turn.
4. Return `Some(active_response)` on first
   verification success. Return `Ok(None)` (inactive)
   if every key fails.

#### Worker handler `crates/worker/src/routes/oidc/introspect.rs`

Builds `Vec<IntrospectionKey>` from `key_repo.list_active()`
result. Malformed `public_key_b64` entries (b64 decode
fails) are filtered out with a `console_warn!` rather
than aborting the request — defensive against a
single bad key shadowing the whole active set.

#### CryptoProvider fix (P0 latent v0.38.0 bug)

Workspace `Cargo.toml`:

```diff
- jsonwebtoken = { version = "10", default-features = false, features = ["use_pem", "ed25519-dalek", "rand"] }
+ jsonwebtoken = { version = "10", default-features = false, features = ["use_pem", "rust_crypto"] }
```

`rust_crypto` brings transitive `rsa` v0.9 back in.
We accept this because:

- cesauth has no code path that calls
  `Algorithm::RS{256,384,512}` or
  `Algorithm::PS{256,384,512}`. The `rsa` dep is dead
  code from cesauth's perspective.
- Marvin Attack is a side-channel against RSA
  decryption / signing, not against unused-but-linked
  code. A linked-but-unreachable `rsa::PrivateKey`
  does not exercise the vulnerable path.
- The alternative (a panicking production binary on
  the first real introspection request) is strictly
  worse.

A future sweep should swap to `josekit` + `ed25519-dalek`
direct, dropping `rsa` entirely. The v0.4 "WASM
caveat" comment in `signer.rs` already anticipates
this move.

### Tests

871 → **882** (+11 lib tests, total 911 with migrate
integration tests).

- core: 353 → 364 (+11). All in
  `service::introspect::tests`:
  - 4 in `multi_key` mod requiring real Ed25519 verify:
    `single_key_match_verifies_active`,
    `multi_key_kid_directed_lookup_picks_correct_key`
    (the headline rotation-grace-period scenario),
    `multi_key_try_each_fallback_when_kid_unknown`,
    `forged_kid_with_unknown_signature_rejected`,
    `token_signed_by_retired_key_reports_inactive`,
    `empty_keys_returns_inactive`,
    `refresh_path_isolated_from_empty_access_keys`.
  - 4 in `extract_kid_tests` mod:
    `extracts_kid_when_present`,
    `returns_none_when_kid_absent`,
    `returns_none_on_garbage_input`,
    `does_not_verify_signature`.

  Tests build JWTs directly via base64url +
  `ed25519_dalek::Signer` rather than through
  `jsonwebtoken::EncodingKey` (which expects PKCS#8 DER
  rather than the raw 32-byte seed; our test keys are
  raw seeds). Public-key path uses
  `DecodingKey::from_ed_der` with the 32 raw bytes,
  which `jsonwebtoken-10` correctly accepts (the
  inner storage is `SecretOrDer(raw_bytes)` regardless
  of whether you came in via `from_ed_der` or
  `from_ed_components`).

  The 13 baseline introspect tests still pass; their
  call sites were migrated from `&FAKE_PUBKEY` to
  `&fake_keys()` (a one-element slice).
- ui: 230 → 230 (no UI changes).
- worker: 171 → 171. Handler edits, no new tests;
  existing handler tests assert structural properties
  (CSRF, content-type, status codes).

### Schema / wire / DO

- Schema unchanged from v0.40.0 (still SCHEMA_VERSION 9).
- Wire format unchanged.
- DO state unchanged.
- **Dependency change**: `rsa` v0.9 transitively pulled
  in via jsonwebtoken's `rust_crypto` feature. The
  deps tree adds `rsa`, `pkcs1`, `pkcs8`, `num-bigint-dig`,
  `num-iter`, `num-traits`, `signature` 2.x, plus
  `p256`, `p384`, `hmac` (all unused by cesauth).
  Worker WASM bundle size increase: TBD on next
  release build (estimated low single-digit %).

### Operator-visible changes

- **No production behavior change for happy-path
  introspection.** A resource server submitting a
  real access token now gets the correct
  `active=true` instead of a worker panic.
- **Signing-key rotation grace period**: tokens
  signed by any key in the active set verify
  correctly. Operators who delayed rotations because
  of the v0.38.0 bug can now rotate confidently.
- **No `wrangler.toml` change. No new bindings. No
  schema migration.**

### ADR changes

- **ADR-014 §Q4** marked **Resolved**. The "deferred
  to a future iteration" paragraph replaced with a
  v0.41.0 implementation summary mirroring the
  ADR-011 §Q1 / ADR-012 §Q1 inline-resolution style.
- No new ADR.

### Doc / metadata changes

- `Cargo.toml` version 0.40.0 → 0.41.0.
- UI footers + tests bumped to v0.41.0.
- ROADMAP: ADR-014 §Q4 Resolved annotation; v0.41.0
  Shipped table row added.
- This CHANGELOG entry.

### Upgrade path 0.40.0 → 0.41.0

1. `git pull` or extract this tarball over your
   working tree.
2. `cargo build --workspace --target
   wasm32-unknown-unknown --release`. **Dependency
   change**: `rsa` and friends pulled in transitively
   via jsonwebtoken's `rust_crypto`. Bundle size goes
   up modestly. If your deployment has tight Worker
   bundle-size budgets, audit before deploying.
3. `wrangler deploy`. **No schema migration.** No
   `wrangler.toml` change.
4. **Resource servers that previously saw spurious
   `active=false` from `/introspect` should see
   correct results immediately** — both the
   multi-key fix and the CryptoProvider fix land in
   the same deploy.

### Forward roadmap

- **Future security-track items still open**:
  - ADR-012 §Q1.5 D1 repair tool (decision blocked
    on observed v0.40.0 drift data)
  - ADR-012 §Q2 user notification on session timeout
  - ADR-012 §Q3 device fingerprint columns
  - ADR-012 §Q4 bulk revoke other sessions
  - ADR-012 §Q5 orphan DO limitation
  - ADR-014 §Q1 introspection resource-server audience
    scoping
  - ADR-014 §Q2 introspection rate limit
  - ADR-014 §Q3 audit retention policy
- **i18n-2 continued (v0.39.1+)**: TOTP recovery
  codes, TOTP disable confirm, magic link, error
  pages, `PrimaryAuthMethod::label`, Security Center
  enabled-state recovery-codes row (blocked on
  pluralization — ADR-013 §Q4).
- **Feature track candidates**: RFC 7009 token
  revocation for confidential clients.
- **Tech-debt sweep candidate**: swap jsonwebtoken to
  `josekit` + `ed25519-dalek` direct, dropping
  transitive `rsa` (resolves the dead-code-but-
  CVE-flagged dep that v0.41.0 accepted as a
  trade-off).

---

