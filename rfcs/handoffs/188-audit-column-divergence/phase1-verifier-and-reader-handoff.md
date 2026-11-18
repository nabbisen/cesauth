# Developer Handoff — RFC 188 Phase 1, the columns are checked and the console says so

**Target**: `0.108.0`, slice A of two · **Level**: minor
**RFC**: `rfcs/accepted/188-the-chain-vouches-for-the-payload-the-console-shows-the-columns.md`
— **accepted** 2026-11-17, amended 2026-11-18 (**Phase 1 = D1–D7**; the
console line ships with the detection)
**Closes**: `docs/src/expert/security-review-2026-q4.md` **F-7** (Medium)
**Baseline**: `46ce300` / tag `0.107.0`

---

## 1. Purpose

`verify_chain` checks three things per row and **none of them reads an
indexed column**, so an in-place `UPDATE audit_events SET actor = …`
leaves verification reporting `valid: true` while changing what the audit
viewer, the admin search and the exported CSV all display. Phase 1 makes
the verifier compare the seven duplicated columns against the payload's
own fields, keeps the finding alive across later runs, and gives it a
reader on the chain-status screen in both locales.

## 2. Why this shape and not the obvious one

**The obvious fix — add the columns to `compute_chain_hash` — is
forbidden** (RFC 188 §4). It would invalidate every `chain_hash` ever
written and require re-chaining the table, and an attacker who can
trigger a legitimate re-chain can launder a rewrite. The columns are
checked **against the payload**, which is already sealed.

**What makes this cheap**: `Event` (`crates/backend/src/audit.rs`) carries
a twin of all seven columns and declares no `skip_serializing_if`, so
`None` is written as `null` rather than omitted; `write_inner`
(`:713-727`) populates the columns from those same fields with no
truncation, trimming or case folding; the D1 adapter binds one-to-one
(`adapter-cloudflare/src/ports/audit.rs:164-185`); and `AuditEventRow`
already carries **both** halves, which `fetch_after_seq` already selects.
The verifier holds both sides and does not compare them. One JSON parse
per row walked, inside a walk already paged at `PAGE_SIZE = 200`.

## 3. Resolved decisions — do not re-open

RFC 188's D1–D7 stand as written. These are the scoping decisions **on
top** of them, made while reading the persistence path, and they are the
part most likely to be got wrong:

- **S1. A column divergence does NOT set `valid = false`.** `valid` means
  *the chain is intact*, and it is — the payload is still sealed and still
  authoritative. Flipping it would make the console say "chain invalid"
  about an index problem, which is the same conflation F-7 is about, and
  would stop the checkpoint advancing (see S2's cost note).
- **S2. Therefore the divergence set must be sticky, and that is not
  optional.** The checkpoint still advances past a divergent row, so the
  **next incremental run does not look at that row again** — "a later run
  found no divergences" is the normal case while the row is still wrong.
  A run that finds none must therefore **not** clear a standing
  unacknowledged set: keep the standing set and stamp the refusal,
  exactly as `persist_result` already does for the chain alarm
  (`clean_walk_refused_at`, RFC 184 round 2).
- **S3. Acknowledgement is per class, with the class named explicitly.**
  One control that clears two different findings is how F-7 happened.
  `POST /admin/console/audit/chain/acknowledge` gains a **required**
  `class` form field, `chain` or `columns`; **absent or unknown → 400**,
  never a default. The handler clears only the named class and writes its
  own audit event. **This is a surface-contract change** — a caller that
  posts without `class` now gets 400 — and it must be disclosed in the
  report and the CHANGELOG even though the only caller is our own console
  form. **Reuse `AdminAction::AcknowledgeTamperAlarm`**: the authority is
  identical, and a new `AdminAction` variant would drag the authz catalog
  and role mappings into a verification cut.
- **S4. No new route.** S3's shape keeps the surface at **197 routes, 0
  added, 0 removed**. If you find yourself adding a route, stop and
  report.
- **S5. Three states, not two.** The console must distinguish **did not
  look** / **looked, found none** / **N diverge**. A blob written before
  this cut deserializes with an empty set, and an empty set must not be
  read as "clean" — the same reasoning RFC 184 gave for `acknowledged`
  defaulting to `false`, applied in the other direction. Carry a
  `column_check_performed: bool` (`#[serde(default)]`, so old blobs are
  `false`) rather than inferring the state from an empty list.
- **S6. A malformed payload is its own reason code, not a column
  mismatch.** `serde_json` failing on a stored payload is a finding
  (`payload_unparseable`), never a panic and never an aborted walk, and
  it must not be reported as though a column had been edited.
- **S7. Cap the stored list at 50 and keep the count separately.** A
  wholesale column rewrite must not produce an unbounded KV blob; the
  count is the number that matters for the console line, the list is for
  naming the first rows to investigate.

## 4. Facts already measured — do not re-derive

- **The column set is 16**, derived from the migrations (`CREATE TABLE
  audit_events` in `0008_audit_chain.sql`, 14 columns; plus
  `ALTER TABLE audit_events ADD COLUMN request_id` in `0015`, and
  `… ADD COLUMN actor` in `0021`). `0009_user_session_index.sql` mentions
  the table but adds no column.
- **The three buckets account for all 16, exactly**:

  | bucket | columns | n |
  |---|---|---|
  | chain inputs (already covered) | `seq`, `id`, `ts`, `kind`, `payload`, `payload_hash`, `previous_hash`, `chain_hash` | 8 |
  | **cross-checked by this cut** | `subject`, `actor`, `client_id`, `ip`, `user_agent`, `reason`, `request_id` | **7** |
  | declared uncovered | `created_at` — no payload twin **by design**, `0008`'s own comment keeps it distinct from `ts` *"if `ts` ever comes from outside the writer"* | 1 |

- **The persistence path**: `verify_chain` → `walk_and_verify` →
  `persist_result` (`crates/core/src/audit/verifier.rs:127`, `:217` for
  the full re-walk, and the `persist_result` helper below them).
  `AuditVerificationResult` lives in `crates/core/src/ports/audit_chain.rs:83`
  and is persisted whole through `write_last_result`.
- **The console**: `AuditChainStatus` (`crates/core/src/admin/types.rs:554`)
  is assembled in `crates/backend/src/routes/admin/console/audit_chain.rs`
  (`read_status`, `:260`) and rendered by
  `crates/frontend/src/pages/operator/audit_chain.rs`, which is **already
  converted** (RFC 185 §5.3 screen 2) — badge + key per state, and
  `alarm_needs_acknowledgement` at `:166` is the shape to copy.
- **The acknowledge handler** is `audit_chain.rs:213`, with the CSRF
  double-submit check, the `!r.valid && !r.acknowledged` guard, and
  `EventKind::AdminAuditChainAlarmAcknowledged`.
- **Test doubles**: `crates/adapter-test/src/audit.rs` already has
  `tamper_set_payload`, `tamper_set_chain_hash`,
  `tamper_set_previous_hash`, **`tamper_set_actor`**, `tamper_delete_seq`
  and `tamper_clear_all`. Six of the seven columns have no helper yet.
- **The test that found F-7** is
  `crates/adapter-test/src/audit_chain/tests.rs:560-598`. Its assertion
  — *"documents the actual behaviour: a column-only tamper does not fail
  chain verification today"* — **inverts in this cut**, and its comment
  must be rewritten rather than deleted: it is the provenance of the
  finding.
- **`pages/operator/audit_chain.rs`'s i18n ceiling row is 0** and must
  stay 0.

## 5. Report-and-stop gates

**G1 — the key table, before the console work.** The three states, the
divergence table's headings, and the acknowledgement control need new
`MessageKey`s in **both** locales. Submit the table the way the RFC 185
screens did: key, `Ja`, `En`, and the reuse list. Say in one line, for
each state, **what an operator is supposed to do next** — that is the
test the copy has to pass, not whether it reads well. Stop for the
ruling before writing the view.

**G2 — the gate's buckets, with the schema parse.** §9's gate needs the
three bucket lists declared somewhere both it and the code can read.
Submit the parse (what you read from the migrations, what you read from
the verifier) and the exact failure messages, before landing it. **Do not
hand-write the 16 column names into the gate**: derive them, and show how.

Everything else proceeds without waiting.

## 6. Change scope

| file | change |
|---|---|
| `crates/core/src/audit/payload.rs` (new) | T1 — the `Deserialize` mirror (RFC 188 D4), `#[serde(default)]` on every field so a pre-`0015`/pre-`0021` payload reads as `None` (D5) |
| `crates/core/src/audit.rs` | T1 — `pub mod payload;` |
| `crates/core/src/audit/verifier.rs` | T2 — the per-row comparison inside `walk_and_verify`; T3 — the sticky/refusal logic in `persist_result` |
| `crates/core/src/ports/audit_chain.rs` | T3 — the new `AuditVerificationResult` fields + the `ColumnDivergence` type |
| `crates/core/src/admin/types.rs` | T4 — the `AuditChainStatus` fields the console needs |
| `crates/backend/src/routes/admin/console/audit_chain.rs` | T4 — `read_status` populates them; T5 — `acknowledge` takes `class` |
| `crates/backend/src/audit.rs` | T5 — one new `EventKind` for the columns-class acknowledgement |
| `crates/core/src/i18n/mod.rs`, `i18n/tests/lookup_completeness.rs` | T6 — the G1 keys, both lists |
| `crates/frontend/src/pages/operator/audit_chain.rs` | T6 — the three-state line, the divergence table, the second ack control |
| `crates/adapter-test/src/audit.rs` | T7 — tamper helpers for the six remaining columns (or one `tamper_set_column`) |
| `crates/adapter-test/src/audit_chain/tests.rs` | T7 — the end-to-end tests, including inverting the test that found F-7 |
| `scripts/drift-scan.sh` | T8 — the schema↔verifier gate (after G2) |
| `docs/src/expert/route-contracts.md` | T5 — the acknowledge row's audit-kind cell gains the new kind |
| `docs/src/expert/security-review-2026-q4.md` | T9 — F-7's disposition |
| `docs/src/expert/adr/010-audit-log-hash-chain.md` | T9 — what the chain now covers, and what it still does not |

## 7. Explicit non-change scope

- **No change to `compute_chain_hash`, no migration, no schema change, no
  re-chaining.** §2.
- **No Phase 2**: the viewer, the admin search and the export keep
  reading the indexed columns this cut. That is the next cut, and the
  residual it leaves — a tampered column can still **hide** a row from a
  filter — is named in the RFC and must be named in the report, not
  quietly fixed here.
- **No new route** (S4), no new `AdminAction` (S3), no authz change.
- **No repair tool.** Nothing writes a column back from the payload:
  what a divergence means for a row is an operator's judgement, and an
  automatic "fix" would destroy the only evidence that something edited
  it (RFC 188 §4).
- **No F-5, no F-6, no RFC 123 work**, and **do not fix F-4** — the
  route-contract table's audit-kind column is unreliable by its own
  recorded finding; add your kind to the one row you touch and leave the
  other 15 alone.
- **No `ts`/`actor` query-parameter rename** (rowed separately).

## 8. Task detail worth stating explicitly

- **T2's comparison is `Option<&str>` against `Option<&str>`**, column
  versus payload field, with **absent key ≡ `NULL` ≡ `None`** (D5). A
  tamper cannot exploit that equivalence: removing a key changes the
  payload bytes, so `payload_hash` fails first, at the existing check,
  before the comparison is reached — say so in a comment where someone
  will read it.
- **The genesis row (`seq = 1`) is exempt by shape** (D6): `payload = '{}'`
  and all columns `NULL`. The walk already special-cases it; do not add
  a second exemption mechanism.
- **T3's new fields, all `#[serde(default)]`**, with the reason in the
  doc comment in RFC 184's own voice (*an absent field must never read as
  a stronger claim than the run actually made*): the divergence list, the
  count, `column_check_performed` (S5), the acknowledgement flag, and the
  clear-refusal stamp (S2).
- **T3 must not disturb the chain alarm's own logic.** `persist_result`
  currently has one sticky class; it will have two, and they are
  independent: a chain alarm standing must not suppress a new divergence
  finding, and an acknowledged divergence must not clear a chain alarm.
  **Write the four-way case table as a test**, not as a comment.
- **T5's `class` field**: parse it before the CSRF check or after, but
  **reject an absent value with 400 and no write and no audit event** —
  the existing handler's "nothing to clear" path already demonstrates the
  no-write-no-event discipline.
- **T6's copy** is G1's ruling applied, and the chain screen is already
  negotiated: `mounted_locale()`, every string through `lookup`, and the
  ceiling row for that file stays **0**.
- **T9's ADR-010 edit is the one most likely to overclaim.** The chain
  still does not *prevent* tampering, and after this cut it detects a
  column edit **at the next walk that covers that row** — which for an
  incremental run means the row is covered once. State what is covered,
  when, and what is not (`created_at`, and anything outside
  `audit_events`).

## 9. Assert machine-checkable things mechanically

**The gate (T8): the schema and the verifier must agree about every
column.** This is the check that would have caught `actor` landing as a
column-only field in the first place.

```
ℹ️   audit column coverage: 16 column(s) in audit_events -- 8 chain input(s),
     7 cross-checked, 1 declared uncovered (created_at)
```

- Derive the column set from `migrations/`: the `CREATE TABLE
  audit_events` body plus every `ALTER TABLE audit_events ADD COLUMN`.
- Derive the cross-checked set from the **verifier**, not from a copy:
  have `verifier.rs` (or `payload.rs`) declare
  `pub const CROSS_CHECKED_COLUMNS: [&str; 7]` and parse that.
- Fail when a column is in **none** of the three buckets (a new column
  landed with no decision), in **two** (a contradiction), or when a
  declared name is **no longer in the schema** (staleness, the
  `RELEASE_RECORD_EXEMPT` pattern).
- **Prove both directions before landing**: add a scratch
  `ALTER TABLE audit_events ADD COLUMN probe TEXT;` and show the gate
  naming `probe`; remove a name from the verifier's const and show the
  gate naming the column that lost its bucket.

**And one in-crate test, not a gate**: serialize a fully-populated mirror
struct and assert its JSON key set equals `CROSS_CHECKED_COLUMNS` — so
the struct and the const cannot drift. The cross-crate pin test (D4)
stays as the RFC specifies, in `cesauth-backend`, where both `Event` and
the mirror are visible.

## 10. Required tests and evidence

The canonical host-test command, quoted literally — **12 `test result:`
lines**, baseline **1,737 / 0 / 4**:

```bash
cargo test -p cesauth-core \
           -p cesauth-adapter-test \
           -p cesauth-frontend \
           -p cesauth-backend \
           -p cesauth-adapter-cloudflare \
           --features cesauth-frontend/csr > 188-evidence/host-tests.log 2>&1

cargo test -p cesauth-migrate-test --test migration_chain > 188-evidence/migrate.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > 188-evidence/wasm32.log 2>&1
cargo check -p cesauth-frontend --target wasm32-unknown-unknown --features csr > 188-evidence/csr-check.log 2>&1
bash scripts/route-contracts-check.sh > 188-evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh > 188-evidence/drift-scan.log 2>&1
```

**The tests that have to exist** (names are yours; the cases are not):

1. **Each of the seven columns**, tampered one at a time via the double →
   reported as a divergence, naming the column and the seq, with
   **`valid` still `true`** and the checkpoint still advancing.
2. **The test that found F-7, inverted** — same fixture, same
   `tamper_set_actor`, opposite assertion, with its comment rewritten to
   record that it documented the gap until `0.108.0`.
3. **Pre-`0015` and pre-`0021` payloads**: a row whose payload JSON omits
   `request_id`, and one that omits `actor`, with the column `NULL` →
   **no divergence** (D5). This is the false-positive case that matters
   most; without it the gate ships an alarm on legitimate history.
4. **Stickiness** (S2): run 1 finds a divergence; run 2 (incremental,
   past the checkpoint) finds none → the standing set survives and the
   refusal is stamped.
5. **The four-way independence table** (S3/T3): chain alarm standing ×
   divergence standing, acknowledged in each class, asserting that each
   acknowledgement clears **only** its own class.
6. **`class` handling**: `chain`, `columns`, absent (→ 400, no write, no
   event), unknown (→ 400).
7. **A malformed payload** (S6) → `payload_unparseable`, the walk
   completes, no panic.
8. **The mirror/const agreement test** and the cross-crate pin test
   (§9).

**G2 evidence — real HTTP, both locales.** Under `wrangler dev --local`
with a seeded `audit_events` table (and **read
`docs/src/expert/contributing.md`'s note on the two local sqlite files
first** — that is exactly the trap this evidence hits):

| request | shows |
|---|---|
| `GET /admin/console/audit/chain` with `Accept-Language: ja`, no divergence | the "looked, found none" line in Japanese |
| same with `en` | the same state in English |
| same after a column tamper | the "N diverge" state, the row named, and the ack control present |
| `POST …/acknowledge` with `class=columns` | 302, the divergence class cleared, the chain class untouched |
| `POST …/acknowledge` with no `class` | **400**, nothing written |

Full headers in the log, and assert `grep -ciE "bearer|authorization"`
over it is **0**, as every round in this programme has.

## 11. What must NOT be claimed

- **Not that the chain prevents tampering.** It detects. Phase 1 adds one
  class of detection.
- **Not that the console now shows verified values.** It shows the
  columns, with a separate statement about whether they match the
  payload. That is Phase 2's job and the report must say so.
- **Not that a divergence is a chain break**, in any wording, anywhere —
  including the CHANGELOG entry.
- **Not that every row is re-checked.** An incremental run checks the
  rows it walks; a row is covered once unless an operator triggers a full
  re-walk (`verify_chain_full`). Say which runs cover what.
- **Not that F-7 is closed by the design.** It closes when this lands, and
  the disposition in the security review should say so with the version.

## 12. Prohibited shortcuts

- Do not run `cargo test --workspace --all-features`
  (`contributing.md:495-504`).
- Do not add the columns to the chain hash (§2).
- Do not make a divergence set `valid = false` to get stickiness for free
  (S1/S2) — that trades a true statement for a convenient one.
- Do not default `class` to `chain` (S3).
- Do not hand-write the column list into the gate (G2).
- Do not widen `TIMESTAMP_RENDERING_EXEMPT`, the i18n ceiling, or any
  other existing gate's pinned numbers to make this cut green. If one
  moves, report it.

## 13. Acceptance criteria

1. All seven columns cross-checked per row; `created_at` declared
   uncovered in code and in the gate; genesis exempt by shape.
2. A divergence leaves `valid: true`, survives a later clean incremental
   run, and clears only on its own acknowledgement.
3. The console distinguishes the three states in both locales, with the
   chain-status screen's ceiling row still **0**.
4. `class` required; absent → 400 with no write and no audit event; the
   surface-contract change disclosed in the report.
5. The schema↔verifier gate green, both failure directions demonstrated.
6. Host **≥ 1,737 / 0 / 4 across 12 lines**, migrate **39**, **197
   routes, 0 added, 0 removed**, `drift-scan` clean with ceiling
   **103 / 65 / 69**, negotiation **13 / 13**, timestamp rendering
   **24 / 15**.
7. F-7's disposition and ADR-010 updated, neither overclaiming.

## 14. Known risks

- **The false-positive case is legitimate history** (test 3). Get it
  wrong and the first production run alarms on every pre-`0021` row.
- **`persist_result` now has two sticky classes** and they interact; the
  four-way table is the only way to know they are independent.
- **The console's three states are easy to collapse into two** — an empty
  list is not "clean" (S5).
- **The walk's cost** is one parse per row; measure it on the largest
  fixture you have rather than asserting it is negligible.

## 15. Review request

`.git-exclude/review-request/188-phase1-keys.md` for G1,
`.git-exclude/review-request/188-phase1-gate-buckets.md` for G2, then
`.git-exclude/review-request/188-phase1-report.md`, evidence under
`188-evidence/`. Report the entry-point path only.
