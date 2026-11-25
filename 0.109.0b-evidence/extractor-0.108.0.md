## [0.108.0] - 2026-11-18

**Minor** — the audit log's indexed columns are now verified against the
payload they duplicate, and a date-formatting bug that had been wrong for
45% of all days since `0.66.0` is fixed. RFC 188 Phase 1 and RFC 111
slice C, two review rounds each.

### Fixed — every date in 2021, 2025 and 2029 rendered one day late

**Read this if you have archived an audit export.**
`cesauth_core::util::days_to_ymd` — the arithmetic behind every visible
timestamp — omitted the 1 March epoch shift that a 400/100/4-year
calendar decomposition requires. Measured over every day from 1970 to
2200: **38,381 of 84,371 days (45.5%) produced the wrong civil date.**

The pattern is whole years, not scattered edge cases:

| dates | what was shown |
|---|---|
| every day of **2021, 2025, 2029** (and 2017, 2013, 2009 …) | **one day later than the truth** |
| **31 December** of 2020, 2024, 2028 (and every leap year) | the following day |
| 31 December of 1973, 1977, 1981 … | a syntactically invalid date — **month 13** |
| 2022, 2023, 2026, 2027 | correct |

**What this did and did not affect.** The hash chain was **never**
affected: `payload_hash` and `chain_hash` cover `ts` as an integer, so
the stored record and its integrity proof were always right — only the
*rendering* was wrong. What was affected is everything a person reads:
the admin and tenancy consoles, the end-user session list, and — the one
that matters most — **the audit export (CSV and JSON), which operators
archive as evidence**. An investigation correlating an incident from an
export taken before this release read the wrong day for any row in an
affected year.

**If you are relying on an archived export, re-export it.** The
underlying rows were never wrong; the dates written into the file were.

Present since **`0.66.0`** (41 minor versions). `0.107.0` did not
introduce it — it widened the display surface from 5 formatter call sites
to 24. Recorded as **F-8** in
`docs/src/expert/security-review-2026-q4.md`.

`days_to_ymd` is now Howard Hinnant's `civil_from_days`, with the
signature unchanged and no call site touched. Its test is a **sweep**,
not an anchor: every day from 1970-01-01 to 2200-12-31 round-trips
through an independently written inverse and is asserted to be a
syntactically valid date, plus ten independently computed boundary
anchors and six named regressions from the bug's own measurement.
Review swept the fixed function against a third oracle over **2,932,897
days, to 9999-12-31** — zero mismatches.

### Added — a test rule, because of how this was missed

`docs/src/expert/contributing.md`: **a date or time test must sweep, or
cover all four positions of a leap-year group.** `0.107.0` added six
caller assertions for this formatter and every one used the same anchor,
`1_704_067_200` (2024-01-01) — a position the bug got right. One anchor
repeated across a suite is one data point.

### Added — the audit log's indexed columns are checked against their payload

RFC 188 Phase 1 closes **F-7**. `audit_events` duplicates seven payload
fields as indexed columns so admin search can run as ordinary SQL:
`subject`, `actor`, `client_id`, `ip`, `user_agent`, `reason`,
`request_id`. Chain verification read **none** of them, so an in-place
`UPDATE` of one changed what the console and the export display while
verification still reported `valid: true`.

`walk_and_verify` now parses each row's payload and compares all seven
against it. **No migration, no new hash input, no re-chaining** — the
comparison costs one JSON parse per row walked, and the data was already
in the row the verifier had fetched.

**A diverging column is not a chain break, and the release is careful
about that distinction**: `valid` stays `true`, because the chain and the
sealed payload really are intact — what diverged is an index. The finding
is reported separately, with its own count, its own list of rows, and its
own acknowledgement.

**It is sticky, and it has to be.** The checkpoint still advances past a
diverged row, so the next incremental run never looks at that row again
— "this run found nothing" is the normal case while the row is still
wrong. A clean run therefore **refuses** to clear a standing
unacknowledged finding, the same discipline RFC 184 gave the chain alarm.

### Added — the chain-status screen says which of three things it knows

`/admin/console/audit/chain` gains a column cross-check section, in both
locales: **not yet checked** (a run that predates this release), **looked
and found none**, or **N columns diverge** with the rows named. The three
states are distinct on purpose — an empty finding list from an older run
must never read as "clean". 11 new `MessageKey`s; the catalog goes
**314 → 325** arms.

The section's note states what the check does **not** reach: the admin
search, the audit viewer and the export still read the indexed columns
directly, so a tampered column can still hide a row from a filter. That
is Phase 2, not in this release.

### Changed — the acknowledgement route takes a required `class`

**Surface-contract change.** `POST /admin/console/audit/chain/acknowledge`
now requires a `class` form field, `chain` or `columns`; absent or
unknown is **400**, with no write and no audit event. There is no
default, deliberately: one control that clears two different findings is
how F-7 came about in the first place. Each class clears only its own
standing finding and writes its own audit event
(`admin_audit_column_divergence_acknowledged` is new). The console's own
forms send the field; no other caller exists.

### Added — the gate that would have caught the original gap

`scripts/drift-scan.sh` gains a schema↔verifier check: every column in
`audit_events` must be in exactly one of three buckets — a chain input, a
cross-checked column, or declared uncovered (`created_at`, which has no
payload twin by design). It derives the column set from the migrations
and the cross-checked set from the verifier's own
`CROSS_CHECKED_COLUMNS`, and fails four ways: a column in no bucket (a
new column landed with no decision — exactly how `actor` arrived in
`0.106.0`), a column in two, a declared name that has left the schema,
and the const disagreeing with the schema. All four demonstrated.

### Changed — the clamp is a decision now, in all four places

`format_unix_as_iso8601` clamps a negative timestamp to the epoch rather
than rendering a pre-1970 date. `crates/core/src/types.rs` called
negative-before-epoch *"a legitimate corner case for imported data"*
while `util.rs` claimed accuracy *"for years 2000-2099"* and never
mentioned the clamp. The formatter's doc comment, `types.rs`, `i18n.md`
and the clamp's own test now say the same thing: the clamp is deliberate,
there is no upper bound, and **an importer must fix the formatter before
it ships**, because the display would otherwise rewrite history to 1970.

### Security answer

The diff touches `crates/backend/src/routes/admin/` and
`crates/core/src/audit/`, so the rubric's path list fires. **Two findings
close and no new surface opens.**

- **F-7 closed** (Medium): the seven duplicated columns are verified
  against the payload. Detection, not prevention — the chain has never
  prevented tampering, and this adds one class of detection to it.
  Coverage is **once per walk that reaches a row**, not continuous: an
  incremental run checks the rows it walks, and a full re-verify
  re-examines everything.
- **F-8 fixed** (Medium): the date arithmetic above. Evidence
  correctness, not a vulnerability — and archived exports stay wrong
  until re-exported.
- **The residual, named**: until Phase 2 moves the readers onto the
  payload, a tampered column can make a row invisible to a filter. The
  new console section says so where an operator would otherwise assume
  the opposite.
- No route added or removed (**197**), no permission added (the new
  acknowledgement reuses `AcknowledgeTamperAlarm`), no migration, no
  schema change, no dependency change, and no change to
  `compute_chain_hash`.

### Gates

Host tests **1,769 / 0 / 4 across 12 `test result:` lines** — **+32**
over `0.107.0`. Migration chain **39**. Route surface **197, 0 added, 0
removed**. `drift-scan` clean: i18n ceiling **103 / 65 / 69**,
negotiation **13 / 13**, timestamp rendering **24 / 15**, release
reconciliation **164 tags / 162 entries**, changelog budget green, and the
new **audit column coverage: 16 columns — 8 chain inputs, 7
cross-checked, 1 declared uncovered**. Clippy 0 errors, `cargo deny` ok
in all four sections, wasm32 backend check clean. Catalog **314 → 325**
arms.

**Bundle, CI to CI**, code and version bump in separate commits:

| commit | `Cargo.toml` | gzip |
|---|---|---|
| `e7061b3` (`0.107.0` tag) | `0.107.0` | 906,075 B |
| `877be6a` (this cut's code) | `0.107.0` | 918,916 B |
| `c76eafc` (`0.108.0` tag) | `0.108.0` | **918,966 B** |

**Code delta at the pinned version: +12,841 B** — **35%** of the
2,621,440 B budget, up from 34%. Absolute at the tag **+12,891 B**; the
version string accounts for **+50 B**.

**That delta is larger than this cut's visible surface explains, and it
is recorded as a question rather than a cause.** `0.106.0` cost
**+1,516 B** for 33 catalog keys and their values in two locales; this
cut adds 11 keys (one with a long note) and a console section, and costs
**8.5×** that. The frontend links `cesauth-core` and does not call the
verifier — the only mention is a doc comment — so the likely explanation
is core-side code reaching the CSR wasm: `verifier.rs` grew 234 lines,
`payload.rs` is new with its own `serde` derive, and nine core files
gained 742 lines between them. Whether dead-code elimination is leaving
verifier or `serde_json` paths in the bundle is checkable (symbol-level
sizing, or feature-gating the verifier out of the wasm target) and is
rowed. No conclusion is drawn here from one measurement.

**CI: 14 push workflow runs, all `success`, 16 check runs, nothing
pending** — the sixteenth again being `Security audit`, the check run
`rustsec/audit-check` creates through the Checks API rather than as any
workflow's job. No scheduled workflow fired on this tip. Second
consecutive release with that composition, which is what `0.106.0`'s
correction predicted.
