# Developer Handoff — the signals get readers (F-5, F-6, F-9)

**Target**: `0.110.0`, slice B of three · **Level**: minor (ships with slice A)
**Design**: settled in
`.git-exclude/reviewed/f5-f6-the-signal-exists-the-reader-does-not.md` —
read it first; this handoff transcribes it
**Closes**: `docs/src/expert/security-review-2026-q4.md` **F-5** and
**F-6** (the two oldest *open, rowed* findings) and **F-9** (opened by
that design note)
**Baseline**: `228eed1` / tag `0.109.0`

---

## 1. Purpose

Three findings, one sentence: **the signal exists, durably and
correctly, and no human can see it.**

- **F-6**: `clean_walk_refused_at` — RFC 184's strongest available signal
  that a wholesale rewrite may have happened — is stamped by
  `persist_result` and reaches **no reader**. `grep` across
  `core/src/admin/types.rs`, `routes/admin/console/audit_chain.rs` and
  `pages/operator/audit_chain.rs` returns nothing: it lives in the KV
  blob and nowhere else.
- **F-5**: the audit export's truncation is announced in
  `x-cesauth-export-truncated`, a **response header a browser download
  discards**, and the form POST is the only path a human uses.
- **F-9**: `build_export_filename` carries **one** of the query's six
  dimensions, so two exports of the same event kind with different
  subjects or date ranges produce **the same filename** — an archive of
  evidence files that cannot be told apart, none carrying the moment
  taken or the range covered.

## 2. Resolved decisions — do not re-open

From the design note, verbatim in effect:

- **F-6's line sits beside the standing alarm, not as its own state** —
  it is a property of that alarm. No new state, no new route, no second
  acknowledgement control.
- **F-6's copy must name the cause and the action.** The literal fact
  (*"a clean walk was refused"*) reads as *"verification is broken"*,
  which is the opposite of the truth. It says: a later run found the
  chain clean and was **not allowed** to clear this alarm because the
  alarm is unacknowledged; the finding above still stands; acknowledge
  it and the next run can advance again.
- **F-5's notice does NOT go in the file.** A CSV a spreadsheet opens
  must not carry a comment row; a JSONL stream must stay one object per
  line. **Corrupting the evidence format to carry a warning about the
  evidence is the wrong trade.**
- **F-5, three parts**: (a) the export form states the **10,000-row
  cap** before the operator clicks — the best version of *"users must
  not be confused"* is the one where there is nothing to explain;
  (b) the marker goes **in the filename**, the one piece of metadata a
  browser download preserves; (c) the response header **stays** — its
  reader was always an API client, and the finding was that it was the
  *only* reader.
- **F-9's filename carries the export moment** in UTC ISO-8601 (through
  the canonical formatter, correct since `0.108.0` slice C, with `:`
  replaced for filesystem safety) **and** the truncation marker.
- **No two-step export flow.** Two clicks for every export to fix a rare
  case that is now visible in the filename is the wrong trade.

**One decision the design note left to this handoff**: whether the
filename also carries the query's other dimensions. **Ruling: the moment
and the marker only.** A filename that encodes subject, actor and a date
range becomes unreadable and filesystem-hostile; the file's *contents*
already carry the rows, and the export's own audit row already records
the filter (`build_filter_desc`, RFC 187 round 2). Two exports a second
apart with different filters still collide — say so in the report rather
than pretending the moment solves every case.

## 3. Report-and-stop gate

**G1 — the keys.** F-6's two keys (the refusal line and its timestamp
label, if you split them), F-5's cap line on the export form, and
anything F-9 needs. For each, *what an operator concludes* — and for
F-6, the sentence must not read as "verification failed".

Nothing else waits.

## 4. Change scope

| file | change |
|---|---|
| `crates/core/src/admin/types.rs` | T1 — `AuditChainStatus` gains `clean_walk_refused_at: Option<i64>` |
| `crates/backend/src/routes/admin/console/audit_chain.rs` | T1 — `read_status` populates it |
| `crates/frontend/src/pages/operator/audit_chain.rs` | T2 — the line, beside the alarm |
| `crates/core/src/admin/service/audit_export.rs` | T3 — `build_export_filename`: the moment and the marker |
| `crates/frontend/src/pages/operator/audit.rs` | T4 — the cap line on the export form |
| `crates/core/src/i18n/mod.rs`, `i18n/tests/lookup_completeness.rs` | T5 — G1's keys |
| `docs/src/expert/security-review-2026-q4.md` | T6 — F-5, F-6, F-9 dispositions, with the version |

## 5. Task detail worth stating explicitly

- **T1 is three layers and nothing more** — field, populate, render. If
  you find yourself editing `verifier.rs` or `persist_result`, stop: the
  stamping already works and is tested.
- **T3's filename**: keep `cesauth-audit-` and the existing
  filter-derived token (it is better than nothing), append the moment
  and, when truncated, the marker. **Sanitise for filesystems** — the
  existing builder already maps non-alphanumerics to `-`, so reuse that
  path rather than writing a second sanitiser, and state in the report
  what a `:` becomes.
- **T4's cap line** must read the cap from the same place the route
  does, not restate `10,000` as copy — `0.108.0`'s G1 ruling (copy that
  repeats a code constant drifts from it) applies.
- **T6 names the version** in each disposition, as F-7's did: *closed by
  `0.110.0`*, with what closed and what did not. F-5's residual: an
  operator who renames the file loses the marker, which is their act and
  not ours to prevent.
- **`pages/operator/audit.rs`'s ceiling is pinned at 2** and
  `audit_chain.rs`'s at **0** — both must stay, so every new string goes
  through `lookup`.

## 6. Required tests and evidence

The canonical host-test command and the rest of the gate set, with
**evidence paths written in full** under
`.git-exclude/review-request/0.110.0b-evidence/` (TEMPLATE.md §10).
Baseline: host **1,779 / 0 / 4 across 12 lines**.

**Cases that must exist:**

1. **The filename**, as a pure-function test: truncated vs not, with a
   fixed clock, asserting the exact string — including what the `:`
   became.
2. **`clean_walk_refused_at` survives the round trip** from a stored
   result into `AuditChainStatus` (the layer that did not exist).
3. **The refusal line renders only when the field is `Some`** and the
   alarm is standing — a pure-function test on the view's badge/line
   helper, the shape `columns_status_badge` already uses.
4. **The cap line's number comes from the constant**, not from copy —
   assert the rendered string contains the configured cap.

**G2 — real HTTP, two requests**: an export that **is** truncated
(seed more rows than the cap, or lower the cap via the form's own
`limit` if that path allows it — say which you used) showing the
filename in `content-disposition` **and** the header; and
`/admin/console/audit/chain` with a standing unacknowledged alarm plus a
refused clean walk, in **both locales**, showing F-6's line. Full
headers, token-free, `grep -ciE "bearer|authorization"` → 0.

## 7. What must NOT be claimed

- **Not that F-5 is closed for every reader** — a renamed file loses the
  marker.
- **Not that F-9 makes every export unique** — two exports a second
  apart with different filters still collide, by §2's ruling.
- **Not that F-6 adds a new control** — it adds a sentence to an alarm
  that already has one.

## 8. Acceptance criteria

1. `clean_walk_refused_at` renders on the chain screen, beside the
   alarm, in both locales, with copy that names the cause and the
   action.
2. The export form states the cap, sourced from the constant.
3. The filename carries the moment and, when truncated, the marker; the
   response header is unchanged.
4. F-5, F-6 and F-9's dispositions name `0.110.0` and state their
   residuals.
5. Both ceilings unchanged (`audit.rs` 2, `audit_chain.rs` 0); gates as
   in §6.

## 9. Review request

`.git-exclude/review-request/0.110.0b-keys.md` for G1, then
`.git-exclude/review-request/0.110.0b-report.md`, evidence under
`.git-exclude/review-request/0.110.0b-evidence/`. Entry-point path only.
