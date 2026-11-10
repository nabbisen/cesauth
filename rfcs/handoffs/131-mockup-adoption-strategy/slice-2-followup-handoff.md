# RFC 131 §0 slice 2 follow-up — two defects review found in the surfaces slice 2 just fixed

**Parent.** `rfcs/handoffs/131-mockup-adoption-strategy/slice-2-chain-status-handoff.md`
— slice 2 itself is **accepted** (`43fc7da`), review at
`.git-exclude/reviewed/131-slice2-chain-status-review.md`.
**Target release.** **`0.97.0`, the same cut** — it is **held** for these two.
**Level.** Unchanged: minor, earned, by slice 2's new route.
**Box.** Very small. One line of behaviour plus a test; three lines of label
logic plus tests.
**Why in this cut and not the next**: both live in the two surfaces `0.97.0`
exists to fix. A release note saying *"the export now honours the operator's
filter"* while the same form silently returns 50 of 268 rows and records
`truncated=false` would be false.

---

## 1. The export silently returns 50 rows and reports that it was not truncated

**Your own evidence found this.** The report's §2 table reads *"unfiltered — 50
(the export's own default row cap)"*. That cap is **10,000**. The 50 comes from
somewhere else, and the chain is:

1. `routes/admin/console/audit_export.rs:47-49` reads `limit` **from the form**,
   clamped to 10,000.
2. The CSR export form sends `csrf`, `subject`, `event`, `since`, `until`,
   `format` — **no `limit`**. (Neither did the 545-line template's form.)
3. `AuditQuery`'s `Default` is derived, so `limit` is `None`.
4. `CloudflareAuditQuerySource::search` applies its own
   `DEFAULT_LIMIT = 50` (`crates/adapter-cloudflare/src/admin/audit_query.rs:40`
   and `:85`) — a constant documented as *"default page size for the admin
   overview"*, not an export cap.
5. `export_audit` then computes `truncated = rows.len() > max_rows`, i.e.
   `50 > 10_000` → **false**. So `x-cesauth-export-truncated` is not set, and
   the `AuditExported` self-audit record says `truncated=false`.

**Net effect**: a 268-row log exports as 50 rows, in a file that looks complete,
with an audit record asserting nothing was dropped.

**Fix it in the handler, not the form.** Default `limit` to `max_rows` when the
form omits it, so the cap lives in one place and `truncated` is meaningful
again. Note the ordering problem this creates and solve it deliberately:
`max_rows` is read from `env` *after* the query is built today, so one of the
two has to move. Say which you moved and why.

**Do not** fix this by adding `limit=10000` to the export form. That papers over
the handler and leaves every other caller of this route on 50.

**Evidence required.** Not "the field is now sent" — the row count:
- An export over a dataset of **more than 50 rows** returning **more than 50**,
  with the row count stated and the dataset's own size stated beside it.
- The `AuditExported` detail string from that same export, showing
  `rows=` matching and `truncated=` telling the truth.
- A truncation case actually driven: set `AUDIT_EXPORT_MAX_ROWS` low (a `--var`,
  never a secrets file) so `truncated=true` fires, and show the header set and
  the record agreeing. **This path has never been exercised.**
- Host tests for whatever decision function you extract. If the fix is genuinely
  one line in a handler with no host-testable seam, say so plainly rather than
  inventing a test that asserts nothing.

## 2. "cold start — no cross-check" is the wrong label after a verify-now

Your §5 observation was right and the code settles *why*:
`crates/core/src/audit/verifier.rs:151` says in so many words that a full walk
*"skip[s]"* the cross-check (`checkpoint_consistent: None`), because walking
from genesis ignores the prior checkpoint. **The verifier is correct. The label
is not.**

`render_checkpoint`'s consistency arm renders `None` as **"cold start — no
cross-check"**. After a verify-now on a chain that *has* a checkpoint — your own
268-row instance — the store is not cold and the operator is told it is.

**`None` has two causes and the component can tell them apart**, because
`checkpoint_seq` is in the same payload:

- `checkpoint_seq.is_none()` → the existing cold-start empty state, unchanged.
- `checkpoint_seq.is_some()` **and** `last_run_checkpoint_match.is_none()` →
  *not applicable* — the last run was a full re-walk, which does not
  cross-check. Write that, in the component's own Japanese register.

**The template has the same bug.** This is therefore a **deliberate improvement
over the specification**, like slice 1's csrf field, and belongs in the parity
table as such — not a parity gap.

**Evidence required**: a host test per branch of the three-way split, and the
live read you already have (`checkpoint_seq: 268`, `last_run_checkpoint_match:
null`) showing the new wording rather than "cold start".

## 3. Explicitly not in this follow-up

- **The truncation signal's reader.** Even once §1 is fixed, a genuine
  truncation is announced only in the `x-cesauth-export-truncated` **response
  header**, which a browser download discards — so the person who downloaded a
  short file still has no way to know. That is its own row; do not design a UI
  for it here.
- **The audit-kind column.** Your `audit_chain_verified` finding generalises:
  **15 of the 42 audit kinds claimed in `route-contracts.md` are produced
  nowhere in `audit.rs`** (9 look like stale renames, 6 have no match, 1 of
  those 6 verified as a genuine fiction). Own row, with its own gate.
- **Adding an audit write to `verify_now`.** A behaviour change; it belongs with
  the row above, after someone decides whether that action should be audited.
- Anything else from slice 2's §7 non-change scope.

## 4. Baselines — slice 2 as accepted, `43fc7da`

| gate | value |
|---|---|
| host tests | **1,700 / 0 / 4**, 12 `test result:` lines |
| `migration_chain` | **35** |
| `route-contracts-check.sh` | exit 0; E3 **47**; GATE_42 **24**; NONCE **13**; E4 **218** = 194 (183+11) + 24 + 0; E5 **19**; E6 **94**; E7 **156**; ✅ **All 196 routes** |
| `drift-scan.sh` | exit 0, clean; route surface **196 pairs — 1 added, 0 removed** |
| backend dead-code warnings | **7** |
| mdbook | **82 pages** |
| Worker bundle | **not an accepted baseline** — slice 2 reported 897,872 B pre-bump and review did not re-measure, because these two fixes land in the same cut. Measure once, after the version bump, and report it against `0.96.0`'s **893,683 B** |

## 5. Review request

Append to `.git-exclude/review-request/131-slice2-chain-status-report.md` as a
§9, or file `131-slice2-followup-report.md` — either is fine, say which.
State the row counts, not the rendered fields.
