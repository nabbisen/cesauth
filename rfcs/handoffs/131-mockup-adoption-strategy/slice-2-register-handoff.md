# RFC 131 §0 slice 2, round 3 — the chain-status screen's Japanese register, and one line

**Parent.** `rfcs/handoffs/131-mockup-adoption-strategy/slice-2-followup-handoff.md`
— round 2 is **accepted** (`32c50b9`), review at
`.git-exclude/reviewed/131-slice2-followup-review.md`.
**Target release.** **`0.97.0`, the same cut**, still held. Level unchanged.
**Box.** One file of copy, plus one line and its tests.
**Credit first**: round 2's `max_rows + 1` was right *against* my own written
instruction, and you found it by driving the evidence case instead of trusting
the handoff. That is the behaviour this process is for.

---

## 1. Localise the chain-status component — §9.2's own finding

You surfaced it; it is in scope now rather than as a row, and the reason is
narrow: this is the screen `0.97.0` exists to add, and the release note would
otherwise claim a register it does not have.

**Measured at review**: `crates/frontend/src/pages/operator/audit_chain.rs`
holds **8 Japanese literals against 44 multi-word English ones**. Japanese
covers only the chrome — the title, `← 監査ログ`, the loading line, the two
error messages. Everything an operator reads *about the chain* is English.

Translate the content into the same register the rest of `pages/operator/`
uses. That is: all five status badges, all three consistency badges (including
round 2's new "not applicable — last run was a full re-walk…"), the table row
headers (`Current chain length`, `Last verification`, `Rows walked in last
run`, `Last verified seq`, `Recorded chain_hash`, `Recorded at`,
`Consistency`), the section headings, the growth hint, the checkpoint
explanation paragraph, and the verify-now copy.

**Keep these in English deliberately, and say so in the report**: identifiers
and field names that appear in the data or the API (`chain_hash`, `seq`),
exactly as slice 1 kept `Export CSV`/`Export JSONL` in English by the
template's own stated design.

**No message catalog.** No CSR page uses it, and whether the console adopts it
is an open question for the owner. Hardcode, like every neighbouring page.

**This does not pre-empt that question** — which is why it is safe to do now.
If Japanese-only becomes policy, this is right; if the pages later adopt the
catalog with `En`, every page is rewritten and nothing here is wasted.

**Evidence**: the same literal census I ran, before and after — multi-word
English literals in that file should go to ~0 beyond the deliberate exceptions
you name. The existing badge/consistency host tests assert on **English
substrings**, so they will fail; update them to the new strings rather than
loosening the assertions, and keep the negative one
(`consistency_badge(Some(268), None)` must not read as a cold start) with its
Japanese equivalent.

## 2. `limit = 0` is accepted and exports an empty file that claims completeness

In `resolve_export_limit`, new in round 2:

- `resolve_export_limit(Some("0"), _)` → `"0".parse::<u32>()` is `Ok(0)`,
  `.min(10_000)` is `0` → `limit = Some(0)`. Zero rows exported, and
  `truncated = 0 > max_rows` → **false**.
- `max_rows.saturating_add(1) as u32` wraps: `max_rows = u32::MAX` casts to
  **0**, `2^32` casts to **1**.

Low severity — the first needs a caller to send `limit=0`, the second an absurd
`AUDIT_EXPORT_MAX_ROWS` — and in this round only because it is the third
instance of this shape inside the one function that round added.

**Fix**: a floor of 1 on the resolved limit, and `u32::try_from(..)
.unwrap_or(u32::MAX)` rather than `as`. Two host tests: `Some("0")` resolves to
at least 1, and a `max_rows` at `u32::MAX` does not resolve to 0 or 1.

## 3. Not in this round

Everything §3 of round 2's handoff excluded, unchanged: the truncation signal's
invisible reader, the audit-kind column (15 of 42), an audit write for
`verify_now`, `audit_chain_status_page`'s deletion, `operations_page`, slices
3–6, the Kani trial.

## 4. Baselines — round 2 as accepted, `32c50b9`

| gate | value |
|---|---|
| host tests | **1,708 / 0 / 4**, 12 `test result:` lines |
| `route-contracts-check.sh` | exit 0; E4 **218 = 194 (183+11) + 24 + 0**; E5 **19**; **All 196 routes** |
| `drift-scan.sh` | exit 0, clean; route surface **196 pairs — 1 added, 0 removed** |
| `migration_chain` | **35** |
| backend dead-code warnings | **7** |
| mdbook | **82 pages** |
| Worker bundle | **no accepted baseline** — measure once, after the version bump, against `0.96.0`'s **893,683 B** |

## 5. Review request

Append as §10 of the same report, or file
`131-slice2-register-report.md` — say which.
