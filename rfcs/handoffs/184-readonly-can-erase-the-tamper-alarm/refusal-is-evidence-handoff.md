# RFC 184 round 2 — the refusal is itself evidence, and right now it is silent

**Parent.** `rfcs/handoffs/184-readonly-can-erase-the-tamper-alarm/alarm-stickiness-handoff.md`
— round 1 **accepted** (`664a7db`), review at
`.git-exclude/reviewed/184-alarm-stickiness-review.md`.
**Target release.** **`0.98.0`, the same cut**, held for this. Level unchanged.
**Box.** Small. One return type, two call sites, and what you choose to record.

**Credit first**: §2's witness was the best-executed evidence step this handoff
chain has produced — real minted tokens at the real roles, the tamper applied
below the application layer, the real cron entry point, and an explicit line
between what the payload proves and what the code proves. This round exists
because that witness was good enough to read closely, not because anything in
it was wrong.

---

## 1. What is wrong

`persist_result` returns `prior_result` on refusal, and `verify_now` builds its
audit detail from the return value. The walk **has already run** —
`verify_chain_full` calls `walk_and_verify(repo, 0, &None)` and computes a
full-walk `valid`, `first_mismatch_seq`, `rows_walked`, `chain_length` — and
that computed result is then discarded.

So your own §1 step 6 records `valid=false first_mismatch_seq=Some(4)
rows_walked=1` for a **full re-walk of a six-row chain**: the previous
*incremental* run's numbers, attributed to this press.

Why it matters more than a wrong number:

- **The log cannot distinguish two different events.** "The walk found the
  tamper again" and "the walk found the chain clean, and the write was refused"
  produce byte-identical audit details.
- **It discards the signature of the attack.** A standing alarm at seq N *plus*
  a fresh full walk that verifies clean is exactly what a wholesale rewrite
  looks like. Round 1 correctly stops the alarm being erased; nothing records
  that the chain had been made to look clean.
- **The cron path loses the same thing, with no actor to carry it.** After a
  rewrite the daily cron computes `valid:true` every night, the refusal holds
  the alarm, and nothing anywhere records the clean verdict — `lib.rs`'s ops
  write stores only `chain_result.is_ok()`, not the verdict.

## 2. What to change

**Make the refusal observable. The design is yours; the behaviour is not
negotiable.** After the round-1 §2 sequence, the record must distinguish "found
tamper again" from "found clean, refused".

Two shapes that work, and you may do both:

- **Return enough to tell them apart** — `persist_result` yields the stored
  result *and* whether it refused, plus the computed verdict it refused to
  write, so `verify_now`'s audit detail can carry both. This covers the operator
  path, which is where an actor exists.
- **Record it on the stored record** — a field capturing that a clean walk was
  refused, and when. This is the only shape that covers the **cron** path, which
  has no actor and today leaves no trace at all.

I lean to both, with the second being the one that closes the cron hole. If you
choose only one, say which hole you are leaving open and why.

**Keep the alarm's own fields authoritative.** Whatever you add must not let a
refused clean walk weaken what the UI reads as the alarm — `last_run_valid` and
`last_run_first_mismatch` must still describe the detected tamper, not the
latest walk.

**If the stored record gains a field**, it is a port surface-contract change
again: `#[serde(default)]`, both adapters read rather than assumed, and the
pre-release-blob reading stated — exactly as you did for `acknowledged`.

## 3. Evidence required

- **Re-run round 1 §2's sequence** to step 6 and show the audit detail now
  distinguishing the two cases. You already have the fixture; this is a re-run,
  not a new build-up.
- **The other case, explicitly**: a later run that is *also* invalid must still
  overwrite with fresher numbers and must **not** be recorded as a refusal.
  Round 1 has the unit test for the overwrite; extend it to the new signal.
- **The cron path**, if you take the second shape: show what a refused nightly
  run leaves behind.
- Host tests for whatever decision function you extract, per usual.

## 4. Report-and-stop

- You conclude the audit detail was right as it stood. Say why and stop — I may
  be wrong about what a reader of that log needs.
- Making the refusal observable would require changing what the **UI** reads as
  the alarm. Report before doing it; §2's constraint exists because an operator
  must not see a tamper alarm soften because someone pressed a button.
- Any need to touch `walk_and_verify`.

## 5. Not in this round

- `route-contracts.md`'s **Role column**, which reads "System admin" for both
  `verify` (every role) and `acknowledge` (not `ReadOnly`) — own row.
- **A reason field on acknowledgement** — a real idea, not a defect, own row.
- `ViewConsole` on the verify route (RFC 184 §5.5, owner-accepted), RFC 185,
  RFC 131 slices 3–6, the audit-kind column's other 14 names.

## 6. Baselines — round 1 as accepted, `664a7db`

| gate | value |
|---|---|
| host tests | **1,718 / 0 / 4**, 12 lines — use the **canonical** five-crate `-p` command |
| `route-contracts-check.sh` | exit 0; E3 **47**; GATE_42 **24**; NONCE **13**; E4 **219** = 195 (184+11) + 24 + 0; E5 **19**; E6 **95** = 86 (66+0+20) + 9 + 0; E7 **156**; ✅ **All 197 routes** |
| `drift-scan.sh` | exit 0, clean; route surface **197 pairs — 1 added, 0 removed** |
| `migration_chain` | **35** · backend warnings **7** · mdbook **82** |
| Worker bundle | round 1 reported **899,244 B** pre-bump; **no accepted baseline** — measure once after the version bump, against `0.97.0`'s **897,801 B** |

## 7. Review request

Append as §8 of the same report, or file
`184-refusal-is-evidence-report.md` — say which.
