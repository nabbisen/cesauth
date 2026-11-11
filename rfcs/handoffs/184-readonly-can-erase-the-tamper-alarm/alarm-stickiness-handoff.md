# RFC 184 — make the tamper alarm un-erasable, and record who tried

**Governing RFC.** `rfcs/accepted/184-readonly-can-erase-the-tamper-alarm.md`
— **accepted by the owner 2026-11-11**, severity read as **P1 for
integrity-of-evidence**.
**Target release.** **`0.98.0`, minor — earned**: it adds an acknowledgement
route. Scope is this RFC and nothing else.
**Box.** Medium. The witness step (§2) comes first and is not optional.

---

## 1. The defect, stated once

`core/src/audit/verifier.rs::verify_chain_full` writes
`checkpoints.write_last_result(&result)` **unconditionally** into a single slot,
then advances the checkpoint when `result.valid`. That slot's own port doc
(`core/src/ports/audit_chain.rs:127-130`) says it exists so *"the admin UI
surfaces the alarm"*.

So a cron-detected `valid=false, first_mismatch_seq=N` is replaced by whatever
the next full re-walk says — and if the chain was rewritten consistently in the
meantime, that is `valid=true`, followed by a new baseline `chain_hash`. One
press of **Verify chain now**, no confirmation, no record. `policy.rs:34` makes
`ViewConsole` true for **every** role, `Role::ReadOnly` included.

## 2. Drive it before you fix it — the witness is a deliverable

**Do this first and report it even if it contradicts the RFC.** The RFC's
evidence term is `reviewed`, not `exercised`: I read this from the code and the
port docs and did **not** reproduce it. If it does not reproduce, that is the
most valuable thing you can tell me and you should stop and say so.

Against a local D1 with `wrangler dev --local`:

1. Build a chain with real events, run a verification, confirm a good checkpoint.
2. **Tamper**: alter a row so the chain breaks at a known `seq=N`.
3. Run the incremental path (the cron's `verify_chain`) and capture
   `chain.json`: expect `last_run_valid: false`, `last_run_first_mismatch: N`,
   and the `⛔ tamper detected at seq=N` badge.
4. **Now rewrite the chain consistently** from `N` onward, so an independent
   full walk finds no internal mismatch. This is the wholesale-rewrite case the
   checkpoint cross-check exists to catch.
5. `POST /admin/console/audit/chain/verify` **as a `ReadOnly`-role principal**.
6. Capture `chain.json` again. **Report exactly what survived**: the
   `last_run_*` fields, `checkpoint_seq`, and `checkpoint_chain_hash` before and
   after.

State plainly whether the alarm was erased and whether the baseline moved. That
pair of payloads is the witness the fix is measured against.

## 3. The fix

**§3.1 — A detected mismatch is sticky.** An unacknowledged `valid=false` must
survive any later run. A hash-chain mismatch means rows were altered; it is not
a transient condition a retry can clear, so "press until green" must not be an
available move. Whether that means a second stored field, an acknowledged flag,
or a short run history is yours to design — **say which and why**. The
constraint is behavioural: after §2 step 5, the alarm is still there.

**§3.2 — Refuse to re-baseline over an unacknowledged alarm.** Do not advance
the checkpoint while an unacknowledged `valid=false` is stored, even when the new
walk is internally consistent. Exactly the §2 step 4–5 sequence.

**§3.3 — An acknowledgement route.** An operator asserting a tamper finding has
been dealt with is the most consequential statement anyone makes in this
subsystem. It needs CSRF, it needs a stronger permission than viewing, and it
needs a control on the chain-status screen.

**Permission**: a **new `AdminAction`**, following the matrix in
`policy.rs:20-31` and documented in that same table. **Use
`VerifyBucketSafety`'s row as the precedent** — `Security | Operations | Super`,
not `ReadOnly`. Do **not** reuse `VerifyBucketSafety` itself; a different
subsystem's action gate is not this one's.

**§3.4 — Audit both.** A new `EventKind` for the operator-triggered re-walk
(who, and the outcome) and one for the acknowledgement. The audit log is
hash-chained and append-only, which is the point: it is the one place this fact
cannot be overwritten by the next press. Add `route-contracts.md` rows for the
new route and **correct `:101`'s existing `audit_chain_verified` claim to the
kind you actually emit** — that row currently names a string the code never
produces.

**§3.5 — Fix the route's module doc.** It currently teaches the next reader that
*"a full re-walk is a non-destructive read operation"*. Say what it does.

## 4. Report-and-stop gates

- **§2 does not reproduce.** Stop. Report the payloads.
- Stickiness cannot be expressed without changing the `AuditChainCheckpointStore`
  **port**. That is allowed, but it is a surface-contract change — report it as
  one (both adapters, the in-memory double included), and **check the double
  agrees with the real adapter**; a dead match arm with a green suite is a shape
  this project has already paid for.
- The cron path (`verify_chain`) would need to change to make stickiness work.
  Report before doing it — the RFC scopes the operator path, and a cron that can
  no longer record a *new* mismatch because an old one is sticky would be a
  worse defect than the one being fixed. **Think about that case explicitly and
  tell me what you chose.**
- Any need to touch `walk_and_verify` itself.

## 5. Not in scope

- **Changing `ViewConsole` on the verify route.** The RFC §5.5 recommends
  leaving it, the owner accepted that, and §3.1/§3.2 are what make it safe. A
  separate ROADMAP row carries the `VerifyBucketSafety`-precedent question for
  the owner; do not pre-empt it.
- RFC 185's locale work, RFC 131 slices 3–6, `operations_page`, the audit-kind
  column's other 14 wrong names, the export truncation header's reader.
- Any change to the cron schedule or to `verify_chain`'s incremental logic
  beyond what §4 forces you to report.

## 6. Baselines at `0.97.0` (`86ae04d`)

| gate | value |
|---|---|
| host tests | **1,710 / 0 / 4**, 12 `test result:` lines |
| `migration_chain` | **35** |
| `route-contracts-check.sh` | exit 0; E3 **47**; GATE_42 **24**; NONCE **13**; E4 **218** = 194 (183+11) + 24 + 0; E5 **19**; E6 **94** = 85 (65+0+20) + 9 + 0; E7 **156**; ✅ **All 196 routes** |
| `drift-scan.sh` | exit 0, clean; route surface **196 pairs** |
| backend dead-code warnings | **7** |
| mdbook | **82 pages** |
| Worker bundle | **897,801 B** gzip at default level (887,101 wasm + 10,700 `shim.js`), sha256 `f738af3f010b7803` / `41137a86c20ebe74` — measure after the version bump |

Expect: route surface **+1** (the acknowledgement route) and a
`route-contracts.md` row for it, E4 **+1**, E6's mutating-row count **+1** with a
CSRF claim, host tests up. **A `patch claim` from the level backstop means the
version was bumped wrongly — stop.**

## 7. Review request

File at `.git-exclude/review-request/184-alarm-stickiness-report.md`. Lead with
§2's before/after payloads, then the fix. If §2 contradicted the RFC, say so in
the first line.
