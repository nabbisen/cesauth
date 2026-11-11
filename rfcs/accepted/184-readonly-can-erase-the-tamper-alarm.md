# RFC 184 — A ReadOnly admin can erase the audit chain's tamper alarm, and nothing records that they did

**Status**: Proposed, 2026-11-11. Needs the owner's authorization.
**Asked**: *"whether `POST .../audit/chain/verify` should write an audit record
at all — review it carefully by yourself with my fundamental philosophy."*
**Answer**: yes, it must. But auditing it is the smallest of three findings, and
shipping only the audit write would record the destruction instead of
preventing it.

---

## 1. What I was asked, and why the answer grew

The question came out of RFC 131 §0 slice 2's review: `route-contracts.md:101`
claims this route writes audit kind `audit_chain_verified`, and **no such
`EventKind` exists** — `verify_now` writes nothing. The obvious resolution is to
add the write and move on.

Reading the route to decide *why* it should be audited is what found the rest.
The route's own module doc states the authorization rationale:

> The chain status is read-only so any role with `AdminAction::ViewConsole` is
> allowed. The verify-now button also gates on `ViewConsole` (no separate
> permission) because **a full re-walk is a non-destructive read operation**
> that produces a fresher status; an attacker who triggers it gains nothing —
> the result is what the chain says, not what the attacker says.

**That premise is false in the code.** The reasoning about *information* is
correct — a re-walk tells you what the chain says. The claim about *state* is
not: a re-walk writes.

## 2. Finding 1 — the re-walk overwrites the alarm it exists to raise

`core/src/audit/verifier.rs::verify_chain_full`:

```rust
let result = AuditVerificationResult { valid: outcome.first_mismatch.is_none(), … };
checkpoints.write_last_result(&result).await?;          // unconditional
if result.valid {
    … checkpoints.write_checkpoint(&AuditChainCheckpoint { … }).await?;   // re-baseline
}
```

`write_last_result` is a **single slot**, and its own port doc says why it
exists (`ports/audit_chain.rs:127-130`): *"a failed verification does NOT
advance the checkpoint but SHOULD update the result so the admin UI surfaces
the alarm."*

So the sequence that matters:

1. The 04:00 cron detects tampering and writes `valid=false,
   first_mismatch_seq=N`. The console shows `⛔ tamper detected at seq=N`.
2. Anyone who can reach the console presses **Verify chain now**.
3. `verify_chain_full` re-walks and **unconditionally overwrites** that record.
4. If the chain has since been rewritten *consistently* — which is precisely
   what a wholesale-rewrite attacker produces, and precisely what the checkpoint
   cross-check exists to catch — the new result is `valid=true`, the alarm is
   gone, and step 5 follows.
5. Because `result.valid`, the checkpoint is **advanced to the rewritten
   chain's head**, replacing the recorded `chain_hash`. The cross-check that
   would have caught the rewrite now has nothing to disagree with.

**One button press converts "tampering detected" into "chain valid", and
re-baselines the evidence.** No confirmation, no record.

The hash-chained audit rows themselves are not altered by this — but the audit
chain's *detection state* is the only thing that tells an operator to look, and
it is a single mutable slot reachable from a button.

## 3. Finding 2 — the role that can do it is called `ReadOnly`

`core/src/admin/policy.rs:34` — `AdminAction::ViewConsole => true, // every
valid role`, with `tests.rs:16` asserting it for `ReadOnly`, `Security`,
`Operations` and `Super`. `types.rs:169` explains the intent: *"every valid role
may inspect what is"*.

So the weakest admin role — the one whose name promises it cannot change
anything — can perform §2. `ManageAdminTokens` is `Super`-only; erasing the
audit chain's tamper alarm is everyone's.

**This is a permission boundary that reads one way and behaves another**, which
is the owner's "APIs and UI/UX for users not to be confused or misunderstand"
applied to the people who operate the system, not just end users.

## 4. Finding 3 — and nothing records that it happened

The original question. `verify_now` writes no audit event; the contract table
says it writes `audit_chain_verified`. Note the asymmetry the codebase already
has: **merely looking at a console page writes `AdminConsoleViewed`** (restored
in 0.95.0 as RFC 161 §6.3's second control). Viewing is recorded. Overwriting
the integrity alarm is not.

The audit log is hash-chained and append-only, so it is the one place this fact
cannot itself be overwritten by the next button press.

## 5. What I propose

Ordered so that each step is useful alone, and the cheap one is not mistaken for
the fix.

**§5.1 — Make a detected mismatch sticky.** `write_last_result` must not
silently replace a stored `valid=false`. A later run may *add* its outcome, but
the unacknowledged alarm survives until an operator explicitly acknowledges it.
This is the actual fix: without it, §5.3's audit record merely documents the
loss. A hash-chain mismatch is not a transient condition that a retry can clear
— rows were altered — so "retry until green" must not be an available move.

**§5.2 — Refuse to re-baseline over an unacknowledged alarm.** Do not advance
the checkpoint while a stored `valid=false` is unacknowledged, even when the new
walk is internally consistent. That is exactly the rewrite case.

**§5.3 — Audit the trigger, and the acknowledgement.** A new `EventKind` for
the operator-triggered re-walk, carrying who and the outcome; and one for the
acknowledgement in §5.1, which is a human asserting that a tamper finding has
been dealt with — the most consequential statement anyone makes in this
subsystem. Then `route-contracts.md:101`'s claim becomes true; today it is one
of **15 of 42** audit kinds in that column that name a string the code never
produces (own ROADMAP row).

**§5.4 — Correct the route's own doc**, which currently teaches the next reader
that this is a non-destructive read.

**§5.5 — The permission is the owner's call, and I am not deciding it.**
Options: leave `ViewConsole` (defensible *if* §5.1 and §5.2 land, because then
the button cannot destroy anything); or introduce a distinct action so that
triggering a re-walk is not implied by "may inspect what is". My recommendation:
**fix the destructiveness first and leave the permission alone**, because
raising the permission without §5.1 still leaves a one-click erase for whoever
holds the higher role, and the plausible actor here is an insider who has it.
Acknowledgement in §5.1, though, should require more than `ReadOnly` — it is an
assertion, not an inspection.

## 6. What I am NOT claiming

- **Not remotely exploitable.** This needs a valid admin session and a matching
  CSRF token pair. It is an insider / stolen-session path, not an open door.
- **The audit rows are not altered** by any of this. What is lost is the
  detection record and the checkpoint baseline.
- **I have not driven the attack.** The sequence in §2 is read from the code and
  from the port's own documentation, not reproduced against a tampered local D1.
  **Evidence term: `reviewed`, not `exercised`** (RFC 000 §22). The implementing
  cycle should exercise it — write a mismatch, confirm the alarm, press the
  button, and show what survives — **before** the fix, so the fix has a witness.
- **Severity is mine to propose, not to assert**: I read it as **P1 for
  integrity-of-evidence**, bounded by requiring an authenticated admin. The
  owner authorizes.

## 7. Why this is not "just add the audit write"

The question I was asked has a one-line answer and a correct one: yes, audit it.
Had I stopped there, `0.98.0` would have shipped a release note saying the
operator-triggered verification is now audited — and the button would still turn
a tamper finding into a clean bill of health, now with a tidy record of who did
it. The owner's standard is *finally clean, safe and secure, and robust*. A
record of an erasure is not a substitute for not being able to erase it.
