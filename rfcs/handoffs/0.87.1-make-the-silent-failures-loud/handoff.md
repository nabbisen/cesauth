# Developer Handoff — 0.87.1, make two silent failures loud

**Governing RFCs.** `rfcs/accepted/148-deletion-leaves-the-email-address-behind.md`
**§7 only** · `rfcs/accepted/156-the-gate-set-has-no-gate.md`

**Target release.** 0.87.1 — **patch.** Neither changes a capability. RFC 148 §7
makes an existing guarantee's failure observable; RFC 156 is CI-only and
changes no shipped artifact.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-28.**

**Both are the same shape**, which is why they ship together: *something can
fail and nobody finds out.* 0.86.3 did this for three controls that held but
had no witness; these two are controls that can stop holding with no trace.

---

## 1. RFC 148 §7 — the scrub's outcome must be reportable

**Read §7 in full.** §7.2 explains why the current shape is *almost* right, and
§7.4 is the specification.

Today, in `core/src/deletion.rs`:

```rust
let email = user_repo.find_by_id(&req.user_id).await.ok().and_then(|u| u.email);
user_repo.delete_by_id(&req.user_id).await.map_err(|_| CoreError::Internal)?;
if let Some(email) = email {
    invitation_repo.scrub_email(&email, request_id).await.ok();
}
```

`-> CoreResult<()>`. A failed read scrubs nothing; a failed write is discarded;
both callers see `Ok(())`.

**Required:**

1. `execute_deletion` returns the scrub outcome — `CoreResult<ExecuteOutcome>`
   carrying `scrub: ScrubOutcome` (`Scrubbed` / `NoEmailOnFile` / `Failed`), or
   the smallest equivalent you prefer. **Name the `Failed` variant so it cannot
   be ignored by accident** — a bare `bool` invites `let _ =`.
2. **Do not make a scrub failure a deletion failure.** §7.2: the user row is
   already gone, so returning `Err` would tell the caller the deletion failed
   and its retry would then get `deletion request is not pending`. This is the
   one constraint that is not negotiable.
3. Both callers act on it — `routes/deletions.rs:445` (admin execute) and
   `sweep.rs:269` (the daily cron):
   - **log** a `Failed`, at a level an operator will see;
   - put it in the **`deletion_executed` audit event's detail**, which already
     carries free text and already distinguishes the sweep from an admin.
4. **`NoEmailOnFile` is not a failure.** An anonymous-promoted account may
   genuinely have no address. But it **must be distinguishable from
   `Scrubbed`**, because today "there was nothing to scrub" and "the scrub did
   not happen" are indistinguishable from outside.
5. **Replace the documentation's best-effort paragraph.**
   `docs/src/expert/admin-operations.md` currently says the scrub is
   best-effort and its outcome is not reported, and points at §7. When it is
   reported, that paragraph must say what is true instead — including that a
   failure is visible and where.

**Evidence — a test per outcome**, and the one that matters is `Failed`:
a repository stub whose `scrub_email` errors, asserting the caller sees
`Failed`, logs it, and that the audit detail carries it. **That is the witness
§7 says is missing; the happy path already has four.**

## 2. RFC 156 — a manifest, and a check that the gates ran

**Read §4.** The manifest is the valuable artifact, more than the check.

1. **A checked-in manifest** of the gates a release is required to pass, with a
   category for *"exists, deliberately not on the release path"* — and an entry
   in that category must carry a reason, the same discipline as `E3_EXEMPT`,
   `GATE_42_EXEMPT` and `NONCE_EXEMPT`.
2. **A check** that fails when the workflows triggered for a commit do not
   match the manifest. It needs the GitHub API, so it is naturally a
   release-time or post-push job rather than a per-PR one. **Say in the report
   where you put it and why** — that placement is a design decision and I will
   read it as one.
3. **Decide the fuzz job, do not inherit it.** §4's first sub-decision.
   `fuzz.yml` triggers on `pull_request` with path filters plus
   `workflow_dispatch`, so **it runs on no push and no release commit is
   covered by it.** My inclination is a **schedule** (nightly or weekly) plus
   the existing PR filter, and explicitly *not* the release set, recorded in
   the manifest as a decision. **Argue me out of it if you disagree** — a fuzz
   run is non-deterministic and a release gate that can fail for reasons
   unrelated to the change is a bad release gate, but the JWT parser is
   independently-implemented code processing adversarial tokens on every
   request (RFC 005), so the case for coverage is real.

**Two facts to use rather than re-derive**, both corrected in my own records
already:

- **A release commit runs 12 workflows, not 13.** I wrote "thirteen" in four
  release records before checking.
- **`fuzz.yml` has run** — three times, including once on `main` on
  2026-09-23, per `gh run list --workflow=fuzz.yml`. I twice wrote "never run
  on `main`", inferring it from the trigger block instead of asking the API.
  **The true statement is "runs on no push".**

## 3. Resolved decisions — do not re-open

- **Patch** for both.
- RFC 148 §7's constraint (2) above: a scrub failure is **not** a deletion
  failure.
- **Out of scope:** RFC 153 (its own cycle), RFC 152 half B and §6, RFC 141
  cycle 2, RFC 123 and its §1.1, RFC 120's duplicate-decision note.
- **Do not run `cargo fix`** on the admin route modules (RFC 145 §13.2).
  `-D warnings` stays off; that decision is mine and still awaits a scoping
  pass over the unrouted `*_json` handlers.
- **Nothing in this cycle is "for 1.0".** A 1.0 is not declared, scoped or
  dated, and that is the owner's to authorize. If you find yourself wanting to
  justify a choice by 1.0, justify it another way or report the question.

## 4. Report-and-stop gates

- the `ExecuteOutcome` change ripples further than the two callers;
- the manifest check cannot be placed without a token or permission the repo
  does not have — **say so rather than weakening it to something that passes**;
- you disagree with §2's fuzz-job inclination;
- an evidence requirement in §5 cannot be constructed. One line beats a silent
  substitution.

## 5. Required evidence

**RFC 000 §22 applies.** RFC 148 closes with this cycle; RFC 156 is new.

1. **A test per `ScrubOutcome`**, with the `Failed` case driven by a stub that
   errors — and a **fires/does-not-fire**: remove the reporting, show the test
   fail, restore byte-identically, show it pass.
2. **The manifest check demonstrated failing**: remove a workflow from the
   manifest, or a manifest entry from the workflows, and show it fail. A check
   whose failure nobody has seen is the thing RFC 156 exists to stop.
3. **Full gate set with counts.** CI's exact host-test command
   (`.github/workflows/test.yml:51-55`, five crates, **no `--lib`**), summed
   programmatically; baseline **1,599**. `migration_chain` baseline **35**,
   routes **192**.
4. **A proposed `**Status**` + `**Evidence**` line** for RFC 148 and RFC 156 in
   the back-fill's normalised format:
   `**Evidence**: **\`term\`** (RFC 000 §22) — <the witness>`.

## 6. What must not be claimed

- Not that deletion is now guaranteed to scrub — it is guaranteed to **report**
  whether it scrubbed. Those are different and the documentation must say the
  second.
- Not that the gate set is now verified continuously, if the check is
  release-time only. Say which.
- No count in prose without its command, no derived total unchecked against its
  parts, and **no delta between a local measurement and a CI baseline** — both
  sides must come from the same host.

## 7. Review request

Write the package to `.git-exclude/review-request/0.87.1-report.md` and give me
the commit. I verify independently before anything is tagged.
