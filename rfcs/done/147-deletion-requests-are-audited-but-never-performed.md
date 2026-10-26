# RFC 147 — Deletion requests are audited but never performed

**Status.** **Done** — cycle 1 `c23dbf9` (shipped v0.85.1), cycle 2 `2099df3`,
accepted 2026-10-27. Awaiting the 0.86.0 cut for a released version.
**Tier.** **P1 · Category A** — a user's request to delete their own account is
silently discarded, a documented irreversible operation does nothing, and the
audit log records a deletion that did not happen.
**Size.** Medium. The repository and the deletion service already exist; three
handlers and a page do not use them.
**Touches.** `crates/backend/src/routes/deletions.rs`,
`docs/src/expert/admin-operations.md`, a template, and whatever tests the wiring
needs.
**Depends on.** Nothing. The adapter and the core service are already built.
**Found by.** The dev team, reporting RFC 145 cycle 1's §5 question on
`/admin/t/:slug/deletion-requests`, 2026-10-25. They reported it as "a third
thing, not just no template" and stopped, which was correct.

## 1. Summary

Three HTTP handlers in `routes/deletions.rs` write an audit event, log, and
redirect with a success parameter — **without touching the deletion-request
repository at all.** The repository is fully implemented and the sweep that
consumes it works.

| Handler | Route | What it does | What it does not do |
|---|---|---|---|
| `request_self` | `POST /me/security/delete-account` | writes `DeletionRequested`, detail *"self-request scheduled in 30d"*; 303 → `/me/security?deletion_requested=1` | create a deletion-request record |
| `admin_cancel` | `POST /admin/t/:slug/deletion-requests/:id/cancel` | writes its event; 303 → `…?cancelled=1` | cancel anything |
| `admin_execute` | `POST /admin/t/:slug/deletion-requests/:id/execute` | writes `DeletionExecuted`, logs at **Warn**; 303 → `…?executed=1` | load the request, validate the id, or delete the user |

Each carries the comment *"Full implementation pending
`CloudflareDeletionRequestRepository`"*. **That repository exists**, with six
`async fn`s, at `crates/adapter-cloudflare/src/ports/repo/deletions.rs`.

## 2. What is established

**Superseded by §13 — this is false, and it was mine.** The sweep function is
complete and **is called by nothing**; see §13.2. What follows describes the
function, correctly, and its claim to be *in use* does not hold.
`sweep.rs:252` constructs
`CloudflareDeletionRequestRepository`, calls `list_due(now)`, and runs
`cesauth_core::deletion::execute_deletion(&del_repo, &user_repo, &req.id,
"sweep", now)` — real deletion, with its own `DeletionExecuted` audit event.

**The handlers do not use it.**

```
$ grep -rn 'CloudflareDeletionRequestRepository' crates/backend/src --include='*.rs'
sweep.rs:240   use …                     ← real
sweep.rs:252   …::new(env)               ← real
routes/deletions.rs:41   // Full implementation pending …   ← comment
routes/deletions.rs:97   // Full implementation pending …   ← comment
routes/deletions.rs:133  // Full implementation pending …   ← comment
```

**The documentation promises what the code does not do.**
`docs/src/expert/admin-operations.md:93` on the execute endpoint:

> **Physically deletes the user. Irreversible.** Emits `DeletionExecuted`.
> ON DELETE CASCADE removes all child data (authenticators, sessions, etc.).

and `:85` on cancel: *"Cancels a pending request before `scheduled_at`."*

**The self-service route is live.** `lib.rs:213` registers
`POST /me/security/delete-account` (RFC 044).

**The page is one of RFC 145's thirty-five.** `admin_list` serves the shell,
`app.rs` has no route for it, so the admin queue renders Not Found; its `.json`
companion returns only a CSRF token, with no deletion-request data.

## 3. Why this is P1, in order of seriousness

**3.1 The audit log is told something false, on demand.** `admin_execute` writes
`DeletionExecuted` for a deletion that did not occur, and it is the *same event
kind* the sweep writes for real ones — separable only by a detail string
(`"admin-triggered"` vs `"sweep"`). An audit trail exists to be believed when
the system cannot be inspected directly. Any tenant admin can generate false
entries, for any `:id`, including ids that do not exist, because nothing
validates them.

**3.2 A user's deletion request is silently discarded.** The user is redirected
to `?deletion_requested=1` and the audit log says *"scheduled in 30d"*. No
record is created, so the working sweep will never find it. Nothing will ever
happen, and both the user and the log say otherwise.

**3.3 A documented irreversible operation is a no-op.** An operator following
`admin-operations.md` believes they have deleted a user's data. They have not.

Note the direction of each: nothing deletes data that should have been kept —
the failure is always that **data survives while the record says it is gone.**
That is the safer direction for a bug to fail in, and it is still wrong in the
way that matters most for an identity service.

## 4. Why nothing caught it

- **The handlers return success.** 303 with `?executed=1` is indistinguishable,
  from outside, from having worked.
- **The audit event fires.** Any check that asks "did this emit its documented
  event?" passes. The event is the *only* thing the handler does.
- **The page that would show the truth renders Not Found** (RFC 145). Nobody can
  look at the queue and notice the request is still there.
- **The sweep works**, so deletions that reach the repository by any other path
  do happen, which makes the subsystem look alive.
- **`route-contracts.md` lists the audit event each route emits** — and these
  rows are correct. The contract never claims the route *performs* the
  operation; only the prose documentation does.

The comment *"Full implementation pending"* is the honest part. It was written
when it was true and was never revisited after the repository landed.

## 5. Proposed design

1. **Wire the three handlers to the existing repository and service.**
   `request_self` creates a request with its `scheduled_at`; `admin_cancel`
   cancels a loaded request; `admin_execute` calls
   `deletion::execute_deletion`, the same entry point the sweep uses, so there
   is one deletion path and not two.
2. **Validate the id before emitting anything.** A request that does not exist,
   or belongs to another tenant, is a 404 — **and writes no audit event.** No
   handler may emit a completion event before the operation succeeds.
3. **Audit events follow the outcome.** Emit after success; on failure emit
   nothing or an explicit failure event. Decide which, and say so — a missing
   event and a false one are not equally bad, and this RFC exists because one
   of them was chosen by accident.
4. **Distinguish the actor.** Admin-triggered and sweep-triggered deletions
   should not be separable only by a free-text detail. Either different event
   kinds or a structured actor field; the implementer proposes, I decide.
5. **The admin queue page** gets a real data path and renders server-side,
   consistent with RFC 145's decision. This removes it from RFC 145's list — see
   §7.
6. **Correct `admin-operations.md`** so the prose matches the code at every step
   of the work, not at the end.
7. **Remove the three "pending" comments** as each is resolved. A stale comment
   is what let this sit.

## 6. Testing strategy

- **A request created by `request_self` is found by `list_due`** once its
  schedule passes. That is the end-to-end property the current code fails, and
  it should be the first test written.
- **`admin_execute` on a nonexistent id**: 404, **no audit event**. Assert the
  absence, not just the status.
- **`admin_execute` on a request from another tenant**: 404, no event.
- **A successful execute deletes the user** and its child rows, through the same
  service the sweep uses.
- **Cancel prevents a later sweep from executing** the request.
- **No completion event precedes its operation** — the invariant behind §5.3.
- Where a `worker::Request` is needed and cannot be built on the host, extract
  a decision function taking primitives, as `decide_verify_get` and
  `render_with_nonce` already do in this codebase.

## 7. Relationship to RFC 145

`/admin/t/:slug/deletion-requests` is one of RFC 145's thirty-five dead pages,
and the **one with no template** (RFC 145 §11.3). RFC 145 cycle 1 was right not
to build it: a template alone would have displayed an empty queue, because there
was no data path to display. **This RFC owns that route**, and RFC 145's scope
drops from 34 to 33 when this lands.

## 8. Acceptance criteria

1. The three handlers perform their operations through the existing repository
   and `deletion::execute_deletion`.
2. No completion audit event is emitted for an operation that did not occur,
   and ids are validated before anything is written.
3. A `request_self` request is executed by the sweep when due.
4. Admin-triggered and sweep-triggered deletions are distinguishable without
   parsing free text.
5. The admin queue renders server-side with real data.
6. `admin-operations.md` matches the code; the three "pending" comments are gone.
7. No existing test weakened.

## 9. Level

**Minor.** Three documented operations begin working for the first time. That is
closer to an added capability than to a fix, whatever the documentation claimed,
and the project's rule is that an added capability is a minor.

## 10. What I am not proposing

- **Not a hotfix.** Nothing regressed; this has never worked. The safer
  direction of the failure (§3) is what makes a scheduled fix acceptable rather
  than an emergency.
- **Not a change to the sweep.** It works and it stays the single execution
  path.
- **Not RFC 044's design.** The grace period, the 30 days and the self-service
  route are its decisions and are not reopened here.

---

## 11. Split into two cycles, after reviewing the schedule against the owner's philosophy (2026-10-25)

The owner's standard is *"finally clean, safe and secure, and robust and
sophisticated design"*, and *"APIs and UI/UX for users not to be confused or
misunderstand"*. Re-reading §5 and §9 against that produced a change I had
missed, and it is the most important sentence in this RFC:

**The lie is the defect. The missing feature is only a gap.**

§9 scheduled all of this as one **minor**, because implementing three
operations is an added capability. That is correct about the implementation and
wrong about the urgency, because it bundles two different things:

- **Claiming success for work not done** — a false `DeletionExecuted` in the
  audit log, a user told their deletion is "scheduled in 30d", and documentation
  promising an irreversible deletion. **This is a defect, it is live now, and
  stopping it does not require implementing anything.**
- **Performing the operations** — real work, correctly a minor, correctly
  scheduled.

Holding the first behind the second means the audit log keeps recording
deletions that did not happen for as long as the implementation takes. Nothing
about the owner's standard permits that when the remedy is small.

### 11.1 Cycle 1 — stop claiming success (patch)

1. **The three handlers emit no completion audit event.** `DeletionRequested`,
   `DeletionCancelled` and `DeletionExecuted` are written **only** by code that
   performed the thing. Until cycle 2, that is the sweep alone.
2. **They return `501 Not Implemented`**, with a body that says the operation
   is not yet available. 501 is the honest status: the route is understood and
   not implemented.
3. **The success redirects go** — no `?executed=1`, `?cancelled=1`, or
   `?deletion_requested=1`. A parameter that tells the UI an operation
   succeeded is the "users must not misunderstand" failure in its most literal
   form.
4. **`docs/src/expert/admin-operations.md` is corrected** — including `:93`'s
   *"Physically deletes the user. Irreversible."* — to state that these
   endpoints are not implemented, with a pointer to this RFC.
5. **The "Full implementation pending" comments stay** until cycle 2 removes
   them. They are the only honest thing in the file today.

**Why 501 rather than deleting the routes.** Deleting them would be cleaner in
the abstract, but it removes a documented surface — a minor — and cycle 2 would
re-add it. 501 plus corrected documentation is honest, keeps cycle 2 a pure
wiring job, and nothing that worked stops working, because nothing worked.
**That makes cycle 1 a patch.**

**Measured, and it limits the user-facing exposure:**
`grep -rn 'deletion_requested\|delete-account' crates/frontend/src --include='*.rs'`
returns **0**. No UI reaches `POST /me/security/delete-account`, and nothing
renders the `?deletion_requested=1` banner, so a user who lands back on
`/me/security` currently sees no confirmation at all. The route is live and
documented, so an integrator can call it — but no cesauth screen leads a user
into this. **That is why cycle 1 is a patch in 0.85.1 and not an emergency.**

### 11.2 Cycle 2 — perform the operations (minor)

§5.1–5.7 and §6 unchanged, minus what cycle 1 already did. The three handlers
are wired to the existing repository and to
`deletion::execute_deletion` — the same entry point the sweep uses, so there is
one deletion path — ids are validated before anything is written, events follow
outcomes, admin and sweep deletions become distinguishable without parsing free
text, and the admin queue page gets a real data path and renders server-side.

**This is the minor**, and it ships alone (schedule §4), because deletion is the
most destructive operation in the system and bundling a console screen beside it
dilutes review attention on the dangerous part.

### 11.3 What I did not change on review

- **Still not a hotfix.** The failure direction is that data survives while the
  record says it is gone, never the reverse (§3), and no UI leads a user here.
- **The sweep is still untouched** and remains the single execution path.
- **RFC 044's grace period and self-service design** are still not reopened.

## 12. Found while dispatching cycle 1: the event column has no gate behind it

`route-contracts.md:107,110,111` declare these routes' audit events
(`deletion_requested`, `deletion_cancelled`, `deletion_executed`). **Nothing
verifies that column.** `scripts/route-contracts-check.sh` does not read it, and
the audit scanner in `crates/backend/src/audit/tests.rs` checks audit call
*arguments* against a secret denylist, not whether a declared event ever fires
or whether the operation beside it happened.

That is how three routes came to emit the events their contract promises while
performing none of the work: **the only part of the contract they satisfied was
the part a gate could see, and no gate saw any of it.**

**Not in scope here.** RFC 123 (audit-event completeness, proposed) is where a
check belongs, and this is a concrete argument for it rather than a new task for
this RFC. Recorded so RFC 123 inherits the example.

## 13. Cycle 1 accepted, and it refuted two of my claims (2026-10-27)

Cycle 1 landed at `c23dbf9` and is accepted: **0** completion events remain in
`deletions.rs`, **0** success parameters, the three "pending" comments intact,
the three contract rows at `none` / `501` with no other column moved, routes
**193**, host tests **1,552**, every gate green. The implementer queried
`audit_events` for `kind LIKE 'deletion%'` after driving all three routes and
got **zero rows** — the absence measured where it lives, not inferred from a
status code. Review: `.git-exclude/reviewed/147-cycle1-review.md`.

Two findings came with it, reported and deliberately not fixed. Both correct
this RFC.

### 13.1 `request_self` has never checked user auth — so §3.2 overstated the harm

`deletions.rs:21` imports `crate::routes::admin::auth` and no `me::auth`, where
a real `/me/*` route uses `crate::routes::me::auth as me_auth`
(`me/security.rs:48`). It predates cycle 1. **A user's own session gets 401 on
`POST /me/security/delete-account`; only an admin bearer passes.**

Three sources agree the code is the outlier: the module doc (`deletions.rs:5-6`,
*"Self-service: authenticated user schedules their own deletion"*),
`route-contracts.md:107` (actor *"authenticated user"*, session *"session"*),
and **RFC 047 line 13**. Not an escalation — stricter than intended, the safe
direction — but the feature is unreachable by the only principal it exists for,
and row 107's actor and session columns are false.

**§3.2 said "a user's deletion request is silently discarded" while the log said
scheduled. No user could ever submit one.** The harm was real but confined to an
admin caller, and the audit-log falsehood (§3.1) is the part that stands.

### 13.2 The sweep has never run — so §2 and §3.1 were wrong

`grep -rn 'sweep_pending_deletions' crates/` returns **two** lines: the
definition at `sweep.rs:239`, and a **doc comment** at
`crates/core/src/deletion.rs:25` claiming *"The daily cron pass calls
`sweep_pending_deletions`"*. Nothing calls it. `scheduled()` (`lib.rs:68`) sends
the daily cron to `sweep::run`, which sweeps anonymous-trial retention only.

**No deletion has ever been executed in cesauth, by any path.**

§2 said *"the machinery is complete and in use elsewhere"* and §3.1 contrasted
the handlers' false events with the sweep's *"real ones"*. **There are no real
ones.** I verified that `sweep_pending_deletions` exists and uses the repository
correctly, and never checked whether anything calls it — the
declared-but-never-wired class, committed by me, in an RFC about that class.

`admin-operations.md`'s cron description — *"3. (RFC 047) Executes pending
deletion requests past `scheduled_at`"* — is false for the same reason.

### 13.3 Cycle 2's scope, revised

In addition to §11.2:

1. **Wire `sweep_pending_deletions` into `scheduled()`.** It is the execution
   path; cycle 2 cannot be verified without it, and its absence is why "the
   sweep is the single execution path" was never true.
2. **Fix `request_self`'s resolver** to a user session check, and
   `route-contracts.md:107`'s actor and session columns with it. A self-service
   route must be reachable by the self it serves.
3. **Correct `core/deletion.rs:25` and `admin-operations.md`'s cron line 3** as
   each becomes true.

**Cycle 2 therefore completes RFC 047**, whose §4 cron sweep and self-service
route have never worked. Annotated in `rfcs/done/047-deletion-worker-layer.md`.

### 13.4 Cycle 1's own framing was wrong, in my favour

D1 of the cycle-1 handoff said *"until cycle 2 that is the sweep alone"* —
naming the sweep as the one true execution path. It is not one. The implementer
flagged exactly that, which is the second time this cycle a handoff assertion of
mine was corrected by someone running it.

## 14. Found while scoping cycle 2: deletion does not reach `invitation_tokens`

Measured across all migrations, taking each table's **last** definition: **every
table that references `users(id)` carries `ON DELETE CASCADE`** — 28 of them,
including `authenticators` (`0020`), `totp_authenticators` and
`totp_recovery_codes` (repaired by `0016`), `user_sessions`, and the four
tenancy membership and role tables (`0012`, which exists for exactly this
purpose). So `execute_deletion`'s comment and `admin-operations.md`'s claim
about child data are **accurate**, and cycle 2 may restore them.

**`invitation_tokens` (`migrations/0018`) is the exception.** It has no
reference to `users(id)` at all. It carries:

- `email` — the recipient's address, **PII**, `COLLATE NOCASE`;
- `issued_by`, `accepted_by`, `revoked_by` — user ids as plain text, no FKs.

**So a deleted user's email address survives in `invitation_tokens`**, as does
their id wherever they issued, accepted or revoked an invitation. For a feature
whose purpose is erasing a user, that is a real residue — and the codebase is
elsewhere explicit that emails are PII, in `audit.rs:428-430`'s own warning not
to put raw emails in an audit subject.

**Not in cycle 2** (§11.2's scope is wiring, and recorded in that handoff as
D14): whether an invitation record should be purged, or its email scrubbed while
the tenant's invite history is kept, is a **policy** question with a competing
claim on the data. Deciding it inside a wiring cycle would be the same mistake as
bundling the implementation with the honesty fix.

**What cycle 2 must do is not over-claim.** The restored documentation says
child data *linked by foreign key* is removed, and names `invitation_tokens` as
retained. A deletion feature that promises complete erasure and leaves an email
behind would be this RFC's own defect, one layer out.

`deletion_requests` retaining `user_id` after execution is deliberate (`0019`'s
comment) and is the audit trail, not a leak.

**This needs its own RFC number before it is scheduled** — the standing lesson
from RFC 144, which was lost once for want of one. Mine to assign.

## 15. Cycle 2 accepted; RFC complete (2026-10-27)

Deletion requests are performed. Verified independently at `2099df3`: **1,556**
host tests (1,552 + 4), `migration_chain` **31** with `migrations/` untouched,
routes **192** (D10's orphaned `.json` removed), clippy / `deny` / `audit` /
drift / mdbook all **exit 0**, **0** new `EventKind`s, and `admin_execute`
ordered auth → gate → `find_by_id` + tenant comparison → 404 → `execute_deletion`
→ **then** the audit event. Review: `.git-exclude/reviewed/147-cycle2-review.md`.

**The end-to-end property that had never held now holds**, and was proven
through `/cdn-cgi/local/scheduled` — the real `#[event(scheduled)]` handler —
rather than by calling `sweep_pending_deletions` from a test, which §9 forbade
precisely because the uncalled function *was* the defect.

### 15.1 §2's table was wrong about the sweep, and running it found that

The handoff listed `sweep_pending_deletions` as *"written, correct-looking"*.
Wiring it was not sufficient: the first real cron execution wrote
`audit_events.subject = null`, because the sweep's own `write_owned` call had
never been reconciled with D5 — which named the sweep explicitly. The
implementer found it by driving the handler, fixed it, and reported it as a
defect they had introduced rather than folding it into the diff.

**Second time this session a live run beat a reasoned plan**, after RFC 146's
measurement, and both times in territory a handoff of mine described as already
correct.

### 15.2 One surface decision was made without being flagged

`request_self` is now **JSON-only** — `Content-Type: application/json` or 400 —
which the report does not state; it appears only as `N/A (JSON)` in row 107's
CSRF column. The decision is **right**: under `csrf.rs:23-29` only
form-encoded bodies need a token, because a cross-origin JSON POST cannot avoid
a preflight, so requiring JSON *is* the defence. No caller breaks (**0**
frontend references).

**But a change to what a caller must send is a decision, and belongs in the
report** even when correct — a destructive user POST whose contract says CSRF is
not applicable is the row a future reader stops at. Recorded as a standing rule
in the review.

### 15.3 What remains, and it is only §14

`invitation_tokens` still retains a deleted user's email address, and
`request_self` answers `302` to an HTML page from a JSON-only endpoint. **Both
are this route's surface, and both go into one follow-up RFC** rather than
staying as notes — §14's own closing instruction, and RFC 144's standing lesson.

**RFC 047 is complete.** Both of its deliverables are reachable and real.
