# Developer Handoff — RFC 147 cycle 2, perform the deletions

**Governing RFC.** `rfcs/accepted/147-deletion-requests-are-audited-but-never-performed.md`
— **read §11.2 and §13 first.** §13 is cycle 1's findings, and they grew this
cycle by three items.

**Target release.** 0.86.0 — **and why that level:** **minor.** Three documented
operations begin working for the first time, and a user gains a capability
(requesting their own deletion) that has never been reachable. Whatever the
documentation claimed, that is an added capability.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. 0.85.1 is cut (`c4970ec`), so this may land on `main`.
**This cycle ships alone** (schedule §4): deletion is the most destructive
operation in the system, and a release that also carried a console screen would
split review attention between the dangerous part and the cosmetic one.

---

## 1. Purpose

**Nothing in cesauth has ever executed a deletion.** Cycle 1 stopped the three
endpoints claiming otherwise. This cycle makes them work, and wires the sweep
that was supposed to be the execution path and is called by nothing.

When this lands, a user can request deletion of their own account, see that it
is pending, an admin can see the tenant's queue and cancel or execute a request,
and the daily cron executes requests whose grace period has passed.

**This completes RFC 047**, which sits in `done/` with both its deliverables
non-functional.

## 2. Almost all of it already exists

This is a wiring job, like RFC 143 and RFC 145 cycle 1 before it. Measured:

| Piece | Where | State |
|---|---|---|
| `schedule_deletion(repo, user_id, tenant_id, requested_by, reason, grace_secs, now)` | `core/deletion.rs:103` | written; rejects a second pending request per user; sets `scheduled_at = now + grace_secs` |
| `execute_deletion(del_repo, user_repo, request_id, executed_by, now)` | `core/deletion.rs:151` | written; loads, requires `status == Pending` |
| `cancel_deletion(repo, request_id, cancelled_by, now)` | `core/deletion.rs:185` | written; same guard |
| `DeletionRequestRepository` | `core/deletion.rs:84` | `create`, `find_by_id`, `find_pending_by_user`, `list_due`, `mark_executed`, `mark_cancelled` |
| `CloudflareDeletionRequestRepository` | `adapter-cloudflare/src/ports/repo/deletions.rs:69` | implemented, 6 methods |
| `sweep_pending_deletions(env)` | `backend/src/sweep.rs:239` | written, correct-looking, **called by nothing** |
| The admin queue template | `frontend/src/tenant_admin/deletions.rs:15` — `deletion_requests_page(principal, tenant, requests: &[DeletionRequest], now_unix)` | written, **unused**, and has a defect (D8) |
| The table | `migrations/0019_deletion_requests.sql` | `tenant_id NOT NULL REFERENCES tenants(id)`, `status` CHECK, two partial indexes |
| The user's data path | `GET /me/security.json` (`lib.rs:196`) | exists, returns `SecurityCenterState` |

**You are connecting these, not designing them.** If a piece seems to be
missing, re-read this table before building anything (§5.5).

## 3. Resolved decisions — do not re-open

**D1. `request_self` uses the user session, not the admin bearer.** Replace
`crate::routes::admin::auth` with `crate::routes::me::auth::resolve_or_redirect`
(`me/auth.rs:235`), as every other `/me/*` route does, and take the user id from
the returned `SessionState`. **Then fix `route-contracts.md:107`'s actor and
session columns** — cycle 1 left them, correctly, because it was not changing
who could call.

**D2. The grace period stays 30 days, as a constant in the handler.** RFC 044
owns that number and this cycle does not reopen it. **Do not add a config
variable** — a new operator-facing knob is a surface decision, not a wiring
detail.

**D3. Add one port method: `list_pending_by_tenant(&self, tenant_id: &str) ->
PortResult<Vec<DeletionRequest>>`.** The queue template takes
`&[DeletionRequest]`, and no existing method can produce a tenant's pending set
— `list_due` is time-scoped, not tenant-scoped. Implement it in the Cloudflare
adapter and in `adapter-test`.

**D4. No new migration and no new index.** The existing partial index
`idx_deletion_requests_pending` already narrows to `status = 'pending'`, and
pending requests per tenant are low-cardinality by nature. A migration would
bump `SCHEMA_VERSION` and `migration_chain` for a query on a small set.
**`migration_chain` stays at 31** — a change there is a report-and-stop (§5.2).

**D5. The audit event's `subject` is the affected user, not the actor.**
`Event.subject` is documented as *"User or subject identifier if known"*
(`audit.rs:428-430`). Cycle 0's code put the **admin's** id there and the sweep
put `None`. Both were wrong. Pass the **deleted/affected user's id** in every
case.

**D6. The actor is recorded structurally on the row, and no new `EventKind` is
added.** §5.4 of the RFC asked for admin and sweep deletions to be
distinguishable without parsing free text. They already are:
`DeletionRequest.requested_by`, `executed_by` and `cancelled_by` are columns,
and the service writes them — `execute_deletion` takes `executed_by`, so pass
`"sweep"` from the sweep and the principal id from the handler.

**Do not add an actor field to `Event`, and do not add new event kinds.** The
audit log is hash-chained (ADR-010); changing its shape to carry something a
queryable row already holds is a large risk for no gain.

**D7. Events are emitted only after the operation succeeds**, and **a rejected
request writes nothing.** This is the defect cycle 1 fixed; do not reintroduce
it in the success path's shadow.

**D8. Validate the tenant before anything else, and 404 without an event.**
`admin_cancel` and `admin_execute` take `:id` from the path. Load it with
`find_by_id`, compare its `tenant_id` to the caller's tenant from the existing
`gate::resolve_or_respond` context, and return **404 with no audit event** if it
is absent or belongs to another tenant. A tenant admin must not learn that
another tenant's request id exists.

**D9. The queue page renders server-side, and the template's CSRF is broken.**
`deletion_requests_page` contains `let csrf = "";` — a hardcoded empty token, so
its forms cannot pass CSRF. Give the template a real token, mint it in the
handler and set the cookie, the way RFC 146's `html_response` callers do.
**Change `route-contracts.md:108`'s render column `client` → `server`**, which
brings the row under E3 — now that E3 follows wrapper indirection, that is real
protection.

**D10. Delete `GET /admin/t/:slug/deletion-requests.json` and its row 109.**
It returns only a CSRF token; once the page is server-rendered it has no
consumer, and leaving it is the orphan class RFC 143 removed `verify.json` for.
**The route count falls 193 → 192** — state it with its command.

**D11. The user sees pending deletion from data, not a URL parameter.** Add the
pending-deletion state to `SecurityCenterState` (served by `GET
/me/security.json`), populate it with `find_pending_by_user`, and render a
notice in the security centre showing that a deletion is scheduled and when.
**Do not reinstate `?deletion_requested=1`** as the mechanism: a parameter is
lost on reload, survives a back button, and can be typed by hand. Cycle 1
removed it because it asserted an outcome; a URL is the wrong place to keep
state the database already holds.

**D12. Wire `sweep_pending_deletions` into the existing daily cron.**
`scheduled()` (`lib.rs:68`) dispatches `"0 4 * * *"` to `sweep::run`. Call
`sweep_pending_deletions` there too, **independently** — the existing comment at
`lib.rs:73-75` already establishes the rule that one scheduled task failing must
not block another, so follow it rather than nesting the call inside
`sweep::run`.

**D14. The cascade claim is accurate, with one exception you must not
over-claim.** I checked the effective schema across all migrations, taking each
table's **last** definition:

- **Every table that references `users(id)` has `ON DELETE CASCADE`** — 28 of
  them, including `authenticators` (`0020`), `totp_authenticators` and
  `totp_recovery_codes` (repaired by `0016`), `user_sessions` and the four
  tenancy membership/role tables (`0012`). So the sentence in
  `admin-operations.md` about child data is **true** and may be restored.
- **`invitation_tokens` (`0018`) has no reference to `users(id)` at all.** It
  carries `email` — the recipient's address, PII — plus `issued_by`,
  `accepted_by` and `revoked_by` as plain text user ids. **Deleting a user does
  not remove it.**
- `deletion_requests` deliberately retains `user_id` after execution; `0019`'s
  own comment says so, and that is the audit trail, not a leak.

**Decision: `invitation_tokens` is out of this cycle's scope**, because whether
an invitation record should be purged or its email scrubbed is a design question
— the tenant's own invite history has a claim on it — and this cycle is wiring,
not policy. **But the restored documentation must say what is actually removed:
child data linked by foreign key, naming `invitation_tokens` as retained.** Do
not write "all child data" or "complete erasure". Recorded as a finding in
RFC 147 §14 so it gets a number rather than a note.

**D13. Remove the three "Full implementation pending" comments** as each handler
is wired, and correct the two false documentation lines: the doc comment at
`core/deletion.rs:25` (*"The daily cron pass calls `sweep_pending_deletions`"*,
which only becomes true with D12) and `admin-operations.md`'s cron description
line 3. Also restore that file's endpoint sections, which cycle 1 marked
not-implemented.

## 4. Facts already measured — do not re-derive

| Fact | Command | Result |
|---|---|---|
| The sweep has no caller | `grep -rn 'sweep_pending_deletions' crates/` | its definition, plus a **doc comment** claiming the cron calls it |
| `request_self` uses admin auth | `grep -n 'use crate::routes::admin::auth' crates/backend/src/routes/deletions.rs` | present; no `me::auth` import |
| Three sources say it should be the user | module doc `deletions.rs:5-6`; `route-contracts.md:107`; **RFC 047 line 13** | all say self-service |
| The repository is implemented | `adapter-cloudflare/.../deletions.rs` | `impl DeletionRequestRepository`, 6 `async fn` |
| The queue template exists | `frontend/src/tenant_admin/deletions.rs:15` | takes `&[DeletionRequest]`; `let csrf = "";` |
| `Event` has no actor field | `audit.rs:424-430` | `ts, id, kind, subject, …`; `subject` is the *subject* |
| The row carries the actor | `migrations/0019_deletion_requests.sql` | `requested_by`, `executed_by`, `cancelled_by` |

## 5. Report-and-stop gates

1. **An audit event would be written before its operation succeeds**, or a
   rejected request would write one. Stop — that is the defect this RFC exists
   for.
2. **`migration_chain` moves off 31.** Nothing here should need a migration
   (D4).
3. **The route count is not 192** after D10.
4. **Any user-linked table turns out not to cascade.** I measured this myself
   rather than leave it to you — see **D14**: every table referencing
   `users(id)` does cascade, and `invitation_tokens` is the one exception
   because it has no such reference. If you find a table D14 does not account
   for, stop: restoring a deletion promise that is not kept is how cycle 1's
   defect would be recreated through the documentation.
5. **Any piece in §2's table is missing or does not work as described.** Report
   it; I measured it from outside and may have made the same mistake I made
   about the sweep.
6. **A tenant admin could reach another tenant's request** by any path you find
   while wiring D8.

## 6. Change scope

- `crates/core/src/deletion.rs` — the trait gains D3's method; the doc comment
  at `:25` corrected (D13).
- `crates/adapter-cloudflare/src/ports/repo/deletions.rs` and the `adapter-test`
  double — D3's implementation.
- `crates/backend/src/routes/deletions.rs` — all four handlers.
- `crates/backend/src/lib.rs` — D12's sweep call; D10's registration removed.
- `crates/backend/src/routes/me/security.rs:89-94` (builds the state) and
  `crates/frontend/src/templates/security_center.rs:68` (the struct) — D11.
- `crates/frontend/src/tenant_admin/deletions.rs` — D9's CSRF parameter.
- `crates/frontend/src/templates/security_center*` — D11's notice.
- `docs/src/expert/route-contracts.md` — rows 107 (actor/session), 108 (render,
  and its event), 110 and 111 (events restored); row **109 deleted**.
- `docs/src/expert/admin-operations.md` — endpoint sections and cron line 3.
- Tests, per §7.

## 7. Required tests and evidence

**The first test to write is the one the current code fails:**

1. **A request created by `request_self` is found by `list_due` once its
   schedule passes.** That is the end-to-end property that has never held.
2. **The sweep executes a due request** and the user and child rows are gone.
   Drive the scheduled handler, not the function directly — D12's wiring is the
   thing that was missing, and calling `sweep_pending_deletions` in a test
   proves nothing about whether the cron reaches it.
3. **`admin_execute` on a nonexistent id**: 404 and **no audit event**. Assert
   the absence.
4. **`admin_execute` on another tenant's request**: 404, no event, and the
   request still `pending`.
5. **A successful execute** writes `DeletionExecuted` with `subject` = the
   **affected user**, and the row's `executed_by` = the principal id; the
   sweep's writes `executed_by` = `"sweep"`. Assert both, since D6 makes the row
   the authoritative distinction.
6. **Cancel prevents a later sweep from executing** the request.
7. **A second `request_self` while one is pending** is rejected, and writes no
   event.
8. **The user sees it**: `GET /me/security.json` reports the pending deletion
   with its scheduled time (D11).
9. **The queue page**: renders the tenant's pending requests server-side, with a
   **real CSRF token** whose value matches the cookie — the RFC 146 invariant,
   asserted here because D9 changes who mints it.
10. **E3 covers row 108** once it is `server`-declared: the check passes, and
    fails if the handler reverts to a shell. Include the pair.

Where a `worker::Request` is needed and cannot be built on the host, extract a
decision function taking primitives, as `decide_verify_get` and
`render_with_nonce` already do.

**A count in prose carries its command**, including the **192**.

## 8. What must NOT be claimed

- **Not** that GDPR compliance is achieved. This implements a documented
  deletion pipeline; whether it satisfies any legal obligation is not a claim
  this project's tests can support.
- **Not** that previously-written false audit entries are corrected. They remain
  (cycle 1 said so); nothing here annotates them.
- **Not** that deletion is reversible or recoverable. It is not — which is
  exactly why §5.4 exists.
- **Not** that the admin console is complete. The queue page becomes real; 33
  other admin pages still answer 200 with Not Found until RFC 145 cycles 2–3.
- **Not** that RFC 047 was "completed as designed" — it shipped non-functional
  and this cycle completes it two years of releases later. Say that plainly.

## 9. Prohibited shortcuts

- **Calling `sweep_pending_deletions` from a test instead of through
  `scheduled()`** to satisfy §7.2. The uncalled function is the whole defect.
- **Adding an `EventKind` or an `Event` field** (D6).
- **A migration** (D4).
- **Reinstating `?deletion_requested=1`** as the mechanism for D11.
- **Restoring `admin-operations.md`'s cascade sentence** without checking the
  schema (§5.4).
- **Deleting or rewriting a test that asserts current behaviour** without
  reporting it.

## 10. Acceptance criteria

1. All three operations execute through the existing core services and
   repository; `request_self` authenticates the **user**.
2. No audit event is emitted for an operation that did not occur; ids are
   validated, and cross-tenant access 404s without an event.
3. A self-requested deletion is executed by the **cron**, not merely by the
   function.
4. Admin and sweep actors are distinguishable from the row, with no new event
   kind and no change to `Event`.
5. The queue page renders server-side with a working CSRF token; row 108 is
   `server` and E3 covers it; row 109 and its route are gone; count **192**.
6. The user can see a pending deletion from `/me/security.json`.
7. `migration_chain` **31**; the three "pending" comments gone; both false
   documentation lines corrected; no existing test weakened.

## 11. Known risks

**R1 — irreversibility.** This is the first cycle in which cesauth can actually
destroy data. Every test that executes a deletion must do so against a disposable
local database, and nothing in this cycle should be driven against anything you
would mind losing.

**R2 — the cascade claim (§5.4).** Restoring documentation is where a false
promise gets recreated. Check the schema.

**R3 — D11's placement.** `SecurityCenterState` is a user-facing payload;
adding a field to it touches the frontend contract. Keep the field minimal —
whether a deletion is pending, and when — and do not put the request id or the
requester in it.

**R4 — the sweep's blast radius.** Once D12 is wired, the daily cron deletes
users. A bug in `list_due`'s boundary or in `is_due` becomes data loss. §7.2 and
§7.6 exist for it; if anything about the boundary looks ambiguous, report rather
than choose.

## 12. Review request

`.git-exclude/review-request/147-cycle2-report.md`, evidence under
`.git-exclude/review-request/evidence-147-cycle2/`.

Lead with §7.1 and §7.2 — a request reaching `list_due`, and the **cron**
executing it — because those are the properties that have never held in this
codebase, and everything else is secondary to them.
