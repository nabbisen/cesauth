# Developer Handoff — RFC 147 cycle 1, stop claiming success

**Governing RFC.** `rfcs/accepted/147-deletion-requests-are-audited-but-never-performed.md`
— **read §11.1 first.** It is the cycle split, and it is why this cycle
implements nothing.

**Target release.** 0.85.1 — **and why that level:** **patch.** Nothing that
worked stops working, because nothing worked. Three endpoints stop asserting
outcomes they never produced.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing.
**Scope.** Three handlers, three contract rows, one documentation section.
**Cycle 2 — performing the deletions — is a separate dispatch and is NOT in
scope here.**

---

## 1. Purpose

`request_self`, `admin_cancel` and `admin_execute` in
`crates/backend/src/routes/deletions.rs` each write an audit event, log, and
redirect with a success parameter — **without ever touching the
deletion-request repository.** The repository is fully implemented and the sweep
that consumes it works.

So: a user's deletion request is silently discarded while the log says
*"scheduled in 30d"*; `admin-operations.md:93` promises the execute endpoint
*"physically deletes the user. Irreversible."* and it deletes nothing; and
`DeletionExecuted` is written for deletions that did not happen, for any `:id`,
unvalidated, under the **same event kind the sweep writes for real ones.**

**This cycle does not fix deletion. It stops the lying.** Ending a false claim
requires implementing nothing, which is why it ships two releases ahead of the
implementation.

## 2. Why this is the shape of the work

The audit log is what you consult when you cannot inspect the system directly.
A `DeletionExecuted` entry that corresponds to no deletion makes every other
entry worth less, and any tenant admin can generate them on demand.

Nothing here is urgent in the user-facing sense — measured,
`grep -rn 'deletion_requested\|delete-account' crates/frontend/src --include='*.rs'`
returns **0**, so no cesauth screen leads a user into this route. It is urgent
in the *record-keeping* sense, and the remedy is small.

## 3. Resolved decisions — do not re-open

**D1. The three handlers emit no audit event at all.** `DeletionRequested`,
`DeletionCancelled` and `DeletionExecuted` are written **only** by code that
performed the thing. Until cycle 2 that is the sweep alone.

**D2. Do not invent a new `EventKind`.** No "attempted" or "not implemented"
event. The audit event vocabulary is contract-bound, a new kind is a design
decision, and this cycle's whole point is to stop writing events that do not
correspond to work.

**D3. Return `501 Not Implemented`**, with a short body saying the operation is
not yet available. 501 is the honest status: the route is understood and not
implemented.

**D4. Keep the auth and gate checks, in their current order, before the 501.**
`resolve_or_respond` then `gate::resolve_or_respond` (and the CSRF the contract
requires) run first, so an unauthenticated or unauthorized caller gets the same
response they get today and learns nothing new about the endpoint. **A 501 that
precedes the auth check would be a disclosure regression** — worse than the
defect being fixed.

**D5. The success redirects go.** No `?executed=1`, `?cancelled=1`, or
`?deletion_requested=1`. A parameter that tells the UI an operation succeeded is
the "users must not misunderstand" failure in its most literal form.

**D6. The `log::emit` lines must not assert the outcome.**
`"deletion executed admin-triggered: request {id}"` is as false as the audit
event. Replace each with a line stating the endpoint was called and is not
implemented. Keep the level or lower it; do not raise it.

**D7. Three contract rows change.** `docs/src/expert/route-contracts.md`:

| Line | Route | Event column | View column |
|---|---|---|---|
| 107 | `POST /me/security/delete-account` | `deletion_requested` → **`none`** | `redirect` → **`501`** |
| 110 | `…/deletion-requests/:id/cancel` | `deletion_cancelled` → **`none`** | `redirect` → **`501`** |
| 111 | `…/deletion-requests/:id/execute` | `deletion_executed` → **`none`** | `redirect` → **`501`** |

Leave every other column, including the CSRF and auth columns, exactly as it is.

**D8. The "Full implementation pending" comments stay.** All three. They are the
only honest statements in the file today, and cycle 2 removes them as it
resolves each one.

**D9. `admin_list` and `admin_list_json` are NOT touched.** The queue page
renders Not Found (RFC 145's class) and its `.json` returns only a CSRF token,
which is what row 109 says. Neither lies, so neither is this cycle's business.
Cycle 2 owns the page.

**D10. The sweep is NOT touched.** It works, and it stays the single execution
path.

## 4. Facts already measured — do not re-derive

| Fact | Command | Result |
|---|---|---|
| The repository exists | `grep` the impl in `adapter-cloudflare/src/ports/repo/deletions.rs` | `impl DeletionRequestRepository for CloudflareDeletionRequestRepository`, **6** `async fn` |
| The handlers never use it | `grep -rn 'CloudflareDeletionRequestRepository' crates/backend/src` | **5** hits: 2 real uses in `sweep.rs`, **3 comments** saying "pending" |
| The sweep is real | `sweep.rs:252` | `del_repo.list_due(now)` → `deletion::execute_deletion(…)`, with its own event |
| The documentation promises deletion | `docs/src/expert/admin-operations.md:93` | *"Physically deletes the user. Irreversible."* |
| The self-service route is live | `lib.rs:213` | `POST /me/security/delete-account` (RFC 044) |
| No UI reaches it | `grep -rn 'deletion_requested\|delete-account' crates/frontend/src` | **0** |
| Nothing verifies the event column | `route-contracts-check.sh` has no reader for it; the audit scanner checks call *arguments* against a secret denylist | no gate behind D7 |

**D7's consequence of that last row:** changing the three event columns is
documentation-only, and **no check will fail if you get it wrong.** Assert it
yourself (§6).

## 5. Report-and-stop gates

1. **A 501 would precede an auth or CSRF check** anywhere. Stop — D4.
2. **Removing an audit event breaks a test** that asserts it fires. Report the
   test; it is asserting the defect, and whether it is deleted or inverted is my
   call, not yours.
3. **Another caller depends on one of the three handlers' 303.** Report it.
4. **`admin-operations.md` turns out to document more unimplemented operations**
   than §3 covers. Report the list; do not expand the cycle.
5. **Any temptation to implement part of the deletion** to make a 501 feel
   unnecessary. That is cycle 2, and mixing it in makes this unreviewable as a
   patch.

## 6. Change scope and the assertions to run

- `crates/backend/src/routes/deletions.rs` — three handlers.
- `docs/src/expert/route-contracts.md` — three rows, per D7.
- `docs/src/expert/admin-operations.md` — the "Deletion request management"
  section, including `:93`'s irreversibility promise, stating that these
  endpoints are not implemented and pointing at RFC 147.
- Tests, per §7.

```
# no completion event remains in the three handlers
grep -cE 'DeletionRequested|DeletionCancelled|DeletionExecuted' crates/backend/src/routes/deletions.rs   # expect 0
# the sweep still writes its own
grep -c 'DeletionExecuted' crates/backend/src/sweep.rs                                                   # expect >= 1
# no success parameters survive anywhere
grep -cE 'executed=1|cancelled=1|deletion_requested=1' crates/backend/src                                # expect 0
# the three pending comments are still there (D8)
grep -c 'Full implementation pending' crates/backend/src/routes/deletions.rs                             # expect 3
# route count unchanged
bash scripts/route-contracts-check.sh | tail -1                                                          # expect 193
```

## 7. Required tests and evidence

1. **Each of the three routes returns 501** to an authorized caller.
2. **Each still returns its current response to an unauthorized one** — same
   status, same `WWW-Authenticate` where applicable. This is D4, and it is the
   one way this cycle could make something worse, so assert it per route rather
   than once.
3. **No audit event is written by any of the three.** Assert the **absence**.
   This is the defect; a test that only checks the 501 would pass on a handler
   that still writes `DeletionExecuted` first.
4. **The sweep's own `DeletionExecuted` still fires** on a real execution —
   untouched, asserted so this cycle cannot have narrowed it.
5. Full gate set, and the route count with its command.

**Evidence** under `.git-exclude/review-request/evidence-147-cycle1/`, as
redirected output. If you can drive the three routes against `wrangler dev` as
you did for RFC 146, the response bodies and the absence of audit rows are worth
more than any assertion here.

## 8. What must NOT be claimed

- **Not** that deletion works, is fixed, or is safe. Nothing is deleted before
  cycle 2. The release note will say the endpoints now refuse honestly.
- **Not** that the audit log is now correct generally. It stops gaining false
  deletion entries; **entries already written remain**, and nothing in this
  cycle removes or annotates them. Say so.
- **Not** that users are now informed. They get a 501 from a route no screen
  links to. The user-facing flow is cycle 2's.

## 9. Acceptance criteria

1. The three handlers write no audit event and return 501 after their existing
   auth, gate and CSRF checks.
2. No success redirect parameter remains; no log line asserts an outcome.
3. The three contract rows read `none` and `501`; no other column moved.
4. `admin-operations.md` no longer promises behaviour the code lacks.
5. The three "pending" comments remain; the sweep is unchanged.
6. Route count **193**; no existing test weakened, or §5.2 reported.

## 10. Known risks

**R1 — disclosure order (D4).** The only way to make things worse. §7.2 exists
for it.

**R2 — a test that asserts the false event.** Plausible, since the event was the
only thing these handlers did. §5.2: report it, do not quietly delete it.

**R3 — documentation drift the other way.** After this, the docs say "not
implemented" and cycle 2 must put them back. That is expected; cycle 2's handoff
will carry it.

## 11. Review request

`.git-exclude/review-request/147-cycle1-report.md`, evidence under
`.git-exclude/review-request/evidence-147-cycle1/`.

Lead with §7.3 — the **absence** of audit events — because that is the defect,
and a 501 on its own does not prove it.
