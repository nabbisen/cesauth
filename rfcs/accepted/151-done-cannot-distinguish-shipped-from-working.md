# RFC 151 — `done/` cannot distinguish "shipped" from "works"

**Status.** **Accepted** 2026-10-27. **Amends RFC 000.** **Not release-bound** —
it is a policy change, implemented by the architect, and it is scheduled
**before the 0.86.1 dispatch** so that RFC 145 is the first RFC filed under the
new rule rather than the last under the old one.
**Tier.** P2 — process, not product. It is here because the cost has been paid
once, measurably, and the catalogue is what the next reader trusts.
**Size.** Small: a definition, a field, and one sweep.
**Touches.** `rfcs/done/000-rfc-lifecycle-policy.md`, `rfcs/README.md`, the
Status line convention used by every RFC in `done/`.
**Depends on.** Nothing. **Evidence:** RFC 047, RFC 147.
**Found by.** The architect, 2026-10-27, on closing RFC 147.

## 1. Summary

`rfcs/README.md:29` defines the folder as `done/ ← shipped (released, or on
main); never delete`, and RFC 000's state table defines **Implemented** as
"the work has shipped … The RFC is now a historical record."
(`000-rfc-lifecycle-policy.md:89`). Both definitions are about **code having
been released**. Neither is about the code **doing what the RFC said it would**.

The two came apart, and the gap was not small:

**RFC 047 — "Deletion request worker layer" — entered `done/` at `99fe324` on
2026-06-05 and sat there while 61 releases were tagged, from 0.53.0 to 0.86.0,
with both of its deliverables non-functional.** Its self-service route checked
the admin bearer resolver instead of a user session, so the principal it existed
for always received 401. Its cron sweep was fully written and called by nothing.
No deletion had ever been executed in cesauth by any path. Both were found in
October 2026 by RFC 147, and fixed in 0.85.1 and 0.86.0.

By the letter of both definitions, RFC 047 was correctly filed the entire time.
**The policy was not violated; the policy is what permitted it.**

**It is not one case any more.** Reviewing RFC 145 cycle 3 on 2026-10-27 turned
up **[RFC 017](../done/017-oidc-audience-admin-editor.md)** — *"OIDC client
audience-scoping admin editor"*, **Status: Implemented**, shipped **v0.53.0** —
whose template exists, has two tests, and renders a form posting to a route
`lib.rs` has never registered. The page has no caller outside its own tests.
**Nobody has ever been able to open it.**

Two independent instances, found five weeks apart and both by accident while
doing something else, are the argument for §22's rule. The second one also
shows what `reviewed` would have been worth here: the template was reviewed, it
was correct, it had tests, **and none of that touched the question of whether
anything routed to it.**

## 2. Why this is not merely tidiness

`rfcs/README.md:135` says "the canonical catalogue is the filesystem at
`done/`". That makes `done/` the answer to "does cesauth do X?" — and it
answered *yes* about account deletion for 61 releases. The reader harmed is
whoever asks next: the owner deciding what to schedule, the dev team deciding
what already exists, and me, who cited RFC 047's machinery as "complete and in
use elsewhere" in RFC 147 §2 **because it was in `done/`** — a claim that was
false, and the clearest possible demonstration of the cost.

This is the same defect class the project keeps meeting from the other side:
**documentation asserting what the code does not do.** `done/` is documentation.

## 3. What is not established

That a verification requirement would have caught RFC 047. It might not have:
the sweep was *written*, and a reviewer confirming "the function exists and its
body is correct" would have passed it — that is exactly the mistake I made in
RFC 147 §2, where I read the body and never checked the callers. **A new field
that can be satisfied by the same shallow check buys nothing.** The design
question this RFC must answer is therefore not "should we verify?" but **"what
evidence is strong enough to be worth recording, and cheap enough to actually be
recorded 150 times?"**

## 4. Direction

**Do not add a fifth lifecycle folder.** RFC 000 §"The states are deliberately
few" argues against formalisation overhead and it is right; a `verified/`
alongside `done/` would split the catalogue and immediately raise "which of the
two do I trust?", which is the problem, not the fix.

**Add a field to the Status line instead**, so the claim travels with the RFC:

```
**Status**: Implemented — shipped v0.86.0; **exercised** by
            e2e/deletion.spec.ts and sweep_pending_deletions_executes_due_requests
```

with a small, closed vocabulary for what the evidence may be, in descending
strength:

| Term | Means |
|---|---|
| **exercised** | A gate in the CI set drives the deliverable end to end and fails if it stops working. The only term that keeps holding after the author leaves. |
| **observed** | Driven once against a real runtime (`wrangler dev`, the scheduled handler) and recorded, with the commit. Decays, and says so. |
| **reviewed** | A human read the code and the callers. Honest, weakest, and **explicitly not enough on its own for a P0 or P1 deliverable.** |

The rule then has teeth without new folders: **a P0 or P1 RFC may not enter
`done/` marked only `reviewed`.** RFC 047's sweep would have had to be
`observed` at minimum — which means someone drives the cron — and that is the
exact act that found the bug in RFC 147 cycle 2.

**The sweep.** Roughly 150 files are in `done/`. Back-filling all of them is
not proposed and would be answered carelessly. Instead: back-fill the **P0 and
P1 security-relevant** RFCs only, and accept `unknown` as the honest value
everywhere else rather than inventing a retrospective claim. A field that is
truthfully `unknown` is worth more than one that is optimistically `reviewed`.

**The sweep is 28 RFCs**, measured rather than guessed:

```
$ cd rfcs/done && grep -liE '^\*\*(Priority|Tier)\*\*[.:]? *\*?\*?P[01]' *.md | wc -l
28
```

**It is not done in this commit, and that is a scheduling decision, not a
deferral.** Each of the 28 needs its gate located and confirmed to fail when the
deliverable breaks — which is the only thing that distinguishes `exercised`
from a hopeful `reviewed`. Twenty-eight of those determinations made quickly,
between an authorization and a dispatch, would be answered the way §22.3 warns
about, and the result would be a catalogue that *looks* verified. **That is the
defect this RFC exists to remove, so producing it here would be self-refuting.**

Scheduled: the architect's own work, in the window after 0.86.1 returns and
before RFC 145 closes into `done/`. RFC 145 itself is filed under the new rule
from its dispatch, so the rule is in force immediately; the back-fill is
retrospective and does not gate it.

**The second place to fix.** RFC 000 §317 already has the maintainer run a
consistency pass when an RFC moves folders. That pass is where the new field
gets checked, so this RFC adds a condition to an existing step rather than a new
step.

## 5. Open question for the owner

This changes the project's own governing policy, which is why it is proposed
rather than decided. The judgement I am asking for is **whether the overhead is
worth it at cesauth's scale.** My recommendation is yes, narrowly: one field,
three words, enforced only for P0/P1, back-filled only for security-relevant
RFCs. Anything broader will be filled in without thought, and a field filled in
without thought is worse than no field — it is the `done/` problem again, one
level down.
