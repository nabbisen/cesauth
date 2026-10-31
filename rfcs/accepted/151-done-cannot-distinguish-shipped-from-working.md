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

**It is not one case any more — it is three.** Reviewing RFC 145 cycle 3 on 2026-10-27 turned
up **[RFC 017](../done/017-oidc-audience-admin-editor.md)** — *"OIDC client
audience-scoping admin editor"*, **Status: Implemented**, shipped **v0.53.0** —
whose template exists, has two tests, and renders a form posting to a route
`lib.rs` has never registered. The page has no caller outside its own tests.
**Nobody has ever been able to open it.**

**And a third, found on purpose.** The back-fill this RFC prescribes began on
2026-10-27 and started at **[RFC 046](../done/046-invitation-worker-layer.md)**
— RFC 047's sibling, same cycle, same shape — on the theory that a defect
found in one half of a pair is worth looking for in the other. It was there.
An accepted invitation produces **no tenant membership and no role
assignment**, which is RFC 043's entire definition of an invitation; the
`role` column is read once in the codebase, into an audit message; and
`revoke_invitation` has no caller, so the `revoked` state is unreachable.
RFC 046 and **[RFC 049](../done/049-accept-invite-full-flow.md)** — titled
*"full implementation"* — are both `done/`, both **Implemented**, both P1.
Now **[RFC 153](../done/153-an-invitation-grants-nothing.md)**.

Three instances, and the third one arrived **before the back-fill had covered
a tenth of its 28 RFCs**. Two found by accident were the argument for §22's
rule; the third, found deliberately by the method §22 implies, is the argument
that the rule is not merely tidy. The second one also
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

### The method, calibrated against the known-false case (2026-10-27)

The back-fill began after 0.86.2. Two things were settled first, because
without them every determination would have been a guess.

**1. Route existence *is* gated.** Deleting a registered route makes
`route-contracts-check.sh` fail — verified by removing
`GET /userinfo`'s registration from `lib.rs`:

```
⚠   Routes documented but NOT registered in lib.rs (stale):
    GET /userinfo
$ echo $?    → 1
```

(The `⚠` glyph is misleading for a hard failure; the branch sets
`exit_code=1`.) So "the route is still there" is machine-checked.

**2. And route existence is *not* sufficient for `exercised`.** RFC 047 is the
proof: its routes were registered and documented for 61 releases while both
deliverables were dead, so the gate was green the whole time. **A term may only
be `exercised` when something fails on a change in *behaviour*, not merely on
removal or on a documentation mismatch.**

That gives a usable rule per RFC: *name the gate or test that would fail if this
deliverable stopped doing what the RFC says it does.* If naming it is hard, the
term is not `exercised`.

**Where the back-fill stands: 4 of 28 examined, 1 of the 4 non-functional.**
It began at RFC 046 deliberately — RFC 047's sibling — and found **RFC 153**
there. RFCs 043, 046, 047 and 049 are annotated; the remaining 24 have had no
determination and are **`unknown` until they do**, which is §22.3's prescribed
value and not a placeholder for an optimistic guess.

### The back-fill is complete — 28 of 28 (2026-10-28)

Every P0/P1 RFC in `done/` now carries a machine-readable
`**Evidence**: **\`term\`**` line. Measured, not asserted:

```
$ # P0/P1 RFCs in done/ with a parseable Evidence term
28 — 16 exercised · 5 reviewed · 7 unknown
```

**What it cost and what it found.** Three new P1 records — **RFC 153**
(an invitation grants nothing), **RFC 154** (the second factor is never
audited), **RFC 155** (two P0 guarantees with no witness) — plus **RFC 156**
(the gate set has no gate), the missing half of **RFC 123**'s coverage gate,
and a note on **RFC 120** that two authorization decision paths are duplicated
with nothing asserting they stay equivalent. **Four of those six came from the
first seven determinations.**

**The seven `unknown`s are not a backlog of ignorance.** Four of them —
RFC 043, 046, 047, 049 — are `unknown` *because the work did not function*,
and they say so. RFC 047's term records history rather than today's code: its
deliverables work now, but nothing asserted them for 61 releases, which is the
fact the field exists to preserve. The remaining three (078, 105, 106) are
honestly undetermined: assertions exist near those surfaces and I could not tie
one to each RFC's property within the budget. **`unknown` there is the correct
value and §22.3 says so.**

**The five `reviewed`s are a worklist, not a verdict.** Each names the property
that has no witness: RFC 072's locale-driven `lang` (only the admin frame's
fixed `ja` is asserted), RFC 075's card, RFC 077's skip link (present in three
frames, tagged by comment, asserted nowhere), RFC 035's workflow set, and
RFC 045's event kinds. **Two P0s that were `reviewed` are now `exercised`,
shipped in 0.86.3 as RFC 155** — the rule's first full cycle from flag to fix.

**One thing the method taught.** The mechanical shortcut does not work: I
scored every RFC by whether it names a test that exists in a CI-run crate, and
**RFC 047 scores 1 of 1 while having been completely dead.** Each of the 28 is
a reading. The one time I tried to shortcut a reading — concluding "no callers"
from a `grep | head -5` — I was one step from filing a false finding that
cesauth's authorization invariants were untested.

### What the back-fill determined, in detail

| RFC | term | what fails if the deliverable breaks |
|---|---|---|
| **033** oidc nonce in id_token | `exercised` | 4 host tests in `cesauth-core` (`exchange_code_id_token_{carries,omits}_nonce_*`, `build_claims_nonce_{present,absent}_*`); two are renamed from the names §Tests gives |
| **034** introspect handler wiring | `exercised` | `find_auth_view` in use at `oidc/introspect.rs:88`, plus a **negative** guard — `revoke/tests.rs:86` panics if revoke ever calls it |
| **040** oidc `/userinfo` | `exercised` | exactly the **10** `#[test]`s its §Tests claims, in `core/src/oidc/userinfo.rs`; route registered twice (GET+POST) |
| **044** deletion requests (core) | `exercised` | `core/src/deletion.rs` host tests, and since RFC 147 cycle 2 the path is driven end to end |
| **045** audit EventKind additions | **`reviewed`** | nothing. The variants exist; **nothing fails if a kind loses its emitter** — which is how 10 of 71 came to have none |
| **043 / 046 / 047 / 049** invitations + deletion worker | **`unknown`** | RFC 047 was dead for 61 releases; 043/046/049 are **RFC 153** |
| **030** magic log sanitization (**P0**) | **`reviewed`** | nothing. `MagicLinkPayload` has a plain `derive(Debug)`; the "never log `code`" guarantee is a doc comment. **RFC 155** |
| **074** generic auth-failure audit (**P0**) | **`reviewed`** | nothing. The generic messages are correct and no test asserts them. **RFC 155** |
| **035** CI gate completeness | **`reviewed`** | its four workflows exist and run, and its `-D warnings` spec was superseded on the record by RFC 125. But **nothing fails if a workflow stops running** — the absence of a job is twelve green checks instead of thirteen. **RFC 156** |
| **052** authz service hardening | **`exercised`** | `rfc_052_hardening.rs` (6 call sites) asserts cross-tenant rejection and the system_admin superset against `check_permission`, which **is** the request-time enforcement path via `tenant_admin/gate.rs` |
| the other 15 | **`unknown`** | not yet determined |

**Two P0s carrying `reviewed` is the rule working in its first week.** §22 bars
that, and the bar is what surfaced them: both guarantees hold today and neither
has a failing witness. Recorded on the RFCs **before** the remedy ships, because
deferring the annotation until the fix lands would have made the rule decorative.

**A method note worth keeping: the mechanical triage does not work.** I scored
every P0/P1 RFC by whether it names a test that exists in a CI-run crate.
**RFC 047 scores 1 of 1 and was completely dead.** So "names a test that
exists" has no predictive power, and the term can only come from asking what
fails *behaviourally*. That is why this table is short: each row is a reading,
not a lookup.

**The back-fill is finding things at a rate that is itself an argument.** Four
RFCs examined produced RFC 153; the fifth (RFC 045) produced RFC 154 and the
missing half of RFC 123's gate. **Two new P1 records from five determinations.**

**This is reported at 4 of 28 rather than held until 28**, because the first
finding is larger than the back-fill's bookkeeping and the owner should not
learn of it a week late. The remaining 24 continue as their own scheduled work.

Scheduled: the architect's own work, in the window after 0.86.1 returns and
before RFC 145 closes into `done/`. RFC 145 itself is filed under the new rule
from its dispatch, so the rule is in force immediately; the back-fill is
retrospective and does not gate it.

**The second place to fix.** RFC 000 §317 already has the maintainer run a
consistency pass when an RFC moves folders. That pass is where the new field
gets checked, so this RFC adds a condition to an existing step rather than a new
step.

## 6. The open question, answered with numbers (architect, 2026-10-31)

The owner asked the architect to judge this one rather than answer §5
(2026-10-31). The judgement is **yes, at exactly the width §5 recommended**, and
it is cheap to state because the rule has been in force since 2026-10-27 and
the cost is now measurable rather than estimated.

**Measured:**

```
$ ls rfcs/done/*.md | wc -l                         # 149
$ # an evidence term in the first 18 lines (the Status block)
$ ... | wc -l                                       # 45
$ # tier stated as P0/P1                            # 17, of which 8 carry no term
```

- **The forward rule costs one field** and is being paid without friction: 45
  of the 149 `done/` RFCs carry a term, which is every RFC closed since the
  amendment.
- **It has already earned its keep once, visibly.** RFC 167 slice 2 shipped
  with its evidence **split per step** — the sequence `exercised`, the six
  remote-only commands `reviewed` and named individually, each with what would
  exercise it — instead of one hedged term for the whole page. Without the
  field there would have been nothing to split, and the page would have shipped
  claiming more than it had walked.
- **The back-fill is eight files, not a hundred.** Only 17 `done/` RFCs state a
  tier at all, and **8 of those are P0/P1 with no term**: RFC 116, 117, 118,
  127 (P0) and 132, 143, 146, 147 (P1). 130 state no tier, and for those "no
  term" is the honest state rather than a gap — inventing one for a 2026 RFC
  nobody is relying on is the *"filled in without thought"* failure §5 warns
  about, one level down.

**Decision.** The rule stands as written. The back-fill is **those eight and no
others**, each assessed against what the code and tests actually do rather than
against what its own RFC says — which is the whole point of the field, and is
why it is the architect's work and not a sweep anyone can run. **RFC 151 stays
in `accepted/` until those eight are done**, because filing it as Implemented
with its own recommended work outstanding would be precisely the defect it was
written about.

## 5. Open question for the owner

This changes the project's own governing policy, which is why it is proposed
rather than decided. The judgement I am asking for is **whether the overhead is
worth it at cesauth's scale.** My recommendation is yes, narrowly: one field,
three words, enforced only for P0/P1, back-filled only for security-relevant
RFCs. Anything broader will be filled in without thought, and a field filled in
without thought is worse than no field — it is the `done/` problem again, one
level down.
