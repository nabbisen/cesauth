# Developer Handoff — RFC 160, decision stage

**Governing RFC.** `rfcs/done/160-every-constraint-failure-is-a-conflict.md`
**Prior art worth reading first.** `rfcs/done/158-no-tenant-but-the-default-has-a-reachable-console.md`
§5.5 and §5.8 — RFC 160 came out of RFC 158's cycle-2 evidence, and §5.8 names
the claim that went unchecked for four cycles.

**Stage.** **Decision only. Write no code.** §4's four items are not
independent: item 1 decides the others. Report and stop.

**Target release.** **Unassigned, and the level is your answer's consequence** —
reusing an existing `PortError` variant is a fix (patch); adding one is
additive surface on `core::ports`, which the CHANGELOG's own preamble calls a
minor. **Say which your answer implies and why**; I will not infer it.

**Prepared by.** Architect · **Decided by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-29**, after 0.89.0 was cut.

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Deliverable (0): the observed error strings

**Before any design argument, get the facts this whole defect is made of.**
Against `wrangler dev` + local D1, provoke each of the four constraint classes
and **print D1's actual error message** for each:

1. a **UNIQUE** violation (a duplicate tenant slug);
2. a **FOREIGN KEY** violation (`user_tenant_memberships.user_id` pointing at
   no user — RFC 158's step C3 reproduces it);
3. a **CHECK** violation (`users.account_type` or `status` has one);
4. a **NOT NULL** violation.

Put the four raw strings in the report. **Everything else in this stage is
argued against those four strings and nothing else** — the defect exists
precisely because `contains("constraint")` was written from an assumption about
them that nobody printed. Do not reason from SQLite documentation; this is D1's
error surface, through `worker::Error`'s `Display`, which may not be SQLite's
text verbatim.

If a class cannot be provoked without changing production code, say so in one
line and say what you substituted.

## 2. The decision: which `PortError` carries "a row you referenced is absent"

`crates/core/src/ports.rs:47-72`. Three candidates, and I have a position I
want argued with rather than agreed to:

- **`NotFound`** (`:48-50`, *"The record does not exist"*). Cheapest, and it
  is the variant `tenant_create.rs::submit`'s dead arm already expects. **But**
  `port_error_response` maps it to **404**, and a 404 for `POST /api/v1/tenants`
  — whose path exists and whose body is the thing at fault — moves the
  confusion rather than removing it.
- **`PreconditionFailed(&'static str)`** (`:59-65`). Maps to 400 with the
  message, and the console already renders that message verbatim, so no new
  consumer arm is needed anywhere. **But** its doc says *"the store recognized
  the key but the requested transition is not permitted from the current
  state"*, and a missing foreign-key target is not a state-transition problem.
  Using it means either stretching the variant or rewriting its doc to mean
  something broader.
- **A new variant** carrying which reference was missing. Honest, and the
  enum's own preamble (`:43-45`) says the variants exist *"so that callers can
  branch on domain-relevant outcomes … without leaking the underlying storage
  technology"* — which is an argument for naming this outcome rather than
  folding it into a neighbour. **The cost is every exhaustive `match`**, which
  is §3's census, and that census is what decides whether "honest" is worth
  paying for.

**My position: the new variant, unless the census says otherwise.** I hold it
loosely. Each of the last three decision stages produced reasoning better than
mine on a question of this exact shape, so if the answer is one of the other
two, say so and say why — that is a better outcome than agreement.

## 3. The census that decides it

Count, with the command that produced each number:

1. **Every exhaustive `match` on `PortError`** in the workspace — a new variant
   touches each. Distinguish exhaustive matches from ones with a `_` arm; the
   latter compile unchanged but may then silently mis-handle the new case,
   which is worse, not better, so list those separately and say what each would
   do with it.
2. **Each of the eight classification sites** (RFC 160 §2) — for each, which
   constraint classes can its statement actually hit? A site whose table has no
   foreign key cannot produce an FK failure, and a site that can only ever
   collide on uniqueness needs no new classification at all. **The eight are
   not necessarily eight changes.**
3. **Each consumer arm that names a cause**: `tenant_create.rs::submit`'s four
   and `port_error_response`'s six. For each, is it reachable by the cause it
   names, after your answer? An arm that cannot fire is the defect this RFC is
   about, one level up.

## 4. Resolved — do not re-open

- **That the current classification is wrong** is established by RFC 160 §2's
  live evidence. The stage is *what replaces it*, not whether to.
- **`contains("unique")` is dead** either way — a UNIQUE message that contains
  `constraint` already matched the second test. Do not preserve it for safety.
- **Out of scope**: the orphan tenant a failed membership insert leaves behind
  (RFC 158 §5.5, still open); the API path's missing `via=` audit marker (same);
  RFC 159's nine; RFC 152 half B and §6; RFC 141 cycle 2; RFC 123; RFC 120.

## 5. Report-and-stop

- the four strings cannot be told apart from each other, in which case this
  RFC's premise is wrong and I want to hear it immediately;
- the census makes all three candidates cost the same, which would mean the
  decision is a naming question and not a design one — say so plainly rather
  than manufacturing a trade-off;
- a fourth candidate exists that §2 does not list.

## 6. Review request

`.git-exclude/review-request/160-decision-report.md`. **No code, no commit** —
this stage reads and reports.
