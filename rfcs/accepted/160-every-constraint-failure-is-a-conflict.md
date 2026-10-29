# RFC 160 — Every constraint failure is a `Conflict`

**Status.** **Accepted** 2026-10-29.
**Sequenced next, ahead of RFC 159.** Both are P2, and 159 was queued first —
but 159's own Status says *"nothing is broken and nothing is reachable; the
value is the check, not the deletions"*, while this one has an operator being
told the wrong field is wrong. *"APIs and UI/UX for users not to be confused or
misunderstand"* is the standard, and this is the last lie left on a form RFC
158 spent four cycles making honest. **Release unassigned**: the version level
is a `§4.1` consequence — reusing `NotFound` is a fix (patch), a new
`PortError` variant is additive surface on `core::ports` (minor) — so it is
decided at dispatch, not now.
**Decision stage dispatched 2026-10-29**, after 0.89.0 was cut:
`handoffs/160-every-constraint-failure-is-a-conflict/decision-stage-handoff.md`
— deliverable (0) is the **four observed D1 error strings**, before any design
argument, because this defect is made of an assumption about them that nobody
printed.
**Decided 2026-10-29: reuse `NotFound`** (§4.5) — the architect's position, a
new variant, lost to the observed error string. **Implementation dispatched**:
`handoffs/160-every-constraint-failure-is-a-conflict/implementation-handoff.md`.
**0.89.1, patch.**
**Tier.** P2. Nothing is exposed, nothing is corrupted, nothing is
unreachable. An operator is told the wrong thing about why their request
failed, and a public API answers with the wrong status class.
**Size.** Small for the classification; the decision about `PortError`'s
vocabulary is the part worth reviewing.
**Touches.** Eight sites in `crates/adapter-cloudflare` (listed in §2),
`crates/backend/src/routes/admin/tenancy_console/forms/tenant_create.rs`,
possibly `crates/core/src/ports/mod.rs` if a variant is added.
**Found by.** The architect, 2026-10-29, reading **the dev team's RFC 158
cycle-2 live evidence** — step C3, which was not asked for.

## 1. Summary

`POST /api/v1/tenants` with an `owner_user_id` that does not exist answers
**`409 {"error":"conflict"}`** — the same answer it gives for a slug that is
already taken. The tenancy console, submitting the same operation, renders
**"Slug already taken in this deployment"** for a bad owner id, and its own
`PortError::NotFound => "Owner user id not found"` arm **cannot be reached by
the cause it was written for.**

The cause is one line, repeated eight times:

```rust
if msg.contains("unique") || msg.contains("constraint") {
    PortError::Conflict
```

SQLite reports every constraint class through a message containing
`constraint` — `UNIQUE constraint failed`, `FOREIGN KEY constraint failed`,
`CHECK constraint failed`, `NOT NULL constraint failed`. So all four collapse
into `Conflict`, and the `contains("unique")` half of the test **never changes
an outcome**, because a UNIQUE message already contains `constraint`.

## 2. What is established

**Live, not reasoned** — `.git-exclude/review-request/evidence-158-cycle2/live-walkthrough.log`,
step C3: `POST /api/v1/tenants` with an unknown owner returned
`{"error":"conflict"}`. That answer is only reachable through
`PortError::Conflict` (`api_v1/auth.rs:74`), from a **foreign-key** violation
on `user_tenant_memberships.user_id` — not a uniqueness collision.

The eight sites, each the same test:

```
adapter-cloudflare/src/tenancy/memberships.rs:117   (map_insert_err, 3 callers)
adapter-cloudflare/src/tenancy/tenants.rs:88
adapter-cloudflare/src/tenancy/organizations.rs:93
adapter-cloudflare/src/tenancy/groups.rs:97
adapter-cloudflare/src/billing/subscriptions.rs:118
adapter-cloudflare/src/authz/roles.rs:95
adapter-cloudflare/src/ports/audit.rs:217
adapter-cloudflare/src/ports/repo/totp_recovery_codes.rs:98
```

Two of them test `contains("UNIQUE")` (upper) alongside `contains("constraint")`
(lower); since the lower-case `constraint` arm does all the work, the casing
difference has never mattered either.

**The consumer side is already written as if the distinction existed.**
`tenant_create.rs::submit` has four arms — `Conflict` → *"Slug already taken
in this deployment"*, `PreconditionFailed` → the message, `NotFound` → *"Owner
user id not found"*, `_` → *"Storage error"*. Someone wrote the third arm
expecting a foreign-key failure to arrive as `NotFound`. The decision stage of
RFC 158 also recorded the mechanism as *"mapped to `PortError::NotFound` by
`map_insert_err`"* — wrong, and nobody checked the variant, including me.

## 3. Why this matters past the one message

An operator who mistypes an owner's id is told their **slug** is taken. They
will change the slug, resubmit, and be told it again. Nothing in the message
points at the field that is actually wrong, and the message that does exist
for that field cannot appear. That is the owner's standard — *"APIs and UI/UX
for users not to be confused or misunderstand"* — failed in the plainest way:
the system knows what went wrong and says something else.

For the API it is also a wrong status class. A reference to a row that does not
exist is not a conflict with an existing one; `409` tells a client to retry
with a different value for the thing they supplied, which is advice that cannot
work here.

**RFC 158 is why this is worth opening now and not folding in.** That RFC spent
three cycles on "the owner you named can or cannot reach their console", and
its cycle 2 shipped a page whose whole job is telling the operator the truth
about the owner they named. The one remaining lie on that form is this one —
but its cause is in a shared adapter helper used by eight unrelated operations,
so it is a different change with a different blast radius, which is why it is
its own RFC rather than a fourth cycle.

## 4. Direction — the decision is `PortError`'s vocabulary, not the regex

1. **Classify by constraint kind.** `FOREIGN KEY` → a variant meaning "a row
   you referenced does not exist"; `UNIQUE` → `Conflict`; `CHECK` / `NOT NULL`
   → a 400-class variant. This needs a decision first: does `PortError` gain a
   variant, or does `NotFound` carry this (it is already the variant the
   console's dead arm expects), or `PreconditionFailed(msg)`? **Reusing
   `NotFound` is the cheapest and matches the one consumer already written for
   it, but "the thing you asked for is absent" and "the thing you referenced is
   absent" are different enough that conflating them may be the same mistake
   one level up.** Answer this before writing code.
2. **Match on something more reliable than a substring.** D1 surfaces the
   message text, so a substring is what is available — but the test must be
   specific (`foreign key`, `unique`) rather than a superset term that matches
   all four, and it must be case-insensitive once, not twice inconsistently.
3. **One helper, not eight copies.** `map_insert_err` already exists and is
   used three times; the other five sites inline the same test.
4. **The consumer arms must be re-checked**, not assumed: whatever the
   classification becomes, `tenant_create.rs::submit`'s four arms and
   `port_error_response`'s six must each be reachable by the cause they name,
   or be removed.

**Not in scope:** the orphan tenant a failed membership insert leaves behind
(RFC 158 §5.5) — same code path, different defect, still open.

## 4.5 Decided 2026-10-29 at the decision stage: reuse `PortError::NotFound`

**Not a new variant**, which was the architect's position, **and the fact that
closes it is the observed error string, not the cost census.** D1's foreign-key
message —

    FOREIGN KEY constraint failed: SQLITE_CONSTRAINT (extended: SQLITE_CONSTRAINT_FOREIGNKEY)

— **names neither the column nor the referenced table**, while UNIQUE, CHECK and
NOT NULL all name their column or constraint expression. A variant *"carrying
which reference was missing"* therefore has no payload available: the adapter's
`context` names the **statement**, not which of its foreign keys failed, and
`user_tenant_memberships` has two (`migrations/0016:171-173`). The
discrimination that justified the variant is unobtainable by anyone.

`PreconditionFailed` is also out: its doc asserts *a state transition the store
refuses*, and a missing row has no state. The symmetry does not apply to
`NotFound` — an INSERT addresses no existing row, so a `NotFound` from an
INSERT has exactly one possible subject, the thing it referenced.

**Eight sites are two changes.** Only `memberships.rs` and `groups.rs` can
produce a foreign-key failure in production. `tenants` has no foreign key at
all; `organizations` is pre-checked in core before the adapter runs;
`subscriptions.rs` and `authz/roles.rs` **have no production caller**;
`audit.rs` and `totp_recovery_codes.rs` are UNIQUE-only in practice.
**`groups.rs` is a second live foreign-key site the governing RFC's evidence
did not name** — `api_v1/groups.rs::create` checks neither `tid` nor
`organization_id`, and `create_group` takes only a `GroupRepository`, so it
structurally cannot.

**Four dead arms come alive, not seven.** §2 named one; the cycle found seven;
four is right. The three in `tenant_admin/forms/membership_add.rs` sit behind
`verify_user_in_tenant`, which already 404s on an absent user, and behind their
own container lookups — both foreign keys are proven present before the
statement runs, so those arms can fire only on a race.

**CHECK and NOT NULL are not classified.** Neither is reachable by any caller:
every `CHECK` column is written from a Rust enum via a `_str()` helper, every
`NOT NULL` column from a non-`Option` field — which is why provoking them for
the record needed a sentinel-gated probe in production code. Classifying two
branches nothing can produce would ship untestable code into the very helper
whose untested assumption caused this RFC. **UNIQUE and FOREIGN KEY only.**

**Patch, 0.89.1**: no `core::ports` edit, and neither exhaustive match
(`api_v1/auth.rs:72-84`, `core/service/clients.rs:186-188`) needs touching.

### 4.6 A revived arm is correct only where the other foreign key is proven

All four revived arms say some form of *"<user> id not found"*, and the error
cannot tell the two foreign keys apart. All four are nonetheless true today —
`tenant_create` inserted the tenant itself moments earlier, and each
`tenancy_console` handler resolves its container first — **so they are correct
by a property of their callers, not by anything the classification guarantees.**
A future handler that inserts a membership without resolving its container
inherits a confidently wrong message, and nothing in this fix would catch it.

**The rule for the implementation stage, and after it:** an arm may name a
subject only where every other foreign key on that statement is already proven
to exist. Otherwise it must name the possibilities or say nothing specific.

### 4.7 The two API paths are decided here, not at the implementation stage

Reuse sends both live foreign-key paths to a bare `404`, which is the objection
the architect raised against reuse. It is answered per handler rather than paid
for with a variant everywhere:

- **`POST /api/v1/tenants`** has no path parameter, so a `NotFound` can only be
  the owner reference → **400 naming `owner_user_id`**.
- **`POST /api/v1/tenants/:tid/groups`** resolves the tenant first — one
  `tenants.get`, as every console handler already does — making `:tid` an
  honest 404, after which the remaining `NotFound` can only be
  `organization_id` → **400 naming it**. **Not** by giving `create_group` a
  `TenantRepository`: that is a core signature change with a test ripple, which
  is RFC 158 §5.2's lesson.

Deciding this here rather than deferring it is RFC 158 §5.6's lesson: a sink
that no person reads is not a report.

## 4.8 The population was wrong, and one site outside it carries the defect

Implemented `28b25b3`; found in review of that commit. **§2's population came
from the architect's grep**, which searched the literal strings
`contains("unique")`, `contains("constraint")` and `contains("foreign")`
**including the closing `")`** — so it could never match
`contains("constraint failed")`. Four more sites spell the test differently and
were in neither the RFC's census nor the cycle's.

**The population, re-derived loosely and completely** — `grep -rn
"msg.contains(" crates/adapter-cloudflare/src`, **9 lines across 6 sites**
after `28b25b3`'s consolidation: `ports/repo.rs:109-111` (the new shared
classifier), `ports/audit.rs:223-224` (its own id-vs-seq logic, tightened),
`anonymous.rs:94-96`, `ports/repo/users.rs:129`, `ports/repo/invitations.rs:84`,
`ports/repo/deletions.rs:91`. **No further site exists.** The count that
mattered was never "eight"; it was "every place a D1 error message is read",
and that is the grep that should have opened this RFC.

**`ports/repo/users.rs:129` carries this RFC's defect.**
`UserRepository::create` tests `msg.contains("UNIQUE") || msg.contains
("constraint failed")`; `users.tenant_id` is a foreign key
(`migrations/0016:46`) and `FOREIGN KEY constraint failed` contains
`constraint failed`. So a user created against a nonexistent tenant returns
`Conflict`, which `admin/legacy.rs:94` renders as **"email already in use",
409** — a missing tenant reported as a duplicate email. Narrow in practice
(`legacy.rs:69` passes `DEFAULT_TENANT_ID`, which migration 0003 seeds), but it
is the defect this RFC is named for, and the helper that fixes it now exists.
**Fixed in cycle 2.**

**The other three are not defects and are deliberately left alone:**
`anonymous.rs:94` **already distinguishes `FOREIGN KEY` explicitly** — the one
place that got this right before this RFC existed; `deletions.rs:91` and
`invitations.rs:84` test `UNIQUE` only, so a foreign-key failure falls through
to a 500 rather than to a wrong message, and their callers pass tenants that
exist, so routing them through the helper would change nothing observable.

### 4.9 The fallthrough is the regression guard, and it has no witness

The cycle correctly flagged that the third classifier test cannot be built:
asserting the fallthrough runs `run_err`, which calls
`worker::console_error!`, which **aborts the host binary**. **But the
requirement was constructible — the structure is what made it impossible.**
Splitting the decision from the logging (a pure `msg -> Option<PortError>`,
with `classify_insert_err` the thin wrapper that logs on `None`) makes all
three branches host-testable, the same extraction used for
`tenant_created_detail`, `accept_invite_page`, and every `worker::Response`
case since RFC 146 §2.

It matters more than a missing test usually would: **nothing currently pins
that an unrecognized constraint message does not become `Conflict`** — which is
exactly this RFC's bug, and exactly what a future re-broadening of the match
would reintroduce, with both existing tests staying green. **Fixed in cycle 2.**

### 4.10 Cycle 2 landed; the ninth site's consumers are three, and none is sensitive

`6280b1b`: `users.rs::create` routes through the shared helper, and
`classify_insert_message` carries the decision as a pure function with
`classify_insert_err` the thin wrapper that logs on `None` — five host tests,
of which CHECK, NOT NULL and an unrelated message are the guard that did not
exist. Re-verified at **1,630** host tests / 0 failed, `migration_chain` 35,
routes 193, bundle 882,731 B reconciling at 33% with full digests.

**The fires witness had to be the pure function, not the wrapper** — found by
the cycle, not specified: reverting the foreign-key arm and calling the wrapper
sends the message into `run_err`, which **aborts** the binary rather than
failing the assertion, so a wrapper-level probe would have proved nothing.

**`UserRepository::create` has three production consumers, not one**:
`admin/legacy.rs:80`, `magic_link/verify.rs:403`, `api_v1/anonymous.rs:128`.
All three match a wildcard rather than the variant, so none is sensitive to the
reclassification and no arm was added anywhere. `magic_link/verify.rs` is the
only one where a foreign-key failure is genuinely reachable — RFC 153 made that
path's `tenant_id` come from an invitation rather than a constant — and it
answers `CoreError::Internal`: vague, true, and not this RFC's to improve.

## 5. The lesson worth keeping in the record

This was found in a cycle's **unrequested** evidence. The dev team ran
`POST /api/v1/tenants` with an unknown owner because they wanted all three
owner-home outcomes on the record, discovered it was not an owner-home outcome
at all, and left the output in the log. Nothing in the handoff asked for it and
no gate would have caught it — the host tests pass, the route is documented,
and both error paths return a valid response. **Evidence gathered past the
question is how this programme finds the things its gates cannot.**
