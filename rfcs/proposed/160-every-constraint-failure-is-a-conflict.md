# RFC 160 — Every constraint failure is a `Conflict`

**Status.** **Proposed** 2026-10-29. Needs nabbisen's acceptance.
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

## 5. The lesson worth keeping in the record

This was found in a cycle's **unrequested** evidence. The dev team ran
`POST /api/v1/tenants` with an unknown owner because they wanted all three
owner-home outcomes on the record, discovered it was not an owner-home outcome
at all, and left the output in the log. Nothing in the handoff asked for it and
no gate would have caught it — the host tests pass, the route is documented,
and both error paths return a valid response. **Evidence gathered past the
question is how this programme finds the things its gates cannot.**
