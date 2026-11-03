# RFC 171 — The arm is written, and the error is never produced

**Status.** **Proposed** 2026-11-03 by the architect. **Not scheduled.**
The immediate repair is already in flight as RFC 141 cycle 2b inside 0.92.0;
this RFC is the systemic half and needs the owner's acceptance.
**Tier.** **P1.** Ten shipped code paths branch on an error their producer
cannot produce — six written operator messages that cannot be displayed, three
public-API responses with the wrong status, and one idempotency arm whose
failure permanently loses an invitation's acceptance record.
**Size.** **Medium**, in two halves of very different cost: a census that needs
nothing new, and a check that cannot run without the CI capability RFC 170
builds.
**Touches.** `scripts/`, `docs/src/expert/contributing.md`, and — for the second
half only — `.github/workflows/`. No product code: the product fix is cycle 2b's.
**Depends on.** [RFC 170](../accepted/170-no-gate-can-drive-a-credentialed-flow.md)
for the second half. §4 says why, and why that is not an excuse to ship the
first half alone.
**Found by.** The architect, 2026-11-03, reviewing the dev team's RFC 141
cycle 2b stop. The stop asked a one-line question about one table; the answer
was that the classifier is wrong for the whole schema, and the reason nobody
noticed is a different defect from the one being fixed.
**Relates to.** [RFC 160](../done/160-every-constraint-failure-is-a-conflict.md)
(the classifier this corrects),
[RFC 166](../accepted/166-reachability-stops-at-the-crate-boundary.md) (the dual
question — see §2.3), [RFC 153](../done/153-an-invitation-grants-nothing.md)
(whose completion ordering this silently defeats),
[RFC 141](../accepted/141-oidc-client-registration.md) (the cycle that found it).

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Summary

`PortError` is this project's error vocabulary across the port boundary.
Handlers branch on its variants to decide status codes and operator messages.
**Nothing checks that the variant a handler matches is one its adapter can
return** — and in the one case now measured, it could not.

`classify_insert_message` (`crates/adapter-cloudflare/src/ports/repo.rs`) maps
D1 constraint failures onto `PortError`. It matches
`sqlite_constraint_unique` and `sqlite_constraint_foreignkey`. SQLite reports a
**primary-key** collision as `SQLITE_CONSTRAINT_PRIMARYKEY`, with a message
whose human-readable text still reads `UNIQUE constraint failed`. Measured
locally against sqlite 3.54.0, outside this project:

```
text_pk        -> SQLITE_CONSTRAINT_PRIMARYKEY     | UNIQUE constraint failed: t.id
composite_pk   -> SQLITE_CONSTRAINT_PRIMARYKEY     | UNIQUE constraint failed: t.a, t.b
separate_uniq  -> SQLITE_CONSTRAINT_UNIQUE         | UNIQUE constraint failed: t.s
```

Of **61** `PRIMARY KEY` declarations in `migrations/`, exactly **one** is
`INTEGER` (`audit_log.seq`), and no classifier caller inserts into it. So for
every table the classifier is used on, a duplicate key falls through to
`Unavailable`.

## 2. What is established

### 2.1 Ten paths, already shipped

| path | branches on | actually gets |
|---|---|---|
| `admin/tenant_admin/forms/membership_add.rs:118`, `:241`, `:355` | `Conflict` → *"User is already a member of this …"* | `_ => "Storage error"` |
| `admin/tenancy_console/forms/membership_add.rs:110`, `:208`, `:292` | the same three sentences | `_ => "Storage error"` |
| `api_v1/memberships.rs:49`, `:112`, `:175` | `Conflict` → **409** via `api_v1/auth.rs:74` | `server_error()` → **500** |
| `magic_link/verify.rs:461` | `Err(PortError::Conflict) => {}` — idempotent | `Err(e) => return` |

All three membership tables have a **composite** primary key and no separate
`UNIQUE`, so the duplicate every one of these arms was written for is the one
case the classifier cannot see.

The last row is the expensive one. `complete_invitation`'s own doc comment names
both triggers — *"a retry after a prior partial failure, or a second invitation
to a tenant they already belong to"* — and calls the case *"not an error."*
Instead the step returns early, `accept_invitation` never runs, no audit row is
written, and because the membership still exists the next attempt fails
identically: **"left pending for retry" is false; the invitation is stuck until
it expires.** RFC 153 §3 ordered these steps precisely so a failure would leave
the invitation re-usable rather than falsely accepted; the ordering held and the
outcome is still wrong, because the step that *"exists to ensure the membership
holds"* reports failure exactly when it already holds.

`crates/core/src/tenancy/service.rs:175` documents the contract — *"Returns
`Conflict` if the user is already a member of the tenant"* — on a pass-through
with no pre-check. There is no second producer. The documentation is false.

### 2.2 The reason nobody noticed is its own defect

`crates/adapter-test/src/tenancy/memberships.rs:30-37` returns
`PortError::Conflict` on a duplicate membership. The D1 adapter returns
`Unavailable`. **Two implementations of one port disagree about the one error
the port documents, and the double is the one that is right.** Every host test
over this path is green against behaviour production does not have.

`grep -rn "already a member" crates/ --include='*.rs'` returns the six strings,
one doc line, one module-doc line — **and no test.** There was nothing to fail.

### 2.3 This is RFC 166's dual, not a special case of it

RFC 166 asks whether a definition has a caller, and puts it memorably: *"E4 asks
whether the door is connected to the corridor; nobody asked whether the corridor
leads to a room."* This RFC asks the opposite direction: **the lock is fitted,
the corridor leads to the room, and no key of that shape is ever cut.** A
reachability gate cannot find it — every function here is called, every match
arm compiles, and `#[warn(unreachable_patterns)]` has nothing to say because the
variant exists in the type. Unreachability lives in the *data*, not the graph.

### 2.4 The matcher lesson, which is more general than SQLite

RFC 160's correct insight was that `contains("constraint")` over-matched: every
constraint class contains that word, and all four collapsed into `Conflict`. Its
fix matched SQLite's extended result code instead. That is more specific — and
it **under-matches in exactly the place the prose does not**. RFC 160 replaced an
over-matching test with an under-matching one, tested it against the single
string it had captured, and shipped the swap as a fix.

> **A more precise matcher is not a more correct one until its vocabulary has
> been enumerated.**

This is the same shape as the project's three grep-extractor blind spots and the
same shape as RFC 159 §4.5's rule: every item of the vocabulary is either
classified or **named with a reason**. RFC 160's classifier doc enumerated four
constraint classes and justified omitting two. `PRIMARYKEY` was never an item,
so no reason was ever owed for it. **A census of four, where the vocabulary has
twelve, is not a census.**

## 3. Direction — two questions, and only one of them is cheap

**Q1 — the producer question.** For every `PortError` variant a handler matches,
can the adapter behind that call return it? Per port method, two sets: the
variants each implementation can produce, and the variants each caller matches.
A caller matching a variant nothing produces is a defect; a producer whose
variant nobody matches is at worst noise.

**Q2 — the parity question.** The in-memory double and the D1 adapter must agree
on each port method's documented error classes. Today they disagree on the one
that matters and no test could have said so.

Q1's answer is derivable from the source and needs no new capability. **Q2 is
not host-testable**: `cesauth-adapter-cloudflare`'s repository code needs a
worker runtime and real D1, which is exactly the capability RFC 170 adds — a CI
job with migrated D1 state. One shared contract suite, asserted on the double by
host test and on D1 by that job, is the only honest form of Q2.

## 4. The one trap this RFC must not fall into

The cheap half of Q1 is a **table**: port method → documented error classes →
which implementation produces each. Writing that table and stopping would make
this the **eleventh** instance of the shape this programme keeps finding — *a
documented rule with no gate.* RFC 156 already says a gate that stops covering
something must fail; a rule that never had one is worse.

So: **the table is only worth writing as the input to the check that reads it.**
If RFC 170 does not land, Q1's check still can — it reads source, not a runtime
— and it is the half that would have caught all ten paths. Q2 is the half that
would have caught the *cause*. Accepting this RFC means accepting that order:
census, then Q1's check, then Q2 behind RFC 170.

## 5. Scope boundaries, named rather than left open

- **Not the product fix.** RFC 141 cycle 2b carries
  `sqlite_constraint_primarykey => Conflict`, the OIDC 409, and live captures
  for the three distinct membership consumers. This RFC owns nothing in 0.92.0.
- **The DELETE side is in the census, not in cycle 2b.** `ON DELETE RESTRICT` on
  `groups`' two foreign keys (`migrations/0017_groups_fk_restrict.sql:46`, `:49`)
  makes a foreign-key failure reachable on a `DELETE`, where there is no
  classifier at all. Not live today: soft delete is the product path, and
  `grep -rn "DELETE FROM organizations\|DELETE FROM groups" crates/
  --include='*.rs'` returns one hit, in `crates/migrate-test`. Named so the next
  schema change cannot quietly make it live.
- **`RoleRepository::create` has no production caller**
  (`grep -rn "CloudflareRoleRepository" crates/backend/src` returns only
  role-*assignment* handlers; the catalog is seeded by migration). That is an
  RFC 166 §3 item, recorded there, not counted here.
- **No count is quoted for the workspace.** §2.1's ten are the paths behind one
  port method. The census derives the rest; nothing in this RFC claims a total
  it has not measured.
