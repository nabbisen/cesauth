# RFC 158 — No tenant but the default has a reachable admin console

**Status.** **Accepted** 2026-10-29. **Sequenced after RFC 153**, and for a
reason rather than a queue position: RFC 153 is about to establish how
`users.tenant_id` comes to hold a non-default value at **create** time, and
§5's option (1) would reuse that. Designing both at once risks two mechanisms
for one column. **Decision stage dispatched 2026-10-29**:
`handoffs/158-no-tenant-but-the-default-has-a-reachable-console/decision-stage-handoff.md`.
**Release not assigned** until the choice is made, because §5's options are
different sizes.

### A fourth option, closed before it was offered

RFC 153 shipping made *"let tenant creation invite the owner, and let RFC 153's
path set the column"* look like the cheap answer. **It only works for an owner
with no account yet.** Verified: `create_tenant` requires an **existing** user
(`owner_user_id`, miss → *"Owner user id not found"*), and
`resolve_or_create_user`'s existing-user branch **returns before** the
`tenant_id` computation — RFC 153 §1's decision, deliberately, so an existing
user's home tenant is never reassigned.

**That new-versus-existing split may itself be the shape of the answer**, and
it is handed to the decision stage rather than settled here.
**Tier.** **P1.** A documented, 35-route administrative surface that exactly
one tenant can open.
**Size.** Small in code — one repository on one function, or one dedicated
path. The design question is which.
**Touches.** `crates/core/src/tenancy/service.rs`,
`crates/adapter-cloudflare/src/ports/repo/users.rs` (an `UPDATE` it currently
refuses to do, deliberately), `crates/backend/src/routes/api_v1/tenants.rs`,
`docs/src/expert/adr/003-*.md` if the answer touches it.
**Depends on.** Nothing. **Complements RFC 153**, which fixes the invited-user
half of the same gap. **Reframes RFC 145**, whose three cycles served this
surface.
**Found by.** The **dev team**, 2026-10-29, while researching RFC 153 §2's
decision — reported as out of scope rather than absorbed. Reach established by
the architect in review.

## 1. Summary

`/admin/t/:slug/*` — the tenant-admin console, 35 routes, three release cycles
of work in RFC 145 — is gated by `resolve_tenant_admin`, which requires a
user-bound principal whose **`users.tenant_id` equals the tenant**. That gate is
correct and ADR-governed.

**No path sets `users.tenant_id` to anything but the default.** So the surface
is reachable only when `:slug` resolves to the default tenant. For every other
tenant, **nobody** can open it: not the tenant's owner, not a system admin.

## 2. What is established

**The gate.** `core/tenant_admin.rs::resolve_tenant_admin` — requires
`principal.user_id` to be `Some` (*"must be user-bound (ADR-003)"*), then
`if user.tenant_id != tenant.id { return Err(WrongTenant) }`. **No
system-admin bypass**; the function has no branch for an unbound or
system-scoped principal beyond rejecting it.

**Tenant creation cannot set the column.**
`core/tenancy/service.rs::create_tenant` takes `TenantRepository` and
`MembershipRepository` — **no `UserRepository` at all.** It grants the owner a
`user_tenant_memberships` row and touches `users` not at all.

**Nothing else sets it either.** Every `User` construction in the workspace
hardcodes the default: `magic_link/verify.rs:275`,
`api_v1/anonymous.rs:118`, `admin/legacy.rs:69`, all
`DEFAULT_TENANT_ID` (`"tenant-default"`, `tenancy/types.rs`). And
`UPDATE users` omits `tenant_id` **deliberately** — the adapter's own comment:
*"moving a user between tenants is a destructive operation that needs its own
dedicated path with audit trail."*

**So the conclusion is structural, not incidental.** One tenant's console
works. Every other tenant's is unreachable by construction.

## 3. What this reframes

**RFC 145** spent v0.85.1, v0.86.1 and v0.86.2 making 35 admin pages render
instead of answering 200 with Not Found. **Thirty-four of them are on this
surface.** The work is not wasted — the default tenant is real and those pages
work there — but **the reach was overstated for three cycles, by the
implementing cycles and by me.** Nobody checked who could open the pages being
fixed.

That is the same omission in a new place: RFC 047 was *"written, correct, and
called by nothing"*; this is *"rendered, correct, and openable by almost
nobody"*. **Verifying that a surface renders is not verifying that anyone can
reach it.**

## 4. What is not established

**Whether the gate or the column is the thing to change.** RFC 153's cycle
decided — correctly, and with better evidence than the RFC had — that
`users.tenant_id` means *home tenant* and the gate stands. That decision is
about the **invitation** path. It does not answer what a tenant's **owner**
should be, because an owner is not invited: they are named by whoever created
the tenant.

## 5. Direction — three candidates, and the choice is the work

1. **`create_tenant` sets the owner's `users.tenant_id`.** Smallest change;
   gives `create_tenant` a `UserRepository`. **But it writes the column the
   adapter explicitly refuses to update**, so it either needs the "dedicated
   path with audit trail" that comment demands, or it must be a `create`-time
   value only — which an owner of an *existing* user is not.
2. **A dedicated "move user to tenant" path**, audited, which tenant creation
   calls for its owner. Honours the adapter's comment rather than working
   around it; costs a route, an event kind and a policy decision about who may
   invoke it.
3. **Relax the gate for a membership-bearing principal** — the option RFC 153's
   cycle rejected **for the invitation path**. It may be the right answer for
   *owners* specifically, but it reopens ADR-003 and so is the owner's call,
   not mine.

**Decided 2026-10-29 at the decision stage: option 2.** My inclination, and
**the reasoning that selects it is the cycle's, not mine.**

- **Option 3 reopens the specific alternative ADR-003 already rejected** —
  *"Single console with role-conditional rendering (rejected)"* (`:147`), whose
  reason 2 reads *"A bug in the conditional-rendering logic leaks cross-tenant
  data."* ADR-003 rejected that shape at the **view** layer; option 3 would
  introduce it at the **gate**, so the objection applies more forcefully. My
  §5 said only "it reopens an accepted ADR", which is shallow by comparison.
- **Option 1's cheapness dissolves when written out.** Shape (a) — widening
  `UserRepository::update` — gives every current and future caller an implicit
  obligation never to pass a mutated `tenant_id`, a permanent wide blast radius
  for a narrow need. Shape (b) — a narrow private write — **is option 2 minus
  the naming.** So there was no trade-off to offer. My framing ("fights an
  explicit comment", a "weaker objection than it sounds") was the wrong
  objection.
- **Option 2 is the house idiom, not an invention.** Four existing narrow
  single-field setters — `billing::set_plan`, `billing::set_status`,
  `tenancy::set_status` for tenants and organizations — each with its own
  emitted `EventKind`. `assign_tenant` is the fifth instance of a pattern
  already used four times in this area. A check I had not made.

**Shape:** `UserRepository::assign_tenant`, a dedicated adapter `UPDATE`, a core
service function, called by `create_tenant` for its owner, inheriting
`ManageTenancy` from the flow that already gates it. **Assignment last**, so a
failure leaves the outcome degraded-but-not-worse — refined by **§5.3**,
which replaces "degraded" with a reported outcome, and by **§5.2**, which
found a second caller. One new `EventKind`, which
makes it **0.89.0, minor** — consistent with RFC 154.

### 5.1 `UserRepository::update()` silently ignores `tenant_id`

Found at the decision stage, verified in review. The statement is
`UPDATE users SET email, email_verified, display_name, account_type, status,
updated_at WHERE id` — **no `tenant_id`.** A caller who fetches a `User`,
mutates `tenant_id` and calls `update()` gets **no error and no effect.**

**Recorded because of what it would cost later**: a future cycle assuming
`update()` can move a user between tenants, because nothing complains when it
tries, **will ship a no-op and call it done.** This programme's signature
failure shape, sitting one function away from the work option 2 adds.

### 5.2 There are two callers, not one — and fifteen call sites, not two

Found by the implementation cycle at the handoff's own first report-and-stop
condition. `crates/backend/src/routes/api_v1/tenants.rs:48` — `POST
/api/v1/tenants`, routed at `lib.rs:467`, documented at
`route-contracts.md:230` — calls `create_tenant` independently of the console
form. Both callers gate on the identical permission (`api_v1/tenants.rs:36`
`require(AdminAction::ManageTenancy, …)`; the console's `require_manage` →
`ensure_role_allows(…, ManageTenancy)`), so the design does not change.

`grep -rn "create_tenant(" crates/ --include='*.rs'` → **15 call sites: 2
production, 13 in `adapter-test`.** The decision report said "the one caller"
and I repeated it into the handoff without running that command; the cycle's
own report then said "three adapter-test call sites, which construct their own
stub `UserRepository` already" — also wrong, in both halves:
`grep -c "InMemoryUserRepository"` over those three files returns `0, 0, 0`,
and `common.rs` does not import `UserRepository` at all.

**Both callers must assign the owner's home tenant.** A tenant whose owner can
open their console beside one whose owner cannot, decided by which door the
tenant came through, is a latent inconsistency an operator cannot see.

### 5.3 So the assignment belongs inside `create_tenant`, with a reported outcome

If each caller performs the assignment, a third caller can omit it and
reintroduce this RFC's own bug. ADR-003's *"URL-prefix separation makes such
bugs structurally impossible"* — the sentence this RFC used to reject option 3
— is the project's preference for structural over conventional guarantees;
applied consistently it puts the assignment where no caller can forget it.

That raises the question the decision stage never reached: **what does a failed
assignment report?** Propagating it tells the caller creation failed when the
tenant and membership rows exist; discarding it lets the caller emit an audit
record for something that may not have happened. **RFC 148 §7 already settled
this shape** for a secondary write after a primary one in a store with no
multi-row transactions (`deletion.rs:159-202`): the failure must not be
reported as a failure of the primary operation, and the caller *must* be able
to tell "nothing to do" from "it did not happen".

So `create_tenant` returns a `#[must_use]` outcome **struct** — for the reason
`ExecuteOutcome`'s own doc gives, that a future field can join it without
another signature change — carrying the tenant and an `OwnerHomeOutcome
{ Assigned, KeptExistingHome, Failed }` with `as_str()`, one-to-one with
`ScrubOutcome`. `Failed` absorbs "the owner row could not be found", which
`ScrubOutcome` already classes as a storage inconsistency rather than evidence
of anything. `user_tenant_assigned` is emitted **only** on `Assigned`; the
other two ride in the `tenant_created` detail, as RFC 148 §7.4 does.

### 5.4 An owner who already has a home tenant keeps it

`resolve_tenant_admin` (`tenant_admin.rs:168-175`) gates on `users.tenant_id ==
tenant.id`, so silently overwriting an existing home **revokes that user's
admin access to their previous tenant** — this RFC's bug, inflicted
deliberately on someone else.

Refusing the creation instead (409) was drafted and rejected: today naming an
already-homed user as owner **succeeds**, so refusing is a behaviour regression
on a live API for a reason about console reach rather than data integrity — the
membership row, which is what confers ownership, is unaffected — and it would
assert a product rule (one owner, one tenant) that is the owner's to make, not
the architect's.

**Decided: create the tenant, keep the existing home, report
`KeptExistingHome`.** `tenant-default` (`tenancy/types.rs:21`; the column's own
`DEFAULT 'tenant-default'` at `migrations/0016:46`) is the only home value the
assignment overwrites.

### 5.5 Two defects found while verifying, recorded and not fixed here

Same discipline as §5.1 — these are not this RFC's defects:

- **A bad owner id leaves an orphan tenant.** `tenants.create()` succeeds, then
  `add_tenant_membership()` fails on the `user_tenant_memberships.user_id`
  foreign key, and the tenant row stays; `create_tenant`'s own doc comment
  admits it. A pre-flight owner read would fix it — and would force 13 test
  call sites to seed users. The owner read therefore goes **after** both
  inserts, immediately before the assignment, leaving this behaviour exactly as
  it is.
- **The API path's audit records carry no `via=` marker**, so the *absence* of a
  marker is how an API-created tenant is distinguished from a console-created
  one. That gets worse once a second event is emitted from both doors, but
  fixing it changes an existing audit detail format.

## 6. Why P1 and not P0

Nothing is exposed and nothing is corrupted. A surface is unusable, and it has
been unusable for the whole life of multi-tenancy — so no regression, no
incident, and the default tenant's deployment is unaffected. **It is P1 because
a 35-route administrative surface that one tenant can open is not a corner
case, and because three release cycles were spent on it without anyone asking
this question.**
