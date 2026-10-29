# Developer Handoff — RFC 158, decision stage only

**Governing RFC.** `rfcs/accepted/158-no-tenant-but-the-default-has-a-reachable-console.md`

**Stage.** **A decision report. No code.** RFC 158 §5 asks for this explicitly,
in RFC 153 §2's shape — that mechanism has now produced a better answer than
the RFC asking the question twice, and three measurement corrections before any
implementation. **A report that says only "here is the choice and why" is the
complete deliverable.**

**Target release.** Unassigned. §5's options are different sizes and the
release follows the choice.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. RFC 157 shipped in 0.88.1. **Dispatched 2026-10-29.**

**On 1.0:** not declared, not scoped, not dated. Nothing here is justified by
it.

---

## 1. The question

`/admin/t/:slug/*` — 35 routes — is gated by `resolve_tenant_admin` on
`users.tenant_id == tenant.id`, with **no system-admin bypass**.
`create_tenant` grants the new tenant's owner a `user_tenant_memberships` row
and **cannot** set that column: it takes `TenantRepository` and
`MembershipRepository` and **no `UserRepository` at all**.

So **a tenant's owner cannot reach their own tenant's console.**

**What should change, and why?** §5 gives three candidates. I have an
inclination and low confidence in it; see §4.

## 2. What RFC 153 established, and why it helps less than it looks

RFC 153 shipped in 0.88.0 and is the first path that ever set
`users.tenant_id` to a non-default value. **It does so only at user
creation.** Verified before writing this:

- `create_tenant` requires an **existing** user — `owner_user_id` is looked up
  and a miss returns *"Owner user id not found"*;
- `resolve_or_create_user`'s existing-user branch **returns before** the
  `tenant_id` computation, so an existing user's home tenant is never
  reassigned — which is §1's decision in RFC 153, deliberately.

**So the obvious fourth option does not work.** "Let tenant creation issue an
invitation to the owner, and let RFC 153's now-working path do the rest" is
attractive and **only succeeds when the owner has no account yet.** For an
owner who already exists — the case `create_tenant`'s own API requires — the
invitation grants a membership and leaves the home tenant alone, so the console
stays unreachable.

**That split may itself be the answer**, and it is yours to assess: a
*new* owner is solvable with machinery that already exists and is tested; an
*existing* owner is not. Whether that argues for changing the API, for one of
§5's three, or for both, is the decision.

## 3. What the report should contain

1. **The choice**, and the reasoning that selects it over the others.
2. **What it costs** — files, whether a migration is needed, whether an ADR is
   touched. §5's option 3 reopens **ADR-003** (Accepted, v0.11.0), whose
   §"Option 2" requires *"a user-as-bearer token whose `users.tenant_id`
   matches the tenant"*. **If your choice reopens an accepted ADR, say so
   plainly** — that is the owner's call, not mine and not yours.
3. **What the adapter's refusal means for it.** `UPDATE users` omits
   `tenant_id` deliberately: *"moving a user between tenants is a destructive
   operation that needs its own dedicated path with audit trail."* Option 1
   writes that column anyway; option 2 builds the path the comment asks for.
   **Whichever you pick, answer that comment rather than stepping around it.**
4. **Who may invoke whatever you add**, if anything. Moving a user between
   tenants is a tenancy-wide operation; `ManageTenancy` is the obvious
   permission and "obvious" is where this project keeps finding gaps.
5. **Research past the question, as the last two cycles did.** Both found
   things the RFC had not: seven reads of `users.tenant_id` where my sketch
   named two, and an accepted ADR I had not checked. **If this one is wrong
   somewhere, I would rather hear it at this stage.**

## 4. My inclination, offered to be argued with

**Option 2** — a dedicated, audited "assign user to tenant" path that
`create_tenant` calls for its owner. It answers the adapter's comment instead
of overriding it, and it is the only option that also serves the case nobody
has raised yet: an operator moving a user between tenants deliberately.

**I am not confident.** Option 1 is materially cheaper and its only real sin is
contradicting a code comment, which is a weaker objection than it sounds if the
comment's concern (an unaudited silent move) is met by auditing the one
call site. **Argue me out of it if the cheaper option is right** — the last
cycle's deviation was better than my instruction, and the one before that found
my instruction impossible.

## 5. Report-and-stop

This whole stage is a stop. If the decision cannot be made without an
experiment — reading a schema, trying a query — do the experiment and report
it; that is not scope creep. **Do not implement the choice.**

## 6. Review request

Write it to `.git-exclude/review-request/158-report.md` and give me the commit
if anything was committed, or say nothing was.
