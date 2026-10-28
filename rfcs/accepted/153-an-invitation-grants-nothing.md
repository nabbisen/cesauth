# RFC 153 — An invitation grants nothing

**Status.** **Accepted** 2026-10-27 — the defect is accepted and the work is
wanted; the owner confirmed tenant-scoped self-service onboarding is in scope
for the product.

**On 1.0: §7 is my recommendation, not a decision.** Corrected 2026-10-28 at
the owner's instruction — *"1.0 needs my clear authorization after
confirmation. It has not been decided yet."* **1.0 is neither declared,
scoped, nor dated.** §7 argues that *if* a 1.0 is cut, this belongs in it, and
gives the reason (the fix changes the shape of the user record, so it is cheap
before a compatibility commitment and expensive after). **Nothing in this RFC
or the index should be read as 1.0 having a scope.**

**Scheduling:** a feature cycle, not a patch, sequenced after the 0.87.x fixes
in flight. Not blocked on the 1.0 question — the defect is worth fixing on its
own merits, and §7's argument only affects *how late* it could safely be left.
**Tier.** P1. The feature's stated purpose is to link an email address to **a
tenant and an initial role**. Neither is ever applied. What ships is an email
with an audit trail.
**Size.** Medium. The flow needs a completion step that does not exist, not a
repair to one that does.
**Touches.** `crates/backend/src/routes/invitations.rs`,
`crates/backend/src/routes/magic_link/{request,verify}.rs`,
`crates/core/src/invitation.rs`, `crates/core/src/tenancy/service.rs`,
`migrations/0018_invitation_tokens.sql` (the `accepted_by` contract),
`docs/src/expert/route-contracts.md`.
**Depends on.** Nothing. **Corrects** RFC 148 §2's table.
**Found by.** The architect, 2026-10-27, **during RFC 000 §22's evidence
back-fill**, by starting at RFC 047's literal sibling on the grounds that it
was written in the same cycle by the same hand in the same shape.

## 1. Summary

RFC 043 defines an invitation as *"an invitation links a pending email address
to a tenant and an initial role"*. RFC 046 ships the worker layer; RFC 049 is
titled *"`/accept-invite` full implementation"*. All three are in `done/`,
**Status: Implemented**, P1.

**An accepted invitation produces no tenant membership and no role
assignment.** The invitee registers into the default tenant as an ordinary
user, exactly as if no invitation had existed. The invitation's `role` column
is written at issue time and **read once in the entire codebase — into an audit
message string.**

## 2. What is established

**`invite_id` is passed forward and read by nobody.** `accept_submit`
(`routes/invitations.rs:253-256`) redirects to
`/magic-link/request?email=…&invite_id=…`, and:

```
$ grep -rn "invite_id" crates/backend/src --include='*.rs' | grep -v routes/invitations.rs
(no output)
```

**The role is never granted.**

```
$ grep -rn 'inv\.role' crates/backend/src --include='*.rs'
routes/invitations.rs:118:  Some(format!("tenant:{} email:{} role:{}", …, inv.role)),
```

One hit, inside the `InvitationIssued` audit event's free-text detail.

**Registration hardcodes the default tenant.**
`routes/magic_link/verify.rs:275` — `tenant_id: cesauth_core::tenancy::DEFAULT_TENANT_ID.to_owned()`.

**Memberships *can* be created — just not by this flow.**
`add_tenant_membership` has three production callers:
`tenant_admin/forms/membership_add.rs:104`, `api_v1/memberships.rs:49`, and
`core/tenancy/service.rs`. **None is on the invitation path.** (My first
measurement said nothing writes memberships at all; that was a backend-only
grep and it was wrong. The narrower claim is the true one and it is worse for
the feature, not better: the capability exists and the invitation flow does not
use it.)

**The invitation is consumed before registration, with a placeholder.**
`routes/invitations.rs:239`:

```rust
invitation::accept_invitation(&inv_repo, &inv.id, "pending-registration", now)
```

`accepted_by` is the **literal string** `"pending-registration"`, written
before the user exists. So:

- **a user who abandons the magic-link step is locked out of their own
  invitation.** The row is `accepted_at IS NOT NULL`, so a second attempt hits
  `InvitationVerifyOutcome::AlreadyAccepted` and renders *"Already accepted.
  Please sign in."* — to somebody with no account. Recovery needs an admin to
  issue a new invitation.
- **`accepted_by` has never held a user id**, in any row, ever.

**Invitations cannot be revoked.** `core::invitation::revoke_invitation`
(`:214`) exists and is host-tested, and its only callers are those tests
(`:312`, `:352`). No route reaches it, so `revoked_by` and `revoked_at` are
always `NULL`, and the `0018` migration's documented `revoked` state is
unreachable.

## 3. Why this is the third instance of one defect, not a new one

| RFC | `done/`, Status | What was dead |
|---|---|---|
| **047** — deletion worker layer | Implemented | self-service route checked the wrong resolver; cron sweep had no caller. **61 releases.** |
| **017** — audience admin editor | Implemented | template with tests, posting to a route never registered |
| **046 / 049** — invitation worker layer, "full implementation" | Implemented | accept grants no tenant and no role; revoke has no route |

All three were found by accident while doing something else. **This one was
found on purpose**, by RFC 000 §22's back-fill, at the first place the method
said to look. That is the back-fill working as RFC 151 argued it would, before
it has covered even a tenth of its 28 RFCs.

## 4. Direction

**The missing piece is a completion step**, and it belongs where registration
finishes, not where the invitation is accepted:

1. **Stop consuming the invitation at `accept_submit`.** Verify it, carry the
   id forward, and leave it pending. Nothing is accepted until an account
   exists.
2. **Carry the invitation through the magic-link flow.** `invite_id` must
   survive `request` → email → `verify`. A query parameter is not enough —
   a signed, short-lived cookie in the style of `post_auth`'s pending-handle
   cookie is the shape this codebase already uses.
3. **On successful registration**: create the user in **the invitation's
   tenant** rather than the default, `add_tenant_membership` with the
   invitation's `role`, then `accept_invitation` with **the real user id**, then
   the audit event with `subject` = that user. In that order, so a failure
   leaves the invitation re-usable.
4. **Wire revoke**: a tenant-admin route calling `revoke_invitation`, and a
   `route-contracts.md` row. The invitations page already exists.

**The acceptance test is the one RFC 147 cycle 2 established**: drive the whole
path against `wrangler dev` and assert the **database rows** — a membership in
the right tenant with the right role, and `accepted_by` equal to the new user's
id. **Not** that the handler returned 303. RFC 047's route returned a plausible
status for its entire broken life.

## 5. Open question for the owner

**Is tenant-scoped self-service onboarding in scope for 1.0 at all?** If
invitations are meant to work, this is a real feature cycle, not a fix. If
they are not, the honest alternative is to **remove the surface** — the issue
route, the accept routes, the admin page, the table — rather than leave three
`done/` RFCs describing a capability that has never existed. I have a
recommendation either way, but the scope judgement is a product decision and
this one is large enough to be genuinely yours.

## 6. What else the same missing step blocks (2026-10-27)

Added while answering the owner's question about 1.0 scope. **I tried to
falsify a larger claim and it did not survive, which is worth recording
alongside what did.**

### 6.1 The claim that did not survive

I formed the view that **cesauth is effectively single-tenant**, on this
evidence: every `User` construction in the workspace hardcodes
`tenant_id: DEFAULT_TENANT_ID` (`"tenant-default"`, `tenancy/types.rs:21`) —
`magic_link/verify.rs:275`, `api_v1/anonymous.rs:118`, `admin/legacy.rs:69` —
and `UPDATE users` (`adapter-cloudflare/.../users.rs:152`) **does not include
`tenant_id`**, so the column can never change after insert.

**That claim is wrong**, and the reason is a distinction I had missed: there
are **two** notions of tenant association, not one.

- `users.tenant_id` — a single column, in practice always `"tenant-default"`.
- `user_tenant_memberships` — the many-to-many table, which **is** written:
  by tenant creation (an owner membership, `tenancy/service.rs:54`) and by
  `api_v1::memberships::add_tenant`.

So multi-tenancy works, through the API and through tenant creation. **Had I
reported the single-tenant claim, it would have been the largest wrong thing I
said this cycle.**

### 6.2 What is true, and is narrower and sharper

**Two tenant-admin capabilities are gated on a premise that is always false.**

`forms/membership_add.rs`'s `verify_user_in_tenant`:

```rust
Ok(Some(u)) if u.tenant_id == tenant_id => Ok(None),
Ok(Some(_)) => Ok(Some(Response::error(
    "target user belongs to a different tenant", 403)?)),
```

and the identical rule on the role-grant path
(`forms/role_assignment_grant.rs:280`, `Scope::User`).

Since every user's `users.tenant_id` is `"tenant-default"`, **a tenant admin of
any created tenant always receives 403** — when adding a member, and when
granting a user-scoped role assignment. Their only working path is to ask an
operator holding `ManageTenancy` to call the API.

**These are two of the routes RFC 145 just finished making reachable.** The
form now renders, and its submit cannot succeed for any tenant but the default.

### 6.3 This is one defect, not two

`verify_user_in_tenant` is not wrong. It encodes the intended invariant — *a
member of tenant X is a user who belongs to tenant X* — and **the invitation
flow is what was supposed to establish it**, by creating the invitee in
`inv.tenant_id`. Because §2's completion step was never written, no user ever
belongs to a non-default tenant, so the check never passes.

So §4's direction is also the fix for §6.2, and the cycle must decide
explicitly whether `users.tenant_id` means *home tenant* (and the check
stands) or whether membership alone should authorise (and the check is
replaced by a membership lookup). **Deciding that is in scope; discovering it
mid-implementation is not.**

## 7. Requirement or option for 1.0 — the architect's recommendation

The owner asked. **Requirement — but a bounded one.**

**Why requirement.** Not because invitations are a valuable feature, which is
not an argument about 1.0. Because **the fix changes the shape of the user
record.** A user must become creatable in a tenant other than the default,
which changes what `users.tenant_id` means, when it is set, and whether
`verify_user_in_tenant` is the right rule. A 1.0, **if and when the owner
authorizes one**, is this project's compatibility
commitment point (`rfcs/README.md`: the public surface *"may change between
minor versions"* — the implication being that after 1.0 it may not). Deferring
means either breaking that promise later or carrying the current model
permanently.

The second reason is the owner's own standard. The surface already exists and
already claims to work: a tenants table, a tenant-admin console, an invitations
page, 35 admin routes just wired across three releases, per-tenant
subscriptions, and RFC 119's tenant-scoping track built on top. **Shipping 1.0
with that present and its onboarding path non-functional is the clearest case
of "users confused or misunderstanding" this codebase has**, because it is the
product's central abstraction rather than a corner of it.

**And "option" cannot mean "leave it".** The honest version of option is to
*remove* the invitation surface and the two 403-ing forms for 1.0 — which
removes most of the tenant-admin console's reason to exist. That is a larger
and more destructive change than fixing it.

**What makes it bounded.** The requirement is the **model**, not the polish:

| In scope for 1.0 | Deferrable past 1.0 |
|---|---|
| a user can be created in a specific tenant | invitation email templates and branding |
| an accepted invitation grants the tenant membership **and** the role | resend / expiry-extension |
| `accepted_by` holds the real user id | a revoke **UI** (the route should exist) |
| the `users.tenant_id` vs membership question decided and documented | bulk invite, CSV import |
| one working end-to-end path, asserted on database rows | self-service tenant signup |

**One working path, model-correct, asserted on rows.** That is a cycle, not a
programme, and it is what 1.0 needs. Everything in the right-hand column is a
convenience on a foundation that is either right or wrong — and it is the
foundation that cannot be changed cheaply after 1.0.
