# Developer Handoff — RFC 153, make an invitation grant something

**Governing RFC.** `rfcs/accepted/153-an-invitation-grants-nothing.md` — read it
in full, including **§6**, which is the half that was added after the RFC was
written and which changes the scope.

**Target release.** 0.88.0 — **minor.** An accepted invitation will place a user
in a tenant with a role, which nothing can do today by any path.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-28.**

**This is a feature cycle, not a fix.** It is the largest piece of work in this
programme so far and the first where the design question is bigger than the
defect. **Expect to report back before finishing** — see §2.

**On 1.0:** RFC 153 §7 recommends this belong in a 1.0 *if one is cut*. **1.0 is
not declared, scoped or dated**, and that is the owner's to authorize. Nothing
in this cycle is justified by 1.0; if a choice seems to need that, justify it
another way or report the question.

---

## 1. What is broken

An invitation records an email, a tenant and a role, sends a link, and
**applies none of it**:

- `accept_submit` marks the invitation accepted with the literal string
  `"pending-registration"` as `accepted_by`, **before any account exists**,
  then redirects to `/magic-link/request?…&invite_id=…`.
- **`invite_id` is read nowhere else in the codebase.**
- **`inv.role` is read exactly once**, into an audit message string.
- Registration hardcodes `tenant_id: DEFAULT_TENANT_ID`
  (`magic_link/verify.rs:275`).
- `revoke_invitation` exists, is host-tested, and **has no caller**, so the
  `revoked` state the `0018` migration documents is unreachable.

**And §6: the same missing step blocks two tenant-admin forms.**
`verify_user_in_tenant` (`forms/membership_add.rs`) and the identical rule on
the role-grant path require `u.tenant_id == tenant_id`. Since every user's
`users.tenant_id` is `"tenant-default"`, **a tenant admin always gets 403**
when adding a member or granting a user-scoped role. Those are routes RFC 145
just made reachable: they render, and cannot succeed.

## 2. The design decision this cycle must make — and report before building

**`verify_user_in_tenant` is not wrong.** It encodes the intended invariant —
*a member of tenant X is a user who belongs to tenant X* — and the invitation
flow is what was supposed to establish it.

So the cycle must decide, explicitly:

- **(a)** `users.tenant_id` means *home tenant*, the invitation flow sets it,
  and `verify_user_in_tenant` stands; or
- **(b)** membership alone authorises, and that check is replaced by a
  membership lookup.

**Report your choice and its reasoning before implementing it.** This is the
one place in this cycle where I want to see the decision before the code —
it changes the meaning of a persisted column, and getting it wrong is
expensive to undo. §6.3 sketches both; neither is obviously right.

**Note for (b):** memberships already work. `add_tenant_membership` has three
production callers — `tenant_admin/forms/membership_add.rs`,
`api_v1/memberships.rs`, and tenant creation via `core/tenancy/service.rs`.
Multi-tenancy is not absent; **the invitation flow simply does not use it.**

## 3. The completion step

**Stop consuming the invitation at `accept_submit`.** Verify it, carry the id
forward, leave it pending. **Nothing is accepted until an account exists.**

**Carry `invite_id` through the magic-link flow** — `request` → email →
`verify`. A query parameter is not enough. **A signed, short-lived cookie in
the style of `post_auth`'s pending-handle cookies is the shape this codebase
already uses**; follow it rather than inventing a mechanism.

**On successful registration, in this order:**

1. create the user in **the invitation's tenant**, not the default;
2. `add_tenant_membership` with the invitation's `role`;
3. `accept_invitation` with **the real user id**;
4. the audit event with `subject` = that user.

**That order matters:** a failure before step 3 must leave the invitation
re-usable. A user who abandons the flow today is told *"Already accepted.
Please sign in"* while having no account — locked out of their own invitation
until an admin re-invites. **That outcome must be impossible when you are
done.**

**Wire revoke:** a tenant-admin route calling `revoke_invitation`, and a
`route-contracts.md` row. The invitations page already exists.

## 4. Resolved decisions — do not re-open

- **Minor.** If the scope grows past §3, stop and report rather than promoting.
- **`accepted_by` must hold a real user id** when the flow completes. RFC 148
  §2.1 recorded that it has never held one; that is the column this fixes.
- **Out of scope:** RFC 152 half B and §6, RFC 141 cycle 2, RFC 123, RFC 120,
  RFC 157 (the unrouted `*_json` handlers — **do not delete any as a
  side-effect of this cycle**, even if you touch their modules; that triage is
  its own RFC awaiting authorization).

## 5. Report-and-stop gates

- **§2's decision, before implementing it** — this one is mandatory, not
  conditional;
- the signed-cookie approach does not survive the magic-link round trip for a
  reason the `post_auth` precedent did not face;
- a step in §3's order cannot be made atomic enough to keep the invitation
  re-usable on failure;
- any evidence requirement in §6 you cannot construct. One line beats a silent
  substitution.

## 6. Required evidence

**Assert the database rows.** This is the cycle where that rule earns its
place: RFC 047 answered plausible status codes for 61 releases while doing
nothing, and this flow currently redirects with a `303` while granting nothing.

1. **A live end-to-end run** against `wrangler dev` + local D1: issue an
   invitation, accept it, complete registration, and assert **by querying the
   database** — a `user_tenant_memberships` row in **the invitation's tenant**
   with **the invitation's role**, `users.tenant_id` consistent with §2's
   decision, and `invitation_tokens.accepted_by` equal to the **new user's
   id**. **Not** that a handler returned 303.
2. **The abandonment case**: accept, then do not complete registration, and
   assert the invitation is **still pending and still usable**.
3. **Revoke**: driven through the new route, asserting `revoked_at` and
   `revoked_by` are set — the first time that state has ever been reachable.
4. **Fires/does-not-fire** on the membership grant: remove it, show the
   end-to-end assertion fail, restore byte-identically, show it pass.
5. **The §6 consequence**: a tenant admin adding a member to a non-default
   tenant now succeeds. That is the 403 this unblocks, and it should be
   demonstrated.
6. **Full gate set with counts.** CI's exact host-test command
   (`test.yml:51-55`, five crates, **no `--lib`**), summed programmatically;
   baseline **1,601**. `migration_chain` **35**, routes **192**. A release
   commit runs **13** workflows now, and the manifest check will tell you if
   that changes.
7. **A proposed `**Status**` + `**Evidence**` line** in the back-fill's
   normalised format.

## 7. What must not be claimed

- Not that invitations are "complete" — email templates, resend, bulk invite
  and self-service tenant signup are explicitly deferred (RFC 153 §7's
  right-hand column).
- Not that `users.tenant_id`'s meaning was obvious. Whichever of §2's options
  you choose, say that it was a choice and why.
- No count in prose without its command, no derived total unchecked against its
  parts, and no delta between a local measurement and a CI baseline.

## 8. Review request

Write the package to `.git-exclude/review-request/153-report.md` and give me
the commit. **If you stop at §2's decision point, write that to the same path**
— a report that says only "here is the design choice and why" is a complete
deliverable for this stage.
