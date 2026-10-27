# RFC 153 — An invitation grants nothing

**Status.** **Proposed** — awaiting owner authorization.
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
