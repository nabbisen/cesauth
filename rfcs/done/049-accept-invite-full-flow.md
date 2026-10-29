# RFC 049 — /accept-invite full implementation

> **2026-10-27 — this RFC's third deliverable does not complete registration.**
> Found by RFC 000 §22's evidence back-fill, which started here because this is
> [RFC 047](./047-deletion-worker-layer.md)'s sibling — same cycle, same shape,
> and RFC 047's two deliverables were both dead.
>
> `POST /accept-invite` marks the invitation accepted with the **literal string**
> `"pending-registration"` as `accepted_by`, before any account exists, then
> redirects to the magic-link flow with `invite_id` in the query string.
> **Nothing reads `invite_id`.** `inv.role` is read once in the whole codebase,
> into an audit message. Registration hardcodes `DEFAULT_TENANT_ID`. So the
> invitee gets **no membership in the inviting tenant and no role** — RFC 043's
> entire definition of an invitation. `revoke_invitation` exists, is
> host-tested, and has no caller, so the `revoked` state is unreachable.
>
> **This RFC's evidence term under RFC 000 §22 is `unknown` at best.** Owned by
> **[RFC 153](./153-an-invitation-grants-nothing.md)**.

> **The title "full implementation" is the part to distrust**: the handler is
> complete as a handler and completes nothing as a flow.

**Status**: Implemented  
**Evidence**: **`unknown`** (RFC 000 §22, back-filled 2026-10-28) — "full implementation" completes no flow. See the annotation above and **RFC 153**.
**Priority**: P1 (RFC 046 placeholder becomes real)  
**Size**: Large

Wire `CloudflareInvitationRepository` into the accept-invite handlers.
Flow: verify_invitation → if Valid: create/link user → grant role → mark_accepted → emit InvitationAccepted → redirect to magic-link or passkey flow.
