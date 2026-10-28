# RFC 046 — Invitation token worker layer

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
> **[RFC 153](../proposed/153-an-invitation-grants-nothing.md)**.

**Status**: Implemented  
**Evidence**: **`unknown`** (RFC 000 §22, back-filled 2026-10-28) — the accept path grants neither the tenant nor the role, and revoke has no caller. See the annotation above and **RFC 153**.
**Priority**: P1 (completes RFC 043 end-to-end)  
**Size**: Large (~300 LOC: D1 adapter + 3 worker routes)  
**Depends on**: RFC 043, RFC 045

## Work

1. `CloudflareInvitationRepository` in `adapter-cloudflare/src/ports/repo/invitations.rs`
2. `InMemoryInvitationRepository` in `adapter-test/src/repo/invitations.rs`
3. Worker routes:
   - `POST /admin/t/:slug/invitations` — admin issues invite, sends via mailer
   - `GET  /accept-invite` — renders accept page (magic link or passkey)
   - `POST /accept-invite` — verify token + complete registration + emit audit
4. route-contracts.md update
