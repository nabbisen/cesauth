# RFC 045 — Audit EventKind additions for RFC 043/044

> **2026-10-27 — one kind this RFC family introduced is never emitted.**
> Determined while assigning this RFC's evidence term under RFC 000 §22.
> `InvitationRevoked` has no emitter because `revoke_invitation` has no caller
> ([RFC 153](./153-an-invitation-grants-nothing.md)). A wider sweep
> found **10 of 71 `EventKind` variants with no reference outside the enum**;
> most are redundant with differently-named kinds that *are* emitted, but
> `MfaVerified` has nothing behind it and the whole `me/totp/` tree emits no
> event at all — **[RFC 154](./154-the-second-factor-is-never-audited.md)**.
> The missing gate direction is recorded in
> [RFC 123](../proposed/123-audit-event-completeness.md) §1.1.
>
> This RFC's own deliverable — the kinds for RFC 043/044 — exists. Its evidence
> term is **`reviewed`**: the variants are present and the deletion ones are
> emitted and asserted, but nothing fails if a kind loses its emitter.

**Status**: Implemented  
**Evidence**: **`reviewed`** (RFC 000 §22, back-filled 2026-10-28) — the variants exist and the deletion kinds are emitted and asserted, but **nothing fails if a kind loses its emitter**, which is how 10 of 71 came to have none. See the annotation above, **RFC 154** and **RFC 123 §1.1**.
**Priority**: P1 — prerequisite for RFC 046/047  
**Size**: Small (~30 LOC enum + as_str)

## New EventKind variants

- `InvitationIssued` / `InvitationAccepted` / `InvitationRevoked`
- `DeletionRequested` / `DeletionExecuted` / `DeletionCancelled`
