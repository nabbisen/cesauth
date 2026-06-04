# RFC 045 — Audit EventKind additions for RFC 043/044

**Status**: Implemented  
**Priority**: P1 — prerequisite for RFC 046/047  
**Size**: Small (~30 LOC enum + as_str)

## New EventKind variants

- `InvitationIssued` / `InvitationAccepted` / `InvitationRevoked`
- `DeletionRequested` / `DeletionExecuted` / `DeletionCancelled`
