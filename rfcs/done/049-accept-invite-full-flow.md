# RFC 049 — /accept-invite full implementation

**Status**: Implemented  
**Priority**: P1 (RFC 046 placeholder becomes real)  
**Size**: Large

Wire `CloudflareInvitationRepository` into the accept-invite handlers.
Flow: verify_invitation → if Valid: create/link user → grant role → mark_accepted → emit InvitationAccepted → redirect to magic-link or passkey flow.
