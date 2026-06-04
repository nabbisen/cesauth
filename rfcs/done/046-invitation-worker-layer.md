# RFC 046 — Invitation token worker layer

**Status**: Implemented  
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
