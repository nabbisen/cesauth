# RFC 047 — Deletion request worker layer

**Status**: Implemented  
**Priority**: P1 (completes RFC 044 end-to-end)  
**Size**: Large (~300 LOC)  
**Depends on**: RFC 044, RFC 045

## Work

1. `CloudflareDeletionRequestRepository` in `adapter-cloudflare/src/ports/repo/deletions.rs`
2. `InMemoryDeletionRequestRepository` in `adapter-test/src/repo/deletions.rs`
3. Worker routes:
   - `POST /me/security/delete-account` — self-service deletion request
   - `GET  /admin/t/:slug/deletion-requests` — admin queue
   - `POST /admin/t/:slug/deletion-requests/:id/cancel`
   - `POST /admin/t/:slug/deletion-requests/:id/execute`
4. Cron sweep in `sweep.rs`: `sweep_pending_deletions`
5. route-contracts.md update
