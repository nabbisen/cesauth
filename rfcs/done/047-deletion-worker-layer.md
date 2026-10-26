# RFC 047 — Deletion request worker layer

> **2026-10-27 — this RFC's deliverables have never functioned.** Found while
> RFC 147 cycle 1 was being verified. **Line 13's self-service route**
> (`POST /me/security/delete-account`) checks the **admin** bearer resolver, not a
> user session, so a user's own session gets 401 and the route is unreachable by
> the principal it exists for. **Line 17's cron sweep** (`sweep_pending_deletions`)
> is fully written and **called by nothing** — `scheduled()` sends the daily cron to
> `sweep::run`, which sweeps anonymous-trial retention only. **No deletion has ever
> been executed by any path.**
>
> This RFC stays in `done/` because the lifecycle defines `done/` as code shipped,
> not behaviour verified — which is precisely the weakness this case exposes, and is
> recorded as such. **RFC 147 cycle 2 completes the work.** Do not read anything
> below as describing live behaviour until then.

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
