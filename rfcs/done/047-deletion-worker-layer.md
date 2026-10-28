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
> **Resolved 2026-10-27 by RFC 147 cycle 2 (`2099df3`).** Both deliverables now
> work: the self-service route authenticates the **user** and creates a real
> request, and the daily cron executes due requests — proven through
> `/cdn-cgi/local/scheduled`, the actual scheduled handler. **This annotation is
> kept rather than deleted:** the record that this RFC sat in `done/` across **61
> releases** — it entered `done/` at `99fe324`, 2026-06-05, and 61 tags were cut
> between 0.53.0 and 0.86.0 — while neither deliverable functioned is worth more than a
> clean-looking file, and it is the evidence behind the open question of whether
> `done/` should mean *verified* rather than *shipped*.

**Status**: Implemented  
**Evidence**: **`unknown`** (RFC 000 §22, back-filled 2026-10-28) — both deliverables were non-functional for 61 releases; fixed by RFC 147 cycle 2, but **nothing asserted them during that time** and the term records the history, not today's code. The deletion path is now covered by RFC 044's term.
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
