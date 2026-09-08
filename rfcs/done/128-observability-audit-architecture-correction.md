# RFC 128 — Correct the audit architecture in the observability guide

**Status.** Implemented (v0.81.3)
**Tier.** P1 · Category A (operator-facing; wrong during incident response)
**Size.** Small (one document section, verified against three sources)
**Tracks.** RFC 126 review, Finding A
(`.git-exclude/reviewed/125-c1-and-126-review.md` §5).
**Touches.** `docs/src/deployment/observability.md` only.
**Depends on.** Nothing.
**Target release.** 0.81.2, alongside RFC 130 if it is ready; it is small
enough not to hold that release up.

## 1. Summary

`docs/src/deployment/observability.md` tells operators that audit events are
**R2 objects**, and gives them R2 query patterns. Audit events have lived in
the D1 `audit_events` table with a hash chain since **v0.32.0 / ADR-010** —
roughly 49 versions ago. The document an operator reaches for during an
incident describes a storage architecture that was removed before most of this
project's history.

## 2. Motivation

This is the last documentation item from the RFC 126 sweep that can cause
operational harm rather than confusion. Two of its three "query patterns" are
unactionable:

> R2 doesn't have SQL. Query patterns:
> 1. **Through the admin console** …
> 2. **Direct R2 list + filter** — list objects, fetch matching ones, parse
>    JSON. Slow at scale.
> 3. **Logpush of audit events** — cesauth doesn't push audit events to an
>    external destination today …

Pattern 2 cannot be attempted — there is no audit bucket to list. An operator
who follows it during an incident spends their time discovering that, instead
of querying the audit trail. Pattern 1 is correct but undersold as "read-only;
no SQL flexibility", when the actual surface is a SQL table with three
purpose-built indexes plus an export endpoint.

The RFC 126 sweep deliberately fixed only this file's one stale crate path and
left the architecture prose alone, because rewriting it is content authorship
rather than a rename. That was the right call; this RFC is the follow-up it
named.

## 3. Background — verified three ways

The error is unambiguous. `wrangler.toml`'s own R2 section records:

> As of v0.32.0 (ADR-010) audit events live in the D1 `audit_events` table
> with a hash chain over their rows. The R2 `AUDIT` bucket binding has been
> removed.

`crates/adapter-cloudflare/src/ports.rs:11` says the same. And a sibling file,
`docs/src/deployment/environments.md`, is already correct: *"v0.32.0+ each
environment's `audit_events` chain is independent."* So one document in the
`deployment/` set contradicts both the code and its own neighbours.

What is actually true, from the tree:

- **Storage.** `migrations/0008_audit_chain.sql:42` creates `audit_events`,
  with indexes `idx_audit_events_ts`, `idx_audit_events_kind_ts`, and a
  partial `idx_audit_events_subject`.
- **Reachable surfaces.** Four routes are registered:
  `/admin/console/audit`, `/admin/console/audit/export`,
  `/admin/console/audit/chain`, `/admin/console/audit/chain/verify`
  (plus `/__dev/audit`, local-dev only).
- **Authoritative reference.** `docs/src/expert/audit-log-hash-chain.md`
  already documents the chain correctly, including how to read it.

## 4. Non-goals

- No change to the audit implementation, schema, or routes. Documentation
  only.
- No rewrite of the log-channel or metrics sections beyond the two incidental
  R2 references in §5.
- Not a new operator runbook. This corrects a wrong section; it does not
  expand scope into incident-response procedure.
- Nothing from RFC 129 (`crates/*.rs` doc-comments) or the remaining RFC 126
  follow-ups.

## 5. Proposed design

**D1 — Rewrite "The audit trail" and "Querying the audit trail".**

The event-shape table is also wrong in detail, not just in storage: it lists
`kind`/`subject`/`client_id`/`ip`/`reason`/`ts` and cites
`crates/backend/src/audit.rs`. Replace it with the actual `audit_events`
columns from migration 0008, and describe the real query surfaces:

1. The admin console browser at `/admin/console/audit`, with its filters.
2. The export endpoint `/admin/console/audit/export`, and the fact that an
   export **is itself an audited event**.
3. Chain verification at `/admin/console/audit/chain/verify`, plus the daily
   cron, and what a chain gap means operationally.
4. `wrangler d1 execute` against `audit_events` for cases the console cannot
   express — this is the capability the current text says does not exist.

Point at `docs/src/expert/audit-log-hash-chain.md` as the reference rather
than restating it. Two documents describing the same chain is how this class
of drift starts.

**D2 — Fix the remaining R2 references. Full inventory, corrected.**

This RFC originally named two. There are **seven**, and one of the five I had
not listed is a second operator-facing error. Dispositions, each verified
against `wrangler.toml` (R2 is still bound, as `ASSETS`):

| Line | Text | Disposition |
|---|---|---|
| 5 | audit trail "(per-event records in R2)" | **Wrong.** The chapter summary is false before the reader reaches §The audit trail |
| 99 | `**Storage errors (D1/R2 failures):**` log filter | **Legitimate, but not for the reason I first gave.** Keep it because it mirrors the code's own definition: `crates/backend/src/log.rs:86` documents `Category::Storage` as "Durable Object / D1 / KV / R2 unexpected failures." My original note ("`ASSETS` is a real R2 binding that can fail") is wrong — see the vestigial-binding note below |
| 115 | "Each audit event is one R2 object with:" | **Wrong.** D1's covered by this RFC |
| 128 | "R2 doesn't have SQL. Query patterns:" | **Wrong** |
| 133 | "Direct R2 list + filter" | **Wrong** — unactionable; there is no audit bucket to list |
| 180 | "each D1 query, R2 fetch, KV read counts" as a subrequest | **Legitimate** — subrequest accounting, unrelated to audit |
| 233 | "**R2 object count.** R2's pricing is per-object-month; the audit log grows inexorably… Lifecycle rules manage cost." | **Wrong, and operator-facing.** It attributes R2 object growth to the audit log and points at R2 lifecycle rules for cost. Audit lives in D1; its growth is managed by the daily `audit_retention_cron` job, configured by the deployment-wide `AUDIT_RETENTION_DAYS` / `AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS` operator env vars (defaults 365 / 30), not by an R2 lifecycle rule |

Line 233 matters as much as the query-patterns section: an operator managing
audit-log cost would go looking for an R2 lifecycle configuration that does not
exist, instead of the retention cron that does.

**The `ASSETS` R2 binding is vestigial — do not build a justification on it.**
Amended 2026-09-08, after the C1-128 review. `wrangler.toml:82-84` declares
the binding, but nothing in `crates/backend/src` or
`crates/adapter-cloudflare/src` makes a single R2 API call:
`crates/adapter-cloudflare/src/admin/metrics.rs:142-152` returns
`ServiceId::R2 => Vec::new()` with the comment "cesauth no longer uses R2."
The frontend bundle is served by **Workers Static Assets**
(`wrangler.toml:147-148`, `[assets] directory = "crates/frontend/dist"`), a
different product that shares the word. The R2 references kept at lines 99 and
180 survive on their own merits — the `log.rs` category definition, and
platform-generic subrequest accounting — not on anything cesauth does with R2.

**D3 — Add a drift rule.** The reason this survived 49 versions is that
nothing checked for it. `scripts/drift-scan.sh` already carries
`"all land in R2"` and `"R2_AUDIT"` patterns from RFC 012 — neither matches
the wording here. Add a pattern that would have caught it, scoped to avoid
the legitimate `ASSETS` references and the historical explanations in ADRs and
`docs/changelog-archive/` (RFC 126's D3 exclusion mechanism makes this
expressible).

D3 is the part that stops a recurrence; D1 and D2 are the one-time fix.

## 6. Data model / API impact

None.

## 7. Testing strategy

1. `mdbook build docs` — clean, no broken intra-book links.
2. Every route named in the rewritten section resolves against
   `crates/backend/src/lib.rs`. Assert it mechanically rather than by eye —
   extract the paths from the doc and grep each against the route table.
3. Every column named resolves against `migrations/0008_audit_chain.sql`.
4. **D3 fires:** plant the old wording, observe drift-scan red; remove,
   observe green. Capture both.
5. Full gate set — no regression.

## 8. Migration / rollout

Single documentation change. No consumer action. Order: D1 → D2 → D3, with D3
last so it lands green.

## 9. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| The rewrite introduces a *new* inaccuracy | Same class of harm, newer | §7.2 and §7.3 assert routes and columns against the source, not against prose |
| D2 removes a legitimate R2 reference | A real log filter stops working | §5 D2 requires checking `wrangler.toml`; `ASSETS` is still bound |
| D3's pattern fires on ADRs or archived changelogs | Gate red on historical records | Use RFC 126 D3's exclude field, as its four crate-name rules already do |
| Duplicating `audit-log-hash-chain.md` | Two documents drifting apart | §5 D1 requires pointing at it, not restating it |

## 10. Acceptance criteria

1. No text in `observability.md` describes audit events as R2 objects or
   suggests R2 query patterns for them.
2. The event-shape table matches `migrations/0008_audit_chain.sql`.
3. Every route named resolves in `crates/backend/src/lib.rs`, asserted
   mechanically.
4. The chapter summary (line 5) is corrected.
5. All seven R2 references are dispositioned per §5 D2's table, and for each
   one kept, the justification is stated in the review request.
6. Line 233 names `audit_retention_cron` and its two operator env vars
   (`AUDIT_RETENTION_DAYS` / `AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS`) as what
   governs audit-log growth — not R2 lifecycle rules. *Amended 2026-09-08: this
   criterion previously said "the plan-level retention policy," which describes
   a mechanism that does not exist — `RetentionConfig`
   (`crates/core/src/audit/retention.rs:137-152`) carries only `global_days`
   and `token_introspected_days`, read deployment-wide, with no tenant or plan
   reference anywhere in the retention path.*
7. A drift rule exists that fires on the old wording, with a captured
   fires/does-not-fire pair.
8. `mdbook build docs` clean; full gate set green.

## 11. Open questions

1. Should `docs/src/deployment/observability.md` keep an audit section at all,
   or link out to `docs/src/expert/audit-log-hash-chain.md` and keep only the
   operator-facing query surfaces? My leaning is the latter — one owner per
   subject is what stops this recurring — but it is a documentation-structure
   call, and the deployment chapter arguably needs enough inline detail to be
   usable during an incident without a second click.
2. Is there other content in `docs/src/deployment/` predating v0.32.0 that no
   sweep has examined? This file was found incidentally, while fixing a single
   crate path. That is not a search strategy, and a 49-version-old error
   surviving in an operator guide suggests the deployment set has never been
   audited against the code as a whole.
