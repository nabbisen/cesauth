# cesauth security review: 2026-Q4

**Reviewer**: internal (architect)
**Date**: 2026-11-14
**Scope**: the audit-log subsystem as changed across `0.97.0`–`0.102.0` —
`crates/core/src/audit/`, `crates/core/src/ports/audit*.rs`,
`crates/backend/src/audit.rs`, `crates/backend/src/routes/admin/console/{audit,audit_chain,audit_export}.rs`,
and `docs/src/expert/route-contracts.md`'s audit-kind column.
**Methodology**: code reading; `grep` census of audit write paths; re-derivation
of figures recorded in the `ROADMAP.md` rows for those releases.

**Why this review exists.** It is the catch-up for the per-release tier added to
[the cadence page](./attack-surface-review-cadence.md) on 2026-11-14. Six of the
nine release intervals `0.93.0`→`0.102.0` would have fired that trigger and none
was recorded — including `0.98.0`, which fixed a privilege escalation on this
very surface. **This is the first file in the `security-review-*` series the
cadence page has specified since v0.52.1.** Rather than backfill six notes, it
covers the whole audit-log surface once.

---

## Starting categories — coverage of this scope

The cadence page's eight categories must each be re-walked. Six are **out of
scope for this surface** and are named rather than silently skipped:

| # | category | this review |
|---|---|---|
| 1 | Open-redirect via `redirect_uri` | out of scope — no redirect handling in the audit surface |
| 2 | JWT alg confusion | out of scope |
| 3 | **Confused deputy in tenant scoping** | **in scope** — F-2, F-3 |
| 4 | Subdomain takeover | out of scope |
| 5 | PKCE enforcement | out of scope |
| 6 | Cookie security attributes | out of scope — unchanged in this range |
| 7 | **Timing side-channels** | **in scope, no finding** — the chain comparison is a hash equality over stored digests, not a secret comparison; no timing property is claimed or needed |
| 8 | Open-registration paths | out of scope |

**A ninth category is proposed for future reviews**, arising from this scope and
absent from the 2026 list: **audit-trail integrity and completeness** — whether
reads of the audit log are themselves recorded, whether the record is sufficient
to reconstruct what was disclosed, and whether the tamper alarm can be erased.
Categories 3 and 7 do not reach it.

## Controls verified present

Recorded because a review that lists only defects cannot be read as evidence
that anything was checked.

- **Reading the audit log is audited.** `routes/admin/console/audit.rs:64`
  writes `EventKind::AdminConsoleViewed` on the viewer page.
- **Exporting the audit log is audited.** `audit_export.rs:126-137` writes
  `EventKind::AuditExported` with format, row count and truncation flag.
- **The tamper alarm is sticky and cannot be cleared by a read.** An
  unacknowledged `valid=false` survives any later verification run, the
  checkpoint does not advance while one stands, and acknowledgement is a
  separate CSRF-protected act gated on `AdminAction::AcknowledgeTamperAlarm`
  (`Security | Operations | Super`, **not** `ReadOnly`). Shipped `0.98.0`.
- **A refused clean walk is itself recorded** — `clean_walk_refused_at` is
  stamped durably on the stored result, with an error-level log line, because
  the nightly cron has no principal to carry an audit write. Shipped `0.98.0`.

## Findings

### F-1: the audit record of an export does not say which rows left

**Severity**: Low
**Surface**: `crates/backend/src/routes/admin/console/audit_export.rs:126-137`
**Status**: **new in this review**

The export's audit detail is
`format={} rows={} truncated={} filter={}`, where `filter` is
`event_exact` or `kind_contains` or `*`. **The date range is absent.** `0.97.0`
added `since`/`until` to the export form — the operator-visible fix for an
export that had been silently dropping the range — and the audit detail was not
extended with it.

So for an export of a specific window the record states how many rows left and
in what format, and **not which rows**. For the question an incident asks —
*what was disclosed?* — row count plus `filter=*` is weak evidence.

**Disposition**: open. One-line change to the `format!`; no schema or port
change. Natural companion to RFC 187, which is already amending this subsystem's
records.

### F-2: a `ReadOnly` admin could erase the tamper alarm

**Severity**: High · **Disposition: fixed in `0.98.0`**
**Surface**: `crates/core/src/audit/verifier.rs`, `routes/admin/console/audit_chain.rs`

`verify_chain_full` wrote its result unconditionally into the single slot the
console reads, and advanced the checkpoint whenever a fresh walk said `valid`.
`role_allows` returns true on `ViewConsole` for **every** role. So anyone who
could open the console could overwrite a stored `valid=false` — and if the chain
had since been rewritten *consistently*, which is what a wholesale-rewrite
attacker produces, the alarm was replaced with `valid=true` and the recorded
baseline `chain_hash` re-based.

Reproduced before the fix over real HTTP against a freshly-migrated local D1 and
KV, with tokens minted at `role=read_only` and `role=security`, the tamper
applied directly to the database below the application layer, and the real
`__scheduled` cron entry point. **Recorded here because it is the trigger for
this review**, and because `0.98.0` shipped without one.

### F-3: the audit log cannot say who performed an action

**Severity**: Medium · **Disposition: accepted as RFC 187, dispatched**
**Surface**: `crates/core/src/ports/audit.rs`, 125 `write_owned` call sites

`subject` is the log's only principal column and `subject_contains` its only
principal filter. Across 125 write sites it carries two meanings: the acting
principal for most kinds, and **the affected user where the actor is a
background job or an admin acting on someone else**. `DeletionExecuted` records
the deleted user while the acting admin's id is passed to `execute_deletion` on
the line above and survives only as free text in `reason`.

**So "which admin deleted this user?" is not answerable from the audit UI** — on
the most destructive operation in the product.

### F-4: the route-contract table's audit-kind column names events the code does not produce

**Severity**: Low (documentation; informational for assurance)
**Surface**: `docs/src/expert/route-contracts.md`
**Status**: known, recorded at `0.98.0`; **15 of 42** kinds named there are
produced nowhere, measured against `EventKind`'s own string mapping.

This is the file every route gate reads, so a wrong cell is a wrong premise for
anyone reasoning about coverage. Nine look like stale renames and six have no
match; exactly one of the six was verified in its handler.

**A re-check during this review produced a different, non-comparable number**
and is **not** offered as a correction: my query matched doc-side backticked
tokens by prefix against two source files, which is cruder than the original
measurement. The recorded figure stands; re-deriving it properly is part of the
row that owns this.

### F-5: a truncated export announces itself to a reader who is not there

**Severity**: Low · **Disposition: open, rowed**
`audit_export.rs` sets `x-cesauth-export-truncated: true` — a **response
header**, which a browser download discards, and the form POST is the only path
a human uses. An operator who receives a short file has no way to learn why.

### F-6: a refused clean walk has no console reader

**Severity**: Low · **Disposition: open, rowed**
`0.98.0` stamps `clean_walk_refused_at` durably and logs it at error level —
the strongest available signal that a wholesale rewrite may have occurred — and
**no console surface displays it.** The operator sees the standing alarm, not
the fact that a later walk came back clean and was refused.

---

## Next review

Per the cadence page: the next **periodic** review is due before `1.0` or by
2027-Q4, whichever is sooner. **Per-release answers resume immediately** and are
recorded in each `CHANGELOG.md` entry; findings from them accumulate into this
file for the remainder of 2026-Q4.
