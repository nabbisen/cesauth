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
**Surface**: `crates/backend/src/routes/admin/console/audit_export.rs`
**Status**: **closed, RFC 187 round 2 §4(b)**

The export's audit detail was
`format={} rows={} truncated={} filter={}`, where `filter` was
`event_exact` or `kind_contains` or `*`. **The date range, the subject filter,
and the actor filter were all absent.** `0.97.0` added `since`/`until` to the
export form without extending the audit detail to match; RFC 187 round 2 found
the same gap for `subject`/`actor` while adding the latter.

So for an export of a specific window the record stated how many rows left and
in what format, and **not which rows**. For the question an incident asks —
*what was disclosed?* — row count plus `filter=*` was weak evidence.

**Fix.** `build_filter_desc` (`audit_export.rs`) now names every applied
dimension — `event`, `subject`, `actor`, `from`, `to` — comma-joined, `*` only
when none is set. Pulled out as its own pure function (same reason
`resolve_export_limit` already was one) and host-tested directly
(`build_filter_desc`'s own test block), rather than only exercised indirectly
through the route handler. Closed in the same cut that added the `actor`
filter, rather than adding a third unrecorded dimension to an audited export.

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

**Severity**: Medium · **Disposition: closed at `0.103.0` (RFC 187)**
**Surface**: `crates/core/src/ports/audit.rs`, 127 `write_owned` call sites
(the 125 recorded below was a regex artifact; the real figure, from a parser,
is 127)

`subject` is the log's only principal column and `subject_contains` its only
principal filter. Across 125 write sites it carries two meanings: the acting
principal for most kinds, and **the affected user where the actor is a
background job or an admin acting on someone else**. `DeletionExecuted` records
the deleted user while the acting admin's id is passed to `execute_deletion` on
the line above and survives only as free text in `reason`.

**So "which admin deleted this user?" is not answerable from the audit UI** — on
the most destructive operation in the product.

**Closed** by migration `0021_audit_actor.sql` plus the `actor` field in the
hashed payload, the 11 explicit call sites a stop-gate classification
identified, the 11 further sites where the default would have recorded an
unverified identity, and the operator console's own Actor filter and column —
all in `0.103.0`. The verifier-scope gap the same RFC uncovered is **F-7**.

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

### F-7: chain verification does not cover the indexed columns the console displays

**Severity**: Medium · **Disposition: open — RFC written 2026-11-17,
`rfcs/proposed/188-the-chain-vouches-for-the-payload-the-console-shows-the-columns.md`,
awaiting the owner's acceptance. Nothing is built, so the finding stands as
written below.**
**Surface**: `crates/core/src/audit/verifier.rs:409-431`, `migrations/0008_audit_chain.sql`

`verify_chain` checks three things: `payload_hash` against the stored
`payload` bytes, `chain_hash` against `compute_chain_hash(previous_hash,
payload_hash, seq, ts, kind, id)`, and `previous_hash` against the
predecessor's `chain_hash`. **None of the three reads an indexed column and
compares it against the payload's own copy of that field.** So an in-place
edit to `subject`, `client_id`, `ip`, `user_agent`, `reason` or `actor` —
leaving `payload`, `payload_hash` and `chain_hash` untouched — changes what
the audit viewer and the admin search display while verification still
reports `valid: true`.

The operator-visible consequence is the one that matters: the console renders
those columns, and the chain-status screen reports *"✓ Chain valid"* beside
them. The two statements are about different data.

**Found by the test RFC 187 required as proof of the opposite.** The RFC's
handoff predicted that a column-only tamper would *fail* verification and
called that "the proof D1 bought"; the test written to demonstrate it
measured `valid: true` and was reported as refuting its own instruction
rather than rewritten to pass. The gap predates `actor` by eleven minor
versions and is not introduced by it — `actor` is simply the first column
whose payload copy was added deliberately, which is what makes the check
below possible for it.

**What the RFC proposes, in one line**: the payload already carries a twin of
every indexed column, the writer populates the columns from those same fields
unmodified, and `AuditEventRow` already holds both halves — so the verifier can
compare them inside the existing walk, with **no migration, no new hash input
and no re-chaining**. The seven cross-checkable columns are `subject`, `actor`,
`client_id`, `ip`, `user_agent`, `reason` and `request_id`; `created_at` has no
payload twin by design and is declared uncovered.

**The fix is detection, not prevention.** Access control over the column
would make such an edit harder, not evident afterwards. The check is: compare
each indexed column against the payload's copy of the same field during
verification — and **treat an absent payload key as no claim**, since `actor`
is absent from every pre-`0021` payload and `request_id` from every pre-`0015`
one. That compatibility rule is why this is its own change with its own
review rather than a line added to the verifier here. `docs/src/expert/adr/
010-audit-log-hash-chain.md` now states the scope limitation outright.

---

## Next review

Per the cadence page: the next **periodic** review is due before `1.0` or by
2027-Q4, whichever is sooner. **Per-release answers resume immediately** and are
recorded in each `CHANGELOG.md` entry; findings from them accumulate into this
file for the remainder of 2026-Q4.
