# RFC 187 — The audit log records what happened and, where it matters most, not who did it

**Status**: Proposed, 2026-11-12. **Needs the owner's authorization** — it
changes the D1 schema, a `core::ports` trait and the export format.
**Found**: 2026-11-12, deciding the owner's delegated question about one field
with four names (`.git-exclude/reviewed/three-decisions-2026-11-12.md`,
decision 1). The naming turned out to be the smaller half.

---

## 1. The finding

`AuditEventRow.subject` is the audit log's **only** principal column, and
`AuditQuery::subject_contains` is the **only** principal filter the viewer
offers. Measured across **125** `audit::write_owned` call sites, that one column
carries two different meanings:

- **Who acted** — ~97 sites pass the acting principal (`principal.id`,
  `ctx_ta.principal.id`, `session.user_id`).
- **Who it was done to** — where the actor is a background job or an admin
  acting on someone else.

The second group is small and it is the group that matters:

| kind | site | `subject` holds | the actor is |
|---|---|---|---|
| `AnonymousExpired` | `sweep.rs:99` | the expired user | the **04:00 cron** — there is no human actor |
| `DeletionExecuted` | `routes/deletions.rs:449` | **the deleted user** | the acting admin, **passed to `execute_deletion` on the line above** |
| `DeletionCancelled` | `routes/deletions.rs:378` | the affected user | the acting admin |

**Where the actor differs from the subject, the actor survives only in free
text.** `DeletionExecuted` writes
`"request:{id} admin-triggered by:{admin_id} scrub:{outcome}"` into `reason`.

**So "which admin deleted this user?" cannot be answered from the audit UI.**
The only principal filter searches `subject`, which holds the victim. An
operator would have to substring-search prose the interface does not expose.

`routes/deletions.rs:246` already documents the split — *"user's own id here, vs.
the admin's principal id in `admin_cancel`"* — so this is a known distinction
that was never given a column.

## 2. Why this is the wrong half to have left undone

`0.98.0` was entirely about audit-chain integrity: a `ReadOnly` admin could
erase the tamper alarm, the alarm became sticky, acknowledgement became a
tiered audited act. All of that hardens **that the record is intact**.

This RFC is about **what the record says**. A tamper-evident log of
`DeletionExecuted` events whose actor is unqueryable answers "was this log
altered?" and not "who deleted my account?" — and the second is the question an
incident actually starts from.

It is also the ADR-010 hash chain's purpose read honestly: the chain exists so
the log can be relied on as evidence. Evidence that omits the agent is weaker
evidence.

## 3. Proposed shape

**§3.1 — `actor` becomes its own column**, distinct from `subject`:

- `subject` keeps its meaning exactly — *who this event concerns* — and **no
  existing write changes meaning**. That is deliberate: a migration that
  re-interprets historical rows would make the hash chain's own history
  unreadable, and the chain is append-only by design.
- `actor` is **new and nullable**. `None` means *no principal acted* (cron,
  system) — which is information, not absence of data, and is distinguishable
  from the pre-migration rows only by `seq` being below the migration point.
- The ~97 sites that pass the acting principal set **both** to the same id.
  That is not redundancy: it is the statement *the actor and the subject are the
  same person*, which is exactly what those events mean.

**§3.2 — `AuditQuery` gains `actor_contains`**, and the viewer gains the filter
and the column. This is the half an operator actually needs.

**§3.3 — the export adds an `actor` column.** A caller-visible format change,
and therefore argued rather than assumed: the CSV header becomes
`seq,timestamp,kind,actor,subject,client,reason`. Appending rather than
reordering would be gentler on a naive consumer; placing `actor` before
`subject` reads better for a human. **I propose appending at the end** —
`seq,timestamp,kind,subject,client,reason,actor` — because this project has no
published consumers but does have an existing downloaded-file format, and a
positional change is the kind of thing that breaks a spreadsheet silently.
Owner's call if they prefer the readable order.

**§3.4 — the free-text actor comes out of `reason` once the column exists**, for
the three kinds that put it there. Not before: until the column is populated,
the prose is the only record and deleting it would lose data.

## 4. What this is not

- **Not a rename.** `subject` keeps its name and its meaning. Decision 1's label
  fix (`Actor` → `Subject` on the viewer) is separate, lands first, and is
  correct independently — *"Actor"* asserts agency the column cannot support.
- **Not a backfill.** Historical rows cannot gain an actor that was never
  recorded, and inventing one would be fabricating audit evidence. Rows below
  the migration point read `actor = NULL`, meaning *unknown*, and the
  documentation must say so in those words.
- **Not a chain change.** `payload_hash`/`chain_hash` computation is untouched;
  this adds a column to new rows, which is what an append-only chain supports.
  **An implementer must verify that claim rather than inherit it** — if adding
  the column changes what is hashed, the migration is a chain break and the RFC
  needs redesigning.
- **Not scoped to tenancy.** Every one of the 125 sites is in scope for being
  *read*, but only the ~28 where actor ≠ subject change behaviour.

## 5. Risks

- **The hash-chain interaction is the one that could sink this.** §4 states the
  expectation; the first task is to prove or refute it, and a refutation is a
  more valuable outcome than an implementation.
- **125 call sites is a wide mechanical change** with a narrow behavioural core.
  The temptation is to touch all 125; only the sites where the two differ need
  thought, and the rest take the same id twice.
- **`None` vs `NULL`-because-old is a real ambiguity** and is handled by
  documentation plus the migration `seq`, not by a sentinel value. A sentinel
  would be a value that looks like data.

## 6. Open, and the owner's

1. **CSV column position** (§3.3) — append, or the readable order.
2. **Whether this precedes or follows RFC 185 §5.3's remaining screens.** My
   recommendation: **after screen 2, before screens 3–5.** Screen 2 closes live
   wrong output that is already shipped; this closes a question an incident
   would ask. Screens 3–5 are volume, and volume should yield to both.
