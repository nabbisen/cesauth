# Developer Handoff — RFC 187, the audit log's actor column

**Governing RFC.** `rfcs/accepted/187-the-audit-log-cannot-say-who-did-it.md` — §6
records the two items the owner's acceptance resolved (export column **appended**;
sequenced after screen 2, which has now shipped as `0.102.0`).
**Target release.** **Minor.** New D1 column, new `core::ports` field, a new
query filter, and a changed export format.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing.

---

## 1. Purpose

After this lands, *"which admin deleted this user?"* is answerable from the audit
UI. Today it is not: the log's only principal column holds **who the event
concerns**, and where that differs from who acted, the actor survives only in
free text inside `reason`.

## 2. The RFC's biggest risk is resolved. Read this before planning.

RFC 187 §5 said the hash-chain interaction *"could sink this"* and that proving
or refuting it was the first task. **I have resolved it, and you must re-verify
rather than inherit it** — but you are not starting from an unknown.

What I measured:

- **`compute_chain_hash(previous_hash, payload_hash, seq, ts, kind, id)`**
  (`crates/core/src/audit/chain.rs:87`). It does **not** take `subject`,
  `client_id`, `reason`, `ip` or `user_agent`. Adding a column changes nothing
  it reads.
- **`payload_hash` is SHA-256 of the row's serialized `Event`** —
  `payload_bytes = serde_json::to_vec(ev)` at `crates/backend/src/audit.rs:606`,
  and `Event` carries `subject`. So the per-field columns are *copies*; the
  payload is the evidence.
- **Verification rehashes the stored bytes, not a re-serialized struct**:
  `verify_payload_hash(&row.payload_hash, row.payload.as_bytes())`
  (`verifier.rs:409`). **This is the fact that makes the change safe** — old rows
  are checked against their own stored payload, so a new field on `Event` cannot
  invalidate them.
- **The schema's author designed for exactly this.**
  `migrations/0008_audit_chain.sql:34-40`: *"Per-field columns … duplicate
  top-level fields from the JSON `payload`. The duplication is deliberate: the
  indexed columns let admin search … run as normal D1 SELECTs, while the
  `payload` blob is the canonical record that participates in the hash chain. A
  future schema change adding a new field can update the `payload` JSON shape
  without altering the indexed [columns]."*

**So: no chain break, and the actor becomes tamper-evident for free — provided
you put it in the payload.** Which is the next section, and it is the one thing
in this cut that is easy to get wrong in a way nothing would catch.

## 3. Resolved decisions — do not re-open

**D1. `actor` goes in BOTH the `Event` struct and the D1 column, and the payload
is the non-negotiable half.** The column is an *index*; the payload is the
*evidence*. Add the column alone and `actor` becomes **the one audit field an
attacker can edit without detection** — every other displayed field is covered
by `payload_hash`, and this project spent `0.98.0` on the chain's integrity. **No
gate would catch that omission**, which is why it is stated here as a decision
rather than left to fall out of the work.

**D2. No backfill, ever.** A row cannot gain an actor that was never recorded,
and inventing one would be fabricating audit evidence. `actor IS NULL` means
**unknown** for rows below the migration point and **"no principal acted"** for
rows above it. The two are distinguished by `seq` relative to the migration, and
the port documentation must say so **in those words**. **No sentinel value** — a
sentinel is a value that looks like data.

**D3. `write_owned` gets a sibling, not a sixth positional argument.** It is
called **125** times. Changing its signature edits all 125 sites to express a
value that is already correct at most of them. Instead: `write_owned` keeps its
signature and sets `actor = subject`, and a new explicit entry point serves the
sites where they differ.

**The trap in that default, stated because it is real**: for a cron-emitted event
the default is *wrong* — `AnonymousExpired` would claim the expired user expired
themselves. So the sites needing explicit treatment are **both** "actor is a
different principal" **and** "no principal acted". §5's G1 is where you tell me
which sites those are.

**D4. Export appends.** `seq,timestamp,kind,subject,client,reason,actor` —
owner-resolved (RFC 187 §6.1). Appending rather than reordering, because this
project has no published consumers but does have a downloaded-file format, and a
positional change breaks a spreadsheet silently. **Disclose it as a
surface-contract change in the report even though it is correct.**

**D5. `subject` keeps its name and its meaning.** Not a rename. `0.102.0`
already corrected the *label* to "Subject"; this adds a capability beside it.

## 4. Facts already measured — do not re-derive

**If any fails to reproduce, that is a finding — report it.**

- **125** `audit::write_owned` call sites.
- **Migrations are `0001`–`0020`, 20 files**, so yours is **`0021_`**. The
  `migration_chain` test count is **35** and will move; report the new figure.
- **Indexes on `audit_events`**: `ts`, `(kind, ts)`, `subject`. An `actor` index
  is the obvious parallel to `subject`'s — justify it on the same grounds or say
  why not.
- **The export header** is built at
  `crates/core/src/admin/service/audit_export.rs:95` and asserted at `:182`.
- **`subject_contains` reaches D1** via
  `crates/adapter-cloudflare/src/admin/audit_query.rs:82` — `actor_contains`
  follows that path.
- **Baseline gates at `0.102.0` (`5fa0ce0`)**: host **1,706 / 0 / 4** across
  **12** `test result:` lines, by **this exact command** —

```sh
cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend \
           -p cesauth-backend -p cesauth-adapter-cloudflare \
           --features cesauth-frontend/csr
```

  `route-contracts-check.sh` exit 0, **197 routes**, E3 47 · GATE_42 24 ·
  NONCE 13 · E4 219 · E5 19 · E6 95 · E7 156. `drift-scan.sh` clean, **103
  scanned, 66 hit, 69 entries**. `cargo check` warnings **8** frontend, **1**
  core. Bundle **901,768 B** absolute; **report the code delta with the version
  pinned** as well as the absolute figure, per `0.101.0`'s finding.

## 5. Report-and-stop gates

**G1 — the call-site classification, before you change any of them.** Enumerate
**all 125** sites and report each as one of:

- **(a) actor == subject** — the default covers it, no edit.
- **(b) actor is a different principal** — explicit; name who, and where the id
  comes from.
- **(c) no principal acted** — explicit `None`; cron and system paths.

**My own sampling is not a substitute and must not be inherited.** I classified
the *top twelve* argument shapes, covering ~110 of the 125, and found ~19 in
groups (b)/(c) plus singletons I did not enumerate. **So the real number is
unknown to me**; produce it. Report the list as a redirected file, with the
aggregate per class in the report body.

**Known members of (c)**, to check rather than trust: `sweep.rs:99`
`AnonymousExpired`. **Known members of (b)**: `routes/deletions.rs:449`
`DeletionExecuted` and `:378` `DeletionCancelled` — the acting admin is
`ctx_ta.principal.id`, passed to `execute_deletion`/`cancel_deletion` on the
line above, and currently recorded only in `reason`.

**G2 — the chain, re-verified independently.** §2 is my proof; confirm it is
still true on your tree, by the gates rather than by reading: write an event
with an `actor`, run the verifier over a chain containing both pre- and
post-migration rows, and show `valid=true`. **If the chain breaks, stop and
report** — that refutes the RFC's design and is worth more than an
implementation.

## 6. Change scope

| # | Task | Files |
|---|---|---|
| **T1** | G1, then stop | — |
| **T2** | Migration `0021_`: `actor TEXT` + index | `migrations/0021_*.sql` |
| **T3** | `AuditEventRow.actor`, `AuditEventNew`/`Event.actor`, so it rides in the payload (**D1**) | `crates/core/src/ports/audit.rs`, `crates/backend/src/audit.rs` |
| **T4** | `write_owned` defaults `actor = subject`; add the explicit sibling; convert G1's (b) and (c) sites only | `crates/backend/src/audit.rs` + G1's list |
| **T5** | `AuditQuery::actor_contains` through the adapter to D1 | `crates/core/src/admin/types.rs`, `crates/adapter-cloudflare/src/admin/audit_query.rs` |
| **T6** | The viewer's actor filter and column, both locales — new `MessageKey`s, so **G1-style copy review applies**: report the strings before writing them | `crates/frontend/src/pages/operator/audit.rs`, `crates/core/src/i18n/mod.rs` + `lookup_completeness.rs` |
| **T7** | Export: append `actor` (**D4**) | `crates/core/src/admin/service/audit_export.rs` |
| **T8** | The three `reason` strings stop carrying the actor — **only after T4 populates the column** (RFC 187 §3.4); until then the prose is the only record | `routes/deletions.rs` |

T2→T3→T4 before T5–T7. **T8 last**, and it is the only destructive step.

## 7. Explicit non-change scope

- **No rename of `subject`** (D5), no change to the `actor` query parameter on
  the audit viewer's form — that is still its own sequenced item.
- **No backfill, no sentinel** (D2).
- **No change to `compute_chain_hash` or `compute_payload_hash`.** If you think
  one is needed, stop — that is G2 failing.
- **No RFC 185 work.** Screens 3–5 are separate; do not convert literals here
  beyond T6's own new keys.
- **Do not touch the audit-kind documentation** in `route-contracts.md` — 15 of
  42 rows are wrong there and it is its own row.
- Standing rules: no `cargo fmt`, no route-string changes, no `#[allow]`.

## 8. Task detail worth stating explicitly

**T3 — the silent-failure risk is the whole of D1.** A column populated but
absent from the payload compiles, stores, displays and filters correctly, and
is the only unprotected field in a tamper-evident log. Assert it mechanically
(§9) and say in the report that you did.

**T4 — the default is a decision encoded in code, so document it where it is
read.** `write_owned`'s doc comment must say *actor defaults to subject, which is
correct only where the acting principal is the subject* and point at the explicit
sibling. A future call site will copy whichever is nearest.

**T8 — `DeletionExecuted`'s detail also carries `scrub:{outcome}`.** Remove only
the actor clause; the scrub outcome is RFC 148's and stays.

## 9. Assert machine-checkable things mechanically

```sh
# 1. actor is in the hashed payload, not just the column (D1).
#    Expect: the Event struct field, and a serialized "actor" in a payload test.
grep -n "actor" crates/backend/src/audit.rs | head
# 2. The chain functions are untouched. Expect: no diff.
git diff crates/core/src/audit/chain.rs
# 3. No backfill in the migration. Expect: no UPDATE/INSERT over existing rows.
grep -niE "update|insert" migrations/0021_*.sql
# 4. The export header appends rather than reorders.
grep -n "seq,timestamp,kind,subject,client,reason" crates/core/src/admin/service/audit_export.rs
# 5. Non-test code changed only where §6 says — hunk headers, not filenames.
git diff -U0 | grep '^@@'
```

## 10. Required tests and evidence

The §4 command and the rest of the standard set, each redirected to
`evidence/` — **quoted literally, and an evidence log must contain the values
the report asserts from it.**

Expected: host tests **up** (migration-chain test, new query test, T6's keys,
the actor round-trip); `migration_chain` **35 → report the new figure**;
route surface **197, 0 added, 0 removed**; `drift-scan.sh` exit 0.

**Required pairs**: (i) a chain containing pre- and post-migration rows verifies
`valid=true` (G2); (ii) a row whose `actor` column is edited in the database but
whose payload is not **fails** verification — that is the proof D1 bought, and
it is the single most valuable test in this cut.

## 11. What must NOT be claimed

- **Not that historical events now have an actor.** They have `NULL`, meaning
  unknown, and the report must use that word.
- **Not that the audit log is now complete.** It answers *who acted* for events
  written after the migration.
- **Not that `reason`'s prose was redundant** — it was the only record until T4.

## 12. Prohibited shortcuts

No column without the payload field (D1). No backfill. No sentinel. No widening
`write_owned`'s positional signature to avoid G1's classification. No `cargo fmt`.

## 13. Acceptance criteria

RFC 187 §3.1–§3.4, with §6's two owner-resolved items honoured.

**Checked hardest:** (1) §9 assertion 1 and §10's pair (ii) — that `actor` is
genuinely covered by `payload_hash`; (2) G1's classification, because a
mis-defaulted site records the wrong principal in a tamper-evident log; (3) that
`chain.rs` is untouched.

## 14. Known risks

- **A mis-defaulted site is worse than a missing column**: it writes a false
  actor into an append-only log, and the chain will faithfully protect the lie.
  G1 exists for that and nothing else.
- **125 sites is wide and mostly mechanical**, which is how the ~34 that are not
  get missed.
- **T8 deletes the only existing record of three events' actors.** Order matters.
- **If the work turns out materially larger than scoped, stop and report.**

## 15. Review request

Write to `.git-exclude/review-request/`. Include: implementation summary ·
changed files · deviations from §6 · **G1's full classification as a redirected
file** · G2's result · T6's key list with both locales · every log from §10 ·
§9's output · both required pairs · the export format change disclosed as a
surface-contract change · gate results against §4 · bundle both ways ·
what remains unverified (§11) · unresolved issues · requested review focus.

**Report the path only.**
