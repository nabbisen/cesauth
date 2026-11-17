# RFC 188 — The chain vouches for the payload; the console shows the columns

**Status**: **Accepted** by the owner, 2026-11-17. **Not yet dispatched** —
`0.107.0` is in flight (RFC 111's formatter conformance and RFC 028's CHANGELOG
budget), and this project does not dispatch the next release while a cut is
pending. §6's three open questions are **resolved by that acceptance to the
recommendations each carried**, recorded in §6 itself; all three are still
reversible, because nothing is built.
**Tier**: P1 · **Size**: Small (Phase 1), Medium (Phase 2)
**Severity of the finding it closes**: Medium — `docs/src/expert/security-review-2026-q4.md` **F-7**
**Found**: 2026-11-13, by the test RFC 187's handoff required as proof of the
*opposite* claim. The handoff predicted a column-only tamper would fail
verification and called that *"the proof D1 bought"*; the test written to
demonstrate it measured `valid: true` and was reported as refuting its own
instruction rather than rewritten to pass
(`crates/adapter-test/src/audit_chain/tests.rs:560-598`).
**Refs**: ADR-010 (audit hash chain) · `migrations/0008_audit_chain.sql` ·
`crates/core/src/audit/verifier.rs:380-446` · RFC 184 (the alarm's
acknowledgement discipline, whose field-addition pattern this follows) ·
RFC 187 (the `actor` column and its payload twin)

---

## 1. The finding

`verify_chain` checks exactly three things per row
(`verifier.rs:408-432`):

1. `payload_hash` against the stored `payload` bytes,
2. `previous_hash` against the predecessor's `chain_hash`,
3. `chain_hash` against `compute_chain_hash(previous_hash, payload_hash,
   seq, ts, kind, id)`.

**None of the three reads an indexed column.** `audit_events` carries eight
columns that duplicate payload fields — `subject`, `actor`, `client_id`,
`ip`, `user_agent`, `reason`, `request_id` — and `0008_audit_chain.sql`
says plainly why: *"the indexed columns let admin search and per-user audit
views run as normal D1 SELECTs, while the `payload` blob is the canonical
record that participates in the hash chain."*

So an in-place `UPDATE audit_events SET actor = 'admin-2' WHERE seq = 2`,
touching neither `payload` nor `payload_hash` nor `chain_hash`, leaves
verification reporting **`valid: true`** — and changes what every reader
sees.

**The readers are the part that matters.** All three render the columns,
not the payload:

| surface | reads | source |
|---|---|---|
| audit viewer (`/admin/console/audit`) | `subject`, `actor`, `kind`, `reason` | the indexed columns, via `AuditQuery` |
| admin search filters | `subject_contains`, `actor_exact` | the indexed columns |
| **audit export** (CSV and JSON, `audit_export.rs:102-140`) | `subject`, `client`, `reason`, `actor` | the indexed columns |

And the chain-status screen (`/admin/console/audit/chain`) reports
**"✓ Chain valid"** beside them. The two statements are about different
data: the chain vouches for a blob no reader displays, while every reader
displays values nothing verifies. An operator reading one screen draws a
conclusion about the other.

The export is the sharpest case. A CSV an operator archives as evidence is
built entirely from unverified columns, and the row's own sealed payload —
which would contradict it — is not in the file.

**This predates `actor` by eleven minor versions.** `actor` is simply the
first column whose payload twin was added deliberately (RFC 187 D1:
*"the column is an INDEX; the payload is the EVIDENCE"*), which is what
makes the check below expressible — and what makes its absence visible.

## 2. Why this is cheap to close, which is the argument for closing it now

The data needed to detect the tamper is **already in the row the verifier
already fetched**:

- **The payload carries a twin of every indexed column.**
  `backend::audit::Event` has `subject`, `actor`, `client_id`, `ip`,
  `user_agent`, `reason`, `request_id`, and it is `Serialize`d whole into
  `payload`. No field is dropped: the struct declares no
  `skip_serializing_if`, so `None` is written as `null` rather than
  omitted.
- **The writer populates the columns from those same fields, unmodified.**
  `write_inner` (`backend/src/audit.rs:713-727`) builds `NewAuditEvent`
  from `ev.subject`, `ev.actor`, … — no truncation, no case folding, no
  trimming — and the D1 adapter binds each one-to-one
  (`adapter-cloudflare/src/ports/audit.rs:164-185`,
  `Option<&str>` → value or `JsValue::NULL`).
- **`AuditEventRow` already carries both halves**
  (`core/src/ports/audit.rs`), and `fetch_after_seq` already selects all
  of them (`AUDIT_COLUMNS`, `audit.rs:118-119`).

So the invariant *"each indexed column equals its payload field"* holds by
construction for every row this system has ever written, and the verifier
holds both sides in hand and does not compare them.

**What this costs: one JSON parse per row walked**, inside a walk that is
already incremental and paged at `PAGE_SIZE = 200`. **No migration. No new
hash input. No re-chaining. No wire or schema change.**

## 3. Proposed shape

### Phase 1 — the verifier compares, and the console says so separately

**D1. Cross-check the seven columns against the payload's own fields,
per row, inside the existing walk.** `subject`, `actor`, `client_id`,
`ip`, `user_agent`, `reason`, `request_id`.

**D2. A column divergence does not break the walk; it accumulates.** The
chain is intact — the payload is still sealed and still authoritative —
and the two findings have different remedies: a chain break means rows
were rewritten and everything after it is suspect; a column divergence
means one row's *index* disagrees with its *evidence*. Stopping at the
first divergence would also mask a later chain break, which is the more
serious of the two. `AuditVerificationResult` gains:

```rust
/// RFC 188. Rows whose indexed columns disagree with their own
/// payload. `valid` above is unaffected: the chain is intact and the
/// payload is still authoritative. #[serde(default)] so a blob
/// written before this field existed reads as "none found", which is
/// correct — an older run did not look.
#[serde(default)]
pub column_divergences: Vec<ColumnDivergence>,   // {seq, column}
#[serde(default)]
pub column_divergence_count: u64,                // total, if the vec is capped
```

following RFC 184's precedent for adding a field to the KV-persisted blob
— with the opposite default, and for the same reason it gave: an absent
field must never read as a stronger claim than the run actually made.
RFC 184's `acknowledged` defaults to `false` because absent must not mean
*"already dealt with"*; this defaults to empty because absent must not
mean *"checked and clean"*. **The status surface must therefore
distinguish "no divergences found" from "this run did not look"**, which
is why `last_run_at` alone is not enough and the console needs its own
line (D7).

**D3. `created_at` is not cross-checkable, and that is declared, not
overlooked.** It has no payload twin by design —
`0008_audit_chain.sql` keeps it separate from `ts` *"to preserve the
distinction if `ts` ever comes from outside the writer"*. `seq`, `id`,
`ts` and `kind` need no cross-check: they are already inputs to
`compute_chain_hash`. So the covered set is exactly seven columns, the
uncovered set is exactly one, and the RFC says which.

**D4. The payload shape the verifier reads is a declared struct in
`cesauth-core`, and a test pins it against the real `Event`.**
`backend::audit::Event` is `Serialize`-only and lives in a crate
`cesauth-core` must not depend on, so the verifier needs its own
`#[derive(Deserialize)]` mirror. Two shapes that must agree and cannot
see each other is exactly the drift this project has already shipped once
(a dead match arm under a green suite). **The pin test lives in
`cesauth-backend`, where both types are visible**: serialize a fully
populated real `Event`, deserialize into the core-side struct, assert all
seven fields survive with their values. A field added to `Event` without
being added to the mirror must fail that test.

**D5. A missing key and a `NULL` column agree.** Rows written before
`0015_audit_request_id.sql` and `0021_audit_actor.sql` have payloads
serialized without those keys, and columns that are `NULL`. Both read as
`None`; that is agreement, not divergence. **This is not an attack
surface**: removing a key from a stored payload changes its bytes, so
`payload_hash` fails first, at check 1, before the column comparison is
reached.

**D6. The genesis row is exempt by shape.** `seq = 1` has `payload = '{}'`
and all-`NULL` columns, and the walk already treats it as a sentinel.

### Phase 2 — the readers read the evidence

**D7. The console gets a line of its own, in both locales.** Not folded
into *"✓ Chain valid"*: the whole finding is that one claim was read as
covering the other. The chain-status screen already negotiates
(RFC 185 §5.3 screen 2), so this is new `MessageKey`s in `Ja` and `En`,
and the wording must distinguish three states — *not looked at*, *looked
and clean*, *N rows diverge* — because D2's default makes the first state
real.

**D8. The viewer, the admin search results and the export render from the
payload; the columns remain indexes.** This removes the gap at its root
rather than reporting on it: what an operator reads, and what a CSV
archives, becomes the sealed record. Filters keep using the indexed
columns, because that is what they are for.

**The residual, named**: a tampered column can still **hide** a row from
a filter — `subject_contains` will not match a value that was overwritten
— which is availability, not integrity, and is precisely what Phase 1's
count exists to surface. A reader who filters and sees nothing is not
told anything; a reader who looks at the chain-status screen is.

**D9. For an untampered row, Phase 2 changes no output.** Column and
payload are equal by construction (§2), so the only observable difference
is on a row that has been edited — which is the point. The export's
field *order* and names stay exactly as RFC 187 D4 fixed them; this
changes where the values come from, not the surface contract.

## 4. What this is not

- **Not a change to ADR-010's hash inputs.** Adding the columns to
  `compute_chain_hash` would invalidate every `chain_hash` ever written
  and require re-chaining the table — the one operation a tamper-evidence
  design must never need, because an attacker who can trigger a legitimate
  re-chain can launder a rewrite. The columns are checked **against the
  payload**, which is already sealed.
- **Not a claim that the chain prevents tampering.** It detects. The
  0.103.0 cut already corrected that claim in three documents; this RFC
  keeps the same discipline and adds detection to one more field class.
- **Not a backfill, and not a repair tool.** What a divergence means for
  a row — index wrong, or evidence wrong — is an operator's judgement, and
  RFC 184's alarm discipline already covers how a finding is held open.
  Automatic "fix the column from the payload" would destroy the only
  evidence that something edited it.
- **Not F-5 or F-6.** Both remain rowed, both are Low, and both are about
  signals with no reader rather than data with no check.
- **Not a new cron, route or permission.** The check rides the existing
  `audit_chain_verify` run and the existing status route.

## 5. Risks

- **A false positive on legitimate history is the main risk**, and D5 is
  the mitigation. The test corpus must include a pre-`0021` row (payload
  without `actor`, column `NULL`) and a pre-`0015` row (no `request_id`),
  and assert a clean result. `tamper_set_actor` already exists on the
  in-memory repository, so the double supports this shape of test today;
  the other six columns need the same helper.
- **The walk gets a JSON parse per row.** Bounded by `PAGE_SIZE = 200`
  per page and by the incremental checkpoint, but it should be measured
  rather than assumed, and a malformed payload must be reported as a
  divergence rather than panicking or aborting the walk.
- **Phase 2 touches an export an operator may already have parsers for.**
  D9 argues the output is identical for untampered rows; the
  implementation must demonstrate that rather than assert it — a
  byte-identical export over a clean corpus, before and after.
- **The verifier is in `cesauth-core` and must stay adapter-agnostic.**
  The mirror struct and the parse belong in core; nothing here may reach
  for D1 or KV types.

## 6. Open questions — resolved by the owner's acceptance, 2026-11-17

**The acceptance carried no separate answers, so each question is resolved
to the recommendation it already stated.** They are written out below as
decisions rather than left as questions, so a disagreement is visible
against a position rather than an absence — and nothing here is built, so
each remains reversible at the scoping of the cut that implements it.

- **Resolved (1): Phase 1 ships alone, first.**
- **Resolved (2): count in Phase 1; mark a divergent row in the viewer only
  if Phase 2 lands.**
- **Resolved (3): a divergence needs acknowledgement, on RFC 184's slot
  discipline.**

The reasoning for each is below, unchanged from the proposal.

1. **Phases together or apart?** Phase 1 is a small cut (one walk, two
   result fields, a console line, a gate). Phase 2 changes what three
   reader surfaces source their values from. My recommendation: **Phase 1
   alone first**, so the detection exists before the display changes —
   if Phase 2 shipped first, a divergence would become invisible rather
   than merely unreported.
2. **Should a divergent row be marked in the viewer itself**, or only
   counted on the chain-status screen? Marking is more honest and costs a
   per-row payload comparison in the query path; counting is cheap and
   keeps the integrity story on the screen that already tells it. My
   recommendation: **count in Phase 1, mark only if Phase 2 lands**, since
   after Phase 2 the viewer is reading the payload anyway and the mark is
   nearly free.
3. **Does a divergence need acknowledgement, like RFC 184's alarm?** My
   recommendation: **yes, the same slot discipline** — a finding that
   clears itself on the next run is a finding nobody had to answer for.

## 7. Acceptance — granted 2026-11-17

The owner accepted §3's nine decisions and the phase split, which is the
**shape**, not the schedule. The release this lands in and the slice
boundaries stay the architect's to scope and the owner's to authorize, and
nothing in §3 is built — so **F-7 stays open in
`docs/src/expert/security-review-2026-q4.md` until the code exists**, with
its disposition naming this RFC rather than claiming a fix.

**Scheduling note.** `0.107.0` is in flight, so this is queued for the
`0.108.0` scoping, where Phase 1's slice boundaries get drawn: the walk's
comparison, the two result fields, the console's three-state line with its
`Ja`/`En` keys, the cross-crate pin test, the pre-`0015`/pre-`0021` corpus
fixtures, and the gate. The acknowledgement half (§6's third resolution)
rides Phase 1, because a finding that clears itself on the next run is a
finding nobody had to answer for.
