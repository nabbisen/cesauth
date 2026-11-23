# Developer Handoff — RFC 188 Phase 2, the readers read the evidence

**Target**: `0.109.0`, slice A of two · **Level**: minor
**RFC**: `rfcs/accepted/188-the-chain-vouches-for-the-payload-the-console-shows-the-columns.md`
— D8/D9, accepted 2026-11-17; Phase 1 shipped in `0.108.0`
**Closes**: the residual `0.108.0`'s own CHANGELOG and the F-7 disposition
both name — *"a tampered column can still hide a row from a filter"*
**Baseline**: `1876cc9` / tag `0.108.0`

---

## 1. Purpose

Phase 1 made the verifier compare the seven duplicated columns against
the payload and gave the finding a reader. **It changed nothing about
what the readers read.** The audit viewer, the admin search and the
CSV/JSON export still display the indexed columns — the values an
in-place `UPDATE` can change — while the chain-status screen reports
separately that they diverge. Phase 2 moves the display onto the payload,
so what an operator reads is the sealed record.

## 2. The good news: it is one mapper

Measured, not assumed:

- `AuditEventRepository::search` returns **`Vec<AuditEventRow>`**
  (`crates/core/src/ports/audit.rs:146`), and `AuditEventRow` **already
  carries `payload`** — the search path fetches it today. **No query
  change, no extra column, no extra bytes from D1.**
- Exactly one place maps a row to what readers see:
  `crates/adapter-cloudflare/src/admin/audit_query.rs:93`, building
  `AdminAuditEntry` from `r.subject`, `r.actor`, `r.client_id`,
  `r.reason`.
- **Everything downstream consumes `AdminAuditEntry`**: the viewer's
  `GET /admin/console/audit.json` serialises it directly
  (`routes/admin/console/audit.rs:146`), the CSR view deserialises a
  subset with `#[serde(default)]` (`pages/operator/audit.rs:74`), and
  `audit_export.rs` builds both the CSV and the JSON from it.

So the display fix is one mapper, its test double, and a type field —
and all three reader surfaces inherit it. State that in the report rather
than implying three separate fixes.

## 3. Resolved decisions — do not re-open

- **D1 (RFC 188 D8). The four display fields come from the payload.**
  `subject`, `actor`, `client_id` → `client`, `reason` are read from
  `AuditPayloadMirror::parse(&r.payload)`, the same mirror Phase 1 added.
  `ts`, `kind`, `id` and `key` keep coming from the row: they are chain
  inputs, already covered.
- **D2. A payload that will not parse does not fall back to the column.**
  A silent fallback would restore the exact gap Phase 1 closed. Those
  four fields render as the unparseable marker instead, and the row is
  flagged (D3). The chain-status screen already reports
  `payload_unparseable` as its own finding; this is the reader's half of
  the same fact.
- **D3. A row whose column disagrees with its payload is marked**, in the
  viewer and in the export. RFC 188 §6's second question resolved to
  *"count in Phase 1, mark only if Phase 2 lands"* — Phase 2 is landing,
  and the mark is now nearly free because the mapper is already comparing
  to decide what to display.
- **D4. The filters keep using the columns, and this is the residual
  being traded, not removed.** The SQL matches on indexed columns; that
  is what indexes are for. After this slice a tampered column can still
  **hide** a row from a filter — but it can no longer make a *shown* row
  lie. The report must say which half closed and which did not, and the
  viewer's own copy must say it too (§7).
- **D5. The export gains one appended column, not an inserted one.**
  RFC 187 D4 ruled on this exact surface: new CSV/JSON fields go on the
  end. The column says whether that row's indexed columns diverge from
  its payload. **This is a surface-contract change** and must be
  disclosed in the report and the CHANGELOG, like `class` was in
  `0.108.0`.
- **D6. The double must agree with the real adapter.**
  `crates/adapter-test/src/admin/audit_query.rs` has its own mapper. If
  it keeps reading columns while production reads the payload, every test
  passes against a double that behaves differently — this project has
  already shipped a dead match arm under a green suite once.
- **D7. No change to Phase 1's verifier, result fields, acknowledgement
  route, or the chain-status screen.** If you find yourself editing
  `verifier.rs`, stop and report.

## 4. Facts already measured — do not re-derive

- `AdminAuditEntry`'s fields today: `ts`, `id`, `kind`, `subject`,
  `actor`, `client`, `reason`, `key`
  (`crates/core/src/admin/types.rs`).
- The CSR view's own struct takes `ts`, `kind`, `subject`, `actor`,
  `reason`, `key` and already uses `#[serde(default)]`, so **adding a
  field to `AdminAuditEntry` reaches the JSON automatically** and the
  frontend opts in when it wants it.
- The export's header is
  `seq,timestamp,kind,subject,client,reason,actor`
  (`audit_export.rs:102`) — `actor` appended last by RFC 187 D4, which is
  the precedent D5 follows.
- `AuditPayloadMirror` is `pub` in `crates/core/src/audit/payload.rs`
  with `parse()` and seven `#[serde(default)]` `Option<String>` fields;
  `CROSS_CHECKED_COLUMNS` is `pub` in `verifier.rs`.
- The viewer's table renders `subject`, `actor`, `kind`, `reason` plus
  the time column and `seq` (`pages/operator/audit.rs:358-378`), all
  through `lookup` — the screen is converted, and its i18n ceiling row is
  **2**, which must not move.

## 5. Report-and-stop gates

**G1 — the mark's copy, before the view.** The marker needs keys in both
locales: the row-level mark, its `aria-label` or title (a visual-only
mark is not accessible), the unparseable-payload marker for the four
fields, and whatever header the export column gets. Submit the table in
the usual shape, and for each key say **what an operator is supposed to
conclude** — specifically, that a marked row's displayed values are the
sealed ones and that the column it was *filtered* on may differ. That
sentence is the hard one; it is also the point of the slice.

Everything else proceeds without waiting.

## 6. Change scope

| file | change |
|---|---|
| `crates/core/src/admin/types.rs` | T1 — `AdminAuditEntry` gains the divergence flag |
| `crates/adapter-cloudflare/src/admin/audit_query.rs` | T2 — map the four fields from the payload, compare, set the flag |
| `crates/adapter-test/src/admin/audit_query.rs` | T2 — the same, in the double (D6) |
| `crates/core/src/admin/service/audit_export.rs` | T3 — the appended column, CSV and JSON |
| `crates/core/src/i18n/mod.rs`, `i18n/tests/lookup_completeness.rs` | T4 — G1's keys, both lists |
| `crates/frontend/src/pages/operator/audit.rs` | T4 — the mark, and the unparseable marker |
| `docs/src/expert/route-contracts.md` | T5 — the export's documented shape |
| `docs/src/expert/security-review-2026-q4.md` | T5 — F-7's residual paragraph, now narrowed to the filter half |
| `docs/src/expert/adr/010-audit-log-hash-chain.md` | T5 — what the readers read |

## 7. Task detail worth stating explicitly

- **T2's comparison is the mapper's own, not a second implementation.**
  Compare the four column values against the mirror's fields; display the
  mirror's; set the flag if any differ. Do not import the verifier, and
  do not reimplement its seven-way comparison — the three fields the
  viewer does not show (`ip`, `user_agent`, `request_id`) still count
  toward the flag, because the row *is* divergent even when the diverging
  field is not on screen.
- **T3's JSON export** gets the same field as the CSV, appended in the
  object too, so the two stay parallel (`audit_export.rs:133`).
- **T4's copy must not say "tampered".** A divergence is a divergence:
  an index that disagrees with the record. Cause is an operator's
  judgement, and the console saying "tampered" would assert one.
- **The viewer's note must state the filter residual** (D4) where an
  operator reading the table will see it — not only on the chain-status
  screen. One sentence: the values shown are the sealed ones; a filter
  matches on the indexed column, so a row whose column was changed may
  not appear for the value you searched.
- **T5's F-7 paragraph narrows rather than closes.** The disposition
  stays *closed* (Phase 1 closed it); what changes is the residual
  sentence: before, three surfaces displayed unverified values **and** a
  tampered column could hide a row; after, only the hiding remains.
- **Watch the ceiling**: `pages/operator/audit.rs` is pinned at **2**
  (the two wire-format literals). New prose must go through `lookup`, so
  the row stays 2 — if it moves, something went in as a literal.

## 8. Assert machine-checkable things mechanically

```bash
# the mapper no longer reads the display columns directly
grep -n "r\.subject\|r\.actor\|r\.client_id\|r\.reason" \
  crates/adapter-cloudflare/src/admin/audit_query.rs   # want: only the comparison, not the assignment

# the double and the real adapter agree about where values come from
grep -c "AuditPayloadMirror" crates/adapter-cloudflare/src/admin/audit_query.rs \
                             crates/adapter-test/src/admin/audit_query.rs   # want: both non-zero

# the export's header gained exactly one column, at the end
grep -n '"seq,timestamp,kind,subject,client,reason,actor' crates/core/src/admin/service/audit_export.rs
```

## 9. Required tests and evidence

The canonical host-test command, quoted literally — baseline
**1,769 / 0 / 4 across 12 lines**:

```bash
cargo test -p cesauth-core \
           -p cesauth-adapter-test \
           -p cesauth-frontend \
           -p cesauth-backend \
           -p cesauth-adapter-cloudflare \
           --features cesauth-frontend/csr > 188p2-evidence/host-tests.log 2>&1

cargo test -p cesauth-migrate-test --test migration_chain > 188p2-evidence/migrate.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > 188p2-evidence/wasm32.log 2>&1
cargo check -p cesauth-frontend --target wasm32-unknown-unknown --features csr > 188p2-evidence/csr-check.log 2>&1
bash scripts/route-contracts-check.sh > 188p2-evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh > 188p2-evidence/drift-scan.log 2>&1
```

**The cases that have to exist:**

1. **A diverged row displays the payload's value, not the column's** —
   one test per display field (`subject`, `actor`, `client`, `reason`),
   asserting the shown value **and** that the column's value does not
   appear.
2. **The flag is set when a non-displayed column diverges** (`ip`,
   `user_agent`, `request_id`) — the row is marked even though nothing
   visibly changed (T7's reasoning, as a test).
3. **An unparseable payload** renders the marker for all four fields and
   sets the flag; it does **not** fall back to the columns (D2).
4. **A clean row is unmarked** and renders exactly what it renders today
   — the no-op case, which is most rows and must stay byte-identical in
   the export.
5. **The export**: a clean corpus exports byte-identically to `0.108.0`
   **except** the new appended column, and a diverged row's row carries
   the flag. Prove the byte-identity rather than asserting it.
6. **The double agrees** (D6): the same four assertions as (1) against
   `cesauth-adapter-test`'s mapper.
7. **The filter residual is real and acknowledged**: a test that a row
   whose `subject` column was changed is **not** returned by a search for
   the payload's subject — the residual, pinned so nobody later believes
   Phase 2 closed it.

**G2 — real HTTP, four requests** under `wrangler dev --local` (read
`contributing.md`'s note on the two local sqlite files first): the viewer
JSON for a clean row and for a diverged row (showing the payload's value
and the flag), and the export in both formats over the same corpus. Full
headers, token-free, asserted with `grep -ciE "bearer|authorization"` → 0.

## 10. What must NOT be claimed

- **Not that the residual is gone.** The filter half remains, by D4, and
  test (7) pins it.
- **Not that the columns are now unused** — they are the indexes the
  search runs on, which is the whole reason they exist.
- **Not that a divergence means tampering.**
- **Not that the export's old shape still parses unchanged** — it gains a
  column, and that is a disclosed surface-contract change (D5).

## 11. Prohibited shortcuts

- No fallback to the column when the payload will not parse (D2).
- No second comparison implementation, and no importing the verifier into
  the adapter (T2).
- No change to Phase 1's verifier, fields, route or screen (D7).
- No inserted export column (D5).
- No `cargo test --workspace --all-features`
  (`contributing.md:495-504`).

## 12. Acceptance criteria

1. The four display fields come from the payload in **both** the real
   adapter and the double; the flag is set by a full seven-column
   comparison.
2. The viewer marks a diverged row accessibly, in both locales, and says
   what a mark means **and** what a filter still does.
3. The export carries one appended column in CSV and JSON, with the
   byte-identity of the clean case demonstrated.
4. Tests (1)–(7) exist, including the residual pin.
5. `pages/operator/audit.rs`'s ceiling row still **2**; catalog grows by
   G1's count only.
6. Host **≥ 1,769 / 0 / 4 across 12 lines**, migrate **39**, **197
   routes**, `drift-scan` clean with ceiling **103 / 65 / 69**,
   negotiation **13 / 13**, timestamp rendering **24 / 15**, audit column
   coverage **16 — 8 / 7 / 1**.
7. F-7's residual paragraph narrowed; ADR-010 says what the readers read.

## 13. Known risks

- **The mapper is in the adapter, where host tests are thinnest.** The
  double exists for exactly this; D6 and test (6) are what keep them
  honest.
- **An unparseable payload is the case nobody will exercise by
  accident.** Phase 1 made it a verifier finding; Phase 2 makes it a
  rendered marker, and the two must agree about what it is.
- **The export is read by machines.** Appending is safe for
  column-counting parsers but not for positional ones that assert a
  length; D5's disclosure is the mitigation this project has chosen
  before.

## 14. Review request

`.git-exclude/review-request/188-phase2-keys.md` for G1, then
`.git-exclude/review-request/188-phase2-report.md`, evidence under
`188p2-evidence/`. Report the entry-point path only.
