# Developer Handoff — RFC 111, the formatter's real range and its clamp

**Target**: `0.108.0`, slice B of two · **Level**: minor (ships with slice A)
**RFC**: `rfcs/done/111-date-rendering-policy.md` · policy doc
`docs/src/expert/i18n.md` §"Date / time rendering"
**Found**: reviewing `0.107.0`'s slice A — the clamp went from 5 call sites
to 24 in that cut, which is what made the contradiction worth closing
**Baseline**: `46ce300` / tag `0.107.0`

---

## 1. Purpose

**Three statements in the tree disagree about one function**, and after
`0.107.0` that function renders every visible timestamp in the product:

1. `crates/core/src/types.rs:28-31` — *"We use `i64` everywhere (not
   `u64`) because SQLite D1 returns signed integers and
   **negative-before-epoch is a legitimate corner case for imported
   data**."*
2. `crates/core/src/util.rs:52-58` — *"Accurate for years **2000-2099** —
   the cesauth deployment window"*, and **no mention of the clamp** that
   the next line performs (`unix.max(0)`).
3. `crates/frontend/src/admin/tests.rs::rfc_111::canonical_formatter_handles_negative_as_epoch`
   — *"Defensive: negative inputs (rare but possible from i64 fields)
   clamp to epoch, not panic."*

So a timestamp the type system calls legitimate renders as
`1970-01-01T00:00:00Z` — **a plausible-looking date standing in for a
value that was something else**, which is precisely what RFC 187 D2 ruled
out for the audit `actor` column (*"a sentinel is a value that looks like
data"*). And the stated accurate range excludes 1970–1999, which the
arithmetic very likely handles correctly, so the doc comment is probably
wrong in the *conservative* direction too.

This slice makes the three agree with **measured** behaviour. It is
documentation and tests; the behaviour does not change.

## 2. Resolved decisions — do not re-open

- **D1. The clamp stays.** No importer exists, no pre-1970 timestamp can
  currently enter the system, and changing `days_to_ymd` to handle
  negative days is real arithmetic work for a hypothetical. **This is the
  decision, recorded as one** — not an omission to be quietly inherited
  by the next reader.
- **D2. The dependency is named rather than deferred.** If an importer
  ever lands — the exact case `types.rs` invokes — the formatter must
  handle negatives **before** that importer ships, because the display
  would otherwise silently rewrite history to 1970. Say that in the
  formatter's own doc comment, where the person adding the importer will
  be standing.
- **D3. No behaviour change in this slice.** Same outputs for every
  input. If a measurement contradicts that, **stop and report** — it
  means the formatter's behaviour was never what any of the three
  statements said.
- **D4. The accurate range is whatever you measure**, not what the
  comment claims and not what this handoff guesses. The comment gets the
  measured range.

## 3. Facts already measured — do not re-derive

- `format_unix_as_iso8601` (`crates/core/src/util.rs:61`) is
  `unix.max(0) as u64`, then `days_to_ymd` (`:74`) using 400/100/4-year
  cycle arithmetic from the epoch, then
  `format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")`.
- It is now the only timestamp formatter in `crates/frontend/src`: **24
  call sites across 15 files**, pinned by `0.107.0`'s
  timestamp-rendering gate.
- `admin/tests.rs::rfc_111` already pins four properties: the `Z` form,
  the epoch for `0`, the negative-clamps-to-epoch behaviour, and the
  absence of the `+00:00` form.
- `docs/src/expert/i18n.md:44-49` is the policy statement and is
  **correct as far as it goes** — it names the canonical formatter and
  the `Z` form, and says nothing about the clamp or the range.

## 4. Report-and-stop gates

**None.** If D3's "no behaviour change" turns out false, that is the stop
condition, and it is worth more than the rest of the slice.

## 5. Change scope

| file | change |
|---|---|
| `crates/core/src/util.rs` | T2 — the doc comment: the measured range, the clamp, and D2's dependency |
| `crates/core/src/types.rs` | T3 — the `UnixSeconds` comment: negatives are accepted by the type and clamped **at display**, with the pointer to the formatter |
| `crates/core/src/util/tests.rs` (or wherever `util`'s tests live — check before assuming) | T1 — the boundary table as a test |
| `docs/src/expert/i18n.md` | T4 — one sentence on the clamp in §"Date / time rendering" |
| `crates/frontend/src/admin/tests.rs` | T5 — the `rfc_111` module's clamp test gains the *why*, not just the *what* |

## 6. Explicit non-change scope

- **No change to `format_unix_as_iso8601`'s behaviour, `days_to_ymd`, or
  any call site** (D1/D3).
- **No new formatter, no parameter, no feature flag.**
- **No change to `0.107.0`'s timestamp-rendering gate** — its pinned
  24 / 15 must still read 24 / 15 afterwards.
- **No per-user timezone, no relative times** — RFC 111 §out-of-scope,
  and ADR-013 Q1 is the owner's.

## 7. Task detail worth stating explicitly

- **T1 is the whole slice's evidence.** A table test over the boundaries,
  each case asserting the exact string: a negative (`-1`, and something
  genuinely pre-epoch like `-86_400`), `0`, a 1970s value, a 1985 value,
  the 1999→2000 boundary, a current-era value, the 2099→2100 boundary,
  and something far enough out to show where (if anywhere) it stops being
  right. **Compute the expected strings independently** — `date -u -d
  @<n>` or Python's `datetime.utcfromtimestamp` — not from the function
  under test.
- **T2's doc comment must say three things**: the measured range, that
  negative inputs **clamp to the epoch rather than rendering a pre-1970
  date**, and D2's dependency sentence. Delete *"Accurate for years
  2000-2099"* if T1 shows it understates; correct it if T1 shows it
  overstates.
- **T3 must not delete `types.rs`'s reasoning.** The `i64`-not-`u64`
  choice is still right and the comment's first half is still true. What
  changes is the second half: an imported negative timestamp is
  *storable* and *not displayable as itself*, and the comment should say
  which.
- **T5**: the existing clamp test's comment says *"Defensive"*. After this
  slice it is a **policy** pin, not a defensive one — it asserts a
  decision someone made, and the comment should name the decision and
  where it is recorded.

## 8. Assert machine-checkable things mechanically

```bash
# the gate from 0.107.0 must not move
bash scripts/drift-scan.sh | grep -i "timestamp rendering"   # want 24 / 15

# no call site changed
git diff --stat -- crates/frontend/src crates/backend/src     # want empty
```

## 9. Required tests and evidence

The canonical host-test command, quoted literally — baseline
**1,737 / 0 / 4 across 12 lines** (slice A will raise the first number;
say which tree you measured on):

```bash
cargo test -p cesauth-core \
           -p cesauth-adapter-test \
           -p cesauth-frontend \
           -p cesauth-backend \
           -p cesauth-adapter-cloudflare \
           --features cesauth-frontend/csr > 111b-evidence/host-tests.log 2>&1

bash scripts/drift-scan.sh > 111b-evidence/drift-scan.log 2>&1
```

No HTTP evidence: nothing rendered changes, which is the claim, and T1 is
how it is demonstrated. Include T1's table in the report as a table —
input, expected, actual — so the measured range is in the record and not
only in a passing test.

## 10. What must NOT be claimed

- **Not that the clamp is now correct.** It is now *documented and
  decided*. A pre-1970 timestamp still renders as 1970, and the record
  says so in three places instead of contradicting itself in three
  places.
- **Not that the formatter is safe for all `i64`** unless T1 shows it —
  and if T1 finds an upper bound where the output goes wrong, that is a
  finding to report, not a comment to write around.

## 11. Acceptance criteria

1. T1's boundary table exists as a test, with expected strings computed
   independently of the function.
2. `util.rs`, `types.rs`, `i18n.md` and the `rfc_111` clamp test all say
   the same thing about the range and the clamp, and that thing is what
   T1 measured.
3. No behaviour change: no call site touched, `drift-scan`'s
   timestamp-rendering line still **24 / 15**, gates otherwise unchanged.
4. D2's dependency sentence is in the formatter's own doc comment.

## 12. Review request

`.git-exclude/review-request/111b-formatter-range-report.md`, evidence
under `111b-evidence/`. Report the entry-point path only.
