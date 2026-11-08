# RFC 168 §3.2 — the level backstop, plus the URL-set diff the RFC does not specify

**Governing RFC.** [`rfcs/accepted/168-the-release-record-does-not-reconcile.md`](../../accepted/168-the-release-record-does-not-reconcile.md)
§3.2, as amended by [RFC 181](../../accepted/181-minor-is-the-default-release-level.md)
and its §Enforcement note (2026-11-07).

**Builds on.** `main` at tag **`0.93.0`** (`183e302`).

**Target release.** **Minor** — RFC 181's default. No patch argument offered.

**Tier.** **P2.** Nothing is broken. This is the last unbuilt check of an RFC
accepted 2026-10-31, and the rule it enforces failed **six times in seven**
across `0.92.x` with nothing to notice.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-08.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. What is actually left to build — one check, not three

**RFC 168 §3 lists three items and only one is unbuilt.** Correcting the
architect's own earlier count: item 1 (reconciliation, both directions) shipped
with RFC 164 in `0.91.2` and `drift-scan.sh` prints its population every run;
item 3 ("both print their population") is a *requirement on* the other two, not
a check. **Only §3.2's level backstop is missing.**

Add it to `scripts/drift-scan.sh`, beside the release-reconciliation section.
**One new section, plus §4's census.**

## 2. RFC 181 changed what this check is for, and that changes its shape

§3.2 as written reads: *"A **patch** must not, versus the previous tag, add a
registered route, add a migration, or change `rust-version`."*

Under RFC 181 **minor is the default**, so a patch is now an **exception someone
has argued for**. The backstop therefore stops being a general level guard and
becomes **the mechanical half of validating a patch claim** — exactly the claim
that was wrong six times in seven.

**But a check that only fires on an exception rots between exceptions.** Patch
claims will now be rare; a backstop that does nothing on a minor will sit
unexercised for months and break silently, which is this project's single most
repeated defect. So:

> **Compute everything on every run. Report everything on every run. Fail only
> when a patch claim is contradicted.**

That way the logic runs at every cut and cannot rot, and the exception path is
exercised by the same code that just printed its census.

**This shape is the architect's refinement, not RFC 168's text** — flagged so
review can challenge it rather than find it buried.

## 3. The level, derived — not asserted

Compare `[workspace.package] version` in `Cargo.toml` against the **highest
existing `X.Y.Z` tag**:

- minor component increased → **minor**. Nothing to validate; print and pass.
- patch component increased, minor unchanged → **patch claim**. Validate §3.1.
- equal to the latest tag → **not a release commit**; print and pass. (This is
  the normal state between cuts and must not fail — RFC 168 §3c's lesson: a
  check that reads the release record has to be run against the act of
  releasing *and* against every ordinary commit.)
- anything else (major bump, version below the latest tag) → **report and
  fail**; that is not a shape this project has, and guessing is worse than
  stopping.

### 3.1 On a patch claim, assert all three, versus the previous tag

| | source | at `0.93.0` |
|---|---|---|
| registered route set unchanged — **neither added nor removed** | `crates/backend/src/lib.rs` | **194 method+path pairs** |
| migration count unchanged | `./migrations/` | **20 files** |
| `rust-version` unchanged | `Cargo.toml:32` | **`1.85`** |

**§3.2's own text says "add".** It must be **add or remove**: `0.92.3` was cut
as a patch and **removed** two live URLs, which no addition-only test sees. That
is the single concrete miss that prompted RFC 181, so an addition-only backstop
would not have caught the thing it exists to catch.

## 4. The URL-set diff — informational, every run

Print the route-set delta against the previous tag on **every** run, whatever
the level:

```
ℹ️   route surface vs 0.93.0: 194 pairs -- 0 added, 0 removed
```

**Why, given a minor needs no justification:** the CHANGELOG has to be honest
about route changes regardless of level, and no gate has ever told a cut what it
did to the route surface. This is the line that makes a removed URL impossible
to miss while writing the entry.

### 4.1 Key on method+path, not path

`150` distinct paths but **194 method+path pairs**. Keying on the path alone
hides *"GET survived, POST was removed"*. Use the pair.

### 4.2 Reconcile 194 against route-contracts' 192 — and report it as a question

`route-contracts-check.sh` prints *"All **192** routes are documented"*. A naive
`grep` of `lib.rs` gives **194** pairs. **I do not know which is right** and did
not chase it. Possibilities: the other script normalises differently, excludes
`.json` siblings, or counts documented rows rather than registrations.

**Reconcile the two and state the reason in your report.** If it is a real
2-route gap, **stop and report it** — that is a finding about route
documentation coverage, not something to fix here. If it is two different
definitions, say which this check uses and why. **Do not silently adopt either
number.**

## 5. Build it with RFC 182's lesson applied from the start

`drift-scan.sh` runs `set -euo pipefail`. RFC 182 (shipped in `0.93.0`) removed
every `cmd | grep -q` / `| head` / `| awk '…exit'` pipe from this file because
each one turns a **real match into a miss** under load, and two of them could
report clean while a violation existed.

**Do not reintroduce the shape.** Use `grep -Fxq "$x" <<< "$list"`,
`mapfile -t arr < <(cmd)`, or a file argument. The file's header comment
(added by RFC 182) states the rule — your new section is the first code written
after it and sets the precedent.

**Especially here**: this check reads `git show <tag>:path` output, which is a
*command*, not a variable. That is the one situation where a pipe is tempting.
Capture with `mapfile` or a command substitution, then match against the
captured value with a here-string.

## 6. Do not

- **Do not audit history.** This check compares the in-flight tree against the
  **previous tag only**. It never looks at `0.92.1`–`0.92.7`, so **it needs no
  historical exemption list** — correcting the architect's own ROADMAP row,
  which claimed it did.
- **Do not fail on an ordinary (non-release) commit.** §3.
- **Do not try to verify the patch *argument*** — it is prose in a handoff. The
  check validates the three mechanical facts; the argument is for review.
- **Do not change the existing reconciliation check or its exemption list.**
- **Do not add a route, a migration, or touch `rust-version`.**

## 7. Evidence required — and this bar is costed

**`drift-scan.sh` runs in ~1.0 s** (measured: 1032, 970, 1223 ms). So:

1. **20 consecutive runs, identical exit code and output.** ~20 s. (Contrast
   RFC 182, where I set this bar for a 140 s script without costing it and the
   team rightly pushed back — here it is cheap, so it is required.)
2. **20 runs under deliberate load**, same result. Another ~30 s.
3. **The `0.92.3` regression, proved**: with the check pointed at `0.92.2` →
   `0.92.3` it must report **2 removed** and, because `0.92.3` was a patch
   claim, **fail**. The two URLs are
   `/admin/console/config/log_level/{preview,apply}` and the pair count goes
   **152 → 150**. A backstop that does not catch this has not been verified.
4. **All four §3 level shapes exercised**: minor, patch-clean, patch-violating,
   non-release commit. Synthetic `Cargo.toml` versions are fine; say so.
5. **§4.2's reconciliation**, with its reason.
6. The new census line's figures, reconciled.
7. Existing gates unchanged: host **1,677 / 0 / 4, 12 lines**;
   `migration_chain` **35**; `route-contracts-check.sh` E7
   **`156 = 8 + 31 + 117`**; `mdbook` **82 pages**. Worker bundle with
   `sha256sum` **and the gzip level** — it should not move, since this is a
   shell script.

## 8. Stop conditions

- §4.2's 194-vs-192 turns out to be a real gap in route documentation.
- Any of the three facts in §3.1 cannot be derived from a `git show` of the
  previous tag without ambiguity.
- The check would fail on an ordinary commit and you cannot see how to avoid it
  — say so rather than weakening it into uselessness.
- You find a way the check could pass while a patch claim is false. **That is
  the same class RFC 182 just found twice**, and it is worth more than shipping
  on time.

## 9. Baselines at `183e302` (tag `0.93.0`)

| | value | command |
|---|---|---|
| route pairs in `lib.rs` | **194** | `grep -oE '\.(get\|post\|put\|delete\|patch)_async *\( *"[^"]+"' crates/backend/src/lib.rs \| sed -E 's/\.([a-z]+)_async *\( *"(.*)"/\1 \2/' \| LC_ALL=C sort -u \| wc -l` |
| distinct paths | 150 | same, path only — **not** the key to use (§4.1) |
| routes per `route-contracts-check.sh` | **192** | its own `✅` line — reconcile, §4.2 |
| migrations | **20** | `ls migrations/ \| wc -l` |
| `rust-version` | **1.85** | `Cargo.toml:32` |
| latest tag | **0.93.0** | `git tag \| grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \| LC_ALL=C sort -V \| tail -1` |
| `drift-scan.sh` | exit 0, ~1.0 s | `./scripts/drift-scan.sh` |
| host tests | **1,677 / 0 / 4**, 12 lines | canonical five-crate command, awk-summed |
| `migration_chain` | **35** | `cargo test -p cesauth-migrate-test` |
| Worker bundle | **890,326 B** gzip-default | `wrangler deploy --dry-run`; an **empty** `crates/frontend/dist/assets/` is required and is a sound substitution here because `LEPTOS_JS`/`LEPTOS_WASM` are hardcoded consts at `leptos_shell.rs:85-86` |

**`trunk` still cannot be installed on this machine** — unchanged, and nothing
in this cycle needs it.
