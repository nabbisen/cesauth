# Both release gates turn a match into a miss under load — `pipefail` + SIGPIPE

**Governing RFC.** None yet. **This is a defect found at the `0.93.0` cut and it
held that cut.** An RFC follows if the fix turns out to need a decision; the
mechanism is proven and the fix is mechanical, so it is dispatched directly.

**Builds on.** `main` at the `0.93.0` preparation commit. **The tag is NOT cut**
— it is held until this lands, because "drift-scan clean" and
"route-contracts-check clean" are claims the tag message makes and they are
currently not obtainable.

**Target release.** **Minor** — RFC 181's default. Part of **`0.93.0`**, not a
release of its own: the version bump and CHANGELOG entry are already on `main`.

**Tier.** **P1.** Not because anything in the product is broken — nothing is —
but because **the project's two primary gates produce different answers on an
unchanged tree**, and every "clean" claim in recent release records rests on
them.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-08.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The symptom, measured

`./scripts/drift-scan.sh`, five consecutive runs, **tree unchanged between
them**:

| run | exit | docs link integrity | release reconciliation |
|---|---|---|---|
| 1 | **1** | **1 broken** | (aborted) |
| 2 | 0 | 0 broken | 0 unexempted — clean |
| 3 | **1** | 0 broken | **1 unexempted** |
| 4 | **1** | **1 broken** | (aborted) |
| 5 | **1** | (aborted) | (aborted) |

`./scripts/route-contracts-check.sh`, three runs: **exit 141 every time**,
output stopping right after the E6 line — so E7 and the final ✅ never print.

**Both reported failures are false.** `docs/src/deployment/production.md`
exists and is listed in `SUMMARY.md:88`; tag `0.33.0` is documented at
`docs/changelog-archive/CHANGELOG-0.31-to-0.40.md:1682`. The underlying
extraction is deterministic — I ran the script's own
`grep -hoE '^## \[…\]'` + `sort -u` pipeline six times and got **148 entries
including `0.33.0`, six for six**.

**141 = 128 + 13 = SIGPIPE.** That is the whole finding.

## 2. The mechanism, reproduced

Both scripts open with `set -euo pipefail` (`drift-scan.sh:17`,
`route-contracts-check.sh:22`). Combine that with a pipeline whose **reader
exits early**:

```bash
if printf '%s\n' "$list" | grep -Fxq "$needle"; then
```

`grep -q` exits **0 on its first match**. The writer (`printf`) is then killed
by SIGPIPE. `pipefail` makes the *pipeline's* status that of the failed
member — 141 — so the `if` takes the **false** branch. **A match is reported as
a miss.**

Minimal reproduction, 40 iterations, needle present as the list's first element:

```bash
set -euo pipefail
list=$(seq 1 200000)
for i in $(seq 1 40); do
  if printf '%s\n' "$list" | grep -Fxq "1"; then hits=$((hits+1)); else misses=$((misses+1)); fi
done
# -> found 0 times, NOT found 40 times, out of 40
```

**At 200,000 lines it fails every time. At 148 it usually passes**, because
`printf` finishes before `grep` is scheduled to exit — the list fits the 64 KiB
pipe buffer. Under heavy load the scheduling flips, which is why these gates
have been green all week and started flapping at load average **134**
(unrelated builds from other projects on the same machine).

**So the gates have been partly luck, and we only noticed because the machine
got busy.**

## 3. Scope — and it is smaller than it looks

Count the pipelines whose reader can exit early:

| form | `drift-scan.sh` | `route-contracts-check.sh` |
|---|---|---|
| `grep -q` / `grep -Fxq` | 9 | 29 |
| `… \| head` | 1 | 12 |
| `\|\| true` sites (failure swallowed) | 7 | 31 |

**But most occurrences are already safe** and must not be touched:

- `grep -qF "…" <<< "$VAR"` — a **here-string, not a pipe**. No writer process,
  no SIGPIPE. Example: `route-contracts-check.sh:1059`, `:1070`.
- `grep -qE "…" "$file"` — a **file argument**. Same reason. Examples: `:330`,
  `:1557`, `:1562`, `:1592`.
- `printf … | grep -Fx "$x"` **without `-q`** — `grep` reads to EOF, so it never
  exits early. Likewise `grep -c`.

**The vulnerable shape is specifically: a pipe whose right-hand side is
`grep -q`/`grep -*q` or `head`.** Examples to start from: `:161`, `:1022`,
`:1683`, `:1791` in `route-contracts-check.sh`.

## 4. The fix

**Replace the pipe with a here-string.** Every vulnerable site's writer is a
`printf` of a shell variable, so there is no reason for a pipe at all:

```bash
# before
if printf '%s\n' "$list" | grep -Fxq "$needle"; then
# after
if grep -Fxq "$needle" <<< "$list"; then
```

That removes the writer process entirely — nothing can receive SIGPIPE.

**For `| head` sites**, prefer a here-string too; where the writer is a real
command (not a variable) and a pipe is unavoidable, confine the status:
`{ cmd || true; } | head -1` is **not** enough — use
`mapfile -t arr < <(cmd)` and take `"${arr[0]}"`, or append `|| true` to the
**whole assignment** and verify the value is still correct.

**Do not "fix" it by removing `pipefail`.** That would silence real pipeline
failures across both scripts and trade a loud wrong answer for a quiet one.

**Do not add retries.** A gate that passes on the third attempt is a gate
nobody will trust, and it would hide the next instance of this.

## 5. The part that needs judgement, not mechanics

**Audit the polarity of every site you change, and report it.** SIGPIPE only
fires when `grep` **matches**, so the error is always *match → miss*. Whether
that is safe depends on what the check asks:

- *"is this tag documented?"* → match→miss means **a false violation**. Loud,
  safe, annoying. This is what we saw.
- *"does this handler call `verify_csrf(`?"* → match→miss means the handler is
  **reported as missing a control it has**. Still a false violation. Safe.
- *"does this file contain a forbidden pattern?"* → match→miss means **the
  violation is not reported at all.** **That is a false pass**, and it is the
  one shape that matters.

I sampled and found no false-pass site, **but I did not audit all 42 and I am
not claiming there is none.** Your report must state, per changed site, which
polarity it has. **If you find a false-pass site, say so prominently** — that
changes this from a trust problem into a correctness problem, and it would mean
a past "clean" run could have hidden a real violation.

## 6. Evidence required

1. **Twenty consecutive runs of each script on an unchanged tree**, exit codes
   listed. All must be identical. Twenty, not three — the bug hid behind load
   for a week.
2. **Run them under deliberate load** (e.g. `nproc`-many busy loops, or simply
   while a `cargo build` runs) and show the exit codes are still identical.
   This is the condition that exposed it; a fix verified only on an idle machine
   is not verified.
3. **The polarity table from §5**, one row per changed site.
4. **The two false failures must stop reproducing**: `0.33.0` reported
   documented, `deployment/production.md` reported resolvable.
5. The E7 and ✅ lines must appear again in `route-contracts-check.sh`'s output
   — currently it dies before them, so **E7's census has not actually run since
   the load rose.**
6. Host tests, `migration_chain`, `mdbook` unchanged. These are not affected
   (cargo and mdbook do not use these pipelines) but state them.
7. **No change to any check's logic or any exemption list.** This is a shell
   plumbing fix. If a check starts reporting a *new, real* violation once it can
   complete, **stop and report it** — that is a finding, not something to fix
   in passing.

## 7. Stop conditions

- A site where the here-string rewrite changes the check's meaning (e.g. the
  writer is a command with side effects): stop and name it.
- A false-pass polarity site: stop and report before fixing, so the blast
  radius is recorded.
- Any check that, once it completes, reports a violation that was previously
  invisible: **stop.** Do not fix it here. It needs its own cycle and its own
  record, and it is the most valuable thing this work could find.

## 8. Baselines

| | value | command |
|---|---|---|
| host tests | **1,677 / 0 / 4**, 12 lines | the canonical five-crate command, awk-summed |
| `migration_chain` | **35** | `cargo test -p cesauth-migrate-test` |
| `drift-scan.sh` | **flaky: 1 clean in 5** | `for i in $(seq 1 5); do ./scripts/drift-scan.sh >/dev/null 2>&1; echo $?; done` |
| `route-contracts-check.sh` | **exit 141, 3 of 3** | same shape |
| entries vs tags | **149 tags, 148 entries**, reconciling with the existing exemption list | the script's own extraction, run 6× identically |
| `mdbook` | 82 pages | `mdbook build docs` |
| Worker bundle at the prep commit | **890,326 B** gzip-default | `wrangler deploy --dry-run`, empty `dist/` substitution |

**`trunk` still cannot be installed here**, so Playwright and the frontend asset
remain out of reach — unchanged, and not this cycle's problem.
