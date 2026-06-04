# RFC 029: `rustfmt.toml` necessity review

**Status**: Implemented
**ROADMAP**: Internal repository hygiene — `rustfmt.toml` may be unnecessary
**ADR**: N/A
**Severity**: **P3 — quality / hygiene; the file is harmless if kept, marginally cleaner if removed**
**Estimated scope**: Tiny — empirical measurement + one PR; ~5 LOC change either way
**Source**: User request in v0.52.1 conversation: "特殊な format 要件として必要か。不要であれば運用を廃止したい"

## Background

`rustfmt.toml` at the repo root contains:

```toml
edition         = "2024"
max_width       = 100
tab_spaces      = 4
newline_style   = "Unix"
use_small_heuristics = "Max"
```

A header comment explains the file's intent:

> The codebase uses hand-aligned columns in several
> places (struct initializers, match arms, `use`
> lists) because the spec we're implementing leans
> heavily on per-column commentary. Default rustfmt
> would collapse those alignments. The settings
> below keep the default behavior where it adds
> value (trailing commas, line width, imports
> granularity) and leave the alignment-sensitive
> rules at their more permissive forms.

Two of these settings are non-defaults:

- `max_width = 100` — rustfmt default is also 100,
  so this is **redundant**.
- `tab_spaces = 4` — rustfmt default is 4,
  **redundant**.
- `newline_style = "Unix"` — rustfmt default is
  `"Auto"`, which produces Unix on Unix and
  CRLF on Windows. `Unix` is a meaningful
  override for Windows contributors.
- `edition = "2024"` — `edition` is also expressed
  in `Cargo.toml`'s `[workspace.package]`. rustfmt
  defers to that when not specified locally; the
  override here is **redundant** for projects
  with workspace-level edition declared.
- `use_small_heuristics = "Max"` — rustfmt default
  is `"Default"`. `"Max"` is the most permissive
  heuristic, allowing more code to stay on one
  line. **This is the genuine non-default.**

So the file's actual delta from rustfmt defaults
is **`use_small_heuristics = "Max"` and
`newline_style = "Unix"`**. The other three lines
are redundant.

The question is: does `use_small_heuristics =
"Max"` materially affect the codebase? If
removing it produces no diff, the file is
near-unnecessary; if it produces noticeable
diff, the file is load-bearing.

## Requirements

The fix must:

1. Empirically determine whether `rustfmt.toml`'s
   non-default settings produce diff against the
   current codebase.
2. Decide one of:
    a. **Keep the file** as-is (status quo; cost is one
       file at the root and the maintainer mental
       overhead of remembering it exists).
    b. **Reduce the file** to only the genuinely-
       non-default settings (drop the redundant
       three).
    c. **Delete the file** entirely if the codebase
       formats identically to defaults under
       `rustfmt --edition=2024`.
3. Whichever option is chosen, the project's
   formatting state is reproducible by a fresh
   contributor running `cargo fmt` without a
   custom config.

## Decision / Plan

The decision is **measurement-driven**. Run the
empirical check before committing to a path:

### Step 1 — Measurement

```bash
# 1. Save the current state.
git stash --include-untracked

# 2. Try removing the file entirely; run cargo fmt;
#    measure diff.
cd /path/to/cesauth-extracted
mv rustfmt.toml rustfmt.toml.bak
cargo fmt --all
git diff --stat
diff_size_no_config=$(git diff | wc -l)

# 3. Restore the file; reset the workspace.
git checkout -- .
mv rustfmt.toml.bak rustfmt.toml

# 4. Try minimal rustfmt.toml (Unix newlines + Max heuristic only); cargo fmt; measure.
cat > rustfmt.toml <<'TOML'
newline_style = "Unix"
use_small_heuristics = "Max"
TOML
cargo fmt --all
git diff --stat
diff_size_minimal=$(git diff | wc -l)

# 5. Restore.
git checkout -- .
git stash pop
```

The measurement results decide the path:

| `diff_size_no_config` | `diff_size_minimal` | Choice |
|---|---|---|
| 0 | 0 | **Delete the file** — defaults match the codebase |
| 0 | 0 (same) | **Delete the file** |
| > 0 | 0 | **Reduce to minimal file** — `Max` heuristic is the only meaningful setting |
| > 0 | > 0 | **Keep the file as-is or with only the non-defaults** — rustfmt is producing meaningful changes |

Empirical-by-default; the right answer depends on
how the codebase has actually evolved.

### Step 2 — Apply the chosen path

#### If "delete the file":

- Remove `rustfmt.toml`.
- Verify `cargo fmt --check` passes on a fresh
  clone with no config.
- Update CI to ensure `cargo fmt --check` is in
  the workflow (it should already be; if not,
  this is a place to add it as a small win).

#### If "reduce to minimal":

- Replace the file with:
  ```toml
  newline_style = "Unix"
  use_small_heuristics = "Max"
  ```
- Drop the redundant three settings.
- Update the file's header comment to be
  accurate: only document the two surviving
  settings and their rationale.

#### If "keep as-is":

- Update the file's header comment to clarify
  which settings are non-default vs redundant
  (so a future maintainer knows which lines
  matter).
- Optionally drop the redundant lines anyway,
  since they confer no behavior — just cleanliness.

### Step 3 — Document the convention

`docs/src/expert/contributing.md` (or the
development directive) gets a short section:

```markdown
## Code formatting

cesauth uses `rustfmt` defaults for Rust 2024
edition, with the small additions in
`rustfmt.toml` (`newline_style = "Unix"` and
`use_small_heuristics = "Max"`).

Run `cargo fmt --all` before submitting a PR.
CI verifies via `cargo fmt --all -- --check`.

If your editor formats files differently from
the project defaults, ensure your editor's
rustfmt invocation reads the project's
`rustfmt.toml`.
```

If the file is deleted, the section is shorter:
"cesauth uses `rustfmt` defaults; run `cargo
fmt`."

### Step 4 — `cargo fmt --check` in CI

Verify that `.github/workflows/` includes a job
running `cargo fmt --all -- --check`. If absent,
add it. This is independent of the rustfmt.toml
question — even if the config file is deleted,
the CI check ensures formatting stability.

## Test plan

Step 1 IS the test. The result determines the
implementation, and the implementation's
correctness is verified by `cargo fmt --check`
passing in CI on the chosen state.

## Security considerations

None.

## Open questions

1. **What about `imports_granularity`?**
   rustfmt has nightly-only options for import
   organization that some projects find useful
   (`Crate` vs `Module`). cesauth's current
   imports look organic; not worth adding
   nightly-only config. Out of scope.

2. **Should we declare the rustfmt edition in
   `Cargo.toml` only, dropping it from
   `rustfmt.toml`?** Yes if the file remains;
   `Cargo.toml`'s `[workspace.package].edition
   = "2024"` is the canonical source. rustfmt
   reads it.

3. **Will `use_small_heuristics = "Max"` ever
   cause rustfmt-version drift?** Possibly — a
   future rustfmt version's interpretation of
   "Max" could change. The risk is low and
   the mitigation is straightforward (re-run
   `cargo fmt`). Not a blocker for adopting it.

## Implementation order

1. Run Step 1 measurement on the current
   v0.52.1 codebase.
2. Apply the chosen path.
3. Update documentation.
4. Verify CI check.
5. Single PR.

## Notes for the implementer

- The measurement should be run on the
  v0.52.1 baseline, not on a working branch
  with un-formatted in-flight changes. Use a
  clean checkout.
- `cargo fmt` may take a couple of seconds
  on the workspace; the diff measurement is
  reliable.
- If the result is "delete the file", the
  PR should also consider whether any
  contributor's editor config (e.g.,
  `.editorconfig`) needs to mirror
  `newline_style = "Unix"` to keep cross-OS
  contributors consistent. cesauth has no
  `.editorconfig` today; adding one with
  `end_of_line = lf` is a small bonus that
  most editors honor automatically.
