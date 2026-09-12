# RFC 133 — Frontend build reproducibility

**Status.** Proposed
**Tier.** P2 · Category B — a real property we do not have; not urgent, not dismissible.
**Size.** Small to measure, unknown to fix. §5 is a measurement gate first.
**Tracks.** 0.81.2 release-candidate review §1–2. Discovered because task 008
asked for a changed byte figure to be reported rather than rounded past.
**Touches.** `Makefile`, `Cargo.toml` profile, `BUNDLE_SIZE_BUDGET.md`,
possibly `.github/workflows/`.
**Depends on.** Nothing. **Blocks.** Nothing.
**Target release.** Unscheduled. Candidate filler for any release with room.

## 1. Summary

The frontend wasm bundle is **run-reproducible but not
environment-reproducible**. The same commit, same dependencies and same
nominal toolchain produced 750,151 bytes on 2026-09-05 and 751,714 bytes on
2026-09-06. We cannot currently assert that a deployed bundle was built from a
given commit.

> **Status note, 2026-09-13.** This RFC was written as an investigation. It now
> carries a concrete defect with a one-line fix (**§5 F1** — `wasm-opt` is
> applied in place and is not idempotent), three eliminated causes (§2.4), and
> one named suspect for the residual. It is closer to *fix and re-measure* than
> to *investigate*, and its priority should be reconsidered on that basis: P2
> was set when nothing was identified.

## 2. What is established

Measured across two sessions, on identical source:

| Property | Result |
|---|---|
| Repeat build, same session | **byte-identical**, same sha256 |
| ~~Clean rebuild~~ | ~~byte-identical, same sha256~~ — **FALSIFIED 2026-09-13, see §2.2** |
| Across sessions, one day apart | **751,714 vs 750,151** — a fixed 1,563-byte delta |
| Across sessions, **same day, same host** (added 2026-09-08) | **751,714 (08:49) vs 751,711 (19:41)** — a 3-byte delta |
| Pre-`wasm-opt` size | 881,519 vs 879,980 — so the difference originates in `cargo`/`rustc`/LTO, not Binaryen |

Ruled out, with evidence:

- **Source.** `git diff 8badb12..95a9c2c --stat -- crates/` is empty.
- **Version string.** No `CARGO_PKG_VERSION` in `crates/frontend/` or
  `crates/backend/`; nothing embeds it.
- **Dependencies.** `Cargo.lock` moved only the seven internal crates' own
  version fields.
- **Toolchain.** Same rustc commit hash, same LLVM version, same `trunk`
  0.21.14, same checksum-verified Binaryen `version_123`.

What remains is the **host environment**, which changed between the two
measurements — the kernel moved 7.2.2 → 7.2.3, implying a system update.
The mechanism is unidentified. Bit-level diffing of two wasm binaries was
judged disproportionate by both the implementer and the reviewer, and that
judgement stands until this RFC is scheduled.

### 2.2 Falsified: a clean rebuild is not byte-identical

**Added 2026-09-13**, from the 0.83.0 release review. §2's second row said a
clean rebuild reproduces byte-for-byte. It does not.

The 0.83.0 cut reported the bundle at **753,095 bytes** against 753,093 before
the version bump, and attributed the +2 to the version string. I tested that,
and the version is **not** the cause:

```
version 0.83.0, clean rebuild              → 753,093 / f07a27b0…
version 0.82.0, clean rebuild (forced)     → 753,093 / f07a27b0…   ← reverting changed nothing
version 0.83.0, incremental (touch lib.rs) → 753,095 / 1b539cd2…
version 0.83.0, clean rebuild again        → 753,095 / 1b539cd2…   ← same version, same commit
```

`cargo clean -p cesauth-frontend` between each, `make build-frontend` after.
The last two lines are the finding: **two clean rebuilds of the same source at
the same commit, minutes apart, produced different output.** Both figures occur
at version 0.83.0.

**This is the strongest evidence this RFC has**, and it removes two candidate
causes at once:

- **Not the version string.** Reverting it produced the same bytes.
- **Not the host environment across time.** §2's first pair was two days apart
  and §2.1's was one host-day; this is minutes apart in one shell session with
  no intervening change of any kind.

What remains is something inside the build itself — incremental-compilation
state surviving `cargo clean -p` (which cleans one package, not the dependency
graph), codegen-unit ordering, or `wasm-opt`'s input differing for a reason not
yet named. **M1 should start here**, not with host images: it is the cheapest
reproduction in the RFC, it takes two commands, and it is available on any
machine.

**Stated with its limit:** a *no-op* rebuild — nothing recompiled — remains
byte-identical, which is what §2's first row actually measured. The claim that
fails is specifically that recompiling the same source yields the same bytes.

### 2.3 `wasm-opt` is not idempotent, and the Makefile applies it in place

**Added 2026-09-13**, narrowing §2.2. Measured with the pinned Binaryen
(`target/binaryen-version_123/bin/wasm-opt`, version 123) on the shipped
bundle, each pass fed the previous pass's output:

```
pass 1 (as shipped)  753,095 / 1b539cd2…
pass 2               752,485 / 84008d0c…     −610
pass 3               752,414 / c969fe55…      −71
```

**`wasm-opt -Oz` is not idempotent.** And `Makefile:140-144` applies it **in
place** — `wasm-opt … -o "$f" "$f"` over `crates/frontend/dist/*_bg.wasm`:

```make
cd crates/frontend && trunk build --release --filehash false
for f in crates/frontend/dist/*_bg.wasm; do wasm-opt … -Oz -o "$$f" "$$f"; done
```

So the emitted bundle is a function of **how many times `wasm-opt` has been
applied to whatever is in `dist/`**, not only of the source.

**Currently latent, not active.** Trunk overwrites the wasm on every build, so
in the normal path `wasm-opt` runs exactly once — confirmed: three builds from
an absent `dist/`, and two more without clearing it, all produced
`753,095 / 1b539cd2…`. But any path where Trunk does *not* overwrite — a
skipped build, a partial failure, a `make` run after a failed `trunk` — yields
a doubly-optimized bundle, ~600 bytes smaller, with no source change.

**This is a strong candidate for §2's original 1,563-byte pair** (751,714 vs
750,151). That gap is the right order of magnitude for one or two extra
optimization passes, and it is the only mechanism found so far that produces a
*large* delta from an unchanged tree.

**Fix, and it belongs in this RFC's §5:** make the step a pure function of its
input. Either optimize to a distinct output path and move it into place, or
clear `dist/` before `trunk build`. One line either way, and afterwards the
bundle cannot depend on the directory's history.

### 2.4 Three causes eliminated; one suspect named

For §2.2's ±2-byte delta, which §2.3 does **not** explain:

- **Not the version string.** Reverting `0.83.0` → `0.82.0` with a forced
  recompile produced the same bytes (§2.2).
- **Not the host environment drifting over time.** §2.2's pair is minutes
  apart in one shell session.
- **Not incremental compilation.** `[profile.release]` is already
  `codegen-units = 1`, `lto = true`; `CARGO_INCREMENTAL` is unset; and
  `target/wasm32-unknown-unknown/release/incremental/` is **empty** — Cargo
  disables incremental for release. The variable in §2.2 correlated with
  `cargo clean -p cesauth-frontend`, but that command does not clear an
  incremental cache that is not being used.

**What remains suspect:** `wasm-bindgen`'s post-processing, which runs between
`cargo` and `wasm-opt` and whose output ordering can vary per process, and
Trunk's own staging. **M1 should test wasm-bindgen's determinism directly** —
run it twice on the same `cargo` output and compare — before looking anywhere
else. That is two commands and it either finds the cause or eliminates the last
cheap candidate.

**Not established:** what produced the ±2. The bundle is reproducible *now*, at
753,095, across five consecutive builds. Whatever moved it from 753,093 has
stopped moving, and I could not make it move back — which is itself a fact
about the phenomenon rather than a resolution of it.

### 2.1 The same-day observation, and what it costs the kernel explanation

Added 2026-09-08, from the 0.81.3 release review. The figure moved **within a
single host-day**: 751,714 at 08:49, 751,711 at 19:41, with no change under
`crates/`, the same pinned `rustc 1.98.1 (48a229cea)`, the same `wasm-opt
version 123`, and the same `trunk 0.21.14`. Both figures were reproducible at
the time they were taken — seven agreeing builds at the first, two at the
second, and I confirmed the second independently:

```sh
sha256sum crates/frontend/dist/cesauth-frontend_bg.wasm
#   751,711 B — 6f65f4f64f9a560e53fa001691e4cee165acb7ff0f9e8addae21aac3204d64b6
cargo build -p cesauth-frontend --features csr       --target wasm32-unknown-unknown --release -v   # 231 units, all Fresh
```

This is the most constraining evidence the RFC has, and it damages the leading
hypothesis: **a kernel or system update cannot explain a delta inside one day
with no intervening update.** M1 should therefore not begin by assuming the
cause is a host-image difference.

The version-bump hypothesis was tested and is **not** supported, by a second
route independent of §2's `CARGO_PKG_VERSION` grep. `crates/frontend/Cargo.toml`
carries `version.workspace = true`, so the crate's own version did change with
the 0.81.3 bump — a genuine source input, which would have made the delta fully
explained rather than environmental. Rebuilding with the workspace version
reverted to `0.81.2` produced **byte-identical** output (751,711 /
`6f65f4f6…`). Also: no version literal appears in the wasm at all
(`strings … | grep -oE '0\.81\.[0-9]'` → nothing).

**Stated with its limit, per criterion 4:** that build completed in ~1.2 s and
was largely cached, so it rules the hypothesis unlikely rather than out. M1
must repeat it from a clean tree before relying on it.

The 3-byte magnitude is itself a lead the 1,563-byte delta did not offer: a
delta that small is more consistent with LEB128 length encodings or section
padding shifting than with different codegen, which is a cheaper thing to
localise.

## 3. Why it is worth an RFC rather than a shrug

cesauth ships a wasm binary to browsers that serves its authentication UI.
Reproducibility is what would let anyone — us included — verify that a
deployed bundle corresponds to a reviewed commit. Condition C1-130 established
that the *tool* producing that binary is checksum-verified; this is the same
concern one step further out, about the *output*.

It is also a precondition for anything that pins or compares artifacts: a
bundle-size CI gate that fails on a delta, an artifact checksum in release
notes, or any future supply-chain attestation. None of those can be built on
an output that moves when the host does.

**It is explicitly not urgent.** Nothing is broken, no gate fails, and the
delta is 0.2 %. The cost of not having it is that a class of verification
remains unavailable, not that anything currently misbehaves.

## 4. Non-goals

- Reducing bundle size. Unrelated.
- Reproducibility of the *Worker* bundle. Same question, different artifact;
  in scope only if the measurement in §5 is cheap to extend.
- Bit-for-bit reproducibility across differing rustc versions. Nobody offers
  that; the target is *same toolchain, different host*.
- Chasing the specific 1,563 bytes. §5 measures whether the problem persists
  before anyone attempts to explain it.

## 5. M1 — measure before designing

**Amended 2026-09-13.** §2.3 found a concrete defect that does not need M1 to
justify fixing: **`wasm-opt` is applied in place to a directory that may already
contain its own output, and `wasm-opt -Oz` is not idempotent.** That makes the
build a function of build history rather than of source, regardless of what M1
concludes about anything else.

**F1 — make the optimization step a pure function of its input.** Either
`wasm-opt -o dist/x.opt.wasm dist/x.wasm && mv`, or clear `dist/` before
`trunk build`. Then re-measure: three builds from a cleared tree must agree, and
a build immediately following another must agree with them.

F1 is independent of M1 and can land first. **M1's first experiment should be
§2.4's**: run `wasm-bindgen` twice on identical `cargo` output and compare —
the last cheap candidate for the residual ±2.



**Do not attempt a fix first.** Establish whether this reproduces:

1. Build at a fixed commit on the current host; record size and sha256.
2. Build the same commit in a **container** pinning the OS image, with the
   same `rust-toolchain.toml`. Compare.
3. If they differ, the host is confirmed as the variable and §6 applies. If
   they match, the earlier delta had a cause that has since been removed, and
   this RFC closes as not-reproducible with the measurements recorded.

Report before proceeding. This is a report-and-stop gate.

## 6. Candidate directions, only if M1 confirms

Recorded so the shape is understood, not as a chosen design:

- **`--remap-path-prefix`** to remove absolute build paths from the binary.
  Cheap, standard, and a common source of environment-dependence.
- **Pin the build environment**, e.g. a container image used by both CI and
  the release process, so "the host" stops being a free variable.
- **`SOURCE_DATE_EPOCH`** and related determinism environment variables.
- Accept and document, if the cost of the above exceeds the value of the
  property at this stage. That is a legitimate outcome and should be recorded
  as a decision, not a silence.

## 7. Testing strategy

1. M1's two builds, with sizes and hashes captured.
2. If a fix is adopted: the same commit built on two different hosts (or host
   and container) produces **identical sha256**. That is the acceptance test;
   a size match alone is not sufficient — two different binaries can be the
   same length.
3. Full gate set green.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Effort sinks into LLVM internals | §5 is a measurement gate; §6 lists bounded options; "accept and document" is an allowed outcome |
| A fix pins us to a container nobody maintains | Weigh in §6; the status quo is a valid alternative |
| The property is asserted after a partial fix | §7.2 requires identical **hashes** across hosts, not sizes |

## 9. Acceptance criteria

1. M1 executed and reported.
2. Either: reproducibility achieved and demonstrated by §7.2; **or** a recorded
   decision to accept non-reproducibility, with the reasoning and the
   measurements behind it.
3. `BUNDLE_SIZE_BUDGET.md` states which of those two holds, so a future reader
   is not misled by a figure that looks invariant.
4. **Every figure this RFC records states its measurement command.** A gzip
   size without a compression level is not a measurement — RFC 130 S4 omitted
   it, and 0.81.2's condition C2 exists because two incompatible numbers both
   then looked like "the gzip size." Raw sizes state the artifact path; gzip
   sizes state the full pipe.

## 10. Open questions

1. Does the Worker bundle share the property? Likely, since it is the same
   toolchain and profile — but unmeasured, and I will not assert it.
2. Is this worth doing before 1.0, or is it a 1.0-hardening item? ROADMAP
   makes an attack-surface review a 1.0 precondition; artifact provenance is
   arguably adjacent to that, and the review is already overdue by its own
   note.
