# RFC 133 — Frontend build reproducibility

**Status.** Accepted. **Half A shipped in v0.84.3** (+C1-133); **half B deferred to 1.0 hardening** (§12.3), which is why this RFC stays in `accepted/` rather than `done/`.
**Tier.** P2 · Category B — a real property we do not have; not urgent, not dismissible.
**Size.** Small to measure, unknown to fix. §5 is a measurement gate first.
**Tracks.** 0.81.2 release-candidate review §1–2. Discovered because task 008
asked for a changed byte figure to be reported rather than rounded past.
**Touches.** `Makefile`, `Cargo.toml` profile, `BUNDLE_SIZE_BUDGET.md`,
possibly `.github/workflows/`.
**Depends on.** Nothing. **Blocks.** Nothing.
**Target release.** The next one, for half A. **Level: patch** — a build-step fix, a measurement, and a documentation correction; no behaviour changes.

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

## 11. Recorded observations, and what they actually show (2026-09-24)

Four measurements of `crates/frontend/dist/assets/cesauth-frontend_bg.wasm`,
each `du -b` + `gzip -c | wc -c` + `sha256sum`, with **no frontend source
change** between any of them:

| Between | Size | Result |
|---|---|---|
| 0.83.1 cut → 0.84.0 cut (version bump) | 753,095 → 753,094 | **−1 byte**, different hash |
| 0.84.0 cut → 0.84.1 cut (version bump) | 753,094 → 753,312 | **+218 bytes**, different hash |
| 0.84.1 cut → 0.84.2 readiness (**no version change**, separate `make build-frontend`) | 753,312 → 753,312 | **byte-identical**, `sha256 9f8f0f1c…` |
| 0.84.1 → 0.84.2 cut (version bump) | 753,312 → 753,092 | **−220 bytes**, different hash |

**Correction to how I first recorded these.** My first note said "every version
bump moves the bundle; a rebuild at an unchanged version does not", which invites
the reading that the *version* is the cause. **It is not**, and §2.2 already
disproved that by reverting the version and getting identical bytes. The
variable is **whether the frontend crate was recompiled**:
`crates/frontend/Cargo.toml` carries `version.workspace = true`, so a workspace
bump changes `CARGO_PKG_VERSION` — a fingerprint input — and forces a rebuild,
while a `make build-frontend` at an unchanged version finds every unit `Fresh`
and re-emits the same file.

So these four rows are **not a new pattern**. They are a fourth, fifth and sixth
confirmation of §2.2's finding, at release scale:

> **recompiling the same source produces different bytes; not recompiling
> produces the same bytes.**

That is worth having — it shows the phenomenon is still live at 0.84.2, on this
host, four months of toolchain-stability later, and that the deltas are not
monotonic (−1, +218, −220), which is awkward for any "padding grew" story. It
adds no new *cause*, and it narrows nothing on its own.

## 12. Recommendation, 2026-09-24 — split the RFC, and do the cheap half now

Reviewed end to end at the owner's request, against "finally clean, safe and
secure, robust and sophisticated design".

### 12.1 There are two RFCs inside this one

**A — a fragile build step.** §2.3's F1: `wasm-opt -Oz` is not idempotent, and
`Makefile:149-153` applies it **in place** (`-o "$$f" "$$f"`) over
`crates/frontend/dist/*_bg.wasm`. Verified still present today.

**Corrected 2026-09-24, after reading the whole recipe** — §2.3 and my own first
draft of this section overstated the live risk, and the correction matters
because it changes why the fix is worth doing:

- Two lines after the optimizer, the wasm is **moved** to `dist/assets/`
  (`mv crates/frontend/dist/*.js crates/frontend/dist/*_bg.wasm
  crates/frontend/dist/assets/`). The next run's glob, `dist/*_bg.wasm`, does
  **not** match it. The previously optimized artifact is not re-optimized.
- `make` aborts on the first failing recipe line, so a failed `trunk build`
  stops the target before the optimizer runs at all.

So §2.3's "a failed or interrupted `trunk build` … silently ships a
doubly-optimized bundle" requires something outside the normal path: `make -k`,
which continues past the failure; a hand-run loop; or an interruption **inside**
the optimizer, which leaves a partially written file at a path that is both its
input and its output.

**What remains true, and is still worth fixing:** the step reads and writes the
same path, and its result depends on what that path already holds. That is
fragile rather than broken — the property "the artifact is a function of the
source" currently holds by luck of Trunk's behaviour rather than by
construction. The two defects are separable and each is one line:

1. **Read–write aliasing.** An interruption mid-optimize leaves a truncated file
   where the input used to be, and nothing downstream would notice. Fix: write
   to a distinct path and move it into place.
2. **History dependence.** The target's output depends on what `dist/` already
   contains. Fix: clear `dist/` before `trunk build`, which also makes a failed
   Trunk produce *no* artifact rather than a stale one.

**This is hardening, not an incident.** No measurement in this RFC was produced
by a doubly-optimized bundle, and the package must not claim one was.

**B — a property we do not have.** Environment reproducibility: the same commit
and toolchain on a different host, or in a container, yielding an identical
hash. §6's directions (`--remap-path-prefix`, a pinned build image,
`SOURCE_DATE_EPOCH`) belong here.

They have been carried as one RFC because they were discovered together. They
have different costs, different value, and different right moments.

### 12.2 Do A now

- **It is hardening with a known shape, not an investigation** (§12.1 as
  corrected). A build step that reads and writes one path, and whose result
  depends on what that path already holds, should not be the last thing standing
  between the source and the shipped artifact. Both fixes are one line, and they
  are **not** alternatives: one removes the aliasing, the other removes the
  history dependence.
- **It is the only mechanism found that produces a *large* delta from an
  unchanged tree**, and §2.3 names it as the likely cause of the original
  1,563-byte pair.
- **The re-measurement is the acceptance test**, and it is cheap: three builds
  from a cleared tree agree, and a build immediately after another agrees with
  them.
- **Alongside it, M1's first experiment** (§2.4): run `wasm-bindgen` twice on
  identical `cargo` output and compare. Two commands, and it either finds the
  residual's cause or eliminates the last cheap candidate. Nothing else in M1
  should start until that is reported.

**Priority: raise A from P2.** P2 was set when nothing was identified. A named
defect with a one-line fix, in the path that produces the artifact every release
records, is ordinary maintenance work — not an investigation to be scheduled
when there is room.

### 12.3 Defer B to 1.0 hardening, and record that as a decision

**Not because it is unimportant — because it has no consumer yet.** cesauth
ships its authentication UI as a wasm binary, so "this bundle is the reviewed
commit" is a security property and not a nicety. But it becomes *usable* only
when there is something to verify against: a deployment, a published artifact,
release-note checksums, or an attestation. There is none of that today — nobody
has deployed this tree.

Committing now to a pinned build image is the expensive half of §8's risk
table: it adds an artifact somebody must maintain, in exchange for a property
nothing yet consumes. **Tie B to the attack-surface review the ROADMAP already
makes a 1.0 precondition**, which is where artifact provenance belongs, and
answer §10 q2 in those terms rather than leaving it open.

### 12.4 One documentation correction, and it is the "do not mislead" case

`BUNDLE_SIZE_BUDGET.md` currently tells a reader:

> The build is **run-reproducible but not environment-reproducible**

**§2.2 falsified the first half of that sentence** — two clean rebuilds of the
same commit, minutes apart, in one shell session, on one host, produced
different bytes. The true statement is narrower: *a rebuild that recompiles
nothing re-emits the same file; a rebuild that recompiles may not.* A reader
acting on the current wording would conclude their own machine reproduces the
artifact, and would be wrong the first time they touch the version.

This is criterion 3's intent, and it should not wait for A or B: the sentence
is wrong now. **Correct it whenever A lands**, and state the property in terms
of *recompilation*, with §11's figures as the evidence.

### 12.5 What I am not recommending

- **Not bit-level diffing of two binaries.** Still disproportionate, and §2.4's
  cheap candidate is not exhausted.
- **Not a CI gate on the hash.** It would fail on every version bump, which is
  precisely the behaviour under investigation; a gate on an artifact we cannot
  yet reproduce would be a gate that teaches people to ignore it.
- **Not closing the RFC.** §2.2's finding is real and unexplained, and the
  figures keep accumulating.


## 13. Scheduled (2026-09-24)

The owner authorized §12: **half A is scheduled**, half B is deferred.

**In scope now (half A):**

1. **F1a — remove the read–write aliasing.** The optimizer writes to a distinct
   path, which is then moved into place.
2. **F1b — remove the history dependence.** `dist/` is cleared before
   `trunk build`, so the target's output cannot depend on what the directory
   already held, and a failed Trunk leaves no artifact rather than a stale one.
3. **M1's first experiment** (§2.4): run `wasm-bindgen` twice over identical
   `cargo` output and compare. Two commands. It either finds the cause of the
   residual or eliminates the last cheap candidate. **Report and stop** — no
   other M1 step begins on its result without a ruling.
4. **The documentation correction** (§12.4): `BUNDLE_SIZE_BUDGET.md` says the
   build is "run-reproducible", which §2.2 falsified. It is corrected to state
   the property in terms of **recompilation**, with §11's figures as evidence.

**Deferred (half B), as a recorded decision rather than a silence:**
environment reproducibility — the same commit and toolchain on a different host
or in a container yielding an identical hash — with §6's directions
(`--remap-path-prefix`, a pinned build image, `SOURCE_DATE_EPOCH`). It has no
consumer until there is a deployment and something to verify against, and
committing to a maintained build image before then buys a property nothing uses.
**It is tied to the attack-surface review the ROADMAP makes a 1.0
precondition**, which answers §10 q2.

**What half A does not do.** It does not make the build reproducible. §2.2's
finding — recompiling the same source can produce different bytes — is
untouched by it, and the package must not imply otherwise.

## 14. The pre-optimizer wasm changed (2026-10-24)

The strongest form of §2.2's finding so far, measured a month after half A
landed, on a host whose kernel moved 7.2.5 → 7.3.0, with **no change under
`crates/`**:

```
$ sha256sum target/wasm-bindgen/release/cesauth-frontend_bg.wasm
  533e1980…      882,608 bytes        ← Trunk's output, BEFORE wasm-opt
      (half A's package recorded 8b51a72c… for this same file)

$ wasm-opt --enable-bulk-memory --enable-bulk-memory-opt -Oz -o pass1 <that>
  752,475        ca7cfd72…
$ wasm-opt … -o pass2 pass1
  751,865        dad12031…
$ sha256sum crates/frontend/dist/assets/cesauth-frontend_bg.wasm
  752,475        ca7cfd72…            ← the shipped file == exactly one pass
```

**Two conclusions, and the second is the useful one.**

1. **The recipe is behaving correctly.** The shipped artifact is the *single*
   pass of the optimizer over Trunk's current output. The bundle moved from
   753,092 to 752,475 — **−617 bytes, which is uncomfortably close to the −610
   that a second optimizer pass produces** (§2.3), and it would have been easy
   to read as a double-optimize that half A was supposed to prevent. It is not:
   two passes give 751,865, and the shipped hash matches one.
2. **The variability is upstream of `wasm-bindgen`, and now it has been seen
   there.** Every earlier figure in this RFC measured the *post*-optimizer
   artifact. This is the first measurement of the **pre-optimizer** wasm
   changing — `533e1980…` where half A recorded `8b51a72c…` — which is exactly
   what T4's conclusion predicts: `wasm-bindgen` is deterministic given a fixed
   `cargo` output, so a changed pre-optimizer wasm means **`cargo`/`rustc`
   emitted something different for unchanged source.**

So §2.2's finding is confirmed at a one-month interval, at the stage where the
difference originates, and the remaining suspects are `rustc`/LLVM codegen and
the host. Both belong to **half B**, which stays deferred to 1.0 hardening. No
cause is claimed, and these figures are recorded, not treated as invariants
(§2.1).

## 15. Half B has a reproducible datum now, measured twice (2026-10-27)

> **RETRACTED 2026-10-27 — see §15.3.** The gap reported below is a measurement
> error of mine, not a host difference. Rebuilding `c4970ec` today puts my
> figure within **94 bytes** of CI's, against the **3,001** claimed here. Two of
> the four rows in §15 and §15.1 do not even reconcile against their own
> components. **Do not cite §15, §15.1 or §15.2's figures.** The reliable
> cross-host readings are 34 / 94 / 157 bytes — 0.004–0.018% of the artifact.


Half B is *environment* reproducibility — the same commit on another host
yielding an identical artifact — deferred to 1.0 hardening by §12.3. Until now
the only cross-host figure on record was **34 bytes**, from RFC 142's review at
0.84.3, which is small enough to dismiss.

Measuring my own `wrangler deploy --dry-run` against CI's `bundle-size` job on
two consecutive commits during the 0.85.1 cut:

| Commit | CI total gzip | Mine | Gap | `shim.js` gap | wasm gap |
|---|---|---|---|---|---|
| `dbbf5f2` (readiness) | 836,559 | 833,699 | **+2,860** | **+120** | +2,740 |
| `c4970ec` (**0.85.1**) | 836,806 | 833,805 | **+3,001** | **+120** | +2,881 |

**It is reproducible in shape and magnitude, so it is a host difference rather
than noise** — about **0.35%** of the artifact, two orders of magnitude above the
34 bytes previously recorded.

Two observations worth keeping, neither of them a cause:

- **The `shim.js` gap is stable near 120 bytes, but not exactly 120** — see
  §15.1, which corrects an over-reading of two samples. `shim.js` is a generated
  loader and `wrangler` is pinned at 4.131.2, so a consistently non-zero gap
  there is still more surprising than the wasm's. One candidate is that the
  loader embeds the wasm's content-hash filename, which necessarily differs when
  the wasm does — but that makes the gap *derivative* of the wasm difference, and
  a 40-character hash is a thin explanation for ~120 compressed bytes.
  **Not established.**
- **The wasm gap grew with the release commit** (2,740 → 2,881) across a change
  that was a version bump plus documentation, which is consistent with §14's
  finding that the pre-optimizer wasm moves on recompilation.

**What this changes:** nothing in the schedule — half B stays deferred, and the
budget conclusion is unaffected (31% on CI, 31.8% on mine, against a 2.5 MiB
ceiling). What it changes is the evidence: half B can now be opened with a
measured, repeatable figure and a named method instead of a single 34-byte
curiosity. **Recorded in `.git-exclude/release/0.85.1-release-cut.md` §4 as a
discrepancy-ledger entry.**

### 15.1 A third reading, and a correction to §15 (2026-10-27)

CI's `bundle-size` job on the **0.86.0** release commit `aae3aca` reports
**847,989 B** gzip (wasm **837,290**, `shim.js` **10,699**) against my
**845,387** (wasm **835,175**, `shim.js` **10,580**).

| Commit | Release | CI total | Mine | Gap | `shim.js` | wasm |
|---|---|---|---|---|---|---|
| `dbbf5f2` | 0.85.1 readiness | 836,559 | 833,699 | +2,860 | +120 | +2,740 |
| `c4970ec` | **0.85.1** | 836,806 | 833,805 | +3,001 | +120 | +2,881 |
| `aae3aca` | **0.86.0** | 847,989 | 845,387 | **+2,602** | **+119** | +2,115 |

**§15 said the `shim.js` gap was "exactly 120 bytes both times". With a third
sample it is 119.** The figure is stable *near* 120, not identical, and I drew a
sharper inference than two samples could support. The correction matters because
"exactly" invited a mechanical explanation — a fixed-length difference — and
"approximately" does not.

**The wasm gap is not constant either**: 2,740 / 2,881 / 2,115. So the honest
statement is **a cross-host gap of roughly 0.25–0.35% of the artifact, present
on every commit measured, varying per build** — which is still two orders of
magnitude above the 34 bytes recorded at 0.84.3, and still the case for opening
half B. It is no longer evidence of a fixed offset, which is what §15 implied.

Both halves of this entry are the same lesson the 0.85.1–0.86.0 cycle kept
teaching: a figure from two samples is a figure, not a pattern.

## 15.2 A fourth reading, and a reason to doubt the first three (2026-10-27)

0.86.1's bundle, CI against local at the same commit `1c180ca`:

| | wasm gzip | `shim.js` gzip | total |
|---|---|---|---|
| CI (`Worker bundle size budget`) | 844,997 | 10,698 | **855,695** |
| Local (`wrangler deploy --dry-run`, CI's method) | 845,153 | 10,699 | **855,852** |
| **gap** | **156** | **1** | **157** |

Against the three readings in §15 and §15.1 — totals **2,860 / 3,001 / 2,602**,
wasm **2,740 / 2,881 / 2,115**, `shim.js` **119 / 120 / 120** — **both
components collapsed by more than an order of magnitude.** The `shim.js`
component, which §15 called "exactly 120 bytes both times" and §15.1 softened to
"stable near 120 bytes", is **1**.

### The likeliest explanation is my own measurement, not the toolchain

**My local `shim.js` changed from 10,580 to 10,699, and 10,699 is what CI was
already producing at 0.86.0.** The two sides did not converge; **mine moved to
meet CI's**, which had been stable.

The procedural difference is that this time I ran `make build-backend`
immediately before `wrangler deploy --dry-run --outdir`. In the earlier
readings I measured artifacts in `dist/`, **a directory that accumulates
build outputs and is not cleaned between builds** — 32 stale `*_bg.wasm` files
are sitting in it at the time of writing.

**So a real possibility is that some or all of the 2,600–3,000 byte gap was a
stale local artifact being compared against a fresh CI one** — a measurement
error of mine, not cross-host nondeterminism. If that is right, §15's central
observation is not evidence for half B at all, and the "two orders of magnitude
above the 34 bytes at 0.84.3" framing is wrong.

### What this does not establish

**That the gap is 157, or that it is my error.** One reading taken with a
changed procedure cannot overturn three taken with another, and the 156-byte
wasm component is still unexplained. Treating this reading as the true one
would repeat §15's original mistake in the opposite direction.

### The controlled test, which has not been run

The question is now answerable cheaply and should be answered before §15 is
cited again:

1. `rm -rf dist/ bundled/`, build once, measure.
2. Build again without cleaning, measure again. A difference here is local
   staleness and nothing to do with hosts.
3. Compare a clean local build against CI at the same commit. **That** number
   is the cross-host gap; everything in §15 and §15.1 predates this control.

**Until step 3 is done, §15, §15.1 and this section are four readings of an
uncontrolled experiment**, and the honest summary of RFC 133 half B's evidence
is that it does not yet have any. The budget gate is unaffected either way —
32% of 2,621,440 B at every reading.

## 15.3 The controlled test ran, and §15 is retracted (2026-10-27)

§15.2 specified three steps. All three ran. **§15's central claim is false, the
error was mine, and half B does not have the datum §15 said it had.**

### Step 1 and 2 — local determinism holds, and staleness was not the cause

`dist/` moved aside (36 files, 33 of them stale `*_bg.wasm`), then a clean
build, then a second build without cleaning:

| | wasm gzip | `shim.js` | total | wasm sha256 |
|---|---|---|---|---|
| A — clean | 845,153 | 10,699 | **855,852** | `64b384082ca9bb59` |
| B — dirty rebuild | 845,153 | 10,699 | **855,852** | `64b384082ca9bb59` |

**A and B are byte-identical, and both equal the figure measured before `dist/`
was cleaned.** So §15.2's hypothesis — that the earlier gap was a stale local
artifact — is **wrong**: `wrangler deploy --dry-run --outdir` does not read
`dist/`, and local builds of one commit are reproducible to the hash. That is a
positive result worth keeping: **local determinism is established**, which §14
left open.

### Step 3 — rebuilding an old commit destroys §15's numbers

The decisive measurement. Checked out `c4970ec` — the 0.85.1 release commit
§15's second row reports — rebuilt, and measured with the same method:

| | wasm gzip | `shim.js` | total |
|---|---|---|---|
| CI at `c4970ec`, as recorded in §15 | — | — | 836,806 |
| **Mine at `c4970ec`, measured today** | 826,013 | 10,699 | **836,712** |
| Mine at `c4970ec`, as recorded in §15 | — | — | 833,805 |

**Today's build of that commit agrees with CI to within 94 bytes. The figure I
recorded at the time was 2,907 bytes lower than a rebuild of the same commit.**

So the "+3,001 cross-host gap" was not a host difference. **It was my local
total being ~2,900 too low**, and the same is almost certainly true of the
"+2,860" row beside it. The method named in §15 was not the method that
produced those numbers; most plausibly a smaller or older artifact was measured.

### What the reliable readings actually say

| Commit | Release | gap | as % of artifact |
|---|---|---|---|
| RFC 142's review | 0.84.3 | 34 | 0.004% |
| `c4970ec`, rebuilt today | 0.85.1 | **94** | 0.011% |
| `1c180ca` | **0.86.1** | **157** | 0.018% |
| `770e4c7` | **0.86.2** | **381** | 0.044% |
| `9d0783a` | **0.86.3** | **10** | 0.001% |
| `d749fef` | **0.87.0** | **15** | 0.002% |
| `a71ca1f` | **0.87.1** | **69** | 0.008% |
| `7f9c8ce` | **0.88.0** | **391** | 0.044% |

(The 0.86.2 row was added after the cut. CI **868,077** = 857,378 + 10,699;
mine **868,458** = 857,760 + 10,698. Both reconcile against their parts.)

**Every internally consistent reading is in the tens-to-low-hundreds of
bytes**: 34, 94, 157, 381, **10**. The first four each roughly doubled, which
looked like a trend until the fifth broke it, and the sixth and seventh
confirmed the break: **34 / 94 / 157 / 381 / 10 / 15 / 69 / 391**, with no
monotonic shape across any four consecutive points — the largest and the
smallest readings sit three apart. **Good thing no curve was drawn** —
the refusal has now survived three additions, two of which would have
contradicted any line fitted to the four before them. Seven readings, and one
claim they all support: **under 0.05% of the artifact, every time.** Four points whose method
changed partway through (the first three predate the clean-build control, and
only the last two were taken with it) cannot support a curve, and reading one
into them would be §15's mistake a fourth time. What the readings support is a
bound: **under 0.05% of the artifact**, on every commit measured.
§15's claim that the gap is *"about 0.35% of the artifact, two orders of
magnitude above the 34 bytes previously recorded"* is **wrong by two orders of
magnitude in the other direction**, and the 34 bytes it dismissed as "small
enough to dismiss" was the representative figure all along.

### Three things I got wrong, in order

1. **§15 reported a ~2,900-byte gap that was a measurement error**, and called
   it "reproducible in shape and magnitude, so it is a host difference rather
   than noise". Two wrong readings agreeing with each other is not
   reproducibility; it is the same mistake twice.
2. **§15.1's "correction" rested on a broken row.** The 0.86.0 reading it used
   to overturn "exactly 120 bytes" does not reconcile with itself: my component
   figures sum to 845,755 against a stated total of 845,387, and the component
   gaps sum to 2,234 against a stated gap of 2,602 — **the same 368 bytes
   missing in both places.** So the `shim.js` figure of 119 that the correction
   turned on is not trustworthy either. Of the four rows on record, **two are
   arithmetically self-inconsistent and both are mine.**
3. **§15.2 blamed the wrong cause.** It proposed stale artifacts and then said
   the matter needed a controlled test — which was right — but it also framed
   staleness as "the likeliest explanation", which steps 1 and 2 refute.

### What this changes

- **§15, §15.1 and §15.2's figures are retracted.** They stay in place rather
  than being deleted, because the record of how a number survived four
  recordings is worth more than a clean file — the same reason RFC 047's
  annotation was kept.
- **Half B stays deferred and now has *less* reason to be opened early**, not
  more. A 0.004–0.018% cross-host difference in a non-reproducible-by-design
  optimizer pipeline is the ordinary case, not a finding.
- **The budget conclusion never moved**: 32% of 2,621,440 B at every reading,
  on either host.
- **The standing lesson is narrower than "two samples are not a pattern".** It
  is: **a derived figure must reconcile against its own parts before it is
  recorded.** Both broken rows would have been caught at entry by adding two
  numbers together, and §15.2's table is where that check finally happened.
