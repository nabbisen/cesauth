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

## 2. What is established

Measured across two sessions, on identical source:

| Property | Result |
|---|---|
| Repeat build, same session | **byte-identical**, same sha256 |
| Clean rebuild (`cargo clean -p cesauth-frontend --target wasm32-unknown-unknown --release`) | **byte-identical**, same sha256 |
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
