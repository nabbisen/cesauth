# How the T5 bundle-attribution figures were produced

**Round 2 correction**: round 1's report cited this directory by path
without ever committing it, and conflated two different grep scopes in
its own prose (see the ruling, `.git-exclude/reviewed/
0.109.0-slice-b-review-and-phase2-g1-decision.md` §1.3). This note plus
the files beside it are the fix: the actual commands, their actual
output, committed.

## Build

```
cd crates/frontend && rm -rf dist
CARGO_PROFILE_RELEASE_STRIP=none trunk build --release --filehash false
```

Same recipe `bundle-size.yml`'s new step runs in CI (see that file).
Reproduced twice, byte-identical both times:

```
sha256: 7642ea6b52c753bfb7cb920f132d337a2dbb058082d44e401e8faeafa88b3412
size:   13,275,952 bytes
```

This is **not** the shipped artifact — `[profile.release] strip = true`
(root `Cargo.toml`) is still in effect everywhere else; only `strip` is
overridden, by an env var, for this one measurement build, so twiggy has
a wasm "name" section to attribute against. `twiggy top` against the
shipped, `wasm-opt`'d bundle and against the pre-`wasm-opt` artifact
(same build, strip left at its real value) were both tried first and
both report zero named symbols — only `code[N]`/`data[N]` — confirming
`strip = true`, not `wasm-opt`, is what removes the names.

## The three commands behind every figure in the report

```
twiggy top -n 40 <wasm>            → twiggy-top-40.txt       (same as the CI artifact)
twiggy top -n 20000 <wasm>         → 10,963 total rows (not committed, see below)
grep "ChainStatusView\|ColumnDivergence" <the 20000-row output>
                                    → twiggy-top-full-chainstatusview-columndivergence-rows.txt
```

The middle command's full output (10,963 rows, ~12 MB, dominated by
`leptos_router`/`reactive_graph` generic closure names that are not
relevant to this question) is not committed; the grep against it is —
every row it matched, unfiltered beyond the two literal substrings, so
nothing is cherry-picked.

## What the grep file actually supports — corrected from round 1

Round 1's report described this as one sum, *"9,155 bytes across 51
rows,"* then separately claimed a 71% share, without saying whether the
sum was `ChainStatusView` alone or `ChainStatusView` **or**
`ColumnDivergence` — it was, in fact, the former; the committed file
contains both patterns, and the two do not overlap (no row matches both
substrings, confirmed: 51 + 20 = 71 exactly):

| scope | rows | bytes | share of +12,841 B |
|---|---|---|---|
| `ChainStatusView` only | 51 | 9,155 | 71.3% |
| `ColumnDivergence` only | 20 | 3,460 | 27.0% |
| both (the committed file's full total) | 71 | 12,615 | 98.2% |

**The 71.3% figure is what round 1 meant to claim and did not support
in the tree; it is now reproducible from the committed file with
`grep "ChainStatusView" twiggy-top-full-chainstatusview-columndivergence-rows.txt`.**
The combined 98.2% is also real, from the same file, and is reported
alongside it rather than instead of it.

## The caveat this number needs, stated rather than omitted

**This measurement is proportions inside an unstripped, non-`wasm-opt`'d
debug build; the +12,841 B figure it is being compared against is a
delta in the shipped, `wasm-opt -Oz`'d, gzip'd artifact.** The two are
not the same unit, and `wasm-opt`'s dead-code elimination, inlining and
deduplication do not necessarily preserve one symbol's size relative to
another's — a function that is 4,301 B here could compress or inline
away to a different share after `-Oz` and gzip. The **direction** of the
finding is solid (named, not theorized: it is the serde/reactive
machinery for the two RFC 188 Phase 1 types the frontend's own
`ChainStatusView` had to widen to match, and it is definitively **not**
the verifier — grepped the full 10,963-row table for `verifier`,
`AuditPayloadMirror`, `CROSS_CHECKED`, `payload_and_divergence`: zero
matches, confirming the frontend links none of it). The **percentage**
should be read as "this is where the growth is concentrated in the
measurement that can see names," not as a byte-exact reconciliation of
the shipped delta — no measurement in this slice reconciles that,
and none is claimed to.
