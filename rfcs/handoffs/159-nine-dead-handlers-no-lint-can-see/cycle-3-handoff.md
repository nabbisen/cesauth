# Developer Handoff — RFC 159, cycle 3 (small)

**Governing RFC.** `rfcs/done/159-nine-dead-handlers-no-lint-can-see.md`
— **§4.3** and **§4.4**, both new, both found reviewing `132c3a0`.
**Review.** `.git-exclude/reviewed/159-continuation-review.md`
**Builds on.** `132c3a0` on `main`, committed and pushed. Nothing to revert.

**Target release.** **0.89.2 — patch**, unchanged. The cut waits on this.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-30.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. §4.1 and §4.2 are met, and §4.2 is better than what I asked for

The tenth is gone and unreferenced, the census is zero, the check exits 0 on a
clean tree and 1 on all four probes — I re-ran the brace probe, the renaming
probe and the unclassified-shape probe myself rather than reading your log, and
all three fire and restore byte-identical.

**The by-value/by-reference split is the find of this cycle.** §4.2 said "either
classified as a handler or named as a non-handler with a reason, and anything
else fails". Naming 193 handlers would have satisfied that sentence and produced
an allowlist nobody reads. You found the invariant instead: a handler owns its
request because it *is* the entry point, a helper borrows it because it is called
*by* one. I printed all 22 `NAMED_NON_HANDLERS` signatures to check it rather
than trusting the claim — `&Request`, `&mut Request`, `&RouteContext<D>`, `&Env`
or no such parameter, 22 for 22, and `gate.rs::resolve_or_respond`'s
by-value `principal: AdminPrincipal` is the only owned parameter anywhere in the
list and is not a request. That is why adding a route costs no script edit, and
it is the difference between a gate that survives and an exemption list that
rots.

Two findings follow. Neither is a reason to revert anything. Both are in the ten
lines around E4's two greps.

## 2. §4.3 — print the count, not the literal

The coverage line ends `0 unclassified` as a **string literal**. The
unclassified block sets `exit_code=1` without exiting, so in a failing run the
gate names the finding and then reports there are none. My probe, verbatim:

```
❌  pub async fn(s) under routes/ matching NEITHER known handler signature shape NOR on NAMED_NON_HANDLERS:
    crates/backend/src/routes/admin/console/_probe_shape.rs:1 (fn weird_new_shape)
…
ℹ️   E4 coverage: scanned 216 pub async fn under routes/ -- 193 classified as handlers (182 RouteContext-shaped, 11 Env-shaped), 22 named non-handlers, 0 unclassified
```

**216 ≠ 193 + 22 + 0.** Nothing dead ships behind it — the build is red — but
that `ℹ️` line is the one a maintainer greps out of a CI log, and in the only
run where it is load-bearing it is false and its arithmetic does not close.

**Do:** count the unclassified entries and print the count. **Make the identity
hold in every run**, passing or failing: `scanned == handlers + named +
unclassified`. If you want to go one step further, assert it in the script and
fail on a mismatch — a coverage line that cannot be inconsistent is worth more
than one that happens to be consistent, and it costs two lines.

**Evidence I want:** probe 3 re-run, showing `216 … 1 unclassified` and the four
figures summing, and a clean run showing `215 … 0 unclassified` with the same
identity holding.

## 3. §4.4 — a commented-out registration reads as live, and as documented

This is the one that matters, and it is the mirror of the bug **you** found and
fixed last cycle.

E4 decides liveness with `grep -qF "routes::<path>("` against `lib.rs` —
unanchored, comment-blind. My probe: comment out `lib.rs:285`, the single edit a
developer makes to disable a route.

```
        // .get_async ("/admin/console.json",  … routes::admin::console::overview::page_json(req, ctx).await })

ℹ️   E4 coverage: scanned 215 … 0 unclassified
✅  All 193 routes are documented in route-contracts.md, and every handler-shaped fn in routes/ is reachable from lib.rs
```

Exit **0**. `GET /admin/console.json` is unserved, `overview::page_json` is
unreachable, and the check built to catch unreachable handlers certifies them all
reachable. (`lib.rs` restored byte-identical, `diff` clean.)

**You already solved this once.** Your `pub use` grep is `^pub use …` — anchored,
which is exactly why the renaming probe fires on a commented-out re-export
instead of silently passing the way your first draft did. The `lib.rs` grep
never got the same treatment. One side of the resolver is comment-safe and the
other is not.

**The half I actually care about is not E4's.** The registered-route extraction
two blocks up (RFC 027/125, `grep -E '\.(get|post|put|delete)_async\s*\("'`) is
comment-blind too — with line 285 commented the count stayed **193**, so
`docs/src/expert/route-contracts.md` is still *required* to document, and still
*credited* with documenting, a route the Worker does not serve. **A disabled
route leaves the published contract table asserting it exists, with every gate
green.** That is a documentation lie reachable by two characters, and it is
user-facing in a way the E4 half is not.

**Do:** make "a line whose first non-whitespace is `//` is not a registration"
true for **both** greps, **from one shared step** — strip once into a variable or
a temp file and have E1's extraction and E4's liveness grep both read it. Two
separately-patched greps is how this file got two different blind spots in the
first place.

**Trap, and I want you to prove you avoided it:** whole `//` lines only, matched
after trimming leading whitespace. `//` occurs inside path and URL string
literals, and `lib.rs:523` registers the catch-all path `"/*catchall"` — a naive
`/* … */` block stripper eats the rest of the file from that line. Do not attempt
block comments; there are none in `lib.rs` and `"/*catchall"` makes the attempt
actively dangerous.

**Evidence I want, four things:**

1. **Fires:** `lib.rs:285` commented out → E4 reports
   `routes::admin::console::overview::page_json` dead, **and** E1 reports
   `GET /admin/console.json` as documented-but-not-registered (the `⚠ stale`
   branch), since the row stays in `route-contracts.md`. Both halves, not one.
2. **Does not fire:** restored, `exit 0`, `diff` against a scratch copy clean,
   `git status --short` empty.
3. **The `"/*catchall"` guard:** show `GET /*catchall`'s registration still
   extracted and the registered count still **193** after the change. A count
   that moves means the stripper ate something.
4. **Unchanged counts:** registered **193**, scanned **215**, handlers **193**
   (182+11), named **22**, unclassified **0**.

## 4. Scope — three things explicitly not yours this cycle

1. **`no_duplicate_route_registrations` in `lib.rs`'s test module.** It is the
   third implementation of this same extraction and it is blind to whitespace as
   well as comments — 88 of the 193 registrations are written `.get_async (`
   with a space and its needle is `.get_async("`, so it covers **105 of 193**,
   including missing `/me/security/sessions`, the route it was written to
   protect. **Do not touch it.** It is RFC 011's deliverable and the question it
   raises (three private extractors, or one) is a fork for the owner:
   `rfcs/accepted/163-two-route-extractors-two-blind-spots.md`. Mentioned here
   only so you do not "fix" it in passing and so you know why §3 says *one
   shared step* rather than *one shared extractor*.
2. **Block comments, `patch_async`, `or_else_any_method_async`, re-export chains
   deeper than one level.** All out of scope, all for the same reason: no route
   in this repository uses them, and a gate that handles cases the codebase does
   not have is a gate nobody can check.
3. **RFC 161, RFC 162, RFC 158 §5.5.** Untouched, as before.

## 5. Gates

The change is confined to `scripts/route-contracts-check.sh`. Run the **full**
set anyway — it is release-gating and this is the commit the tag will sit on —
and report with counts and their commands, as usual:

- Host tests, CI's exact five-crate command, **no `--lib`**, summed with `awk`
  over the full output. Baseline **1,630** passed / 0 failed / 12 `test result`
  lines. Nothing in this cycle touches Rust, so a change here is a finding.
- `migration_chain` — **35**.
- `route-contracts-check.sh` — **193** routes, census **zero**, coverage
  identity holding; plus §2's and §3's probes.
- clippy (six crates, `-D clippy::correctness`), both `wasm32` checks,
  `cargo deny`, `cargo audit`, `drift-scan.sh --verbose`, `mdbook build docs`,
  `make build-frontend` / `build-backend`, `runtime-smoke-check.sh`, Playwright
  (**20**).
- Bundle by CI's own method, with `du -b`, gzip **and** full **64-character**
  sha256 per module, and the parts reconciled against the total.
- `.github/release-gate-manifest.json` — **13** release entries, unchanged.

**One process note on evidence.** Last cycle's report said "all logs in
`evidence-159-continuation/`" and there were seven, for a thirteen-row table —
§5's four-endpoint 401/404 proof had no log at all, so the one claim I could not
re-run is the one I could only corroborate statically. Either every row in the
table gets a log or the report says which rows do not. "All" should mean all.

## 6. Back-fill

Propose the §4.3/§4.4 Status and Evidence lines in RFC 159's terms
(`exercised` / `observed` / `reviewed` / `unknown`, RFC 000 §22) the way you did
last cycle. I will apply them, move the RFC to `done/`, and write the CHANGELOG
and ROADMAP entries at the cut.

Report into `.git-exclude/review-request/`.
