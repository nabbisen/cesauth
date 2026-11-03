# Developer Handoff — RFC 174(b) follow-up: delete the preview cluster

**Governing RFC.** [`rfcs/accepted/174-applying-a-log-level-writes-an-audit-event-for-nothing.md`](../../accepted/174-applying-a-log-level-writes-an-audit-event-for-nothing.md)
**Review.** `.git-exclude/reviewed/174-review.md` — **§4 is this cycle's whole
reason, and it reverses `removal-handoff.md` §2.**
**Builds on.** `abf1020` on `main`.

**Target release.** **Patch — the same cut as `abf1020`.** The cut is held for
this: there is no sense tagging a release that removes a dead flow while the
flow's entire support cluster stays in the tree.
**Tier.** **P2.** No behaviour changes. Nothing reachable is touched.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-03.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. You asked, and the answer reverses what I told you

Your report's §3 asked whether four now-caller-less items should be annotated or
deleted, and did not guess. **Checking it properly made the answer bigger than
the question**: it is not four items, it is **two whole modules**.

Measured — references **outside** `crates/core/src/admin/preview.rs` and
`crates/frontend/src/admin/preview.rs`:

```
preview_body 0   preview_body_noop 0   DiffEntry 0   ImpactStatement 0
ImpactSeverity 0   log_level_impact 0   admin_token_rotation_impact 0
PreviewTokenPayload 0
```

**`removal-handoff.md` §2 told you to keep `mint_preview_token`/
`verify_preview_token` and gave two reasons. The load-bearing one is false.** I
wrote that the generic bucket preview/apply pair was *"the obvious future
consumer"*; it is not and never was — `config::preview` returns a plain
`json_response` and has no preview-token or impact-statement concept in it. **I
asserted a consumer without checking that it consumed.** The annotation you
added exactly as instructed gets deleted with the module; following the
instruction was right.

## 2. Delete

- `crates/core/src/admin/preview.rs` — whole file, **12 tests**.
- `crates/frontend/src/admin/preview.rs` — whole file, **7 tests**.
- `pub mod preview;` at `crates/core/src/admin.rs:41` and
  `crates/frontend/src/admin.rs:33`.
- Any now-unused `use` left behind in either crate. `cesauth-backend` denies
  `unused_imports` as a crate attribute; **`core` and `frontend` do not**, so
  clippy's warning is the only signal there — read it, do not rely on the build
  failing.

**`admin_token_rotation_impact` goes with the file**, which resolves your
separate observation: it never had a caller, it lives in the cluster, and it
leaves in the same commit instead of becoming its own census line.

## 3. Record where it went, because deleting is not the same as losing

Add a dated entry to **RFC 166 §3's census list** naming the cluster, the
commit it is recoverable from (`git show <this commit>^:crates/core/src/admin/preview.rs`),
and the one-line reason: its only consumer was removed by RFC 174(b), the
"future consumer" argument was checked and found false, and keeping two dead
modules would be a deliberate instance of the class RFC 166 exists to stop.

**That entry is the deliverable, not a courtesy.** A deletion with no record is
how the same thing gets rebuilt worse in a year.

## 4. Expected movement — report each with its command

- **host tests drop by 19** — 1,694 → **1,675**. If it is not exactly 19,
  something else was dragged along: **stop and report rather than adjusting the
  number.**
- route figures **unchanged**: 192 routes, E4 `216 = 192 + 24 + 0`,
  E6 `92 = 83 + 9 + 0`. No route is touched. **If any of these move, stop.**
- `drift-scan.sh` clean, `mdbook build docs` clean — **no doc references either
  module** (I checked: zero hits across `docs/src` for every name above). If you
  find one, fix it in this cycle and say so.
- bundle **should shrink again**; report it with its gzip level named.

## 5. Stop conditions

- The host-test delta is not exactly **19**.
- Any route or E6 figure moves.
- Either module turns out to have a consumer my grep missed — **report it and
  delete nothing.** My last two assertions about consumers in this area were
  wrong, so treat this one as a claim to test, not a fact to act on.
- Deleting either file forces a change anywhere outside the two `pub mod` lines
  and unused imports.

## 6. Baselines at `abf1020`, each with its command

- host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,694 passed, 0 failed, 4 ignored, 12 lines**;
- `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
- `bash scripts/route-contracts-check.sh` → **192 routes**; E4 `216 = 192 + 24 + 0`; E5 `17 = 17 + 0 + 0`; **E6 `92 = 83 + 9 + 0`**, `83 = 65 + 0 + 18`;
- `bash scripts/drift-scan.sh` → clean;
- `mdbook build docs` → clean, 82 pages;
- `npx playwright test` in `e2e/` → **20** — needs `wrangler dev --port 8787` serving **and warm**;
- `bash scripts/runtime-smoke-check.sh` → passed;
- bundle, `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15 at its default level** → **888,983 B** (878,283 wasm + 10,700 `shim.js`), your own figure at `abf1020`.
