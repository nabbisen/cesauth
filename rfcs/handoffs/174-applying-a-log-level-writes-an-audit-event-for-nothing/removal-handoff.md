# Developer Handoff — RFC 174 (b): remove the log-level apply flow

**Governing RFC.** [`rfcs/accepted/174-applying-a-log-level-writes-an-audit-event-for-nothing.md`](../../accepted/174-applying-a-log-level-writes-an-audit-event-for-nothing.md)
— **read §0 first.** It corrects the RFC's own §1 with a live probe and records
the owner's decision: **§3(b), remove the action and document the log level as
deploy-time only.**
**Supersedes.** `stage-1-handoff.md` in this directory, withdrawn — see its
footer. **Nothing from it is wanted.**
**Builds on.** `main` at or after tag `0.92.2` (`fc3e0d8`).

**Target release.** **Patch — the next cut after 0.92.2.** Number at the cut.
**Tier.** **P2** (downgraded in §0; the architect wrote the P1 and was wrong
about its most quotable claim).
**Trigger: none, argued.** Nothing gains capability and nothing an operator can
reach changes behaviour: the console renders **no** log-level control, and the
apply route answers **400** to the only form that posts to it. This removes two
routes that can never complete.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-03.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. What to remove

- `log_level_preview` and `log_level_apply` in
  `crates/backend/src/routes/admin/console/config.rs` (handlers at **337** and
  **426**), and their two registrations in `lib.rs` (**298**, **299**).
- Their two rows in `docs/src/expert/route-contracts.md` (**115**, **116**).
- The misleading comments that go with them — `config.rs:462`'s *"KV binding:
  CONFIG_KV (must be declared in wrangler.toml)"* names a requirement never met,
  and the lines above it describe a `LogConfig::from_env` preference that does
  not exist. **They go out with the code, not after it.**
- `e6_mechanism_check`'s `"preview-token binding")` arm in
  `scripts/route-contracts-check.sh` (**1375**) — see §3.

**Leave alone:** the generic `/admin/console/config/:bucket/{preview,apply,edit}`
routes (they are a different flow and do not use preview tokens), the
`EditBucketSafety` action (still used by them), and `config::page` itself.

## 2. What NOT to remove, and why it is a decision rather than an oversight

**`cesauth_core::admin::preview` stays.** After this change
`mint_preview_token`/`verify_preview_token` have **no production caller** —
`grep -rn "mint_preview_token\|verify_preview_token" crates/` returns only
`config.rs:381` and `:447`, both of which you are deleting.

**Keeping it is the architect's call, and the reason is on the record**: it is
**12 host tests** of a correct HMAC mechanism that binds a CSRF value into a
signed token, the generic bucket preview/apply pair is the obvious future
consumer, and deleting a well-tested primitive to satisfy a reachability rule is
how it gets rewritten worse later.

**But RFC 166's discipline is that a caller-less `pub` item is *named with a
reason*, not silently kept.** So: **add it to RFC 166 §3's census list** as a
deliberate, dated entry. If you think it should go instead, **say so and do not
delete it** — that is a design argument, not an implementation step.

## 3. Numbers that move, and a gate arm nothing would have caught

Expect, and **report with the command**:

- routes **194 → 192**;
- E4 scanned **218 → 216**, handlers **194 → 192**, named non-handlers **24**
  unchanged;
- E6 scanned **94 → 92**, claims **85 → 83**, resolved **67 → 65**, declared
  **9** and exempted **18** unchanged.

**And the dead gate arm.** Removing the only two rows whose cell reads
`required (preview-token binding)` leaves `e6_mechanism_check`'s arm for it
matching nothing. **I checked: nothing fails.** The "scanned-but-never-matched"
staleness discipline covers `NAMED_NON_HANDLERS` and the exemption lists, not
the mechanism `case`'s arms. So **remove the arm as part of this change** — and
note that this is the same lesson your own RFC 152 half D cycle taught: *a
gate's unused code path is not a working code path.* **Extending the staleness
check to the mechanism arms is queued separately; do not build it here.**

## 4. Tests

- **Host tests will drop** by whatever the deleted handlers' own tests cover —
  report the number and which tests went, so the count's movement is explained
  rather than noticed. `preview.rs`'s 12 tests **stay** (§2).
- **No new test is owed for deleted code.** Do not add a test asserting a 404;
  E4 and the route-contract check already assert the registered set, and a test
  that a route does not exist rots the day someone adds it back for a reason.
- **A live capture** that the two paths are gone: `POST` each and capture the
  status. Expect whatever `lib.rs`'s fallback gives an unregistered admin POST —
  **capture it, do not predict it**, and if it is a 200 of any kind say so
  loudly, because that is RFC 141 §10.2's shape.

## 5. Stop conditions

- **Anything in `docs/src` claims the log level is changeable at runtime or from
  the console.** I checked and nothing does — every mention treats `LOG_LEVEL`
  as a `wrangler.toml` `[vars]` value. **If you find one I missed, fix the doc in
  this cycle** and say so: removing a route while a page still promises it is
  this project's signature failure, and it would turn a P2 cleanup into a new
  instance of it.
- **The frontend references either path.** E5 covers `.json` fetches only, so
  check `crates/frontend/` by hand; a dangling client reference is RFC 162's
  class.
- **`config::page` turns out to render the control after all** — I probed it and
  it rendered **zero** forms, but I probed one page with one role. If a role or
  state makes it appear, **stop**: that is an operator affordance and (b)'s
  premise changes again.
- Either deletion forces a change in `cesauth-core` beyond §2's census entry.

## 6. Baselines at tag `0.92.2` (`fc3e0d8`), each with its command

- host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,694 passed, 0 failed, 4 ignored, 12 `test result:` lines**;
- `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
- `bash scripts/route-contracts-check.sh` → **194 routes**; E4 `218 = 194 + 24 + 0`; E5 `17 = 17 + 0 + 0`; **E6 `94 = 85 + 9 + 0`**, `85 = 67 + 0 + 18`;
- `bash scripts/drift-scan.sh` → clean;
- `mdbook build docs` → clean, 82 pages;
- `npx playwright test` in `e2e/` → **20** — needs `node_modules/.bin/wrangler dev --port 8787` already serving **and warm**;
- `bash scripts/runtime-smoke-check.sh` → passed;
- bundle, `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15 at its default level** → **897,191 B** (886,492 wasm + 10,699 `shim.js`), raw 2,454,460 + 61,887. **Expect it to shrink** — this deletes two handlers and their rendering. Report the figure with its level named.
