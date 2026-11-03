# Developer Handoff — RFC 174 stage 1: stop the ledger claiming an action that did not happen

**Governing RFC.** [`rfcs/accepted/174-applying-a-log-level-writes-an-audit-event-for-nothing.md`](../../accepted/174-applying-a-log-level-writes-an-audit-event-for-nothing.md)
— accepted by the owner 2026-11-03. **Read §3 and then read this §1: only one
part of §3 is dispatched, and it is not the part that chooses the feature.**
**Review that found it.** `.git-exclude/reviewed/173-review.md` §4
**Builds on.** `main` at or after tag `0.92.2` (`fc3e0d8`).

**Target release.** **Patch — the next cut after 0.92.2.** Number assigned at
the cut.
**Tier.** **P1.** Not an exposure. A hash-chained audit row asserts an operation
that cannot occur, and the operator is shown success.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing in this stage. **Dispatched 2026-11-03.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. What is dispatched, and what is deliberately not

`POST /admin/console/config/log_level/apply` (`config.rs:459-473`) writes to
`env.kv("CONFIG_KV")` — a namespace this project does not declare, and which can
only come from `wrangler.toml` — inside `if let Ok(kv)`, so the write is skipped
in silence. `LogConfig::from_env` (`log.rs:155-163`) reads only
`env.var("LOG_LEVEL")`, so the value would be ignored even if it landed. The
handler then writes **`OperationApplied` — `"log_level applied: X -> Y"`** into
the audit chain, unconditionally, and 303s back to the page.

**In scope: make it tell the truth.** True under both of §3's answers, which is
exactly why it goes first.

**NOT in scope — do not do either of these:**

- **Do not declare `CONFIG_KV` and do not make `from_env` read it.** That is
  §3(a), it is a runtime override this product has never had, it wants a caching
  and TTL decision on a hot path, and the RFC says it is a **minor**.
- **Do not remove the route, the preview, or the page's affordance.** That is
  §3(b). It is the architect's recommendation and it is **not yet the owner's
  decision**; removing an operator affordance is not a call a cycle makes.

**If you find yourself needing either to finish stage 1, stop and report** —
that would mean §3's question blocks the honest-failure fix, which I do not
believe it does, and I would rather be told than have it decided inside a patch.

## 2. The change

1. **The audit event is written only if the change actually took effect.** No
   `OperationApplied` row on a path where nothing was stored. If you keep an
   audit row for the attempt, it must not read `applied` — a different
   `EventKind`, or wording that says what happened, and say in the report which
   you chose and why.
2. **The operator is told.** A silent 303 to a page that looks like success is
   the same lie one layer out. Fail closed and visible: the existing
   `?preview_error=1` pattern three lines above is the precedent in this very
   handler for redirecting with a reason the page renders. **Reuse the
   established shape rather than inventing a new one**, and make the message say
   that the level was *not* changed — not that something generic went wrong.
3. **The misleading comments go.** `config.rs:462`'s *"KV binding: CONFIG_KV
   (must be declared in wrangler.toml)"* states a requirement that was never
   met, and the lines above it describe a `from_env` preference that does not
   exist. Replace them with what is true, including a pointer to RFC 174 §3 for
   why the feature's shape is still open.

## 3. Tests

- **A host test on the decision**, not on `worker::Env`: the choice *"was
  anything stored, and therefore may an `applied` audit row be written"* should
  be a pure function you can call. If that is not extractable without a bigger
  refactor than this fix warrants, **say so in one line and test what you can**
  — the standing rule about an impossible evidence requirement applies, and this
  handler's `Env` dependency is real.
- **A live capture** against `wrangler dev`: `POST` the apply action with a
  valid preview token and capture the status line **and the response body or
  redirect target** — the operator-visible outcome must say the level was not
  changed. `contributing.md`'s refined live-probe ruling applies: where two
  outcomes share a status, the status is not the evidence.
- **Confirm no `OperationApplied` row is written** for that request, by querying
  `audit_events` directly rather than inferring from the response. The whole
  finding is that the response and the ledger disagreed with reality, so neither
  one alone is a witness.

## 4. Stop conditions

- The honest-failure path cannot be built without declaring the binding or
  touching `from_env` — report it; that is §3's question surfacing and it is not
  yours to answer.
- `EventKind` has no variant that fits an attempt that did not apply, and adding
  one looks like more than a patch — report what you would add rather than
  adding it.
- The preview half (`/log_level/preview`) turns out to be affected too — it is
  one of the two `required (preview-token binding)` rows E6 validates, so a
  change there moves a CSRF cell and that is a different conversation.
- Any route-contracts row needs to change. None should in this stage.

## 5. Not in this cycle, named so it is not quietly assumed

- **§3's (a)/(b) choice** — put to the owner with this dispatch.
- **`operations_route.rs`'s never-constructed `CronRecord`** — RFC 174 §5 item
  4. The cron records finally persist as of 0.92.2 and nothing displays them;
  building a reader is unscoped work in RFC 161's family.
- **The config-only binding gate** (`env.kv`/`env.d1`/`env.bucket`/
  `env.durable_object` names must be declared in `wrangler.toml`) — RFC 174 §4.
  It belongs with RFC 171's family and a P1 fix should not wait on it. **Note
  the narrowing in §4 before you are tempted to widen it**: run over
  `env.secret` and `env.var` too, the same census produces thirteen false
  positives.

## 6. Baselines at tag `0.92.2` (`fc3e0d8`), each with its command

- host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,694 passed, 0 failed, 4 ignored, 12 `test result:` lines**;
- `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
- `bash scripts/route-contracts-check.sh` → 194 routes; E4 `218 = 194 + 24 + 0`; E5 `17 = 17 + 0 + 0`; **E6 `94 = 85 claims + 9 declared + 0 unclassified`**, `85 = 67 + 0 + 18`;
- `bash scripts/drift-scan.sh` → clean;
- `mdbook build docs` → clean, 82 pages;
- `npx playwright test` in `e2e/` → **20** — needs `node_modules/.bin/wrangler dev --port 8787` already serving **and warm**;
- `bash scripts/runtime-smoke-check.sh` → passed;
- bundle, `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15 at its default level** → **897,191 B** (886,492 wasm + 10,699 `shim.js`), raw 2,454,460 + 61,887, measured at the tag after its version bump.

**Name the command, the commit and the gzip level for every figure.** `-9` reads
~4.2 KB lower on identical bytes and that gap was once mistaken for an
environment difference (RFC 133 §16).

---

# WITHDRAWN and replaced — 2026-11-03

**Do not implement anything above.** The owner has chosen RFC 174 §3**(b)**
(*"Your recommendation is accepted."*), so the handler this handoff asked you to
make honest **is being deleted instead.** Building an honest failure message for
a route that is about to go would be work with a one-cycle lifespan, and the
reason I split the RFC in two — that stage 1 was true under either answer — stops
applying the moment (b) is chosen.

**If you already started: stop, and keep nothing.** Report what you had, so the
record says what was thrown away and why.

**The replacement is `removal-handoff.md`, in this directory.** It is smaller
than this was.

**And read RFC 174 §0 first.** A live probe found that this handoff's premise was
partly wrong — the console renders no log-level control at all, and the apply
route answers **400** before it can reach either the KV write or the audit row.
The defect is narrower than the RFC first said, the tier is now **P2**, and the
correction is the architect's.
