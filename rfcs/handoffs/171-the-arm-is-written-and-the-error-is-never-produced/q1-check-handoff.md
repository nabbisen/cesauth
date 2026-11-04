# Developer Handoff — RFC 171 §3 Q1: build the check

**Governing RFC.** [`rfcs/accepted/171-the-arm-is-written-and-the-error-is-never-produced.md`](../../accepted/171-the-arm-is-written-and-the-error-is-never-produced.md)
§3 Q1 and §4.
**The census is the specification**:
[`q1-census.md`](q1-census.md) in this directory — **§6 is the shape, §5 is the
expected output, §3's per-section tables are the data.**
**Review.** `.git-exclude/reviewed/171-q1-census-review.md`
**Builds on.** `main` at or after tag `0.92.4` (`4a4cdad`), **14/14 CI green**.

**Target release.** **Patch — the next cut after 0.92.4.** Number at the cut.
**Tier.** **P1** by RFC 171's own tiering. **Trigger: none** — a gate.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-04.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The predicate, and it is the whole check

**Fail when a method's caller-matched `PortError` set is not a subset of its
production adapter's producible set.** Census §6.3, unchanged. Everything below
exists to make that computable.

**Home: `scripts/route-contracts-check.sh`**, alongside E4/E5/E6. It already has
the census arithmetic shape (`scanned = classified + declared + 0`), the
exemption-staleness discipline (RFC 165 §3) and a named-mechanism table — all
three of which this check needs, and none of which is worth re-inventing in a
new script.

## 2. The two registries — enumerated in the census, not committed as data

**Check this before you plan around it** (I did): §6 and §5.1 *enumerate* both
registries in prose, concretely and by name. **They are not a committed data
file.** So the contents do not need rediscovering, but they do need
transcribing, and the transcription is yours.

**Dispatcher registry** — "matches every variant it names" (census §6.1):
`api_v1::port_error_response` / `unwrap_storage`, `ClientOpError`'s
`From<PortError>`, `AuthFailure`'s. **This is the one that matters**: two of the
census's four sweeps initially under-reported chokepoint-routed calls as "no
named match" until the dispatcher was recognised. A name-grep without this
registry is wrong in the quiet direction.

**Producer registry** — the other direction (census §6.2): `run_err` always
`Unavailable`; `classify_insert_err`/`classify_insert_message` per RFC 160
§4.11's twelve-code table; and the three ad-hoc `contains("UNIQUE")` sites named
in census §5.1, each resolved to its **actual** producible set rather than
guessed from the call site's text.

**Both registries get the staleness discipline from the start** — an entry that
stops matching is a hard failure, per RFC 165 §3. **Do not copy
`e6_mechanism_check`'s own shape here**: its `case` arms are *not*
staleness-checked, which 0.92.3 found the hard way when removing the last row
using a mechanism left a dead arm and nothing failed. That extension is queued
separately; **your new registries should not need it.**

## 3. The acceptance criterion, with real content

A census-derived check that cannot rediscover the census's own findings is not
working. So:

- **It must report the three `chokepoint` DEFECTs** — `PlanRepository::get`,
  `SubscriptionRepository::current_for_tenant`,
  `SubscriptionHistoryRepository::list_for_subscription` (census §5.4).
- **It must report the two `written` DEFECTs as resolved**, not as defects:
  `AdminTokenRepository::create` and `::disable` were **fixed in 0.92.4**
  (RFC 175). A check that still flags them is reading stale data; a check that
  flags nothing is broken.
- **Expect more than three.** The chokepoint residual is explicitly open: the
  shared dispatcher appears at **~50 call sites across 7 files** and the census
  traced **three**. **The check is what closes that residual, so a larger number
  is the check working — not a regression and not something to tune away.**
  If it reports twenty, report twenty.
- **Its own census must reconcile**: `unclassified = 0`, and the arithmetic
  printed the way E6 prints its own. The census's figures to inherit and check
  against: **156 methods = 27 resolved + 5 DEFECT + 124 no_caller** (§3's ten
  subtotals sum to 156 — I verified).

## 4. Do not

- **Do not fix anything the check finds.** Each is its own sizing decision, and
  RFC 175 is the precedent for how one gets handled.
- **Do not touch Q2.** Different half, needs the credentialed job, separate
  check over the same table.
- **Do not widen past `PortError`.** `CoreError` and `worker::Error` are out of
  RFC 171's vocabulary.
- **Do not edit `CHANGELOG.md`.** I write the entry at the cut — and see §6.

## 5. Stop conditions

- **The predicate cannot be computed for some method** without a judgement call
  — name the method and the call you would make, and stop. The census hit
  exactly one such question (§4, the dispatcher) and resolved it centrally
  against RFC 171's own worked example; do the same rather than deciding locally.
- **The check cannot reproduce the three chokepoint DEFECTs** — that is a
  defect in the check, not in the census; report it rather than adjusting the
  expected set.
- **It reports one of the two fixed `written` defects as still a defect** — stop,
  because then either the fix or the check is wrong and knowing which matters
  more than finishing.
- **A registry entry has no stable textual anchor** to match on — report it;
  a registry that silently stops matching is the failure mode this whole RFC is
  about.

## 6. Baselines at tag `0.92.4` (`4a4cdad`), each with its command

- host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,675 passed, 0 failed, 4 ignored, 12 `test result:` lines**;
- `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
- `bash scripts/route-contracts-check.sh` → **192 routes**; E4 `216 = 192 + 24 + 0`; E5 `17 = 17 + 0 + 0`; **E6 `92 = 83 + 9 + 0`**, `83 = 65 + 0 + 18`;
- `bash scripts/drift-scan.sh` → clean;
- `mdbook build docs` → clean, 82 pages;
- `npx playwright test` in `e2e/` → **20** — needs `node_modules/.bin/wrangler dev --port 8787` serving **and warm**;
- `bash scripts/runtime-smoke-check.sh` → passed;
- bundle, `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15 at its default level** → **888,890 B** (878,192 wasm + 10,698 `shim.js`). **Expect it unchanged** — a gate ships no Worker code.

**The cut may wait, and not on you.** `CHANGELOG.md` sits at **82,071 B**, which
RFC 028's guard reads as exactly 80 KB and passes with zero headroom, so the
next entry of any size crosses it — while the file already holds exactly the
five minor series the other rule wants. That conflict is the owner's to settle
and it is unrelated to this work. **Finish and report normally.**
