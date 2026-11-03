# Developer Handoff — RFC 171 §3 Q1: the producer census

**Governing RFC.** [`rfcs/accepted/171-the-arm-is-written-and-the-error-is-never-produced.md`](../../accepted/171-the-arm-is-written-and-the-error-is-never-produced.md)
— **§3 Q1 and §4. Read §4 before you start; it is the trap this cycle exists to
avoid.**
**Builds on.** `main` at or after tag `0.92.3` (`5cff52e`), **14/14 CI green**.

**Target release.** **Patch — the next cut after 0.92.3.** Number at the cut.
**This is a census: a stage, not a release.** It produces a table and a number;
**the check that reads them is the next dispatch, not this one.**
**Tier.** **P1** by RFC 171's own tiering — ten shipped paths branched on an
error nothing produced, and nothing asks the question.
**Trigger: none** — no product code changes. A census is a document.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-04.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The question, and why the census comes first

**Q1: for every `PortError` variant a handler matches, can the adapter behind
that call return it?** A caller matching a variant nothing produces is a defect
— that is RFC 160 §4.11's ten paths, found by hand. A producer whose variant
nobody matches is at worst noise.

**The census runs first and alone because its number decides the check's
shape.** Same discipline as RFC 166 §3, and the reason is in RFC 171 §4: *the
cheap half of Q1 is a table, and writing the table and stopping would make this
the eleventh instance of a documented rule with no gate.* **So the deliverable
is the table *and* the number that sizes the check** — not an essay about how
nice a check would be.

## 2. What I verified before writing this, and one number I refused to quote

Per a standing correction of mine: four consecutive dispatches named an
artifact that did not exist or did not behave as stated. **Everything numbered
below I ran. The one I could not stand behind, I left out and said so.**

**`PortError` has five variants** (`crates/core/src/ports.rs:47`): `NotFound`,
`Conflict`, `Unavailable`, `PreconditionFailed`, `Serialization`.

**Matched in `cesauth-backend` — 60 mentions:**

| variant | backend mentions |
|---|---|
| `NotFound` | 19 |
| `Conflict` | 17 |
| `Unavailable` | 16 |
| `PreconditionFailed` | 6 |
| `Serialization` | 2 |

**Produced:**

| variant | `adapter-cloudflare` | `adapter-test` |
|---|---|---|
| `Unavailable` | 158 | 89 |
| `Serialization` | 77 | **0** |
| `NotFound` | 31 | 39 |
| `Conflict` | 16 | 38 |
| `PreconditionFailed` | 5 | 4 |

**`adapter-test` produces no `Serialization` at all.** That is a parity gap
visible from a source-only census, before Q2's runtime half exists — and it is
RFC 171's own shape: if any caller matches `Serialization` on a path whose only
test double is `adapter-test`, that arm is green in tests and unreachable in
them. **Start there; it is the census's first real question, not a bonus.**

**The number I am not quoting.** I counted `async fn` per port-definition file
and got figures like `deletion.rs: 52` — which is not 52 port methods; that file
holds services and stubs alongside its trait. **Quoting it as the census
population would have been wrong, so the population is yours to derive.** For
scale only: `grep -rh "^pub trait " crates/core/src --include='*.rs' | wc -l`
is **38**, and I have *not* checked how many of those are ports rather than
service traits. **Treat both numbers as unverified scale, not as the
population.**

## 3. The deliverable

1. **The population, derived and stated**: which traits are ports, how many
   methods, and **how you decided** — a port is a trait the adapters implement,
   and the boundary needs one sentence, not a judgement call per row.
2. **The table.** Per port method: the variants each implementation can return,
   and the variants each caller matches. Where a method has no caller matching
   anything, say so — that is a row, not an omission.
3. **Every item classified or named with a reason** (RFC 159 §4.5), and
   **`unclassified` must be 0.** The established shape is E6's own
   `scanned = classified + declared + 0`; follow it so the eventual check can
   reuse the arithmetic.
4. **The findings, separated from the census.** A caller matching a variant no
   implementation produces is a defect; list them, do **not** fix them. Each
   one is its own sizing decision, exactly as RFC 160 §4.11's ten were.
5. **The number that sizes the check**, and a one-paragraph statement of what
   shape it implies — per method, per variant, or per crate. **That sentence is
   what the next dispatch is built from.**

## 4. What this cycle must not do

- **Do not build the check.** RFC 171 §4 is explicit and so is this.
- **Do not fix any defect the census finds**, however small. The census's
  credibility is that it reports what is there.
- **Do not touch Q2.** It needs the credentialed job 0.92.2 built, it is a
  separate half, and conflating them loses the cheap answer in the expensive
  one.
- **Do not widen to `CoreError` or `worker::Error`.** `PortError` is the
  vocabulary RFC 171 names. If the boundary looks wrong, say so in the report.

## 5. Stop conditions

- **The population cannot be derived without a judgement call per trait** —
  report the rule you would use and stop; that is the census's shape question
  and it belongs in a reply, not in a guess.
- **The table cannot be built from source** for some method — name it and why;
  an item named with a reason is a census result, an item silently dropped is
  not.
- **A defect the census finds looks exploitable** rather than merely wrong —
  stop and report it immediately rather than finishing the table first.
- `unclassified` cannot be driven to 0.

## 6. Baselines at tag `0.92.3` (`5cff52e`), each with its command

- host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,675 passed, 0 failed, 4 ignored, 12 `test result:` lines**;
- `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
- `bash scripts/route-contracts-check.sh` → **192 routes**; E4 `216 = 192 + 24 + 0`; E5 `17 = 17 + 0 + 0`; **E6 `92 = 83 + 9 + 0`**, `83 = 65 + 0 + 18`;
- `bash scripts/drift-scan.sh` → clean;
- `mdbook build docs` → clean, 82 pages;
- `npx playwright test` in `e2e/` → **20** — needs `node_modules/.bin/wrangler dev --port 8787` serving **and warm**;
- `bash scripts/runtime-smoke-check.sh` → passed;
- bundle, `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15 at its default level** → **888,787 B** (878,087 wasm + 10,700 `shim.js`), raw 2,433,164 + 61,887, measured at the tag after its version bump. **Expect it unchanged** — a census ships no code. If it moves, something was fixed that should not have been.

**One more thing, and it is about the release rather than the work.**
`CHANGELOG.md` is at **79,192 B** and the archive script's guard fires above
80 KB, so this cut's entry will cross it if it is the size recent ones have
been. **Keep the entry short** — the detail belongs in the census document and
the RFC. That is the architect's own practice being corrected, not a new rule
for you.
