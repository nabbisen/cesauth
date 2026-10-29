# Developer Handoff — RFC 159, continuation

**Governing RFC.** `rfcs/accepted/159-nine-dead-handlers-no-lint-can-see.md`
— **§4.1** (the tenth, decided) and **§4.2** (what the check cannot see), both
new.
**Review.** `.git-exclude/reviewed/159-implementation-review.md`
**Builds on.** your uncommitted working tree. **Do not revert it.**

**Target release.** **0.89.2 — patch**, unchanged.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-29.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The stop was right, and so was stopping rather than deciding

"The census is not zero" was the condition, you hit it, and you did not quietly
make it an eleventh deletion or a first exemption. Both deliverables check out:
the nine are the right nine, the tree carries no probe residue, and the check
exits **1** with exactly one finding, named by qualified path.

Two things you did that are worth saying back to you:

- **Your renaming probe did not fire, and you treated that as a finding.** The
  draft's `pub use` grep was not line-anchored, so the commented-out statement
  still matched and the probe **silently passed**. A fires probe that passes
  when it should fail is the most dangerous result a gate can produce, and the
  only defence is exactly what you did. (I checked the anchor is safe: zero
  indented `pub use` in `crates/backend/src`.)
- **The name-collision probe is the right probe**, and you understood that a
  file no `mod` declares still exercises a grep-based check.

## 2. §4.1 — the tenth: delete it

`routes::admin::console::preview::handler` is dead. Verified independently:
`lib.rs:294` routes that path to `config::preview` (`config.rs:77`, a real
gated implementation), a qualified grep for `preview::handler` returns zero,
and `route-contracts.md:100` documents the live handler.

**Delete `crates/backend/src/routes/admin/console/preview.rs` and
`console.rs:41`'s `pub mod preview;`.** Not an `E4_EXEMPT` entry — an exemption
list carrying entries that should have been deleted stops being read, which is
the RFC's own argument against false positives turned on its own escape hatch.

**Worth your attention while you are in there**: that file's doc comment claims
*"the route itself is registered"*, which is false and is why it survived. If
anything else you touch in this cycle makes a claim like that about its own
registration, say so — RFC 138's described-vs-actual discipline applies to
comments, not only to docs.

## 3. §4.2 — the check cannot see eleven live handlers

Your report says the check matches *"183 of them."* I re-derived the
population:

```
pub async fn in routes/, non-test                     216
matched by your signature-shape regex                 183
unmatched                                              33
  … registered handlers in the me:: family             11
  … helpers and pure decision functions                22
```

The eleven — `me::security::{get_handler,get_json_handler}` and the handlers
under `me::totp::{disable,enroll,verify,recover}` — are **all registered**, so
nothing is hiding today. They are invisible because the regex wants
`(req: Request, ctx: RouteContext<D>)` on one line and that family is written
`(req: Request, env: worker::Env)` (see `lib.rs:223`, which passes `ctx.env`)
or across several lines.

**This RFC exists because a bare-name test let nine handlers through.** A
qualified-path test that silently excludes a signature family leaves a dead
handler added to `me/totp/` tomorrow exactly as invisible — and the check will
say nothing, not even that it examined 183 of 194.

**The requirement, which is not negotiable:** a `pub async fn` in `routes/`
must be **either** classified as a handler **or** named as a non-handler with a
reason, and anything that is neither **fails the check**. The covered
population must not be able to shrink silently. That is RFC 156's subject
inside the gate RFC 156's successor is adding.

**The mechanism is yours.** Widening the matcher, asserting coverage against a
named non-handler list, or something better — your last three cycles each
produced a better mechanism than the one I would have specified, so I am
stating the invariant and leaving the design to you. If the honest answer is
that the twenty-two helpers need naming one by one, name them; a list written
once with reasons is cheaper than a gate nobody can trust.

**Report and stop if** closing this blind spot turns up a handler in the
eleven, or anywhere else, that is *not* registered. That is an eleventh
finding, not cleanup.

## 4. Then finish the evidence pass you deferred

With the census at zero and the gate honest, everything in the original §3
becomes gatherable in one pass. In full, plus:

1. **The coverage figure, printed by the check itself**, so a reader of CI
   output can see what it examined — and a demonstration that the count moving
   without a reason fails.
2. **Both fires/does-not-fire pairs re-run** after §3's change, since the
   matcher or the classification will have moved under them. The
   **name-collision case is mandatory** either way.
3. **RFC 157's census re-run with the final check**, and the number recorded —
   this is the project's first trustworthy count of unrouted handlers, and it
   must be **zero** before this ships.
4. **The four operator-console JSON endpoints still answering**
   (`/admin/console.json`, `/admin/console/tokens.json`, `/admin/tenancy.json`,
   `/admin/tenancy/tenants.json`), proved rather than assumed.
5. **The gate-set record updated**: `docs/src/expert/contributing.md`'s table
   and `.github/release-gate-manifest.json` — the latter unchanged at **13** if
   E4 stays inside `route-contracts.yml`, which is the right call and needs
   only to be stated.
6. **Full gate set with counts.** Host baseline **1,630**; `migration_chain`
   **35**; routes **193**; bundle with full 64-character sha256 copied from the
   log.
7. **A `Status` + `Evidence` back-fill line.**

## 5. Resolved — do not re-open

- The nine, and now the tenth: deleted, not exempted.
- E4 lives inside `route-contracts-check.sh`; no new workflow.
- `E4_EXEMPT` stays **empty**.
- **Patch**, 0.89.2.
- **Not RFC 162's inverse check** — *"every URL the frontend fetches has a
  route"* — and **not RFC 161's six placeholder pages.** Both will look
  adjacent. Leave both.
- Still open, still not this RFC's: RFC 158 §5.5's two.

## 6. Review request

`.git-exclude/review-request/159-continuation-report.md`. Give me the commit.
