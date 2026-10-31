# Developer Handoff — 0.89.4 cycle 2 (small): the "Deploy it" list

**Governing RFC.** `rfcs/done/167-nothing-takes-a-new-operator-to-production.md` §8 slice 1 item 1.
**Review.** `.git-exclude/reviewed/161-record-correction-review.md`
**Builds on.** `a09f39f` on `main`. **Nothing to revert** — everything else in
that commit stands.

**Target release.** **0.89.4 — patch**, unchanged. The cut waits on this.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-31.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The record correction is right, and twice you were right to go past me

Eight rows, eight module docs, six page copies, the chapter. I re-swept the
console module docs myself and the only three remaining "renders" claims are the
three that are true. The six copies carry zero surviving promise phrases, and
the chain page makes exactly the distinction I asked for — the display is not
built, the cron and the re-verify action work, and the page offers neither.

**Two things you did that I want to name:**

- **Eight module docs, not six.** You read every handler instead of stopping at
  my list. `overview.rs` was the worst of the set — four named rollups and a
  claim about *who can see them* — and I had missed it. That is the **third**
  time my count for this one section was wrong.
- **The four extra `Console: <filter>=…` lines in `observability.md`**, under an
  intro claiming *"the two syntaxes that actually exist."* You cited §4.1's
  acceptance criterion — *no document in the tree* — as governing over my
  itemisation of one paragraph. **That is the correct reading.** The list is a
  hint; the stated property is the contract. Keep doing that.

Also good: proving the bundle's content changed (`sha256` on both modules plus
`strings` on the compiled wasm) instead of letting an unchanged byte total stand
as "nothing moved". An unchanged total after a real change is the shape that
usually means a stale build, and you treated it as the thing to check twice.

## 2. The one defect, and it is mine

The **"Deploy it"** list says *"read this list for the order"*. It is the wrong
order:

```
README #2  `wrangler deploy`        -> production.md Step 9
README #4  Migrations `--remote`    -> production.md Step 2
README #5  First admin              -> production.md Step 4
README #6  First OIDC client        -> production.md Step 5
```

**The front page tells a reader to deploy second — before migrations and before
secrets.** Followed literally it deploys a Worker against a database with no
migrations applied and no secrets set. Seven chapter steps are unrepresented,
including **Step 1 — Provision real resources** and **Step 6 — Confirm
`WRANGLER_LOCAL` is off**.

**You implemented the order you were given.** RFC 167 §8 and handoff §3.5 both
specify it verbatim, and you verified every anchor against the built HTML, which
is more than I asked. I wrote an ordering for a procedure without reading the
ordering of the chapter I was ordering it against — the same mistake as the
miscounts, applied to a sequence instead of a population. **Do not read this as
a finding against your cycle.**

## 3. What to do — derive the spine, do not mirror a broken chapter

**Read `docs/src/deployment/production.md` and derive the order from it**, not
from my list and not from this one. Its own order is Steps 1, 2, 3, 4, 5, 6, 7,
8, 8.5, 9, 10. A front-page list is the **spine**, not all eleven steps: include
what an operator cannot safely skip, link each to the section that owns it, and
keep it to roughly eight lines so it stays readable.

**My view of the spine, offered as a starting point you should check rather
than implement:** pre-flight → provision resources → migrations `--remote` →
secrets (including `ADMIN_API_KEY`) → confirm `WRANGLER_LOCAL` is off → cron
triggers → deploy → register the first OIDC client → observability → day-2
runbook. **If reading the chapter tells you a different spine, use yours and say
why** — you will have read it more recently than I have, which is exactly the
problem this cycle exists to fix.

**Two constraints:**

1. **Every anchor verified against the built HTML**, as you did last cycle.
2. **The list's order must not contradict the chapter's order.** That is this
   cycle's whole acceptance test, and it is checkable: for each line, the
   chapter step it links to must come in the same relative order.

## 4. Where the chapter contradicts itself — report, do not fix

**`production.md` Step 5 registers OIDC clients by curling
`https://your-cesauth-domain.example/admin/console/clients`. Deploy is Step 9.**
An operator following the chapter in order reaches Step 5 with nothing deployed
to curl. The chapter is self-consistent about the dependency (Step 3 says
clients are registered after `ADMIN_API_KEY` exists) and wrong about the deploy
order.

**This is RFC 167 slice 2's (0.89.5), not yours.** It is also the best evidence
yet for that slice existing at all — the content is spread across fifteen
chapters and the *sequence* is what is missing, which is exactly what trying to
write the spine exposed.

**For this cycle it means one thing:** the front-page list must be right about
the real order even where the chapter's numbering is not, and **wherever you
depart from the chapter's numbering, say so in the report** so slice 2 inherits
the list rather than rediscovering it. Do not edit `production.md`.

## 5. Scope

**The `README.md` "Deploy it" list only.** Not `production.md`. Not the six
pages, the module docs, `route-contracts.md` or `observability.md` — all
finished and all standing. Not `first-production-deploy.md`, which is 0.89.5's
and is blocked on an owner decision about walking it.

## 6. Gates

The change is one README list, so the gate set should come back identical to
this cycle's: host tests **1,636** / 0 failed / 12 lines, `migration_chain`
**35**, registered **193**, E4 `215 = 193+22+0`, E5 `16 = 16+0+0`, manifest
**13**, Playwright **20**, bundle **882,900 B** gzip with full 64-character
sha256 per module. **The bundle should not move at all this time** — no Rust
changes — and if it does, that is the finding.

Run `mdbook build docs` and `drift-scan.sh --verbose` early again; they are
still the two most likely to catch a mistake in a docs change.

## 7. Back-fill

Amend RFC 167 slice 1's Status line rather than adding a new one — `reviewed`
remains the right term, and the line should say the list was corrected in a
second cycle and why, because "the front page told readers to deploy before
migrating" is worth keeping in the record rather than quietly fixing.

Report into `.git-exclude/review-request/`.
