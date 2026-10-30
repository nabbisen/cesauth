# Developer Handoff — RFC 167 slice 2: `first-production-deploy.md`

**Governing RFC.** `rfcs/accepted/167-nothing-takes-a-new-operator-to-production.md` §5, §8 slice 2.
**Builds on.** `main` at the `0.89.4` tag or later.

**Target release.** **Patch.** **Trigger: none of the policy's minor triggers is
hit** — one new documentation page; no route, no migration, no public type, no
permission slug, no config knob, no renamed URL, and nothing an operator must
act on. Argued rather than assumed, per `contributing.md` §Cutting a release's
new ruling.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-31.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. The deliverable is the sequence, not the content

`docs/src/deployment/` has fifteen chapters and they are good. **What does not
exist is one ordered pass** from an empty Cloudflare account to a tenant
completing an OIDC flow. Write `docs/src/deployment/first-production-deploy.md`
as that pass: each step one short paragraph saying what you are doing and why it
comes here, then a link to the chapter that owns the procedure.

**Link out; do not restate.** A second copy of Step 4's secret list is a second
thing to drift. The page's value is ordering and completeness; every sentence
duplicating a chapter is a liability.

`docs/src/beginner/first-oidc-flow.md` is the model for shape and tone — and it
is also this page's tail: once deployed, the flow it walks is what proves the
deployment works.

## 2. I was wrong about what verifying this requires

The RFC and my earlier framing said this page could not ship honestly without a
walk against a real Cloudflare account. **That was over-specified.** A real
account is needed for **six commands**, not for the page.

**Genuinely remote-only — not exercisable locally:**

1. `wrangler d1 create` / `kv namespace create` / `r2 bucket create` (Step 1)
2. `wrangler d1 migrations apply --remote` (Step 2)
3. `wrangler secret put` (Step 4 — locally this is `.dev.vars`)
4. `wrangler deploy` (Step 9)
5. Cron triggers actually firing (Step 8.5 — declared in `wrangler.toml`, fired
   by Cloudflare)
6. `wrangler tail` / dashboard monitoring (Step 10), and custom domains / DNS

**Everything else is locally rehearsable**, which is most of the deliverable:
the ordering of all ten steps, Step 3's seed rows, Step 5's client-registration
`curl` (it works against `wrangler dev`), Step 8's dependency check, and the
entire post-deploy OIDC flow. `wrangler dev` auto-provisions D1, KV, the four
Durable Objects and R2 from the `wrangler.toml` bindings, and
`scripts/runtime-smoke-check.sh` already boots that runtime in CI.

**The one thing a local walk could never discover is already written.**
Account-level prerequisites — the **Workers Paid plan**, billing, billing alerts
— are in `deployment/preflight.md` §A, which is the first thing the spine points
at.

## 3. So: rehearse it locally, and split the evidence

**Walk the whole sequence**, substituting the local analogue for each of §2's
six: `--local` for `--remote`, `.dev.vars` for `wrangler secret put`,
`wrangler dev` for `wrangler deploy`. Then run `first-oidc-flow.md` against it.

**What you are verifying is that the order holds and no step is missing.** If
you reach a step whose prerequisite has not happened yet, that is the finding —
the same class as the chapter's own Step 5/Step 9 inversion in §4.

**The evidence term splits per step, and that is the point:**

- **The sequence: `exercised`.** You walked it; the order held; nothing missing.
- **§2's six: `reviewed`, named individually**, each with one line saying what
  would exercise it. A list, not a blanket hedge over the page.

**State plainly what the local rehearsal cannot close:** a remote-only command's
output or failure mode differing from what the page claims. Naming the six makes
that visible instead of burying it under one word.

## 4. The chapter's own defect, which this page must not inherit

**`production.md` Step 5 registers OIDC clients by curling
`https://your-cesauth-domain.example/admin/console/clients` — and Deploy is Step
9.** An operator following the chapter in order reaches Step 5 with nothing
deployed to curl. The chapter is self-consistent about the dependency (Step 3:
clients are registered after `ADMIN_API_KEY` exists) and wrong about the deploy
order.

**Your page orders it correctly** — client registration after deploy — and says
in one clause that it departs from the chapter's numbering and why, exactly as
`README.md`'s "Deploy it" list now does. **Do not edit `production.md`:**
renumbering a fifteen-chapter set is its own decision. Report anything else of
this shape you hit.

## 5. Scope

The one new page plus its `docs/src/SUMMARY.md` entry. **Not** `production.md`,
not the other fourteen chapters, not `README.md` — its "Deploy it" spine shipped
in 0.89.4 and is the index this page expands. Keep them consistent, and say so
if you find them disagreeing.

## 6. Gates

One Markdown page and one `SUMMARY.md` line, so the set should come back
identical to the `0.89.4` tag: host tests **1,636** / 0 failed / 12 lines,
`migration_chain` **35**, registered **193**, E4 `215 = 193+22+0`, E5
`16 = 16+0+0`, manifest **13**, Playwright **20**, bundle **882,900 B** gzip.
**Nothing should move, including the bundle** — if anything does, that is the
finding.

Run `mdbook build docs` early — it catches a `SUMMARY.md` entry that does not
resolve — and `drift-scan.sh --verbose`, which now also carries RFC 028's
archive exclusions.

## 7. Back-fill

Propose slice 2's Status and Evidence lines with §3's per-step split rather than
one term for the page. **If a step turns out not to be walkable for a reason I
have not anticipated, say so and propose the weaker term for that step** — the
point of the split is that one unwalkable step costs one line, not the page's
credibility.

Report into `.git-exclude/review-request/`.
