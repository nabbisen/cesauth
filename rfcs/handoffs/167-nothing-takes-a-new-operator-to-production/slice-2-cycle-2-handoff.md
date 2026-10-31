# Developer Handoff — RFC 167 slice 2, cycle 2 (one line)

**Governing RFC.** `rfcs/done/167-nothing-takes-a-new-operator-to-production.md` §8 slice 1 item 1.
**Review.** `.git-exclude/reviewed/167-slice-2-review.md`
**Builds on.** `80cf753` on `main`. **Nothing to revert** — the page stands.

**Target release.** **Patch**, unchanged. **Trigger: none hit** — one line of
`README.md`; no route, no migration, no public type, no config knob, nothing an
operator must act on beyond reading a step that should always have been there.
The cut waits on this.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-31.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. You found a hole in the spine I wrote, and you were right to report it

The page is right: ordered, links out, the Step 5/Step 9 departure stated where
a reader meets it, and placed first under `# Deployment` because it is the page
that says what order to read the rest in — a placement I had not specified and
you got right.

**The walk earned its keep three times**, and all three are things reading could
not have produced: Step 3 reproduced as a real symptom (`/jwks.json` serving
`{"keys":[]}` against an emptied local D1); the discovery that
`first-oidc-flow.md` **cannot be run as-is against production**, because
`/__dev/stage-auth-code` is gated off by step 5 on purpose and a confidential
client authenticates via HTTP Basic; and an actual OIDC flow completed against a
client you registered through the documented call. The second of those is
exactly *"a step the page did not mention"* — the acceptance test's own words —
and neither the RFC nor my handoff anticipated it.

**And §4 of your report is the finding of this cycle.** `README.md`'s "Deploy
it" spine has nine lines; your page has ten. The missing one is
`production.md` **Step 3 — Seed production rows**, and your own rehearsal proved
it is not optional: without it every token cesauth issues fails verification
everywhere. **That spine is mine**, specified in RFC 167 §8 and repeated in the
slice-1 handoff. You implemented what you were given, checked the two lists
against each other as §5 asked, found the disagreement, and reported it instead
of editing a file that was out of scope. Right on every count.

## 2. The change

**One numbered line in `README.md`'s "Deploy it" list**, between *Migrations
`--remote`* and *Secrets*, matching the page's own §3 ordering:

- **Seed the signing key** — pointing at
  `docs/src/deployment/production.md#step-3--seed-production-rows`, with a
  clause saying why it cannot be skipped: without the public half in
  `jwt_signing_keys`, `/jwks.json` serves no keys and every issued token fails
  verification.

Renumber the lines after it. **Verify the anchor against the built HTML** as you
did last time — you already confirmed it for the page, so this is confirming it
in its new home, not re-deriving it.

**Do not touch the closing paragraph's two named exclusions.** Steps 7 and 8
remain correctly excluded: *"Real steps, just not ones a first deploy breaks
without."* Step 3 is a step a first deploy breaks without, which is why it
belongs in the list and not in that sentence.

## 3. Scope

`README.md`'s "Deploy it" list only. Not the page, not `production.md`, not
`SUMMARY.md`, not the other chapters. Ten lines in one list.

## 4. Gates

The set should come back identical to `80cf753`: host **1,636** / 0 failed / 12
lines, `migration_chain` **35**, registered **193**, E4 `215 = 193+22+0`, E5
`16 = 16+0+0`, manifest **13**, Playwright **20**.

**On the bundle — read this before you measure it.** Your −70 byte delta was
real, and I ran the experiment: reverting the workspace version to `0.89.3` and
rebuilding reproduces **872,201 / `73e8acc5…`** and **10,699 / `3c308676…`**,
byte-identical to the recorded figure with both digests exact. So **the build is
reproducible and the −70 bytes is the version bump**, through crate metadata in
symbol mangling. The defect was mine: I gave you a baseline measured on a
pre-bump tree.

**The baseline for this cycle is `80cf753`'s figure: total gzip 882,830**
(`*_bg.wasm` 872,130 / `c3c51a44…`, `shim.js` 10,700 / `07dd2837…`). One README
line changes no Rust, so it should come back identical to that — and if it
does not, *that* is a finding.

Your handling of this was the right handling: you reported a movement you could
not explain, you proved it was stable across two builds rather than calling it
noise, and you declined to offer a diagnosis you did not have. Keep doing that.
One correction for next time: `298e203` is not the 0.89.4 tag's commit —
`1d767a1` is. Your base genuinely was the tag, so the conclusion held, but
citing the right commit is what turns an unexplained delta into a one-line
known offset.

## 5. Back-fill

Amend slice 1's Status line, not slice 2's: the defect was in slice 1's spine,
found by slice 2's walk. One clause — the seed step was missing from the "Deploy
it" list and was added after the walk showed it is not skippable.

Report into `.git-exclude/review-request/`.
