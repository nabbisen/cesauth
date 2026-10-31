# RFC 167 — Nothing takes a new operator from zero to production

**Status.** **DONE — both slices shipped.** Slice 1 in **v0.89.4**,
2026-10-31, in two cycles (§8); slice 2 in **v0.89.5**, 2026-10-31, also in two
cycles. **Evidence: slice 1 `reviewed`; slice 2 `exercised` for the sequence and
`reviewed` for the six remote-only commands, each named** (§8) — the split the
RFC itself proposed, used as proposed. The "blocked on an owner decision"
condition this line carried was the architect's own over-specification and was
withdrawn before dispatch, not satisfied.

**Accepted** 2026-10-30 — *"Understood. Should be improved and
enhanced with actual schedule and plans."* The schedule is §8, and it puts this
**ahead of the three accepted gate RFCs**, which is a deliberate re-sequencing
and not an oversight: 164, 165 §3 and 163 are each a verified **latent** finding,
and this is a surface every prospective operator meets first.
**Tier.** **P2.** Nothing is broken and nothing is exposed. A reader who wants
to run cesauth in production has 15 deployment chapters available and no path
into them, and the first page they see contains two claims that are not true.
**Size.** Small for §4 (the README is 125 lines and the chapters already exist).
The ordered production walkthrough in §5 is Medium and is the only part that
writes new prose.
**Touches.** `README.md`, `docs/src/SUMMARY.md`, one new
`docs/src/deployment/` page, `docs/src/deployment/observability.md`.
**Found by.** nabbisen, 2026-10-30: *"To enhance Quick Start. Currently, only
poor dev guide is in `README.md`. Not kind enough and not easy enough for users
on production use at all."*
**Relates to.** RFC 012 (the previous README-drift correction, `done/`),
RFC 141 (client registration, whose cycle-1 API in v0.85.0 is what makes an
honest production walkthrough possible at all), RFC 161 §9(a) (the record
corrections overlap — see §6).

**On 1.0:** not declared, not scoped, not dated. Nothing here is a 1.0
requirement.

---

## 1. Summary

The observation is correct, and the cause is navigational rather than missing
documentation. **The production documentation exists and is good.**
`docs/src/deployment/` carries 15 chapters — pre-flight checklist, Wrangler
configuration, secrets, cron triggers, custom domains, multi-environment
workflow, local→production migration, backup/restore, data migration, migration
procedures, observability, security headers, TOTP, a day-2 runbook, disaster
recovery. `docs/src/integrating.md` covers the integrator. None of it is reached
from the README's Quick Start, and none of it is sequenced as one path.

What `README.md` offers under **Quick start** is four commands:

```sh
cargo test
wrangler d1 migrations apply cesauth --local
wrangler dev
```

That is a **contributor's** loop — `cargo test` is the first line. There is no
`wrangler deploy`, no secrets step, no first-admin step, no first-client step,
and the README's four documentation bullets point at
`docs/src/deployment/wrangler.md`, not at
[`preflight.md`](../../docs/src/deployment/preflight.md) or
[`production.md`](../../docs/src/deployment/production.md) — the two chapters a
production reader needs first.

## 2. Two claims on the front page that are not true

Both verified against the tree, and both are the kind this project has spent
several RFCs removing:

1. **The SIEM sentence.** `README.md`: *"Operators forward to external SIEM via
   Cloudflare Logpush."* `docs/src/deployment/observability.md`: *"cesauth does
   not push audit events to an external destination (SIEM) today."* Logpush
   carries Worker **log lines**; audit events are **D1 rows**. The README is
   asserting a security-relevant integration the deployment chapter denies in
   as many words. (Also recorded as RFC 161 §7.)
2. **Three badges advertising a Rust crate that cannot be used.** The README
   opens with crates.io, docs.rs and deps.rs badges for `cesauth`. What is
   published under that name is a **`0.0.0` placeholder reserved 2026-09-10**;
   all seven real crates carry `publish = false`, and
   `docs/src/expert/contributing.md:325-334` records that the seven real names
   are **deliberately unreserved**. The reservation review of 2026-09-10 asked
   for exactly one mitigation — *"add one line to the description or README that
   the real crates are not published, so nobody reads the reservation as an
   index of available packages"* — and **that line was never added.** So
   `cargo add cesauth` gets an inert crate, and `docs.rs/cesauth` documents
   nothing.

## 3. What is established

- **15 deployment chapters, 6 beginner chapters, 1 integrator chapter**, all
  listed in `docs/src/SUMMARY.md`; `docs/book/` is **not** tracked, so there is
  no stale build output in the tree.
- **`wrangler deploy` is the supported production path** and Docker is
  explicitly out of scope (`ROADMAP.md`, "Explicitly out of scope"), so the
  walkthrough §5 asks for is a documentation job and not a packaging one.
- **RFC 141 cycle 1 shipped in v0.85.0**, so client registration is an API call
  and the docs already say *"No SQL, ever (RFC 141 — this replaces a
  hand-written `INSERT INTO oidc_clients`)"*. **An honest end-to-end production
  walkthrough became possible with that release and has not been written since.**
- **No RFC and no ROADMAP item covers this.** The only prior work is RFC 012
  (`done/`), which corrected README drift, and ROADMAP's out-of-scope note on
  containers.

## 4. Direction — the README first, because it is cheap and it is the front page

1. **Split the Quick start in two, by reader.** *"Run it locally"* keeps today's
   four commands (and should say it is the contributor/evaluation loop).
   *"Deploy it"* is a short numbered list that ends at a working deployment,
   each step one line pointing at the chapter that owns it — pre-flight,
   `wrangler deploy`, secrets, migrations `--remote`, first admin, first OIDC
   client, then Observability and the day-2 runbook.
2. **Fix §2's two claims** in the same change: correct the SIEM sentence to what
   `observability.md` actually says, and add the one line the 2026-09-10 review
   asked for next to the badges.
3. **Link the two entry chapters by name** in the documentation bullets.

## 5. Direction — one ordered production walkthrough

A single page, `docs/src/deployment/first-production-deploy.md`, that is to
production what `beginner/first-oidc-flow.md` is to local: **one ordered pass
from an empty Cloudflare account to a tenant that can complete an OIDC flow**,
linking out rather than restating. It is the page the README's *"Deploy it"*
list points at, and the thing that does not exist today is the **sequence**, not
the content.

**Its acceptance test is the owner's standard and should be literal:** a reader
who has never deployed cesauth follows it start to finish without opening a
chapter out of order and without discovering a step the page did not mention.
Which means it must be **walked, not reviewed** — and that is a real cost,
because walking it needs a Cloudflare account and a deploy. **If the walk cannot
be done, the page ships marked as unwalked rather than presented as verified**
(RFC 000 §22: `reviewed`, not `exercised`).

## 6. Overlap with RFC 161 §9(a), stated so it is not done twice

RFC 161 §9(a) also corrects the README's SIEM sentence and
`observability.md`'s audit-browser entry. **Whichever is dispatched first takes
both**, and the other's handoff drops them. They are the same two sentences; I
would rather say so here than have two cycles each believe they own them.

## 7. What this does not claim

- Not that the deployment chapters are wrong or thin. They are neither — §1's
  point is that nothing routes a reader into them.
- Not that `cesauth-core` should be published to crates.io. That is a separate
  question with its own preconditions; §2.2 is only about the README not
  advertising a crate that cannot be used.
- Not a verdict on the integrator path (`docs/src/integrating.md`). One page for
  the audience that matters most commercially may well be thin, but this RFC
  did not assess it and does not assert it.

## 8. Schedule and plan

Two slices. The first is almost free and rides with work already queued; the
second is the one that writes new prose and needs something only the owner can
provide.

### Slice 1 — the README, merged into RFC 161 §9(a)'s cycle · **patch** · **second in the queue**, after RFC 162

Merged rather than sequenced separately because both edit `README.md` and
`docs/src/deployment/observability.md`, and two cycles each believing they own
the same two sentences is how a correction gets applied twice or not at all
(§6). Deliverables, all of them edits to files that exist:

1. **Quick start split by reader.** *"Run it locally"* keeps today's four
   commands and says plainly that it is the contributor/evaluation loop.
   *"Deploy it"* is a numbered list, one line per step, each pointing at the
   chapter that owns it: pre-flight → `wrangler deploy` → secrets → migrations
   `--remote` → first admin → first OIDC client → Observability → day-2 runbook.
2. **§2.1 — the SIEM sentence** corrected to what `observability.md` says.
3. **§2.2 — the badge line** the 2026-09-10 reservation review asked for and
   never got, next to the three badges.
4. **The two entry chapters linked by name** in the documentation bullets —
   `deployment/preflight.md` and `deployment/production.md`.

**Acceptance:** a reader who wants to deploy finds the deploy path without
opening `docs/src/SUMMARY.md`, and no sentence on the front page contradicts a
chapter.

**Slice 1 shipped three of its four items in `a09f39f` and failed the fourth,
on the acceptance test above** (review 2026-10-31). The SIEM correction, the
badge note and the named chapter links are right. **The "Deploy it" list was
not**: it placed `wrangler deploy` second — before migrations and secrets —
while every line linked into a chapter whose own order puts deploy at **Step
9**. Followed literally it deploys a Worker against a database with no
migrations applied. Seven chapter steps were unrepresented, including
*Provision real resources* and *Confirm `WRANGLER_LOCAL` is off*.

**A third defect in the same spine, found later and by walking rather than
reading** (v0.89.5, 2026-10-31): the corrected nine-line list still had **no
line for `production.md` Step 3**, seeding the JWT signing key's public half.
It was not among the two steps the list names as deliberately excluded; it was
simply absent. Slice 2's local rehearsal reproduced the symptom rather than
inferring it — with the key unseeded, `/jwks.json` serves `{"keys":[]}` and
every token cesauth issues fails verification everywhere, which is the
definition of a step a first deploy breaks without. Added in slice 2's cycle 2
(`4d4dea6`), bringing the list to ten lines. **All three of this slice's
defects were the architect's specification rather than the implementation**, and
the third was invisible to every reading of the spine, including the reviews
that passed it.

**The order was the architect's**, specified in item 1 above and again in the
handoff, and implemented faithfully. An ordering was written for a procedure
without reading the ordering of the chapter it was being ordered against — the
same failure as the four miscounts of that week, applied to a sequence instead
of a population. **Corrected in a second cycle** (`298e203`), which derived the spine from the
chapter instead of from a list: nine lines, pre-flight/provision → migrations
`--remote` → secrets → `WRANGLER_LOCAL` → cron → deploy → first OIDC client →
observability → day-2, every anchor re-verified against the built HTML, and the
two chapter steps left off (Magic Link mail, local `cargo audit`) named in a
closing line rather than dropped.

**And cycle 2 amended the architect's acceptance test, which was also wrong.**
It read *"the list's order must not contradict the chapter's order"* — a test
no correct list can pass when the chapter contradicts itself, as this one does
(§5's Step 5/Step 9 finding). The list departs once and says so **in the list,
where a reader meets it**: *"comes after deploy here, even though the chapter
numbers it Step 5."* Silently reordering would have been the philosophy
failure; the departure is not. Both of this slice's defects were the
architect's specification rather than the implementation.

### Slice 2 — `docs/src/deployment/first-production-deploy.md` · **patch** · **third in the queue**

One ordered pass from an empty Cloudflare account to a tenant completing an OIDC
flow, linking out rather than restating — what `beginner/first-oidc-flow.md` is
to local. The content exists across the 15 chapters; **the sequence does not**,
and that is the whole deliverable.

**A known defect to fix, not just a gap to fill** (found 2026-10-31, writing
slice 1's spine): **`production.md` Step 5 registers OIDC clients by curling
`https://your-cesauth-domain.example/admin/console/clients` — and Deploy is Step
9.** An operator following the chapter in order reaches Step 5 with nothing
deployed to curl. The chapter is self-consistent about the *dependency*
(Step 3: clients are registered after `ADMIN_API_KEY` exists) and wrong about
the *deploy order*. This is the sharpest evidence for §5 existing at all: the
content is spread across fifteen chapters and the sequence is what is missing,
which only became visible when someone tried to write the sequence down.

**~~This slice needs an owner action~~ — corrected 2026-10-31. It does not.**
The architect's framing treated the page as a single all-or-nothing walk
requiring a real Cloudflare account. **Checked: a real account is needed for six
commands, not for the page** — `d1/kv/r2 create`, `--remote` migrations,
`wrangler secret put`, `wrangler deploy`, cron triggers firing, and
`wrangler tail`/DNS. Everything else is locally rehearsable: the ordering of all
ten steps, the seed rows, the client-registration `curl` (which works against
`wrangler dev`), the dependency check, and the entire post-deploy OIDC flow.
`wrangler dev` auto-provisions D1, KV, the four Durable Objects and R2 from the
`wrangler.toml` bindings, and `runtime-smoke-check.sh` already boots that
runtime in CI. The one thing a local walk could never discover — account-level
prerequisites, the **Workers Paid plan** and billing — is already written in
`deployment/preflight.md` §A, which the spine's first line points at.

**So the evidence term splits per step instead of hedging the page:** the
sequence is `exercised` from a local rehearsal, and the six remote-only commands
are `reviewed`, **named individually**, each with what would exercise it. One
unwalkable step then costs one line rather than the page's credibility.

**Dispatched 2026-10-31**, unblocked:
`handoffs/167-nothing-takes-a-new-operator-to-production/slice-2-handoff.md`.
Third correction this week in which the architect's specification, not the work,
was the obstacle — the deploy order, the acceptance test, and this.

**SHIPPED in v0.89.5**, 2026-10-31, in two cycles. The page is
`docs/src/deployment/first-production-deploy.md`, placed **first** under
`# Deployment` in `SUMMARY.md` — before `preflight.md`, because it is the page
that tells a reader which order to read the rest in. Eleven sections: §0 for the
one prerequisite a walk cannot discover (Workers Paid plan, linking
`preflight.md § A`), the ten chapter steps in the order they actually run, and
*"Prove it works"*, which hands off to `beginner/first-oidc-flow.md`.

**The local rehearsal earned its place three times over**, each a thing no
amount of reading would have produced:

1. **Step 3 reproduced as a symptom**, which is what exposed slice 1's third
   defect above.
2. **`first-oidc-flow.md` cannot be run as-is against production** — a finding
   neither this RFC nor the handoff anticipated. Its Step 4b uses
   `/__dev/stage-auth-code`, which step 5 of the walk deliberately gates off,
   and a `confidential` client authenticates at `/token` by HTTP Basic rather
   than the tutorial's bare `client_id` form field. Both adjustments are now
   named in the page's closing section, so the companion chapter the page hands
   off to does not strand the reader it was handed.
3. **A real OIDC flow completed** against a client registered through the
   documented `POST /admin/console/clients` call: user created, Magic Link
   requested and verified, authorization code exchanged, access/id/refresh
   tokens returned, refresh rotation confirmed.

**Cycle 2** added the one missing README line and nothing else. The dispatch
level was **patch** with the trigger stated at dispatch (none of the minor
triggers hit), and it held through both cycles.

### What this displaces, and why that is the right call

The queue becomes **RFC 162 → (RFC 161 §9(a) + slice 1) → slice 2 →
RFC 131 slice 1 (audit, minor) → RFC 164 → RFC 165 §3 → RFC 163**.

The three gate RFCs slip by three positions. Each is a finding I verified as
**latent** — 164's nine rotted links are repaired and only the gate is missing,
165's three live exempt entries all still match, 163's duplicate-route test
covers 105 of 193 with no duplicate present. None of them is currently
mis-reporting anything. A front page that contradicts itself is.
