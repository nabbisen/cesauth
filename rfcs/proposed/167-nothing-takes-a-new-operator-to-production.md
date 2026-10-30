# RFC 167 — Nothing takes a new operator from zero to production

**Status.** **Proposed** 2026-10-30. Awaiting nabbisen's acceptance.
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
