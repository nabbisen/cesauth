# Developer Handoff — 0.89.4: RFC 161 §9(a) + RFC 167 slice 1

**Governing RFCs.** `rfcs/accepted/161-six-operator-pages-promise-data-and-render-none.md` **§9(a)**
and `rfcs/accepted/167-nothing-takes-a-new-operator-to-production.md` **§8 slice 1**.
**Why one cycle.** Both edit `README.md` and
`docs/src/deployment/observability.md`. Two cycles each believing they own the
same two sentences is how a correction gets applied twice or not at all
(RFC 167 §6).
**Builds on.** `main` at the `0.89.3` tag or later.

**Target release.** **0.89.4 — patch.** Sequence authorized by the owner
2026-10-30; see `ROADMAP.md` §Next minor releases.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-30.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. What this cycle is, and the one thing it must not become

Six operator console pages were **built, shipped, and disconnected** by one
commit in May (RFC 161 §6). The restoration is approved and scheduled as
RFC 131 §0's slices, at 0.92.0 and 0.93.0.

**This cycle restores nothing.** It makes the documents stop claiming the
features work. That is the whole scope, and it is a patch.

If you find yourself editing anything under `crates/backend/src/routes/` or
`crates/core/`, stop — that is 0.92.0's cycle and doing it here would put
restoration code under a tag that says "documentation".

## 2. Derive the population. Do not work from my list

**Two of my own counts for this were wrong, and both understated.** I said four
`route-contracts.md` rows; it is eight. I said three handler doc comments; it is
six. Both corrected in RFC 161 §9(a) before this dispatch — and that is the
**fourth** figure of mine this week not to survive re-derivation.

So the first deliverable is a census, reported before any edit:

1. **Every `GET` row under `/admin/console` in `route-contracts.md` whose
   `View / template` column names something the page does not render.** My count
   is **eight** — `cost`, `safety`, `audit`, `audit/chain`, `config`, `alerts`,
   `tokens` (*"token list"*, lists nothing), `clients` (*"client list"*, renders
   `NotFound`) — with `/admin/console` (*"overview page"*) a ninth that
   overstates without being false. **Check each one by reading the component**,
   and report any I have miscounted in either direction.
2. **Every module doc under `routes/admin/console/` that describes rendering the
   handler does not do.** My count is **six**. Note that `audit_chain.rs`,
   `safety.rs` and `config.rs` each mix a **false** claim about the page with
   **accurate** claims about their `POST` handlers — those POST descriptions are
   correct and must survive.
3. **`/admin/tenancy/*` is out of scope** (RFC 161 §4), but if your census
   trips over the same condition there, **report it and do not fix it** —
   RFC 131 §0 already says that half must be counted before it is scoped.

## 3. The edits

### 3.1 `route-contracts.md` — say what renders

Rename each affected `View / template` cell to what the page actually produces,
and add one short note per row pointing at RFC 161. A cell reading
*"placeholder — RFC 161"* is honest; *"audit search page"* is not.

**Do not change the `Rendering` column.** Those rows are `client` and stay
`client` — RFC 161 §9(b) chose to finish the CSR migration, so `client` is the
target state, not an error.

### 3.2 The six module docs — surgically

Cut the claims about rendering. Keep every accurate sentence about the `POST`
handlers. Each file gets one line saying the read surface is not built and
naming RFC 161.

`audit.rs` is the hard one: its nine-row query-parameter table with per-field
matching semantics is a specification of a feature that does not exist.
**Delete the table, do not "mark it planned"** — it is the single most
convincing false document in the tree, and a reader who meets it concludes
audit search is implemented, parameters and all. If any of it is worth keeping
for whoever builds slice 1, it belongs in RFC 131 §0's slice notes, not in a
module doc.

### 3.3 `observability.md` — the chapter read during an incident

Its *"Four routes surface the table"* list presents `/admin/console/audit` as
*"the admin console's audit browser"* with per-filter semantics and an
edge-case note about invalid `from`/`to` values — all describing a rendering
path that does not exist. The chapter then says *"For day-to-day incident
response, the admin console covers most needs."*

Replace that with what is true: **`wrangler d1 execute --remote` is the
production read path today**, and the chapter already documents it as route 4
with a worked query. Say the console surfaces are not built yet and name
RFC 161. Keep routes 3 and 4 as they are; `audit/chain/verify` and
`audit/export` are real, implemented, role-gated endpoints — they simply have no
UI.

### 3.4 The six placeholder pages — per-page copy, in Japanese

`crates/frontend/src/pages/operator/console.rs`. **This is the only code in the
cycle** — six strings, no logic.

**Not one sentence repeated.** Only **audit** has a real alternative to name
(`wrangler d1 execute`, documented in `observability.md` §Querying).
**Cost, safety, alerts and config have no read path at all** — their copy says
the feature is not built and points at nothing, because pointing at a workaround
that does not exist is the same defect in a new costume. Chain status sits in
between: the daily cron writes an outcome and `POST …/chain/verify` works, but
nothing renders either.

**Japanese, per ADR-013** — every page under `pages/operator/` is `lang="ja"`
and there is no locale negotiation. Write idiomatic copy; do not translate my
English literally. **Keep the nav links** — they are re-linked work in 0.92.0,
and de-linking now only to re-link later is churn.

### 3.5 `README.md` — RFC 167 slice 1

1. **Split Quick start by reader.** *"Run it locally"* keeps today's four
   commands and says plainly it is the contributor/evaluation loop. *"Deploy
   it"* is a numbered list, one line per step, each pointing at the chapter that
   owns it: pre-flight → `wrangler deploy` → secrets → migrations `--remote` →
   first admin → first OIDC client → Observability → day-2 runbook.
2. **The SIEM sentence.** `README.md` says operators forward audit events to a
   SIEM via Logpush. `observability.md` says *"cesauth does not push audit
   events to an external destination (SIEM) today."* Logpush carries Worker log
   lines; audit events are D1 rows. **Correct the README to the chapter**, not
   the other way round.
3. **The badge line.** Three badges advertise `cesauth` on crates.io, docs.rs
   and deps.rs. What is published is a **`0.0.0` name reservation**; all seven
   real crates carry `publish = false`. Add the one line the 2026-09-10
   reservation review asked for and never got, so nobody reads the reservation
   as an index of available packages. `docs/src/expert/contributing.md`
   §Publishing to crates.io is the record, including the owner's 2026-10-30
   ruling that `cesauth-core` may take the `cesauth` name **when reasonable** —
   the README must not imply that has happened.
4. **Link `deployment/preflight.md` and `deployment/production.md` by name** in
   the documentation bullets. Today they point at `wrangler.md`.

**Do not write `first-production-deploy.md`.** That is 0.89.5 and it is blocked
on an owner decision about walking it.

## 4. Acceptance

Two properties, both checkable by reading:

1. **No document in the tree claims a console read surface that does not
   render** — the census in §2 is the list, and each item is either corrected or
   reported as a miscount of mine.
2. **No sentence on the front page contradicts a chapter.** Today two do.

## 5. Gates

Full set, with counts and their commands. Baselines at the `0.89.3` tag: host
tests **1,636** passed / 0 failed / 12 `test result` lines (with
`--features cesauth-frontend/csr`); `migration_chain` **35**; registered routes
**193**; E4 **215** = 193 + 22 + 0; E5 **16** = 16 + 0 + 0; manifest **13**;
Playwright **20**; bundle **882,900 B** gzip with full 64-character sha256 per
module and the parts reconciled.

**What should move, and nothing else:** the bundle, by the six strings' net
size. Host tests should not move — if they do, you changed behaviour, and that
is the finding. `mdbook build docs` and `scripts/drift-scan.sh --verbose` are
the two gates most likely to catch a mistake here; run them early rather than
last.

**One trap.** `drift-scan.sh` enforces RFC 108/126's stale-phrase rules over
the docs. If a phrase you remove is one it pins, it will fail — read its output
rather than working around it, and if it pins a phrase that is part of the
falsehood, **say so**: that is a finding about the gate, not an obstacle.

## 6. Back-fill

Propose Status and Evidence lines for RFC 161 §9(a) and RFC 167 slice 1 in
RFC 000 §22's terms. The honest term for a documentation correction is likely
`reviewed` — there is no behaviour to exercise — and **saying `reviewed` where
`reviewed` is the truth is worth more than reaching for `observed`.**

Report into `.git-exclude/review-request/`.
