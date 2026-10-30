# RFC 161 — Six operator console pages promise data and render none

**Status.** **Accepted** 2026-10-30. **Re-reviewed 2026-10-30 at the owner's
request, against the fundamental philosophy — see §6-§9, which overturn §2's
premise, §3's cost estimate and this RFC's own tier.** Full review:
`.git-exclude/reviewed/161-architect-review.md`.

**§9(a) SHIPPED in v0.89.4**, 2026-10-31, in two cycles — the second corrected
a "Deploy it" list whose order was the architect's own and told readers to
deploy before migrating. **Evidence: `reviewed`** (RFC 000 §22) — a
documentation correction has no behaviour to exercise. Eight route-contract
rows, **eight** handler doc comments (two beyond the six the architect named,
found by the implementing cycle), the incident-response chapter including four
false `Console: <filter>` recipes nobody had itemised, and the six pages' own
copy. **Stays in `accepted/`: §9(b) and §9(c) are outstanding** as
[RFC 131](./131-mockup-adoption-strategy.md) §0's slices, and moving this to
`done/` would assert a completion the tree does not have.

**§9's recommendation is APPROVED by the owner, 2026-10-30.** All three parts:
(a) the record correction first, as a docs-only patch; (b) restoration as
[RFC 131](./131-mockup-adoption-strategy.md) slices, **audit first**, by
**finishing the CSR migration** rather than re-pointing at the server views;
(c) the two dropped controls restored with the first slice.

**Release.** §9(a) goes **next after RFC 162**, merged with
[RFC 167](./167-nothing-takes-a-new-operator-to-production.md) slice 1 — both
edit `README.md` and `observability.md`, so one cycle touches them once
(RFC 167 §6). **Patch.** §9(b)'s first slice is a **minor**: restoring the audit
browser adds a JSON route surface, which `ROADMAP.md`'s versioning policy makes
a minor regardless of the capability having existed before. Numbers assigned at
dispatch. **The restoration is slices of
[RFC 131](./131-mockup-adoption-strategy.md), not a release of its own**, and
carries the two controls §6.3 found dropped.

**~~This one is a product-scope question~~** — **it is not.** The owner ruled
the operator console a **first-class product surface on 2026-09-09**
(`ROADMAP.md`, the comment retiring "Management GUI" from out-of-scope), and
RFC 131 §1 already owns *"collapse the two rendering paths production currently
runs into one"*. The question this RFC put to the owner had been answered seven
weeks before it was written. What remains is **how**, in §9.
**Tier.** ~~P2~~ → **P1** (re-tiered 2026-10-30). P2's text was *"nothing is
exposed, nothing is corrupted, nothing is broken"*. **The third clause is
false:** a shipped operator capability regressed in `580eeba`, two controls went
with it (§6.3), and four documents still assert it works (§7). Nothing is
exposed — `shell()` authenticates all six — and nothing is corrupted.
**Size.** ~~The removal is small; building them is a feature programme.~~
**Both estimates were wrong** (§6.2): the core services and the views both
exist, so restoring is wiring, and *removing* is the larger diff — ~1,750 lines
of tested views plus six core services plus the console's only route to the
audit trail.
**Touches.** `crates/frontend/src/pages/operator/console.rs`,
`crates/frontend/src/app.rs`, and — if any page is built —
`crates/backend/src/routes/admin/console/*`, `route-contracts.md`.
**Found by.** The architect, 2026-10-29, doing RFC 159 §4 step 1's per-page
archaeology before dispatching it.

## 1. Summary

`/admin/console/{audit,audit/chain,safety,cost,alerts,config}` are six real,
routed, reachable pages in the operator console. Each renders a heading, a
back-link, and **one sentence promising data**:

```
安全性チェック      「バケット検証の結果がここに表示されます。」
コスト              「テナントごとのコストスナップショットがここに表示されます。」
アラート            「オペレーターアラートがここに表示されます。」
設定                「ライブ設定の確認・適用はここから行います。」
監査チェーン検証    「チェーンの整合性検証をここから実行できます。」
監査ログ            「監査ログの検索・表示機能はここに表示されます。」
```

None of them fetches anything. `console.rs`'s own section comment says so:
`// ─── Generic placeholder pages ───`.

## 2. What is established

- **Six, and the count reconciles against its parts.**
  `grep -c "ここに表示されます\|ここから行います\|ここから実行できます"
  crates/frontend/src/pages/operator/console.rs` → **6**, one per routed page
  (`app.rs:79-85`).
- **None fetches.** The fetch idiom in this crate is
  `gloo_net::http::Request::get("/admin/console.json")` — present in
  `operator/console.rs`'s `ConsoleOverview` and `ConsoleTokens`, and in
  `operator/tenancy.rs`. **Absent from all six.**
- **Their server-side companions are dead**, which is how this was found: the
  six `admin::console::*::page_json` handlers in RFC 159's list of nine are
  registered by nothing and fetched by nothing. ~~**Handler and page are two
  unconnected halves of the same unbuilt feature.**~~ **This sentence is
  wrong — see §6.** Both halves exist, are tested, and shipped; one commit
  removed the call between them. The nine dead `page_json` handlers RFC 159
  deleted were the smallest layer of the same disconnection, not evidence that
  the feature was never built.
- **Not an i18n defect.** Every page under `pages/operator/` is `lang="ja"`
  (`grep -rn 'lang="' pages/operator/*.rs` finds no other value), so
  Japanese-only is this surface's house style and not something this RFC
  found. Checked before writing, so it would not be reported as a finding.

## 3. Why this is the owner's question and not the architect's

RFC 145 spent three cycles on admin pages that answered `200` and rendered the
wrong thing. These do not lie — they say plainly that the feature is not there
yet. **But an operator who reaches `/admin/console/cost` from the console's own
navigation learns only that cost data exists somewhere and not here**, with no
indication whether that is a week away or a year, and that is the standard this
project is held to: *APIs and UI/UX for users not to be confused or
misunderstand.*

Three ways out, and **choosing between them is a product decision**:

1. **Build them.** Six operator features — audit-log search, chain
   verification, bucket safety, cost snapshots, alerts, live config. The
   backend data already exists for several (`admin/cost_snapshots.rs`,
   `admin/bucket_safety.rs`, `ports/audit_chain.rs`), which is presumably why
   the pages were sketched. This is a programme, not a cycle.
2. **Remove the routes and the links**, and let the console show only what it
   has. Smallest, and reversible when a feature is built.
3. **Keep them and say when.** A placeholder that names a target — or that is
   reachable only from a documented "not yet built" list rather than from live
   navigation — is honest in a way a bare promise is not.

**No recommendation here, deliberately.** The architect's remit is design and
schedule; whether cesauth's operator console ships these six surfaces is
scope, and the last time a scoping answer was turned into a statement about
what the product *will* contain, it had to be corrected everywhere.

## 4. Not in scope

- **RFC 159's nine dead handlers.** They go whether or not these pages are
  built: an unrouted stub with no contract row and no data query saves none of
  the work a real page would need. RFC 159 removes them; this RFC does not
  depend on that and is not blocked by it.
- The three `admin::tenancy_console::*` handlers in RFC 159's list — their
  `page` siblings are server-rendered and routed (`lib.rs:334-336`), so those
  pages are real and this RFC has nothing to say about them.

## 5. The lesson worth keeping in the record

**RFC 159 §3 argued that six of its nine handlers might deserve wiring rather
than deletion**, because they sit beside *"live, `client`-declared Leptos
pages"* and *"a `page_json` companion is exactly the shape a CSR page would
consume."* That reasoning was mine and it was sound in form. It was wrong in
fact, and three greps settled it: the pages those six sit beside render
nothing and fetch nothing, so there was never a consumer to wire.

**The archaeology I scheduled a decision stage for was cheaper than the stage
would have been.** Doing it before dispatching turned one design fork into
zero and produced this RFC instead. Check the premise of a stage before paying
for the stage.

## 6. Re-review, 2026-10-30: it was built, shipped, and disconnected

Asked by the owner to review this RFC against the fundamental philosophy. Every
figure below is re-derived; the commands are in
`.git-exclude/reviewed/161-architect-review.md`.

### 6.1 One commit, three layers

**`580eeba` — "RFC-115 Phase C complete: old string templates removed"** —
replaced each of the six handlers' bodies with
`operator_json_api::shell(&req, &ctx, "…")` and nothing else. The CSR components
meant to replace the removed server rendering were written as the one-sentence
placeholders §1 quotes. Nothing since has reconnected either side.

### 6.2 The halves both exist

**`crates/core/src/admin/service/mod.rs`** — ten public services; backend
callers per name:

```
build_overview         0     verify_bucket_safety           1
build_cost_trend       0     apply_bucket_safety_change     2
build_cost_dashboard   0     preview_bucket_safety_change   2
build_safety_report    0     update_threshold               1
search_audit           0
generate_alerts        0
```

**Every read service is uncalled; every write service is called.** The six
uncalled ones are exactly these six pages.

**`crates/frontend/src/admin/`** — 3,229 lines of server-rendered operator
views. Four of the twelve re-exported names are called, plus `frame::admin_frame`
and `preview::preview_body`. **Uncalled:** `alerts_page`, `audit_page`,
`audit_chain_status_page`, `config_page`, `cost_page`, `overview_page`,
`safety_page`, `tokens_list_page`, `operations_page`. The modules whose only
export is uncalled total **1,746 lines**, plus **496 lines** of passing tests in
`admin/tests.rs` that pin views nothing renders. `audit.rs` alone is 546 lines
and contains both the filter form and the export form.

**So "build them" is not a programme.** The work is the call between two halves
that are already written and already tested.

### 6.3 Two controls went with the bodies

- **`ensure_role_allows(AdminAction::ViewConsole)`.** The pre-`580eeba`
  handlers called it; the six no longer do. Every console surface that still
  works does. `shell()` authenticates, so **nothing is exposed** — but the gap
  is specific to these six and anyone rebuilding on `shell()` inherits it.
- **`AdminConsoleViewed` has no emitter.** Two hits in the whole workspace, both
  in `audit.rs`: the variant and its string. **Console page views are no longer
  audited**, which is RFC 045's finding class arriving by regression.

### 6.4 The write side is intact and unreachable

`POST /admin/console/audit/export` is implemented, role-gated, and had its CSRF
hardened by **RFC 141 C1-141** — and the only form that posts to it, carrying
the `csrf` field it requires, is in the uncalled `admin/audit.rs`. **A cycle was
spent hardening a form no page renders.** The same holds for
`safety/:bucket/verify`, `audit/chain/verify` and `thresholds/:name`.
`/admin/console/audit/chain` appears exactly once in the frontend — `app.rs:80`,
its own route declaration — so **no link reaches it.**

## 7. Four documents say these features work

The page copy is the *only* hedged artifact, and it is the one a user meets last.

1. **`route-contracts.md`** names the views *"audit search page"*, *"chain
   status page"*, *"cost page"*, *"safety page"*, *"alerts page"*, *"token
   list"*, all declared `client`.
2. **The handler doc comments.** `audit.rs` documents **nine query parameters**
   with their matching semantics and parsing rules, citing RFC 109 and v0.71.0;
   the handler reads none. `cost.rs` explains why it snapshots on every view and
   that `CostSnapshotRepository` dedupes by hour bucket; it calls no repository.
   `alerts.rs` says it *"combines every alert source … newest first."* **This is
   `preview.rs`'s "the route itself is registered" defect — the one RFC 159
   deleted a file over — at twenty times the size.**
3. **`docs/src/deployment/observability.md`**, the chapter read *during an
   incident*: *"Four routes surface the table. 1. `/admin/console/audit` — the
   admin console's audit browser. Filters, per `…/console/audit.rs`: …"*, with
   per-filter semantics and a note that an invalid `from`/`to` *"is dropped
   silently … the page still renders"* — a statement about the behaviour of a
   rendering path that does not exist. The chapter concludes *"For day-to-day
   incident response, the admin console covers most needs."*
4. **v0.79.7's release note:** *"35 GET routes under `/admin/console/*` …
   migrated."* Six were emptied, not migrated.

**Stated accurately:** the audit trail *is* readable in production — the same
chapter's route 4, `wrangler d1 execute --remote`, works. The defect is that the
**only** production read path is raw SQL against production D1 from a terminal,
itself privileged, role-unchecked and unaudited, while the document that says
the console covers it points at a page with one sentence on it.

**And the README contradicts that chapter.** `README.md`: *"Operators forward to
external SIEM via Cloudflare Logpush."* `observability.md`: *"cesauth does not
push audit events to an external destination (SIEM) today."* Logpush carries
Worker log lines; audit events are D1 rows.

## 8. §3's fork, measured

- **Remove** contradicts the 2026-09-09 ruling and is the **largest** diff:
  ~1,750 lines of tested views, six core services, and the console's only route
  to the audit trail.
- **Say when** is honest copy and nothing more — the right stopgap, the wrong
  answer.
- **Build** is the unfinished half of RFC 131 §1's own goal: *"collapse the two
  rendering paths production currently runs into one."* The two paths are
  `frontend/src/admin/*` and `frontend/src/pages/*`, and these six pages are
  what fell between them.

## 9. Recommendation

**(a) Correct the record now, as its own patch — 0.89.4, authorized
2026-10-30.** No product decision gates it and it is the half that misleads
today.

**Two counts in the first draft of this section were wrong, and both
understated** (re-derived 2026-10-30 before dispatch):

- **Not "four" `route-contracts.md` rows — eight name a view that does not
  render.** The six here, plus `/admin/console/tokens` (*"token list"*, which
  lists nothing) and `/admin/console/clients` (*"client list"*, which renders
  `NotFound`; see [RFC 141](./141-oidc-client-registration.md)). A ninth,
  `/admin/console` (*"overview page"*), shows a navigation list and a ✓/⚠ line
  derived from a CSRF-only endpoint — it overstates without being false.
- **Not "three" handler doc comments — all six do it**, and three
  (`audit_chain.rs`, `safety.rs`, `config.rs`) mix a false claim about the page
  with **accurate** claims about their `POST` handlers: *"This handler renders
  that outcome plus a button for an immediate full re-walk"*, *"renders the
  per-bucket safety report"*, *"renders the attested bucket-safety rows and the
  current threshold values"*. The correction is surgical, not wholesale
  deletion.

**That is the fourth figure of mine this week not to survive re-derivation**,
which is why the handoff makes the implementer derive the population rather than
work from the list above.

The work: those rows renamed to what they render, the six handler doc comments
cut to the truth with a pointer here, `observability.md`'s audit-browser entry
replaced by the `wrangler d1 execute` path it already documents, and the
README's SIEM sentence corrected.

**The page copy is per-page, not one sentence repeated.** Only audit has a real
alternative to name (`wrangler d1 execute`, which `observability.md` already
documents). **Cost, safety, alerts and config have no read path at all**, so
their copy says the feature is not built and points at nothing — pointing at a
workaround that does not exist is the same defect in a new costume. All copy is
Japanese, per ADR-013.

**(b) Restore as named slices of RFC 131**, in the order an operator misses
them: **audit (browser + the export form that exists) → chain status → safety →
alerts → cost → config.** Audit first — it is the incident-response surface, the
one the docs promise most specifically, and its view is the largest and most
complete of the six.

**The owner's remaining decision is only this:** finish the CSR migration (six
components plus the six JSON endpoints never added — `overview`, `operations`
and `tokens` JSON serve only a CSRF token; the other six have no JSON at all),
or re-point the handlers at the server views that already exist and flip those
rows from `client` to `server`. **I recommend finishing the migration.**
Re-adopting the string templates would re-create the two rendering paths RFC 131
exists to collapse, and finishing it makes the 496 lines of view tests honestly
deletable instead of kept alive to pin dead code.

**(c) Restore §6.3's two controls with the first slice**, not after it.

**Not in scope of this recommendation:** the `/admin/tenancy/*` half of the same
migration, which §4 excluded and I did not re-derive. The method is three greps
per surface if the owner wants it checked.

**The gate that would have caught this is [RFC 166](../proposed/166-reachability-stops-at-the-crate-boundary.md).**
RFC 157, 159 and 162 all stop at the `cesauth-backend` boundary; nothing asks
whether a `core` service or a `frontend` view has a caller. Six services and
nine views have had none since May, through eleven releases and two dead-code
sweeps — and E4 could not have caught any of it, because all six handlers *are*
registered.
