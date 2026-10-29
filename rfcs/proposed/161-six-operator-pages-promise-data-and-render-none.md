# RFC 161 — Six operator console pages promise data and render none

**Status.** **Proposed** 2026-10-29. Needs nabbisen's acceptance — **this one
is a product-scope question, not a cleanup**, which is why it is not folded
into RFC 159.
**Tier.** P2. Nothing is exposed, nothing is corrupted, nothing is broken. Six
routed pages an operator can reach tell them data will appear there, and it
never does.
**Size.** The removal is small. **Building them is a feature programme**, not an
RFC-sized change, and §3 does not pretend otherwise.
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
  registered by nothing and fetched by nothing. **Handler and page are two
  unconnected halves of the same unbuilt feature.**
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
