# Developer Handoff — RFC 159, implementation

**Governing RFC.** `rfcs/accepted/159-nine-dead-handlers-no-lint-can-see.md`
— **§2.1 first**, which disproves §3 and is why there is no decision stage,
then **§4 steps 2 and 3**, which are the whole of the work.
**Related, not yours.** `rfcs/accepted/161-six-operator-pages-promise-data-and-render-none.md`
— the other half of the same unbuilt feature. **Do not touch those pages.**

**Target release.** **0.89.2 — patch.** Deleting dead code and adding a check,
the same shape that made RFC 157's twenty-nine deletions a patch.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-29**, after 0.89.1 was cut.

**On 1.0:** not declared, not scoped, not dated.

---

## 1. §4 step 1 is already answered — do not redo it

The RFC sent you to establish, per page, whether each `page_json` was meant to
be fetched. **That archaeology is done and recorded in §2.1**: all six
`admin::console::*` pages are explicit placeholders that fetch nothing and
render nothing, so there is no consumer to wire; the three
`admin::tenancy_console::*` ones are companions to routed, server-rendered
`page` handlers (`lib.rs:334-336`), which is RFC 157's mechanical shape.

**All nine are dead with no fork. Delete them.** If you disagree with that for
any one of the nine, that is a report-and-stop, not a judgement call to make
inside the work.

## 2. Build

1. **Delete the nine**, exactly the list in §2 of the RFC. Nothing else in
   those files: six of them are files whose `page` sibling is live.
2. **The check, which is the lasting part.** A handler-shaped `pub async fn` in
   `crates/backend/src/routes/` whose **qualified path** appears nowhere in
   `lib.rs` fails. A routing check in `route-contracts-check.sh`'s family, with
   a **named and dated exemption list** whose entries each carry a reason — the
   shape RFC 156's manifest check established, where an unreasoned exemption is
   itself a failure.
3. **It must not be a bare-name test.** That is what hid these nine, and then
   fourteen more. Match the qualified path, and handle **both** re-export
   forms, both of which exist today:
   - **brace** — `admin.rs:32`'s `pub use legacy::{create_user, revoke_session}`;
   - **renaming** — `oidc.rs:16`'s `pub use userinfo::handler as
     userinfo_handler`, `:20`'s `pub use introspect::handler as introspect`.

   **The renaming form is the one that caught me out**: a path test handling
   only braces reported `oidc::{introspect,userinfo}::handler` as dead when
   both are routed. **False positives are the worse direction for a gate** —
   they teach people to write exemptions for things that are fine, and an
   exemption list carrying correct entries stops being read.
4. **Fires/does-not-fire must include a name-collision case** — a dead handler
   sharing a name with a routed one. That is the class that produced this RFC,
   and a pair without it proves nothing about the thing being guarded. Show the
   check pass over the real tree, fail on an introduced collision-shaped dead
   handler, and pass again once removed byte-identically.
5. **Re-run RFC 157's census with the check and record the number it gives.**
   RFC 157's own figure came from the bare-name test; this is the first
   trustworthy count of unrouted handlers the project will have. If it is not
   zero after the nine are gone, **stop and report** — that is a tenth finding,
   not something to clean up quietly.

## 3. Required evidence

1. **The nine gone**, with the qualified-path grep returning 0 for each, and
   the six live `page` siblings still routed and still rendering. **Prove the
   four operator-console JSON endpoints adjacent to your deletions still
   answer** — `/admin/console.json`, `/admin/console/tokens.json`,
   `/admin/tenancy.json`, `/admin/tenancy/tenants.json` — because RFC 157's
   cycle removed a smoke probe instead of converting it to a 404 assertion, so
   prove rather than assume. (The frontend references **sixteen** `.json` paths
   in all, not the five RFC 159 §2 claimed; the rest are other modules' and
   two of them are **not routed at all**, which is RFC 162's, not yours.)
2. **The check's fires/does-not-fire pair including the name-collision case**,
   per §2.4.
3. **Both re-export forms demonstrated passing** — brace and renaming — by the
   check running clean over the real tree with `oidc::introspect` and
   `oidc::userinfo_handler` in it. If you must add a test fixture to prove it,
   say so.
4. **RFC 157's census re-run**, with the command and the number.
5. **The exemption list**, if it has any entry at all, with each entry's reason
   — and the demonstration that an entry with an empty reason **fails the
   check**, which is RFC 156's lesson and was the one thing its own cycle left
   undemonstrated until review.
6. **Full gate set with counts.** Host baseline **1,630**; `migration_chain`
   **35**; routes **193** — this should not change, since the nine were never
   routed; bundle with full 64-character sha256 copied from the log; and
   **14 workflows against the manifest if you add a workflow**, 13 if the check
   runs inside an existing one. Say which, and update
   `.github/release-gate-manifest.json` and
   `docs/src/expert/contributing.md`'s gate-set table either way — RFC 138's
   described-vs-actual discipline, and RFC 156 exists because a gate that
   stops running is twelve green checks instead of thirteen and nobody counts.
7. **A `Status` + `Evidence` back-fill line** in the normalised format.

## 4. Resolved — do not re-open

- **All nine are deleted**, not wired. §2.1.
- **The six placeholder pages are untouched.** They are RFC 161's, proposed and
  not yet accepted. Deleting a page, a route or a navigation link is **not** in
  this RFC's scope even though it will look adjacent while you are in the file.
- **Patch**, 0.89.2.
- **Not the inverse check** — *"every URL the frontend fetches has a route"* is
  RFC 162's and will look adjacent while you are writing step 2's. Leave it.
- **Still open, still not this RFC's**: the orphan tenant and the API path's
  missing `via=` audit marker (RFC 158 §5.5). Also out of scope: RFC 152 half B
  and §6; RFC 141 cycle 2; RFC 123; RFC 120.

## 5. Report-and-stop

- any one of the nine looks to you like it should be wired rather than deleted;
- the census after deletion is **not zero**;
- the check cannot distinguish a dead handler from a renamed re-export without
  an exemption — an exemption for a *correct* handler means the check is wrong,
  not that the handler needs excusing;
- an evidence requirement cannot be constructed.

## 6. Review request

`.git-exclude/review-request/159-implementation-report.md`. Give me the commit.
