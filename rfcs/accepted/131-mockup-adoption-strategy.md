# RFC 131 — Mockup adoption strategy

**Status.** Accepted — approved by the owner 2026-09-05. R0's spike is the
first work item.
**Tier.** P1 · Category B — a strategy RFC. It decides *how* adoption happens
and spawns the implementation RFCs; it is not itself a unit of work.
**Size.** Large (programme). Individual slices are Medium at most.
**Tracks.** Owner decision 2026-09-03: adopt the GUI mockup
(`cesauth-mockup` v0.14.0). Closes the longest-standing open decision from the
v0.81.0 architect review.
**Touches.** `crates/frontend/`, `crates/backend/src/routes/` (shell and
template call sites), `e2e/` (new), `docs/src/`.
**Depends on.** RFC 130 — the build pipeline and toolchain pin must be
verified before the frontend's contents are rewritten.
**Target release.** Programme; first slice no earlier than 0.81.3.

## 1. Summary

Adopt the mockup's presentation layer — components, view-model contracts,
shells, i18n and its accessibility harness — onto cesauth's existing data
wiring. Collapse the two rendering paths production currently runs into one.
Bring no mock data across at any point.

The owner's stated goal is the acceptance test for this RFC: **"finally clean,
safe and secure, robust and sophisticated design."** §3 turns that into
checkable properties.

## 2. What this is, precisely

**A merge, not a port.** Established by inspection of the v0.14.0 tarball:

| Fact | Evidence |
|---|---|
| Mockup screens carry **no** `ssr`/`hydrate` gating | zero `cfg(feature` in `mockup-workbench/src/routes/` |
| `cesauth-ui` components/view-models carry one feature gate, and it is `mockup-workbench` | not a rendering-mode gate |
| Mockup screens perform **no data fetching at all** | no `gloo`, `Resource`, `LocalResource`, or `fetch` anywhere in `routes/` |
| Production screens **do** have the data layer | RFC 127 R3 converted 18 `LocalResource` fetch sites in `crates/frontend/src/pages/` |
| Screens are not extracted | `crates/ui/src/screens/mod.rs` is 6 lines — the declared boundary, empty |
| Split | `cesauth-ui` 3,489 LOC · `mockup-workbench` 9,162 LOC |

So the mockup supplies **presentation**; cesauth already supplies **data**.
The work is pairing them screen by screen — not moving 9,162 lines.

The earlier concern that `cesauth-ui` lacks a `csr` feature is **resolved**:
its ssr/hydrate feature set is an artifact of the Axum preview harness, not a
property of the components. Adding a `csr` feature is plumbing.

### 2.1 What adoption covers — and what it cannot

The mockup's screen set is a **superset** of production's route surface.
Production registers no routes for four of its screen groups:

| Mockup screens | Production routes today |
|---|---|
| TA-OIDC-01/02/03 — OIDC client management | none |
| TA-ROLES / TA-ROLES-D — roles catalogue | none (role *assignment* routes exist; a catalogue does not) |
| ME-APPS — connected applications | none |
| SO-INV — investigate hub | none |

Those are **new features**, not presentation swaps: each needs backend routes
and `.json` endpoints that do not exist. §4 and §6 put both out of scope, so
they are **not part of this programme**. Each earns its own RFC, and each
carries the owner's §4 caveat that our own UI/UX judgement governs rather than
the mockup's product decisions.

**This determines versioning.** A slice that re-skins a screen production
already serves changes no route, no contract, and no observable surface — a
**patch**. A slice that introduces a screen production has no route for adds
HTTP route surface, which is the first item in ROADMAP's minor-bump rubric — a
**minor**. Because this programme contains only the former, it ships as
`0.81.x` patches. The screens above, when their own RFCs are written, are
`0.82.0` work.

## 3. The goal, as checkable properties

**Clean.**
- **One rendering path per surface, chosen deliberately.** Production runs two
  today, accidentally: the Leptos CSR
  shells *and* the `format!` template layer, which RFC 115 Phase C reported
  removed but which is still live — `routes/magic_link/verify.rs:35` calls
  `magic_link_sent_page_for`; `backend/src/flash.rs` uses
  `templates::FlashView`. Adoption collapses this.
- No orphaned modules. `crates/frontend/src/render_context.rs` (74 lines) has
  no `mod` declaration anywhere and contains a test that has never run.
- Nothing imported that is not used. The mockup's `DevPanel`, `mock/`,
  `ScenarioSwitcher` and workbench harness do **not** cross.

**Safe and secure.**
- **Mock data never enters the production codebase.** Not transitionally, not
  behind a feature flag, not "to be cleaned up later."
- Every screen arrives already wired to a real data source.
- The security properties the mockup encodes are preserved: explicit scope on
  every role assignment, audit notices on privileged mutations, typed-phrase
  confirmation on destructive actions, one-time reveal for secrets.

**Robust.**
- The mockup's Playwright harness comes across — 7 specs including Axe
  WCAG 2 AA, focus-trap, mobile layout and hydration smoke. cesauth has **no
  browser-level verification of any kind**; this closes that gap and answers a
  separate open decision.

**Sophisticated.**
- "Less is more" progressive disclosure (mockup RFCs 038/039, and the
  project's own UI/UX rule) — immature users see essentials; detail is opt-in.
- Our own UI/UX judgement governs. The mockup is a vocabulary and a set of
  contracts, not a product specification to be accepted whole.

## 4. Non-goals

- Adopting the mockup's *product* decisions unexamined. The four stub sidebar
  areas (Branding, Federation, Webhooks, API tokens) are **not** imported as
  dead navigation; if wanted, each earns its own RFC.
- Leptos 0.9.x migration.
- Changing any backend route, wire format, schema, DO payload, or cookie.
- Re-deciding the rendering mode as part of this RFC — see §5 R0.
- RFC 130's pipeline work. This depends on it; it does not repeat it.

## 5. Proposed design

**R0 — ~~Decide the rendering mode~~ SUPERSEDED by RFC 132.**

R0 asked which global rendering mode to adopt. RFC 132 establishes that there
is no global answer: mode is **derived per surface** from whether the user can
route around a failure, whether the surface is pre-authentication, whether it
needs client interactivity, and whether it is machine-facing. See RFC 132 §5
for the rule and §5.1 for the classification of all 188 routes.

R3 therefore inherits an assignment rather than a preference, and the
SSR+hydrate spike is not required for this programme to proceed — RFC 132 §7.

*Why this was superseded rather than answered: posing the question globally is
what produced the state RFC 132 §3 documents. RFC 115 chose per screen and a
split emerged instead of being decided.*

**R1 — Land the pipeline first.** RFC 130 must be complete: `trunk build
--release` working, artifact naming resolved, toolchain pinned. Rewriting the
frontend's contents on an unverified build pipeline would confound two sets of
failures.

**R2 — Import the foundation.** `cesauth-ui`'s primitives, shells, view-models,
i18n and icons — the 3,489 LOC that RFC 027 already made production-safe.
Rename to avoid the `cesauth-ui` collision (RFC 126's drift rule now treats
that name as stale; the crate it names was renamed by RFC 114). Reconcile the
Leptos pins **after** RFC 130's M2 reports, not before —
`DEPENDENCIES.md` records `=0.8.19` as *"unverified for production"* and M2 is
the first thing that will actually verify it.

**R3 — Pair screens with data, one at a time.** For each screen: take the
mockup's presentation, wire it to the production fetch logic that already
exists in `crates/frontend/src/pages/`, delete the corresponding `format!`
template, and land it. One screen per reviewable unit where practical.

**Mock fixtures are never committed, at any intermediate step.** Because
mockup screens take props from mock data, wiring must happen *as* the screen
moves, not after. A mechanical move followed by cleanup would put fake
credentials in the tree, however briefly.

**R4 — Collapse to one path per surface class**, per RFC 132 §5.1 — not to one
path overall. `render_context.rs` (74 orphaned lines) is deleted outright. The
`format!` templates serving the **pre-authentication** surfaces are **kept**:
RFC 132 classifies those `server`, and they are the reason a user without
JavaScript can still authenticate. What gets deleted is every *duplicate* — a
screen rendered two ways — which is the accidental condition this programme
exists to end.

One conformance gap falls out of RFC 132 and belongs to this step: `/` and
`/login` render through `leptos_html_shell` and must render server-side.

**R5 — Adopt the e2e harness.** Bring `e2e/` across and gate it in CI. Do this
early rather than last: it is the only check that would catch a screen that
compiles, is served, and does not work.

## 6. Data model / API impact

None. The `.json` endpoints documented in RFC 125's C1 are the contract
between presentation and data, and they do not change. If a screen needs data
no endpoint provides, that is a finding to report — not a licence to add a
route inside this programme.

## 7. Testing strategy

1. Full gate set green at every slice.
2. **No mock-data markers in the tree**, asserted mechanically and gated in CI:
   `grep -rn 'doNotUse\|example\.test' crates/` returns nothing outside tests.
   This is the enforcement that replaces the workbench's safety tests, which
   stay in the mockup repository where they belong.
3. Playwright suite green once R5 lands.
4. Per screen: the route renders, fetches its data, and the a11y spec passes.
5. When R4 completes: no `format!` template call site remains in
   `crates/backend/`, asserted by grep.

## 8. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Mock fixtures land transitionally | Fake credentials in production source | §5 R3 forbids the intermediate state; §7.2 gates it in CI |
| Two rendering paths persist indefinitely | The exact confusion this RFC exists to remove | R4 is an acceptance criterion, not an aspiration; each slice deletes its template |
| The mockup's product decisions get adopted by default | UI we did not choose | §4 non-goal; stub areas explicitly excluded |
| Programme stalls half-migrated | Worst of both — two paths, two vocabularies | Slice by screen so every landing is independently valuable; if it stalls, what shipped still works |
| Screen needs data no endpoint provides | Scope creep into backend routes | §6 — report it, do not add routes here |
| Leptos pin reconciled before verification | Repeats the v0.80.2 mistake | R2 waits for RFC 130's M2 |

## 9. Acceptance criteria

1. Rendering mode decided and recorded (R0).
2. Foundation imported under a non-colliding name; drift-scan clean.
3. Every screen paired with real data; no mock fixture ever committed.
4. `format!` template layer and `render_context.rs` deleted; **one** rendering
   path remains, asserted by grep.
5. Playwright suite in CI, blocking, demonstrated to fire.
6. No `doNotUse` / `example.test` markers outside tests, gated.
7. Full gate set green.
8. Stub sidebar areas absent unless separately authorised.

## 10. Open questions

1. **R0's answer** — resolved by the spike in §5 R0, not by argument. The
   question changed once it emerged that the authentication path is
   server-rendered today and works without JavaScript.
2. **Screen-by-screen or shell-first?** Landing the four shells early gives
   every subsequent screen a consistent frame, at the cost of a period where
   shells and old templates interleave. My leaning is shells first, but it
   depends on how cleanly the shells sit over existing routes.
3. **What happens to the mockup repository afterwards?** Once its presentation
   layer lives here, keeping it as a design sandbox invites drift between two
   component libraries. Archiving it loses the preview harness. Worth deciding
   before, not after.
4. **Does the operator console's JA-only rule (ADR-013) survive?** The mockup
   implements it (its RFC 034). Confirm it is still wanted rather than
   inheriting it silently.
