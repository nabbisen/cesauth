# cesauth RFCs

Implementation-handover specifications for ROADMAP themes.
Governed by **RFC 000 — RFC lifecycle policy** (`done/000-rfc-lifecycle-policy.md`),
adopted 2026-09-03 in its **5-folder variant**. It supersedes RFC 019, now in
`archive/`.

## What an RFC is here

An RFC is the **engineering spec** for an upcoming theme — the thing an
implementer reads after the ROADMAP to know what to build, how to test it,
and which invariants must not break. It is **not** the design forum (that's
the ADR system in `docs/src/expert/adr/`).

| Document | Audience | Question it answers |
|---|---|---|
| ADR | Architect / reviewer | *Why* this design; trade-offs; alternatives rejected |
| RFC | Implementer | *What* to build; acceptance criteria; test strategy |
| CHANGELOG | Operator | *What shipped* and upgrade notes |

## Lifecycle

Folder = source of truth for state. `Status` field inside each file mirrors folder.

```
rfcs/
  proposed/    ← under review; implementer should NOT start
  accepted/    ← owner approved; implementer may start
  done/        ← shipped AND the Status field says what evidence
               says it works (RFC 000 §22); never delete
  archive/     ← withdrawn or superseded; never delete
  handoffs/    ← companion execution docs; state inherited from the RFC
  README.md    ← this index (update in same commit as any move)
```

`draft/` is deliberately absent — RFC 000's guidance is to add it only when
multiple authors need a shared drafting space.

`accepted/` is the state that makes owner approval an explicit, visible event
rather than a sentence buried in a Status field. Before it existed, three
accepted RFCs carried an apologetic parenthetical instead.

Full policy: `done/000-rfc-lifecycle-policy.md`.

**`done/` means shipped *and* evidenced.** RFC 000 §22 — added by
[RFC 151](./accepted/151-done-cannot-distinguish-shipped-from-working.md) — requires an
Implemented RFC's Status field to carry one of **exercised** / **observed** /
**reviewed** / **unknown**, and bars a P0 or P1 RFC from entering `done/` on
`reviewed` or `unknown` alone. The rule exists because [RFC 047](./done/047-deletion-worker-layer.md)
sat here across 61 releases, correctly filed, with both deliverables dead.

---

## Proposed

### Awaiting owner authorization

| ID | Title | Tier | Target |
|----|-------|------|--------|
| [166](./proposed/166-reachability-stops-at-the-crate-boundary.md) | **Reachability stops at the crate boundary.** RFC 157, 159, 162 and 165 all ask reachability questions, and **every one of them stops at `cesauth-backend`.** Nothing asks whether a `cesauth-core` service has a caller or a `cesauth-frontend` view does — the answer is **no for 6 of 10 services and 9 of 12 views**, all six of RFC 161's pages, since May, through eleven releases and two dead-code sweeps. **E4 could not have caught it: all six handlers *are* registered.** The compiler cannot either — everything is `pub` in a library crate. **Deliverable (0) counts it before the check is designed**, because the number decides whether an allowlist is honest or a structural rule is needed, and a large one is itself the finding. The frontend layer is the hard half and must not be faked | **P1** | unassigned |
| [144](./proposed/144-introspection-reveals-family-existence.md) | **Introspection reveals that a family exists** to an authenticated caller presenting a forged jti: `expired`/`revoked` are classified before the jti comparison, which the mismatch path conflates to `unknown` precisely to avoid this. **Recorded as an RFC because it was lost once** as "recorded for RFC 118" | P3 | filler |

### Other proposed

UI/UX finishing track (v0.67.0 → v0.71.0). Source: v0.50.1 UI/UX design
deck (overview onepage + dev-support PDF) compared against v0.66.0 state.
The deck is largely shipped through v0.53/v0.62/v0.63; this batch closes
the residual gaps. See ROADMAP.md "UI/UX finishing track" for grouping.

| ID | Title | Tier | Target |
|----|-------|------|--------|
| [112](./proposed/112-worker-auth-macro-batch-migration.md) | Worker auth macro batch migration (RFC 100 全面適用) | P2 | env-blocked |
| [110a](./proposed/110a-rate-limit-summary.md) | Rate limit summary surface (RFC 110 sub-RFC) | P2 | v0.75.0+ (KV-heavy, env-blocked) |

Security-critical assurance track. Source: architect instruction
`security-critical-assurance-strategy-v0.80.2.md`; audit report at
`docs/src/expert/security-assurance-audit-v0.80.2.md`. Implement in ID
order (116 first — later RFCs consume its newtypes). Numbers 114/115 are
consumed by the v0.79/v0.80 workspace-restructure and Leptos-migration
work (see CHANGELOG); per RFC 000, numbers are never reused.

RFC 116 shipped in v0.81.0 and now lives in
[`done/`](./done/116-security-type-modeling-baseline.md). Two carve-outs
were deferred out of it and are tracked as follow-ups: secret-newtype
adoption at the remaining credential call sites (handoff RISK-001), and
`ports::repo`, which RFC 116 did not reach — it remains entirely `&str`
and un-scoped, and is folded into RFC 119.

Build integrity.

| ID | Title | Tier | Category | Depends on |
|----|-------|------|----------|------------|

Security-critical assurance track, continued.

| ID | Title | Tier | Category | Depends on |
|----|-------|------|----------|------------|
| [117](./done/117-authorization-code-lifecycle-assurance.md) | Authorization code lifecycle assurance — **shipped v0.84.1** | P0 | A | 116, 137, 140 |
| [118](./done/118-refresh-rotation-assurance.md) | Refresh token rotation & reuse-detection assurance — **shipped v0.84.2** | P0 | A | 116, 117, 139 |
| [119](./proposed/119-tenant-scoped-repository-apis.md) | Tenant boundary & scoped repository APIs | P1 | B | 116 |
| [120](./proposed/120-authz-core-sealing-and-property-tests.md) | Authorization core: sealing & property tests | P0/P1 | A/B | 116 |
| [121](./proposed/121-security-state-machine-testing.md) | Security state-machine testing with proptest | P1 | B | 117, 118 |
| [122](./proposed/122-fuzzing-untrusted-input-boundaries.md) | Fuzzing for untrusted input boundaries | P1 | B | 117 |
| [123](./proposed/123-audit-event-completeness.md) | Audit event completeness for privileged operations | P1 | B | 116 |
| [124](./proposed/124-formal-methods-pilot.md) | Lightweight formal/model-checking pilot | P2 | C | 118, 120 |

---

## Accepted

Owner-approved; implementation may start. Rows are in **sequencing** order.

**The active queue begins at RFC 162** (dispatched 2026-10-30) and runs
162 → 161 §9(a) + 167 slice 1 → 167 slice 2 → 131 §0 slice 1 → 141 cycle 2 →
164 → 165 §3 → 163. **RFC 133, 151 and 152 sit above it and are not sequenced
against it** — they are long-standing accepted items that have been
out-prioritised release after release, and saying so is better than a table that
implies they are next. Re-sequencing or re-scoping them is its own decision and
has not been made.

| ID | Title | Tier | Dispatched | Depends on |
|----|-------|------|---|---|
| [133](./accepted/133-build-reproducibility.md) | Build reproducibility — **narrowed and split 2026-09-24 (§12)**. Half A scheduled: the optimizer's read–write aliasing and history dependence, the wasm-bindgen determinism experiment, and a false "run-reproducible" claim in `BUNDLE_SIZE_BUDGET.md`. Half B (environment reproducibility) deferred to 1.0 hardening — and **§15's cross-host gap is retracted (§15.3)**: it was my measurement error, not a host difference. Rebuilding the same commit puts local within **94 bytes** of CI against the 3,001 claimed, and two of the four recorded rows do not reconcile against their own components. Local builds are byte-reproducible. Half B now has **less** reason to open early | P2 | 2026-09-24 | — |
| [151](./accepted/151-done-cannot-distinguish-shipped-from-working.md) | **`done/` cannot distinguish "shipped" from "works"**, and amends RFC 000. RFC 047 sat in `done/` across **61 releases** (0.53.0 → 0.86.0) with both deliverables non-functional, correctly filed by the letter of both definitions. One Status field — `exercised` / `observed` / `reviewed` — with P0/P1 barred from entering `done/` on `reviewed` alone. No new folder | P2 | **architect's own work, before the 0.86.1 dispatch** — so RFC 145 is the first RFC filed under the new rule | — |
| [152](./accepted/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one.md) | **The admin surfaces' documented CSRF control is not the real one.** All 35 `POST` rows under `/admin/t/:slug/*` and `/admin/tenancy/*` document CSRF as `required`; **33 never call `csrf::verify`** — the 2 that do are the newest, from RFC 147 cycle 2, so the pattern is applied to new work and was never retrofitted. Not exploitable today (`SameSite=Strict`), but **fifteen destructive operations rest on one cookie attribute** no row names and no test asserts. §5: **both halves** — A documents and pins the real control, B adds the 33 checks | P1 | **A: 0.86.3 · B: after 0.87.0** | — |
| [162](./accepted/162-two-console-pages-fetch-urls-nothing-serves.md) | **Two console pages fetch URLs nothing serves.** `tenant_admin/overview.rs:17` asks for `/admin/t/{slug}.json` and `operator/tenancy.rs:129` for `/admin/tenancy/tenants/{tid}.json`; the routes are `…/detail.json` in both cases, so each resolves against the HTML route's `:slug`/`:tid` capture — **RFC 145 cycle 3's mechanism** — and both swallow the parse failure with `.ok()`, so the page renders empty with no error. Visible only on **client-side** navigation, since a hard load is server-rendered. **One of them is the tenant-admin overview**, the first page a tenant owner reaches on the console RFC 158 opened. **Found by checking RFC 159 §2's claim that the frontend fetches five `.json` paths — it references sixteen** | **P1** | **complete** (`c895e1b`), **patch, ready to cut**. Both URLs fixed and proven live; **E5** built beside E4 — the inverse check, ranking same-length routes by fewest captures so an already-correct literal route is never misreported (a false positive I hit in a prototype and they reproduced); all **16** `.json` fetches now resolve exactly; `TenancyFormPlaceholder` deleted. **Two of my claims corrected by the cycle and right both times**: `overview.rs` never used `.ok()` (only `tenancy.rs` does, so the tenant-admin page showed an **error**, not a blank — the tier stands for the other page's reason), and my predicted status codes were wrong (404, not 200). Host tests **1,636** (+6) after adding `--features cesauth-frontend/csr` to the canonical command, which trades nothing — `csr` is purely additive and the 61 `admin::` view tests run identically either way. **§3 deliverable (0) is a report-and-stop**: observe both URLs with `curl` and observe the page on client-side navigation before changing a line; if either URL turns out to be served, the premise is wrong. Then two one-line fixes, then the inverse check — *every URL the frontend fetches has a route* — which must handle `format!`-built paths, since both defects are in one | 158, 159 |
| [161](./accepted/161-six-operator-pages-promise-data-and-render-none.md) | **Six operator console pages promise data and render none** — and the re-review the owner asked for on 2026-10-30 (§6-§9) overturned this RFC's own premise. They are **not unbuilt**: `580eeba` ("RFC-115 Phase C complete") replaced six handler bodies with a bare shell, and the halves both still exist — **6 of 10 `cesauth-core` admin services have no caller**, and **9 of 12 `cesauth-frontend` admin views have none** (1,746 lines, plus 496 lines of passing tests pinning views nothing renders). Two controls went with the bodies: the `ViewConsole` role check, and `AdminConsoleViewed`, which now **has no emitter anywhere**. **Four documents still say the features work** — `route-contracts.md` ("audit search page"), the handler doc comments (`audit.rs` documents nine query parameters it never reads), `deployment/observability.md` (*"the admin console's audit browser"*, in the chapter read during an incident), and v0.79.7's *"35 GET routes … migrated"*. RFC 141 C1-141 hardened the CSRF of an export form **no page renders** | **P1** (was P2) | **§9 APPROVED by the owner 2026-10-30.** Record correction → **patch, second**, merged with [RFC 167](./accepted/167-nothing-takes-a-new-operator-to-production.md) slice 1 since both edit the README and `observability.md`; restoration = slices of [RFC 131](./accepted/131-mockup-adoption-strategy.md), audit first. The product question was answered **2026-09-09** when the owner ruled the console first-class; the owner chose **finish the CSR migration**; the restoration is [RFC 131](./accepted/131-mockup-adoption-strategy.md) **§0**, six named slices, audit first, each a **minor** (every one adds a JSON route surface) | 131, 115 |
| [167](./accepted/167-nothing-takes-a-new-operator-to-production.md) | **Nothing takes a new operator from zero to production.** The production docs **exist and are good** — 15 deployment chapters, pre-flight through disaster recovery — and nothing routes a reader into them: the README's Quick start is four commands beginning `cargo test`, a contributor loop with no `wrangler deploy`, no secrets step, no first admin and no first client, and its doc bullets point at `wrangler.md` rather than `preflight.md` or `production.md`. **Two claims on the front page are false**: the README says operators forward audit events to a SIEM via Logpush, which `observability.md` denies in as many words (Logpush carries log lines; audit events are D1 rows), and three badges advertise a crates.io/docs.rs crate that is a **`0.0.0` placeholder** — the one-line mitigation the 2026-09-10 reservation review asked for was never added. **RFC 141 cycle 1 (v0.85.0) made an honest walkthrough possible** and none has been written | P2 | **accepted 2026-10-30** — *"should be improved and enhanced with actual schedule and plans"*. §8 is the plan: **slice 1 (README, merged into RFC 161 §9(a)'s cycle, patch, second)** and **slice 2 (`first-production-deploy.md`, patch, third)**. Slice 2 **needs an owner action**: its acceptance test is that a reader follows it without opening a chapter out of order, which means walking it against a real Cloudflare account — so the owner walks it, authorises an account for the walk, or it ships marked `reviewed`, not `exercised`. This **displaces RFC 164 / 165 §3 / 163 by three positions**, deliberately: each of those is a verified **latent** finding, and a front page that contradicts a chapter is not | 141, 161 |
| [131](./accepted/131-mockup-adoption-strategy.md) | Mockup adoption strategy (merge, not port) | P1 | R2a shipped v0.82.0; **R5b–e shipped v0.83.0** (+ C1-R5); R2b awaits 132 §13 q1; R3 awaits 132 §13 q1 | 130, 132, 134 |
| [141](./accepted/141-oidc-client-registration.md) | **OIDC client registration has no API.** No route creates a client; the production guide tells an operator to hand-write `INSERT INTO oidc_clients (…) VALUES (…)` with the columns elided, including a hash they must compute. Adds the API, the console screen, an integrator chapter, and enforcement of the registered auth method | P1 | cycle 1 + C1-141 accepted **2026-10-25**; cycle 2 (console screen + §13's six unregistered `page_json` handlers) pending | 116, 137 |
| [164](./accepted/164-the-link-sweep-rfc-000-mandates-is-unenforced.md) | **The link sweep RFC 000 mandates is unenforced.** A relative-link check over `rfcs/**/*.md` finds **25 broken links**. **Nine are folder-move rot** — RFC **142**, **153**, **154**, **155** all moved to `done/` and nine inbound links still say `../proposed/` or `../accepted/`, so in a project where **the folder is authoritative** a stale link is a wrong **status** claim, which is RFC 151's subject arriving through the links. Two more are one `../` short. **All eleven are repaired in the commit proposing this** — the RFC is for the gate, not the repair. RFC 000 names this failure itself (*"broken links accumulating silently is worse"*, *"Or CI enforcement. Either works; doing nothing does not"*) and nothing reads `rfcs/`; `mdbook` passes because `rfcs/` is not in the book. **Found by running the sweep RFC 000 requires, with a script instead of by eye, while moving RFC 161/162 into `accepted/`** | P2 | **accepted 2026-10-30**; **patch, third in the queue** behind RFC 162 and RFC 161 §9(a); not dispatched. The gate goes in `drift-scan.sh`, so the workflow count stays at **13**, with a non-zero-link assertion so a matcher that stops matching fails loudly (RFC 125 T5). §4 recommendation: **de-link** the fourteen example links rather than exempt the two files that define the rule | — |
| [165](./accepted/165-the-gates-exemption-lists-are-unvalidated.md) | **The gate's exemption lists are unvalidated, and the longest one need not exist.** RFC 159 §4.5 made a stale `NAMED_NON_HANDLERS` entry a hard failure, because such an entry is a **pre-authorised exemption for whatever is written at that key next**. `route-contracts-check.sh` carries **four more lists of the same kind and checks none of them** — `E3_EXEMPT` (2 entries: `GET /`, `GET /login`), `GATE_42_EXEMPT` (1: `GET /admin/console/clients`), `NONCE_EXEMPT` and `E4_EXEMPT` (empty by design, which is when the check is free). Nothing is stale today; all three live entries and all 22 named entries were verified. **The fix-one-matcher pattern for the fourth time in one RFC.** §4 also offers the reduction: the by-value/by-reference split would classify 19 of the 22 structurally, taking the only rot-prone list from **22 entries to 3** — recommended *after* §3, not instead of it, since a classifier is a standing promise about code not yet written | P2 | **accepted 2026-10-30**; **§3 → patch, fourth in the queue** behind RFC 162, RFC 161 §9(a) and RFC 164; not dispatched. **§4 release-unassigned** by design: shrinking the list from 22 entries to 3 trades a one-time judgement about code that exists for a standing promise about code not yet written, and that decision is made at its own dispatch rather than carried in on a bug fix | 159 |
| [163](./accepted/163-two-route-extractors-two-blind-spots.md) | **Two route extractors, two blind spots.** `lib.rs`'s `no_duplicate_route_registrations` (RFC 011) searches for `.get_async("` with **no space**; the registration block is column-aligned, so **88 of 193** routes are written `.get_async ("` and are invisible to it — including `GET /me/security/sessions`, **the exact duplicate the test was written to prevent from re-appearing**. Re-introduce it today and the test passes. No duplicates exist now (193 distinct / 193 total), so this is a guard that cannot guard, not a live defect; `workers-rs`'s last-wins routing is what makes it worth having. The test reports no coverage figure and has no non-zero assertion, so the shortfall is silent — RFC 125 T5 and RFC 156's shape. **Three private implementations of "extract the routes from lib.rs" now exist with three different blind spots**, which is the fork: fix the needle, normalise the idiom, or one extractor with two consumers. **Found by probing RFC 159's new E4 check** | **P1** | **accepted 2026-10-30**; **patch, fifth in the queue** behind RFC 162, RFC 161 §9(a), RFC 164 and RFC 165 §3; not dispatched. §4 recommendation: **fix the needle and add a non-zero-count assertion now** (RFC 125 T5 — a matcher that stops matching must fail loudly), **record the single-extractor end state** for its own cycle, and **decline the 193-line reformat** | 159, 165 |
Numbers are assignment order and are never reused or renumbered (RFC 000), so
a higher number can be earlier work: 130 continues 127, and 131 continues 130.

RFC 130 shipped in v0.81.2 and is in [`done/`](./done/130-deployable-frontend-bundle.md):
`make build-frontend` produces a verified, optimized, correctly-named artifact.
131 replaces what that bundle *contains*, and 132 (shipped v0.82.0, in
[`done/`](./done/132-view-rendering-policy.md)) governs how each surface
renders it.

RFC 128 shipped in v0.81.3 and is in [`done/`](./done/128-observability-audit-architecture-correction.md).
RFC 134 shipped in v0.82.0 and is in [`done/`](./done/134-router-pattern-conflict.md):
the router no longer panics on construction, and cesauth serves a request for
the first time since 2026-07-07.

Whether the app mounts in a browser is still unverified; RFC 131 R5 brings the
harness that closes it.

---

## Done

135 RFCs shipped between v0.50.3 and v0.86.0 (001–106, 107, 108–111, 110b–110e, 113, 116, 117, 118, 125, 126, 127, 128, 129, 130, 132, 134, 135, 136, 137, 138, 139, 140, 142, 143, 146, 147). Full
list with shipped-in versions: see ROADMAP.md "Shipped" section and
CHANGELOG.md release entries. Selected highlights only listed here; the
canonical catalogue is the filesystem at `done/`.

| ID | Title | Shipped |
|----|-------|---------|
| [001](./done/001-id-token-issuance.md) | OIDC `id_token` issuance | v0.54.0 |
| [016](./done/016-admin-scope-badge.md) | Admin scope badge | v0.53.0 |
| [017](./done/017-oidc-audience-admin-editor.md) | OIDC audience admin editor | v0.53.0 |
| [018](./done/018-preview-and-apply-pattern.md) | Preview-and-apply pattern | v0.53.0 |
| [019](./archive/019-rfc-lifecycle-policy.md) | RFC lifecycle policy (superseded by RFC 000) | v0.51.2 |
| [027](./done/027-accessibility-and-route-contracts.md) | A11y verification + route contracts | v0.53.0 |
| [071–078](./done/) | UI/UX alignment from PDF v0.50.1 | v0.62.0 |
| [079–084](./done/) | P2 operations UX + UI consistency | v0.63.0 |
| [096–104](./done/) | Codebase audit remediation | v0.66.0 |
| [105](./done/105-admin-frame-design-token-unification.md) | Admin frame design-token unification | v0.67.0 |
| [106](./done/106-security-center-i18n-closure.md) | Security Center i18n closure (TOTP/recovery banners) | v0.67.0 |
| [107](./done/107-recovery-code-pluralization.md) | Recovery code pluralization (ADR-013 §Q4 plural side) | v0.73.0 |
| [108](./done/108-ui-template-route-catalog-migration.md) | UI template route-catalog migration (closed v0.70.0) | v0.68.0–v0.70.0 |
| [109](./done/109-audit-log-viewer-ui.md) | Audit log viewer UI surface | v0.71.0 |
| [110](./done/110-safety-controls-alignment.md) | Safety controls dashboard alignment audit (verification + pin tests; gap-fills 110a–110e split) | v0.72.0 + v0.74.0 |
| [110b](./done/110b-turnstile-configured-indicator.md) | Turnstile configured indicator | v0.74.0 |
| [110c](./done/110c-refresh-reuse-summary.md) | Refresh-token reuse alerts summary | v0.74.0 |
| [110d](./done/110d-totp-key-status-indicator.md) | TOTP key status indicator | v0.74.0 |
| [110e](./done/110e-safety-controls-landing-section.md) | Open-runbook hyperlink + Safety controls landing section | v0.74.0 |
| [111](./done/111-date-rendering-policy.md) | Date rendering policy (ADR-013 §Q4 date side) | v0.73.0 |
| [113](./done/113-ui-rendering-acceptance-harness.md) | UI rendering acceptance harness | v0.72.0 |
| [116](./done/116-security-type-modeling-baseline.md) | Security-critical type modeling baseline (Phases 1–3; carve-outs deferred) | v0.81.0 |
| [125](./done/125-release-gate-integrity-restoration.md) | Release-gate integrity restoration (+ condition C1: 23 route contracts) | v0.81.1 |
| [127](./done/127-csr-bundle-buildability.md) | CSR bundle buildability and its missing gate (criterion 3 unmet — closed by RFC 130) | v0.81.1 |
| [130](./done/130-deployable-frontend-bundle.md) | Deployable frontend bundle (Trunk release build, artifact naming, toolchain pin, Binaryen checksum) | v0.81.2 |
| [126](./done/126-documentation-rename-sweep-and-drift-rule.md) | Documentation rename sweep + drift-scan crate-name rule (D5 deferred) | v0.81.1 |
| [128](./done/128-observability-audit-architecture-correction.md) | Correct the audit architecture in the observability guide (audit is D1, not R2, since v0.32.0; + conditions C1-128, C2-128) | v0.81.3 |
| [135](./done/135-wasm-under-csp.md) | **WebAssembly under the CSP** — the browser refused to compile the bundle, so every `client` surface was a blank page while ten `curl` assertions read healthy. `'wasm-unsafe-eval'` scoped to the Leptos shell by construction, ADR-007 amended, mount into `#root` | v0.83.0 |
| [159](./done/159-nine-dead-handlers-no-lint-can-see.md) | **Ten dead handlers no lint could see** — registered by nothing, referenced by nothing, fetched by nothing, and invisible to RFC 157's gate because each used its parameters before doing nothing useful. The tenth was found by the new check on its own first run, its doc comment falsely claiming its route was registered. **E4** now fails the build for any handler-shaped `pub async fn` with no qualified path reachable from `lib.rs`, and asserts its own coverage: every `pub async fn` classified or named, the arithmetic closing on every run, one comment-stripped view of `lib.rs` behind all four extractors, and a stale remainder-list entry a hard failure. **Four cycles, each review finding a coverage hole in the mechanism built to close the last one** | v0.89.2 |
| [136](./done/136-backend-test-rot.md) | **Backend test rot** — 159 tests in the deployed crate did not compile, behind an exclusion whose stated reason covered two of 36 errors; the RFC 008 audit-secret invariant had never once executed (+ conditions C1-136, C2-136) | v0.83.0 |
| [129](./done/129-drift-scan-coverage.md) | Drift-scan coverage — the `crates/` blind spot: 19 dead pointers, 6 true historical statements, 1 broken command; `ROADMAP.md` added to the scan (+ condition C1-129) | v0.83.0 |
| [137](./done/137-token-endpoint-client-binding.md) | **`/token` client authentication and binding — P0, security.** A confidential client's secret was never checked, and codes and refresh families were bound to their client by PKCE alone. Both grants now authenticate before consuming, bind to the issuing client, and revoke a family refreshed by the wrong client (+ condition C1-137: one method per request, Basic without a body `client_id`, `WWW-Authenticate` on `invalid_client`) | v0.83.1 |
| [138](./done/138-ci-gate-set-parity.md) | CI gate-set parity — mdbook gated with `create-missing = false`; wrangler pinned and called only through the local install, which fails loudly; tool-installing Actions pinned; drift-scan reads workflows (+ condition C1-138: no `npx wrangler`, clippy over all six crates) | v0.83.1 |
| [139](./done/139-refresh-token-lifetime.md) | Refresh-token lifetime — idle window + absolute cap, enforced at rotation | v0.84.0 |
| [140](./done/140-challenge-expiry-at-read.md) | Challenge stores enforce expiry at read | v0.84.0 |
| [117](./done/117-authorization-code-lifecycle-assurance.md) | Authorization-code exchange as a typestate pipeline | v0.84.1 |
| [118](./done/118-refresh-rotation-assurance.md) | Refresh-family lifecycle: reference model + generated sequences | v0.84.2 |
| [142](./done/142-ci-has-never-executed.md) | CI runs, four gates were red, and nothing was enforced — now all thirteen are required checks | v0.84.3 + enforcement |
| [143](./done/143-totp-verify-without-javascript.md) | A no-JS user was stranded at the second factor — the server-rendered page already existed and only the POST error path reached it | v0.85.0 |
| [146](./done/146-admin-csp-nonce-cannot-match-its-document.md) | The admin surface's CSP nonce could not match its own document — `html_response` minted it after its caller had rendered the body | v0.85.1 |
| [150](./done/150-the-csp-nonce-is-per-isolate-not-per-request.md) | **Outside the admin console the CSP nonce is per-isolate, not per-request.** Seven HTML responders never set one, so the middleware reuses whatever the isolate's previous request left — header and document agree, nothing looks broken, and RFC 006's invariant is unmet. `admin_login.rs`'s inline `<style>` carries no nonce attribute at all. Measure first, then RFC 146's `render_with_nonce`, then the gate | v0.86.3 |
| [155](./done/155-two-p0-guarantees-rest-on-nothing-that-fails.md) | **Two P0 security guarantees rest on nothing that fails.** RFC 030's *"never allow `MagicLinkPayload.code` to reach `Debug`"* is carried by a doc comment on a struct with a plain `derive(Debug)` — and for invitations that field is a full accept URL, not an expiring OTP. RFC 074's generic auth-failure messages are correct and **no test asserts them**, so splitting "expired" from "wrong" would restore the oracle silently. Neither is violated today; neither has a witness | v0.86.3 |
| [157](./done/157-unrouted-handlers-and-the-warnings-gate.md) | **Sixteen unrouted route handlers, and the gate they are blocking.** Of 218 handler-shaped `pub async fn`s in `routes/`, **16 are routed by nothing** — 15 `*_json` companions plus `admin::auth::list_tokens`; 3 are referenced nowhere in the crate at all. **RFC 145 §13.2's prohibition on touching the unused imports has expired**: the defect whose evidence it preserved was fixed in v0.86.1/v0.86.2, and the rule outlived its reason. Clears the way for `-D unused_imports -D unused_variables`; blanket `-D warnings` stays rejected, now for the sharper reason that rustc's and clippy's warning populations are two different sets | **v0.88.1** |
| [153](./done/153-an-invitation-grants-nothing.md) | **An invitation grants nothing.** An accepted invitation produces no tenant membership and no role assignment — `invite_id` is read nowhere, `inv.role` only in an audit string, registration hardcodes `DEFAULT_TENANT_ID`, the invite is consumed before registration, and `revoke_invitation` has no caller. **Same missing step blocks two tenant-admin forms**, which 403 for every non-default tenant because `verify_user_in_tenant`'s premise is never true. Third instance of RFC 047's class and the first found on purpose. **§7 recommends** that it be in a 1.0 **if one is cut** — the fix changes the shape of the user record, so it is cheap before a compatibility commitment and expensive after. **1.0 itself is not decided**; that is the owner's to authorize | **v0.88.0** |
| [148](./done/148-deletion-leaves-the-email-address-behind.md) | **Account deletion leaves the user's email address behind.** `invitation_tokens` holds no key to `users(id)`, so a deleted user's rows survive carrying `email` in plain text. The only one of three surviving tables that retains a personal datum and does not declare it. §5: **scrub, not purge** — tombstone the address, keep the administrative record | v0.87.0 + **v0.87.1** |
| [156](./done/156-the-gate-set-has-no-gate.md) | **The gate set has no gate.** RFC 035 added the workflows, RFC 138 aligned them once, RFC 142 found CI had never run — and none left anything that fails when a gate *stops* running, because a missing job is twelve green checks instead of thirteen and nobody counts. **I didn't**: I wrote "all thirteen checks green" in four release records before checking. `fuzz.yml` is the live shape — it runs on no push, so no release commit is covered by it | **v0.87.1** |
| [158](./done/158-no-tenant-but-the-default-has-a-reachable-console.md) | **No tenant but the default has a reachable admin console.** `/admin/t/:slug/*` — 35 routes, three RFC 145 cycles — is gated on `users.tenant_id == tenant.id` with **no system-admin bypass**, and **nothing ever set that column off the default**, so **nobody** could open any other tenant's console: not its owner, not a system admin. **Reframes RFC 145**: 34 of the 35 pages it fixed served a surface one tenant could open. Fixed inside `create_tenant`, for both of its independent callers, with the outcome reported to the operator and the API caller rather than only to the audit table; an owner already homed elsewhere keeps that home. **Four cycles, each finding something the one before asserted** — including a second caller both the decision stage and the architect called "the one caller", and, in unrequested evidence, RFC 160 | **v0.89.0** |
| [160](./done/160-every-constraint-failure-is-a-conflict.md) | **Every constraint failure is a `Conflict`.** `msg.contains("constraint")` — every SQLite class contains it — collapsed UNIQUE, FOREIGN KEY, CHECK and NOT NULL into one variant, so `POST /api/v1/tenants` with an unknown owner answered **409 `conflict`** and the console rendered **"Slug already taken"** for a mistyped owner id while its own "Owner user id not found" arm could not be reached by the cause it was written for. **Found in the dev team's unrequested RFC 158 cycle-2 evidence.** Fixed by matching SQLite's extended result code; CHECK and NOT NULL left unclassified because no caller can produce either. **The architect's preferred option — a new `PortError` variant — lost to an observed error string**: D1's FK message names neither the column nor the referenced table, so the payload that justified it does not exist. A tenth site was missed by the architect's own grep | **v0.89.1** |
| [149](./done/149-no-user-can-request-their-own-deletion.md) | **No user can request their own deletion.** The route is registered and documented and **has no caller**. `/me/security` renders "Account deletion scheduled" for a state a user cannot enter and cannot cancel. `302` answers both success and not-authenticated, so a redirect-following client cannot tell whether it scheduled the destruction of an account. §5: self-service cancellation decided **yes** | **v0.87.0** |
| [154](./done/154-the-second-factor-is-never-audited.md) | **The second factor is never audited.** No TOTP operation emits any event — enrolment, verification success, verification failure, disablement and recovery-code use all leave no record; `MfaVerified` is declared and emitted nowhere. **RFC 143's attempt lockout therefore trips silently**, so a brute-force attempt on a TOTP gate is invisible afterwards. Three `recover.rs` comments describe records that are never written | **v0.87.0** |
| [145](./done/145-admin-pages-answer-200-and-render-not-found.md) | **Thirty-five admin pages answered 200 and rendered Not Found** — documented `render=client`, serving the Leptos shell, with no route in `app.rs`. Triaged in three cycles (3 + 12 + 21 routes… one became RFC 147, one is RFC 141's), plus the **§4.2 gate**: a `client`-declared GET that is *absent* or ***shadowed*** by a sibling `:param` in `app.rs` now fails the check. First RFC to close under RFC 000 §22, as **`exercised`** | cycle 1 v0.85.1; cycle 2 v0.86.1; cycle 3 **v0.86.2** |
| [147](./done/147-deletion-requests-are-audited-but-never-performed.md) | Deletion requests were audited but never performed — and nothing in cesauth had ever executed a deletion by any path. Cycle 1 stopped the claims (v0.85.1); cycle 2 performs the operations and wires the cron. Completes **RFC 047** | cycle 1 v0.85.1; cycle 2 **v0.86.0** |
| [134](./done/134-router-pattern-conflict.md) | Router pattern conflict — `:param.json` routes panicked `worker`'s router on construction, every request, since 2026-07-07 (+ condition C1-134: the shell's assets resolve) | v0.82.0 |
| [132](./done/132-view-rendering-policy.md) | View rendering policy — Q1–Q4 derived per surface, `Rendering` column on all 188 routes, E2/E3 blocking gates (+ conditions C1-132, C2-132) | v0.82.0 |

For the full mapping (every shipped RFC with its release tag), the
authoritative record is each file's own `**Status**: Implemented (vX.Y.Z)`
field plus ROADMAP.md.

---

## Archive

Withdrawn or superseded. Never deleted — an archived RFC is the record that the
discussion happened.

| ID | Title | Reason |
|----|-------|--------|
| [019](./archive/019-rfc-lifecycle-policy.md) | RFC lifecycle policy | Superseded by RFC 000 (5-folder variant adopted 2026-09-03). Was Implemented (v0.51.2). |

---

## Adding a new RFC

Next number: **163**. Create `rfcs/proposed/163-slug.md` with `**Status.** Proposed`
and add a row above, in the same commit.

Transitions (folder is authoritative; update Status and this index in the same
commit as every move, and sweep inbound links first):

1. **Owner accepts** → `proposed/` → `accepted/`, Status `Accepted`.
2. **Shipped** → `accepted/` → `done/`, Status `Implemented (vX.Y.Z)`, plus a
   CHANGELOG entry and a ROADMAP update.
3. **Withdrawn or superseded** → `archive/`, Status carrying the reason or the
   replacing RFC number, with a reciprocal note in the replacement.

Numbers are permanent and never reused.

---

## RFCs 105–113 — context for the v0.67.0 → v0.71.0 batch (UI/UX finishing track)

The nine RFCs numbered 105–113 are the UI/UX finishing track triggered
by comparing the v0.50.1 UI/UX design deck against the v0.66.0 state.
Most deck themes were already shipped in v0.53.0 / v0.62.0 / v0.63.0;
this batch closes the residual gaps surfaced in the v0.66.0 HANDOFF
document and the deck's "Acceptance criteria" page.

Sources:

- **PDF v0.50.1 page 6 / page 12** (Self-service + i18n contract) → RFCs
  **106** (Security Center i18n closure) and **107** / **111** (ADR-013 §Q4
  closure — plural and date sides).
- **PDF v0.50.1 page 8 + HANDOFF residual #3** (admin frame design tokens) →
  RFC **105**.
- **HANDOFF residual #2** (202 hardcoded URLs in templates) → RFC **108**.
- **PDF v0.50.1 page 9** (Operations UX — Audit log viewer + Safety
  controls) → RFCs **109** and **110**.
- **HANDOFF residual #1** (RFC 100 macro partial migration) → RFC **112**.
- **PDF v0.50.1 page 14** (Acceptance criteria checklist) → RFC **113**.

Actual shipping order:

| Release | RFCs | Theme |
|---------|------|-------|
| v0.67.0 | 105, 106 | Design tokens + Security Center i18n |
| v0.68.0 | 108 (partial) | Catalog correction + end-user template migration |
| v0.69.0 | 108 (continued) | Catalog completion + admin/console migration |
| v0.70.0 | 108 (closure) | tenant_admin + tenancy_console migration + drift-scan |
| v0.71.0 | 109 | Audit log viewer (new surface) |
| v0.72.0 | 110, 113 | Safety alignment audit + acceptance harness |
| v0.73.0 | 107, 111 | ADR-013 §Q4 closure (plural-aware lookup + UTC ISO-8601 policy) |
| v0.74.0 | 110b, 110c, 110d, 110e | Safety controls panel gap-fills (4 of 5) |
| v0.75.0+ (planned) | 110a | Rate limit summary (KV-heavy, env-blocked) |
| Pending env | 112 | Worker auth macro batch (rustup/wasm32 required) |

Dependencies between RFCs are minimal:

- 108 should land before 109 so the viewer references catalog paths. (Done.)
- 113 is more useful after 105 (token consistency easier to assert).
- 107 and 111 are independent of each other but logically pair for the
  ADR-013 §Q4 closure release note.
- 112 is environment-blocked (sandbox lacks rustup/wasm32) and ships on
  its own once an environment with worker compile-verify is available.

---

## Historical context — RFCs 020–029 (v0.52.1 → v0.53.x batch)

These were the v0.52.1 review-driven batch (data structure / codebase /
UI/UX / hygiene). All shipped in v0.53.0 / v0.54.0 / v0.62.0. See
ROADMAP.md "Shipped" rows for the actual shipped-in mapping. The
individual RFCs are in `done/`.
