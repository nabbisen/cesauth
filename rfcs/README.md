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
  done/        ← shipped (released, or on main); never delete
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

---

## Proposed

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

Security-critical assurance track, continued.

| ID | Title | Tier | Category | Depends on |
|----|-------|------|----------|------------|
| [117](./proposed/117-authorization-code-lifecycle-assurance.md) | Authorization code lifecycle assurance | P0 | A | 116 |
| [118](./proposed/118-refresh-rotation-assurance.md) | Refresh token rotation & reuse-detection assurance | P0 | A | 116 |
| [119](./proposed/119-tenant-scoped-repository-apis.md) | Tenant boundary & scoped repository APIs | P1 | B | 116 |
| [120](./proposed/120-authz-core-sealing-and-property-tests.md) | Authorization core: sealing & property tests | P0/P1 | A/B | 116 |
| [121](./proposed/121-security-state-machine-testing.md) | Security state-machine testing with proptest | P1 | B | 117, 118 |
| [122](./proposed/122-fuzzing-untrusted-input-boundaries.md) | Fuzzing for untrusted input boundaries | P1 | B | 117 |
| [123](./proposed/123-audit-event-completeness.md) | Audit event completeness for privileged operations | P1 | B | 116 |
| [124](./proposed/124-formal-methods-pilot.md) | Lightweight formal/model-checking pilot | P2 | C | 118, 120 |

---

## Accepted

Owner-approved; implementation may start. Rows are in **sequencing** order.

| ID | Title | Tier | Dispatched | Depends on |
|----|-------|------|---|---|
| [130](./accepted/130-deployable-frontend-bundle.md) | Deployable frontend bundle (Trunk release build, artifact naming, toolchain pin) | **P0** | task 005 — **complete**, awaiting 0.81.2 | 127 |
| [128](./accepted/128-observability-audit-architecture-correction.md) | Correct the audit architecture in the observability guide | P1 | 0.81.3 | — |
| [131](./accepted/131-mockup-adoption-strategy.md) | Mockup adoption strategy (merge, not port) | P1 | 0.81.4 — R2 + R5 first | 130 |

Numbers are assignment order and are never reused or renumbered (RFC 000), so
a higher number can be earlier work: 130 continues 127, and 131 continues 130.

RFC 127 delivered the crate's *buildability* and a CI gate; **130 made the
bundle deployable and is complete** — `make build-frontend` produces a
verified, optimized, correctly-named artifact. 131 replaces what that bundle
*contains*.

Everything to this point is build-time verified only. Whether the app mounts in
a browser is still unverified; RFC 131 brings the harness that closes it.

---

## Done

118 RFCs shipped between v0.50.3 and v0.81.1 (001–106, 107, 108–111, 110b–110e, 113, 116, 125, 126, 127). Full
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
| [127](./done/127-csr-bundle-buildability.md) | CSR bundle buildability and its missing gate (criterion 3 unmet — see RFC 130) | v0.81.1 |
| [126](./done/126-documentation-rename-sweep-and-drift-rule.md) | Documentation rename sweep + drift-scan crate-name rule (D5 deferred) | v0.81.1 |

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

Next number: **132**. Create `rfcs/proposed/132-slug.md` with `**Status.** Proposed`
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
