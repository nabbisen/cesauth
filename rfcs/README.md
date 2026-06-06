# cesauth RFCs

Implementation-handover specifications for ROADMAP themes.
Governed by **RFC 019 — RFC lifecycle policy** (`done/019-rfc-lifecycle-policy.md`).

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
  proposed/    ← open for implementation
  done/        ← shipped; historical record — never delete
  archive/     ← withdrawn or superseded
  README.md    ← this index (update in same commit as any move)
```

Full policy: `done/019-rfc-lifecycle-policy.md`.

---

## Proposed

UI/UX finishing track (v0.67.0 → v0.71.0). Source: v0.50.1 UI/UX design
deck (overview onepage + dev-support PDF) compared against v0.66.0 state.
The deck is largely shipped through v0.53/v0.62/v0.63; this batch closes
the residual gaps. See ROADMAP.md "UI/UX finishing track" for grouping.

| ID | Title | Tier | Target |
|----|-------|------|--------|
| [107](./proposed/107-recovery-code-pluralization.md) | Recovery code pluralization (ADR-013 §Q4 closure / plural side) | P2 | v0.73.0 |
| [111](./proposed/111-date-rendering-policy.md) | Date rendering policy (ADR-013 §Q4 closure / date side) | P2 | v0.73.0 |
| [112](./proposed/112-worker-auth-macro-batch-migration.md) | Worker auth macro batch migration (RFC 100 全面適用) | P2 | env-blocked |

---

## Done

108 RFCs (001–106, 108–110, 113) shipped between v0.50.3 and v0.72.0. Full
list with shipped-in versions: see ROADMAP.md "Shipped" section and
CHANGELOG.md release entries. Selected highlights only listed here; the
canonical catalogue is the filesystem at `done/`.

| ID | Title | Shipped |
|----|-------|---------|
| [001](./done/001-id-token-issuance.md) | OIDC `id_token` issuance | v0.54.0 |
| [016](./done/016-admin-scope-badge.md) | Admin scope badge | v0.53.0 |
| [017](./done/017-oidc-audience-admin-editor.md) | OIDC audience admin editor | v0.53.0 |
| [018](./done/018-preview-and-apply-pattern.md) | Preview-and-apply pattern | v0.53.0 |
| [019](./done/019-rfc-lifecycle-policy.md) | RFC lifecycle policy | v0.51.2 |
| [027](./done/027-accessibility-and-route-contracts.md) | A11y verification + route contracts | v0.53.0 |
| [071–078](./done/) | UI/UX alignment from PDF v0.50.1 | v0.62.0 |
| [079–084](./done/) | P2 operations UX + UI consistency | v0.63.0 |
| [096–104](./done/) | Codebase audit remediation | v0.66.0 |
| [105](./done/105-admin-frame-design-token-unification.md) | Admin frame design-token unification | v0.67.0 |
| [106](./done/106-security-center-i18n-closure.md) | Security Center i18n closure (TOTP/recovery banners) | v0.67.0 |
| [108](./done/108-ui-template-route-catalog-migration.md) | UI template route-catalog migration (closed v0.70.0) | v0.68.0–v0.70.0 |
| [109](./done/109-audit-log-viewer-ui.md) | Audit log viewer UI surface | v0.71.0 |
| [110](./done/110-safety-controls-alignment.md) | Safety controls dashboard alignment audit (verification + pin tests; gap-fills 110a–110e deferred) | v0.72.0 |
| [113](./done/113-ui-rendering-acceptance-harness.md) | UI rendering acceptance harness | v0.72.0 |

For the full mapping (every shipped RFC with its release tag), the
authoritative record is each file's own `**Status**: Implemented (vX.Y.Z)`
field plus ROADMAP.md.

---

## Archive

*(none)*

---

## Adding a new RFC

Next number: **114**. Create `rfcs/proposed/114-slug.md`, set `**Status**: Proposed`,
add a row above, and update in the same commit. When shipped: move to `done/`,
update Status to `Implemented (vX.Y.Z)`, update README row. Numbers are permanent.

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
| v0.73.0 (planned) | 107, 111 | ADR-013 §Q4 closure |
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
