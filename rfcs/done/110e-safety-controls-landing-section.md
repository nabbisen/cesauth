# RFC 110e — Open-runbook hyperlink + Safety controls landing section

**Status**: Implemented (v0.74.0)  
**Tier**: P2  
**Size**: Small  
**Target**: v0.74.0  
**Phase**: Safety controls panel gap-fill (RFC 110 follow-up)  
**Refs**: PDF v0.50.1 page 9 "Operations UX: Safety controls" / RFC 110 / `docs/src/deployment/day-2-runbook.md` / RFC 110b–110d (composed under the same landing section)

## Problem

The PDF v0.50.1 page 9 "Safety controls" panel ends with an
`[ Open runbook ]` button. RFC 110's v0.72.0 audit recorded that the
day-2 runbook exists at `docs/src/deployment/day-2-runbook.md` but
nothing in the admin console hyperlinks to it. v0.74.0 ships the link
and also defines the broader "Safety controls landing section" that
gathers RFC 110b–110d's indicators in one place.

## Design

### Section composition

`/admin/console/safety` renders two top-level sections:

1. **Data Safety Dashboard** (existing, RFC 047) — per-bucket safety
   table.
2. **Safety controls** (new, RFC 110b–110e) — the four PDF page-9
   indicators plus the runbook link.

The two surfaces share a page because operators reach for both from
the same nav tab; splitting would just add cognitive load.

### Runbook link contract

The link is gated on `RUNBOOK_URL` env var:

- **Set**: render
  `<a class="action" href="{url}" target="_blank" rel="noopener noreferrer">Open runbook ↗</a>`
- **Unset**: render a hint paragraph telling the operator to set
  `RUNBOOK_URL` (so the deployment knows the feature exists).

The link opens in a new tab because operators are usually mid-incident
when they reach for the runbook — they need the safety dashboard
pinned in the original tab.

`rel="noopener noreferrer"` is mandatory: prevents the runbook page
from getting a `window.opener` reference back to the admin console
(a 2017-era tabnabbing class of attack).

### Why not a config option for the link text

Keeping the link text fixed (`Open runbook ↗`) means every cesauth
deployment looks the same from an operator perspective — switching
between deployments doesn't require relearning the chrome. The
*destination* is per-deployment; the *affordance* is universal.

## Implementation

- Added field `runbook_url: Option<String>` to `SafetyControlsReport`.
- Worker handler reads `env.var("RUNBOOK_URL")` and forwards
  `Option<String>` (empty string is treated as None).
- UI renderer `crates/ui/src/admin/safety.rs::render_safety_controls`
  emits the anchor when present, the hint when absent.

## Acceptance

- [x] `cargo-1.91 test --workspace --lib` green
- [x] `safety_page_renders_runbook_link_when_url_present` passes
- [x] `safety_page_omits_runbook_link_when_url_missing` passes
- [x] Link carries `target="_blank"` + `rel="noopener noreferrer"`
- [x] Hint message appears when URL is None
- [x] No empty `href=""` ever emitted
- [x] No production warnings

## Migration / compatibility

- Backward-compatible: same as RFC 110b/c/d.
- Existing deployments without `RUNBOOK_URL` see the hint message
  (which is informative, not an error).

## Open questions

None.
