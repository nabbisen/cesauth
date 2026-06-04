# RFC 027: Accessibility verification and route-addition checklist

**Status**: Implemented
**ROADMAP**: External UI/UX design update v0.50.1 — page 12 (accessibility) + page 13 (form contracts matrix)
**ADR**: N/A — verification of existing implementation + lightweight process artifact
**Severity**: **P2 — most accessibility groundwork shipped in v0.31.0; this RFC verifies coverage and adds a per-route metadata table to prevent regression**
**Estimated scope**: Small — accessibility audit script + per-route metadata table doc + ~50 LOC of CI checks
**Source**: External UI/UX design update PDF v0.50.1 + onepage overview

## Background

Two themes from the v0.50.1 UI/UX deck don't have
existing RFC coverage but represent finite, valuable
work:

### Theme 1 — color-only-status verification

Page 12 ("Accessible by default") declares:

> 色だけに依存しない状態表示 (Don't rely on color alone for state display)

v0.31.0's flash-message infrastructure already pairs
color with icon (✓ ⚠ ⛔ ℹ) and text label, per
the v0.31.0 CHANGELOG entry. v0.31.0 also added
WCAG 1.4.1-aware design tokens.

What's missing is *verification* that every place
in the UI that conveys state actually pairs all
three (color + icon + text) and not just two.
The deck's acceptance criterion is "every state
display passes the color-blind test" — there is
no test today.

### Theme 2 — route-addition checklist

Page 13 ("Form contracts") presents the per-route
matrix and says:

> route 追加時は actor / scope / audit kind /
> MessageKey / rendering test / CSRF 要否を同時に
> 更新する

Today there is no checklist; the maintainer's
mental model has to recall six concerns each time
a route is added. Past releases occasionally missed
one (e.g., v0.24.0 discovered a missing CSRF
hidden input on `magic_link_sent_page` during
audit — not at PR time).

The deck calls it a "development helper rule"
(開発補助ルール). RFC 012 added `drift-scan.sh`
as a stale-phrase detector; RFC 027 is the same
shape for route metadata.

## Requirements

The fix must:

1. Every `flash--*` and `badge--*` rendering
   path is verified to render an icon and a
   text label as well as a color, with a test
   that fails if any path drops one of the
   three.
2. A per-route metadata table is maintained at
   `docs/src/expert/route-contracts.md`, with one
   row per browser-facing route covering: actor,
   scope, audit-event-kind, MessageKey or template
   used, rendering-test reference, and CSRF
   requirement.
3. A CI check parses the metadata table and
   asserts that every route registered in
   `crates/worker/src/lib.rs` has a row in the
   table. Adding a route without updating the
   doc fails the PR.

## Decision / Plan

### Step 1 — Accessibility unit tests

In `cesauth_ui::templates::tests`, add:

```rust
#[test]
fn every_flash_level_pairs_color_icon_and_text() {
    use cesauth_ui::flash::{FlashView, FlashLevel};

    for level in [FlashLevel::Success, FlashLevel::Warning,
                  FlashLevel::Danger,  FlashLevel::Info] {
        let html = render_flash_block(&FlashView {
            level,
            text: "test message".into(),
        });

        // The color is in the CSS class:
        assert!(html.contains(&format!("flash--{}",
                                       level.css_modifier())),
                "level {level:?} missing css class");

        // The icon is in a span with class flash__icon:
        assert!(html.contains("class=\"flash__icon\""),
                "level {level:?} missing icon span");
        // And the icon character itself is non-empty:
        let icon_char = level.icon();
        assert!(html.contains(icon_char), "level {level:?} missing icon char");

        // The text is non-empty (test message is the input;
        // production checks render_view_for produces non-empty
        // for every MessageKey via the existing catalog tests).
        assert!(html.contains("test message"),
                "level {level:?} missing text content");
    }
}

#[test]
fn every_badge_pairs_color_and_text() {
    // Similar shape for status badges (TOTP enabled, recovery codes
    // remaining, primary auth method, etc.).
}
```

If any rendering helper is found that emits a
state-bearing element with color but no icon or
no text, RFC 027's first commit fixes it; the test
locks the fix in.

### Step 2 — Route contracts table

`docs/src/expert/route-contracts.md`, structured as
markdown tables (one section per scope). Skeleton:

```markdown
# Route contracts

Every browser-facing route is recorded here with
the six fields the v0.50.1 UI/UX deck named: actor,
scope, audit kind, view (MessageKey or template),
rendering test reference, CSRF requirement.

This table is enforced by `scripts/route-contracts-check.sh`
(see RFC 012's `drift-scan.sh` companion); a route
in `crates/worker/src/lib.rs` without a corresponding
row here fails CI.

## End-user routes

| Method+Path | Actor | Audit kind | View | Rendering test | CSRF |
|---|---|---|---|---|---|
| GET /authorize | Anonymous / End user | none (read) | `authorize_login_page` | `templates::tests::authorize_login_page_*` | N/A (GET) |
| POST /authorize | End user | `authorization_code_minted` (success) / `authorization_failed` (fail) | redirect / `error_page` | n/a | required |
| GET /login | Anonymous / End user | none (read) | `login_page` | `templates::tests::login_page_renders` | N/A (GET) |
| POST /magic-link/request | Anonymous / End user | `magic_link_issued` | `magic_link_sent_page` | `templates::tests::magic_link_sent_page_*` | required |
| POST /magic-link/verify | End user | `magic_link_verified` | `complete_auth` redirect | n/a | required (form path) |
| GET /me/security | Authenticated | none (read) | `security_center_page_for` | `templates::tests::security_center_*` | N/A (GET) |
| GET /me/security/totp/enroll | Authenticated | none (read) | `totp_enroll_page` | `templates::tests::totp_enroll_page_*` | N/A (GET) |
| POST /me/security/totp/enroll/confirm | Authenticated | `totp_enrolled` | `totp_recovery_codes_page` | `templates::tests::totp_recovery_codes_page_*` | required |
| GET /me/security/totp/verify | End user mid-auth | none (read) | `totp_verify_page` | `templates::tests::totp_verify_*` | N/A (GET) |
| POST /me/security/totp/verify | End user mid-auth | `totp_verified` / `totp_verify_failed` | `complete_auth` redirect | n/a | required |
| POST /me/security/totp/recover | End user mid-auth | `totp_recovered` | `complete_auth` redirect | n/a | required |
| GET /me/security/totp/disable | Authenticated | none (read) | `totp_disable_confirm_page` | `templates::tests::totp_disable_*` | N/A (GET) |
| POST /me/security/totp/disable | Authenticated | `totp_disabled` | redirect to /me/security | n/a | required |
| GET /me/security/sessions | Authenticated | none (read) | `sessions_page_for` | `templates::tests::sessions_page_*` | N/A (GET) |
| POST /me/security/sessions/:id/revoke | Authenticated | `session_revoked_by_user` | redirect | n/a | required |
| POST /me/security/sessions/revoke-others | Authenticated | `session_revoked_by_user` (bulk:true) | redirect | n/a | required |
| POST /logout | Authenticated | `session_revoked_by_user` | redirect | n/a | required (origin check) |

## OAuth/OIDC routes

| Method+Path | Actor | Audit kind | View | Rendering test | CSRF |
|---|---|---|---|---|---|
| GET /.well-known/openid-configuration | RP | none | JSON | n/a | N/A (GET, JSON) |
| GET /jwks.json | RP | none | JSON | n/a | N/A (GET, JSON) |
| POST /token | RP | `token_issued` / `token_refresh_rejected` / `refresh_token_reuse_detected` | JSON | n/a | N/A (CORS preflight) |
| POST /introspect | RS | `token_introspected` / `introspection_audience_mismatch` / `introspection_rate_limited` | JSON | n/a | N/A (Authorization-only) |
| POST /revoke | RP/RS | `revocation_requested` | JSON | n/a | N/A (RFC 7009 §2.2) |

## Admin routes

| Method+Path | Actor | Audit kind | View | Rendering test | CSRF |
|---|---|---|---|---|---|
| GET /admin/console | System admin | none | `admin/console.rs` | `admin::tests::console_*` | N/A (GET) |
... (snip) ...
```

The table is the contract; rows reference what
already exists in v0.52.1 plus the existing tests.

### Step 3 — Route-contracts CI check

`scripts/route-contracts-check.sh`, called from a
new GitHub Actions workflow:

```bash
#!/bin/bash
set -euo pipefail

# Extract registered (METHOD, PATH) pairs from lib.rs
registered=$(grep -E '\.(get|post|put|delete)_async\("' \
                   crates/worker/src/lib.rs |
             sed -E 's/.*\.(get|post|put|delete)_async\("([^"]+)".*/\U\1\E \2/' |
             sort -u)

# Extract documented pairs from the contracts table
documented=$(grep -E '^\|\s*(GET|POST|PUT|DELETE)\s+/' \
                   docs/src/expert/route-contracts.md |
             sed -E 's/^\|\s*([A-Z]+)\s+([^ |]+).*/\1 \2/' |
             sort -u)

# Diff. Anything in registered but not documented is a CI failure.
missing=$(comm -23 <(echo "$registered") <(echo "$documented") || true)
if [ -n "$missing" ]; then
    echo "Routes registered in lib.rs but missing from route-contracts.md:" >&2
    echo "$missing" >&2
    exit 1
fi

extra=$(comm -13 <(echo "$registered") <(echo "$documented") || true)
if [ -n "$extra" ]; then
    echo "Routes documented but not registered (stale):" >&2
    echo "$extra" >&2
    exit 1
fi
```

Workflow file
`.github/workflows/route-contracts.yml`, runs on
PR and main push, no Rust toolchain required.

The check is intentionally simple: it doesn't
parse Markdown formally, it doesn't validate the
content of the metadata fields, it just enforces
"there's a row for every registered route". If
the row's content is wrong, that's a code-review
catch.

### Step 4 — Mobile and a11y review pass

The deck's page 12 also calls out:

- aria-live for flash (existing v0.31.0 work
  already sets `role="alert"|"status"` and
  `aria-live="assertive|polite"` per FlashLevel).
- inputmode + pattern for numeric codes (TOTP,
  recovery). v0.31.0 added `autofocus`; check
  current implementation for `inputmode="numeric"`
  + `pattern="[0-9]*"` on the TOTP code input.
- visible focus state. CSS already has
  `:focus-visible` per BASE_CSS; verify against
  every interactive element type by visual
  audit (this is a manual review pass).

The audit's findings, if any, become small
fix-up commits in the same PR; if no
findings, the audit is recorded in a
`docs/src/expert/accessibility-review-2026-Q3.md`
analogous to the attack-surface review document
from RFC 007.

## Test plan

- New unit tests per Step 1.
- New CI workflow per Step 3.
- Audit recorded per Step 4.

## Security considerations

Accessibility issues are not security-critical
themselves. Indirect link: a user who can't
read a "TOTP enrolled successfully" flash because
they're using a screen reader and the icon's
text label is missing might re-enroll, ending up
with two TOTP authenticators or duplicate recovery
codes. The functional reliability of the security
flows depends on accessible state communication.

## Open questions

1. **Should color-contrast ratios be measured
   automatically?** Out of scope for RFC 027;
   that's lighthouse / axe-core territory. The
   v0.31.0 design tokens were chosen for WCAG
   AA contrast; manual verification on a
   representative page is the bar.

2. **Should the route-contracts table be
   generated from code annotations
   (e.g., `#[route_contract(actor="...")]`)?**
   Considered. The static markdown table is
   simpler to author and review; macro-generated
   would couple the build process. Reconsider
   if route count grows past ~80 (currently ~30).

3. **What about JSON-only routes — should they
   be in the table?** Yes, with N/A for the
   "Rendering test" and "View" columns. The
   table is the route-surface inventory, not
   just an HTML inventory.

## Implementation order

1. Run color-only-status audit; fix gaps.
2. Add the rendering tests.
3. Author `route-contracts.md` with the current
   route surface.
4. Add the CI check + workflow.
5. Optionally do the manual a11y review pass and
   record findings.
6. One PR (small change set; the audit may be
   pure-additive if v0.31.0 work was thorough).

## Notes for the implementer

- The route-contracts CI is intentionally
  brittle: changing a route name in lib.rs
  without updating the table fails the PR.
  This is the desired behavior — the table is
  the documentation contract.
- Headers in the Markdown table use Unicode
  pipe characters that some editors auto-format
  weirdly; keep ASCII pipes.
- The accessibility-review document follows the
  cadence of RFC 007's attack-surface review:
  no calendar gate; runs on demand and at
  v1.0.
