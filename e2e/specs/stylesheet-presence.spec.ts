/**
 * RFC 178 §4 / §4b — stylesheet-presence.spec.ts
 *
 * One assertion: the mounted SPA has at least one author stylesheet rule.
 * Cheap (no session, runs in the existing anonymous suite), and it would
 * have caught RFC 178's own finding years earlier — `/login` renders with
 * zero stylesheets, zero `<style>` tags, and zero author CSS rules, so the
 * body falls back to the browser default (Times New Roman at 16px) and
 * `sr-only`-class elements, with nothing to hide them, are visible to
 * everyone instead of screen readers alone.
 *
 * Deliberately does not assert *which* rules, on *which* selectors, or
 * where the stylesheet lives — RFC 178 §3 (was the SPA ever styled, or is
 * this deferred behind RFC 131 R3?) is the owner's question, not this
 * suite's. This assertion passes the moment any author stylesheet exists,
 * however it gets there.
 *
 * "Author" rules excludes the user-agent stylesheet every browser ships —
 * `document.styleSheets` only ever lists stylesheets the page itself
 * loaded (`<link>`/`<style>`), so no extra filtering is needed to exclude
 * browser defaults.
 *
 * ## The exemption (RFC 178 §4b, 2026-11-07)
 *
 * Landing this bare meant two release gates red forever: the gap is
 * `RFC 131 R3`'s presentation wiring, an unbuilt slice of an accepted
 * programme, not a short cycle — see `rfcs/done/135-wasm-under-csp.md`
 * §4 ("no stylesheet exists ... presentation wiring is RFC 131 R3") and
 * `rfcs/accepted/131-mockup-adoption-strategy.md`. Removing the gate
 * instead would return the project to documented-and-ungated, which is
 * the exact condition that let the gap persist for months undetected.
 *
 * `KNOWN_NO_STYLESHEET` names every route this applies to today (every
 * `PUBLIC_ROUTES` entry) with a dated reason, the same shape as
 * `E6_BEARER_LEGACY_EXEMPT` in `scripts/route-contracts-check.sh`.
 * **This is not a skip.** A listed route with zero rules still runs the
 * full check, passes, and prints an `ℹ️` line naming the exemption and
 * the owning RFC on every run, so the gap keeps reporting instead of
 * going quiet. A listed route that gains even one author rule fails
 * loudly, naming itself stale — the entry must be deleted before the
 * gate can pass again, and from then on it enforces permanently. An
 * unlisted route still has no exemption at all: the plain assertion is
 * the only path for it, exactly as before.
 */
import { test, expect } from '@playwright/test';
import { PUBLIC_ROUTES, gotoMounted } from './support';

const KNOWN_NO_STYLESHEET: Record<string, string> = {
  '/': 'RFC 135 §4 / RFC 131 R3 (2026-11-07) — no stylesheet exists anywhere in the tree; presentation wiring is R3\'s, not yet built',
  '/login': 'RFC 135 §4 / RFC 131 R3 (2026-11-07) — same reason as /; R3 owns both',
};

for (const route of PUBLIC_ROUTES) {
  test(`the mounted app has at least one author stylesheet rule: ${route}`, async ({ page }) => {
    await gotoMounted(page, route);

    const ruleCount = await page.evaluate(() => {
      let count = 0;
      for (const sheet of Array.from(document.styleSheets)) {
        try {
          count += sheet.cssRules.length;
        } catch {
          // A cross-origin stylesheet throws on .cssRules; this app loads
          // none, but failing closed (not counting it) is the safe default.
        }
      }
      return count;
    });

    const exemptReason = KNOWN_NO_STYLESHEET[route];

    if (exemptReason !== undefined) {
      if (ruleCount > 0) {
        throw new Error(
          `${route}: KNOWN_NO_STYLESHEET's exemption no longer matches -- `
            + `this route now has ${ruleCount} author rule(s). Remove its `
            + 'entry from KNOWN_NO_STYLESHEET so this gate enforces, rather '
            + 'than leaving a pre-authorised exemption nobody is reviewing '
            + '(RFC 178 §4b).',
        );
      }
      console.log(
        `ℹ️  ${route}: exempted from the author-stylesheet check -- ${exemptReason}`,
      );
      return;
    }

    expect(
      ruleCount,
      `${route}: the mounted app has no author CSS rules at all — it renders `
        + 'at browser defaults, and any sr-only-style class does nothing '
        + '(RFC 178)',
    ).toBeGreaterThan(0);
  });
}
