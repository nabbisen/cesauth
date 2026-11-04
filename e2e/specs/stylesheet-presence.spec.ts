/**
 * RFC 178 §4 — stylesheet-presence.spec.ts
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
 */
import { test, expect } from '@playwright/test';
import { PUBLIC_ROUTES, gotoMounted } from './support';

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

    expect(
      ruleCount,
      `${route}: the mounted app has no author CSS rules at all — it renders `
        + 'at browser defaults, and any sr-only-style class does nothing '
        + '(RFC 178)',
    ).toBeGreaterThan(0);
  });
}
