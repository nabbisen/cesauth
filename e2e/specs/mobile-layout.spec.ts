/**
 * RFC 131 R5b — mobile-layout.spec.ts
 *
 * **Adapted with a deliberate change of mechanism, reported with R5b.** The
 * mockup's spec was a pixel screenshot baseline (`toHaveScreenshot`, 6
 * screens, 375 px). That mechanism is wrong for cesauth today, for three
 * reasons:
 *
 * 1. **There is nothing stable to photograph.** No stylesheet exists anywhere
 *    in the tree (RFC 135 §4); the page renders in browser defaults. A
 *    baseline would capture unstyled output that RFC 131 R3 replaces
 *    wholesale, so every screenshot would need regenerating the moment
 *    styling lands — and a baseline that is always about to be invalidated
 *    teaches a reviewer to regenerate rather than to look.
 * 2. **A screenshot gate cannot fail on its first run.** Playwright *creates*
 *    a missing baseline and passes. The first CI run would therefore be green
 *    by construction, which is the one thing this project does not accept
 *    from a new gate.
 * 3. **The baselines would be unverifiable.** Pixel output depends on the
 *    font stack of the machine that rendered it; a baseline generated here
 *    would differ from CI's for reasons unrelated to the code, and I cannot
 *    generate CI's. Committing binary artifacts I cannot reproduce is also
 *    the shape §10 bars for fixtures.
 *
 * What is asserted instead are **layout properties that hold regardless of
 * styling** and that a real phone user would feel: the document must not
 * scroll sideways, and every interactive control must be inside the viewport.
 * These are the failures a 375 px check exists to catch — a fixed-width table
 * or an over-wide form pushing the submit button off-screen — and they are
 * environment-robust.
 *
 * When R3 lands styling, screenshot baselines become worth having, and the
 * suite will have a styled page to generate them from.
 */
import { test, expect } from '@playwright/test';
import { PUBLIC_ROUTES, gotoMounted } from './support';

// iPhone-class width. Height is generous so vertical scrolling — which is
// expected and fine — never confuses the horizontal assertions.
test.use({ viewport: { width: 375, height: 812 } });

for (const route of PUBLIC_ROUTES) {
  test(`mobile 375px: ${route} does not scroll sideways`, async ({ page }) => {
    await gotoMounted(page, route);

    const { scrollWidth, clientWidth } = await page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      clientWidth: document.documentElement.clientWidth,
    }));

    // 1 px of slack: sub-pixel layout rounding is not a defect.
    expect(
      scrollWidth,
      `${route}: content is ${scrollWidth}px wide in a ${clientWidth}px viewport — ` +
        `the page scrolls horizontally on a phone`,
    ).toBeLessThanOrEqual(clientWidth + 1);
  });

  test(`mobile 375px: ${route} keeps its controls on screen`, async ({ page }) => {
    await gotoMounted(page, route);

    const offscreen = await page.evaluate(() => {
      const vw = document.documentElement.clientWidth;
      return Array.from(
        document.querySelectorAll<HTMLElement>('a[href], button, input, select, textarea'),
      )
        .map((el) => {
          const r = el.getBoundingClientRect();
          return { tag: el.tagName.toLowerCase(), left: Math.round(r.left), right: Math.round(r.right) };
        })
        // Zero-size elements are not rendered; ignore rather than flag.
        .filter((b) => b.right !== b.left)
        .filter((b) => b.left < 0 || b.right > vw + 1);
    });

    expect(
      offscreen,
      `${route}: control(s) outside the 375px viewport — ` +
        offscreen.map((b) => `${b.tag} spans ${b.left}..${b.right}`).join('; '),
    ).toHaveLength(0);
  });

  test(`mobile 375px: ${route} still has reachable controls`, async ({ page }) => {
    await gotoMounted(page, route);

    // Without this, the two assertions above pass on a page that renders no
    // controls at all — the vacuous-pass shape this project keeps finding.
    const count = await page.evaluate(
      () =>
        document.querySelectorAll('a[href], button, input, select, textarea').length,
    );

    expect(count, `${route}: no interactive controls rendered at 375px`)
      .toBeGreaterThan(0);
  });
}
