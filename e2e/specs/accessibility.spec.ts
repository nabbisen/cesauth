/**
 * RFC 131 R5b — accessibility.spec.ts
 *
 * Axe WCAG 2 A/AA checks: zero critical or serious violations on every page a
 * browser can reach unauthenticated.
 *
 * Adapted from the mockup's spec. Two changes beyond the route list:
 *
 * 1. **The import is different because the mockup's was wrong.** It used
 *    `import AxeBuilder from 'axe-playwright'`. `axe-playwright@2.2.2`
 *    exports `injectAxe, configureAxe, getAxeResults, getViolations,
 *    reportViolations, checkA11y, DefaultTerminalReporter` — no `AxeBuilder`,
 *    and no default export. `AxeBuilder` is `@axe-core/playwright`'s API, a
 *    different package. As written the mockup's spec could not have run.
 *    Reported with R5b rather than silently corrected.
 *
 * 2. **Impact filtering is kept.** Only `critical` and `serious` fail. `minor`
 *    and `moderate` findings on an unstyled page are dominated by contrast
 *    and spacing rules that R3 will settle when a stylesheet exists; failing
 *    on them now would make the gate a styling to-do list.
 *
 * **What a pass here does not mean.** The page currently renders with no CSS
 * at all — no stylesheet exists anywhere in the tree (RFC 135 §4). Colour
 * contrast, focus-visible styling, and target size are therefore untested by
 * construction, not merely passing. This suite will need re-running against a
 * styled page when R3 lands, and the result then is the meaningful one.
 */
import { test, expect } from '@playwright/test';
import { injectAxe, getViolations } from 'axe-playwright';
import { PUBLIC_ROUTES, gotoMounted } from './support';

for (const route of PUBLIC_ROUTES) {
  test(`axe wcag2a/wcag2aa: ${route}`, async ({ page }) => {
    await gotoMounted(page, route);

    await injectAxe(page);
    const violations = await getViolations(page, undefined, {
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa'] },
    });

    const blocking = violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );

    expect(
      blocking,
      `Axe critical/serious violations on ${route}:\n` +
        blocking
          .map((v) => `  ${v.impact}/${v.id}: ${v.description} (${v.nodes.length} node(s))`)
          .join('\n'),
    ).toHaveLength(0);
  });
}
