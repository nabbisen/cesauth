/**
 * RFC 131 R5b — route-smoke.spec.ts
 *
 * **Rewritten, not adapted.** The mockup's version listed 26 of its own
 * routes; of the 9 sampled during R5's preparation, 5 do not exist in cesauth
 * and `/magic-link/request` is POST-only (handoff §4). Nothing of its route
 * list survives. What survives is the shape: for every page a browser can
 * reach, assert it renders and that the browser reported nothing wrong.
 *
 * **This does not duplicate `runtime-smoke-check.sh`** (handoff §2). That
 * script already asserts, via curl, that these routes return 200 HTML with a
 * CSP header and that every referenced asset resolves. All ten of its checks
 * passed throughout the RFC 135 outage, when both pages were blank. The
 * assertions here are the ones curl structurally cannot make: that the WASM
 * bundle instantiated, that Leptos mounted, and that the browser threw
 * nothing.
 */
import { test, expect } from '@playwright/test';
import { PUBLIC_ROUTES, gotoMounted, collectFailures } from './support';

for (const route of PUBLIC_ROUTES) {
  test(`smoke: ${route} mounts and renders cleanly`, async ({ page }) => {
    const { consoleErrors, pageErrors } = collectFailures(page);

    await gotoMounted(page, route);

    // The mount itself. Non-empty `#root` is the difference between "served"
    // and "renders" — see support.ts.
    const rootLength = await page.evaluate(
      () => document.getElementById('root')!.innerHTML.trim().length,
    );
    expect(rootLength, `${route}: #root is empty — the app did not mount`)
      .toBeGreaterThan(0);

    // Exactly one <h1>: a page with none is unlabelled, and a page with two
    // has a document-outline bug the axe ruleset will not always catch.
    await expect(
      page.locator('h1'),
      `${route}: expected exactly one <h1>`,
    ).toHaveCount(1);

    expect(
      pageErrors,
      `${route}: uncaught exceptions or rejections — ${pageErrors.join(' | ')}`,
    ).toHaveLength(0);

    expect(
      consoleErrors,
      `${route}: console errors — ${consoleErrors.join(' | ')}`,
    ).toHaveLength(0);
  });
}

/**
 * `/` and `/login` are the same page, served at two paths — both call
 * `login_page_for`. Pinning that keeps the two route assertions above honest
 * about what they cover: if these ever diverge, the suite is testing two
 * things and should say so, and if one path stops resolving, this fails
 * rather than quietly halving the coverage.
 */
test('/ and /login render the same document', async ({ page }) => {
  const rendered: string[] = [];

  for (const route of PUBLIC_ROUTES) {
    await gotoMounted(page, route);
    rendered.push(
      await page.evaluate(() => document.getElementById('root')!.innerHTML),
    );
  }

  expect(
    rendered[1],
    '/ and /login no longer render the same document — the suite covers two pages now, not one',
  ).toBe(rendered[0]);
});
