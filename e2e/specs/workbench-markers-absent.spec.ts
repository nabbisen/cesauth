/**
 * RFC 131 R5d — workbench-markers-absent.spec.ts
 *
 * **The mockup's `devpanel-absent.spec.ts`, inverted.** That spec asserted
 * the DevPanel *is* present and carries a `data-workbench-only` marker, so a
 * production build could strip it. Its own comment concedes it is "a design
 * contract test... a placeholder", and its body is
 * `if (await panel.count() > 0) { expect(true).toBe(true) }` — which passes
 * whether the panel exists or not.
 *
 * Here the assertion runs the other way and means something. RFC 131 R2a
 * imported view models, icons and components **from that mockup** into
 * `cesauth-frontend`. If a workbench-only affordance ever rides along with a
 * later import — R2b, R3, R4 all pull from the same source — it must not
 * reach a page cesauth serves. This is the gate that says so.
 *
 * It is an import-safety check, not a UI check: the risk is not that someone
 * designs a scenario switcher into cesauth, it is that one arrives unnoticed
 * inside an otherwise-wanted component.
 *
 * The marker set below is what the mockup actually uses to tag its
 * workbench-only UI, taken from its own `devpanel-absent` spec
 * (`data-workbench-only`, `.scenario-switcher`) rather than guessed.
 */
import { test, expect } from '@playwright/test';
import { PUBLIC_ROUTES, gotoMounted } from './support';

/**
 * Selectors that must never match anything cesauth serves.
 *
 * Add to this list when a new workbench-only marker is discovered in the
 * mockup — not when one is found in cesauth's output. A hit here is a finding
 * to report, never a selector to remove.
 */
const WORKBENCH_MARKERS = [
  '[data-workbench-only]',
  '.scenario-switcher',
  '[data-testid]', // the mockup's dev affordances key off these; cesauth uses none
] as const;

for (const route of PUBLIC_ROUTES) {
  test(`no workbench-only markup reaches ${route}`, async ({ page }) => {
    await gotoMounted(page, route);

    const found = await page.evaluate((selectors) => {
      const hits: { selector: string; count: number; sample: string }[] = [];
      for (const selector of selectors) {
        const els = document.querySelectorAll(selector);
        if (els.length > 0) {
          hits.push({
            selector,
            count: els.length,
            sample: (els[0] as HTMLElement).outerHTML.slice(0, 200),
          });
        }
      }
      return hits;
    }, WORKBENCH_MARKERS as unknown as string[]);

    expect(
      found,
      `${route}: workbench-only markup in served output — ` +
        found.map((h) => `${h.selector} ×${h.count}: ${h.sample}`).join(' | ') +
        `\nThis is an import-safety finding (RFC 131 R2a imported from the mockup). ` +
        `Report it; do not delete the selector.`,
    ).toHaveLength(0);
  });
}

/**
 * The inverse guard: prove the selectors can still match.
 *
 * Without this, the test above passes identically whether cesauth is clean or
 * the selector list has rotted into nonsense — the same "asserts nothing"
 * shape the mockup's original had, and the shape this project has now found
 * four times. Injecting a marker into a throwaway page and confirming each
 * selector fires keeps the list honest.
 */
test('the workbench-marker selectors still match something', async ({ page }) => {
  await page.setContent(`
    <div data-workbench-only="1">panel</div>
    <div class="scenario-switcher">switcher</div>
    <button data-testid="x">btn</button>
  `);

  for (const selector of WORKBENCH_MARKERS) {
    const count = await page.locator(selector).count();
    expect(count, `selector ${selector} matched nothing in a document built to contain it`)
      .toBeGreaterThan(0);
  }
});
