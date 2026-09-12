/**
 * RFC 131 R5b — duplicate-ids.spec.ts
 *
 * A duplicate `id` silently breaks `<label for>`, `aria-labelledby`, and
 * in-page anchors — the browser resolves the first match and the rest of the
 * markup points at the wrong element. Rust's rendering tests cannot catch it:
 * they assert on fragments, and a duplicate only exists once fragments are
 * composed into a document.
 *
 * Adapted from the mockup's spec, which checked two of its own authenticated
 * admin pages. Route list replaced with cesauth's public surface; the check
 * itself is unchanged.
 *
 * The login page currently carries four ids — `root`, `passkey-heading`,
 * `email-heading`, `email` — three of which are referenced by `for` or
 * `aria-labelledby`. That is exactly the shape this protects.
 */
import { test, expect } from '@playwright/test';
import { PUBLIC_ROUTES, gotoMounted } from './support';

for (const route of PUBLIC_ROUTES) {
  test(`no duplicate ids: ${route}`, async ({ page }) => {
    await gotoMounted(page, route);

    const { duplicates, total } = await page.evaluate(() => {
      const ids = Array.from(document.querySelectorAll('[id]')).map((el) => el.id);
      const seen = new Set<string>();
      const dupes = new Set<string>();
      for (const id of ids) {
        if (seen.has(id)) dupes.add(id);
        seen.add(id);
      }
      return { duplicates: Array.from(dupes), total: ids.length };
    });

    // Guard against the check passing because nothing rendered: a page with
    // no ids at all trivially has no duplicates. `#root` alone guarantees one.
    expect(total, `${route}: no elements with an id — did the page render?`)
      .toBeGreaterThan(0);

    expect(
      duplicates,
      `${route}: duplicate id(s) ${duplicates.join(', ')} — label/aria references will resolve to the wrong element`,
    ).toHaveLength(0);
  });
}
