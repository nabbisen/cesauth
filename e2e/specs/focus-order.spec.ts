/**
 * RFC 131 R5b — focus-order.spec.ts
 *
 * **This replaces the mockup's `focus-trap.spec.ts`, whose subject does not
 * exist here. Reported with R5b.** That spec opened modal dialogs on
 * authenticated admin screens (`[data-testid="revoke-role-btn"]`,
 * `[role="dialog"]`) and asserted Tab cycles within the dialog and Escape
 * closes it. On cesauth's public surface:
 *
 * - there are **no dialogs** — `[role="dialog"], dialog` returns 0 on both
 *   routes;
 * - there are no `data-testid` attributes at all;
 * - the screens that might one day have dialogs are all authenticated, and
 *   R5 does not authenticate (handoff §7).
 *
 * A dialog focus-trap spec written against this surface would have to invent
 * its subject or skip itself, and the handoff is explicit that a spec must not
 * be adapted into something vacuous (§6, R5c). So the mechanism is dropped and
 * the *property* is kept: keyboard users must be able to reach every control,
 * in the order the document presents them.
 *
 * That is a real assertion about this page. The login page's three controls —
 * passkey button, email field, submit — are the entire authentication entry
 * point; if Tab cannot reach the submit button, the page is unusable by
 * keyboard and no Rust rendering test would notice, because tab order is a
 * property of the composed document and the browser's focus model.
 *
 * A genuine focus-trap spec arrives with the first real dialog, which is R3's
 * or later.
 */
import { test, expect } from '@playwright/test';
import { PUBLIC_ROUTES, gotoMounted } from './support';

for (const route of PUBLIC_ROUTES) {
  test(`keyboard reaches every control in document order: ${route}`, async ({ page }) => {
    await gotoMounted(page, route);

    // Document order, as the browser sees it. No explicit tabindex is used on
    // this page, so DOM order is tab order — which is the property worth
    // holding: a positive tabindex anywhere would reorder it invisibly.
    const expected = await page.evaluate(() =>
      Array.from(
        document.querySelectorAll<HTMLElement>('a[href], button, input, select, textarea'),
      ).map((el) => {
        const t = el.getAttribute('type');
        return el.tagName.toLowerCase() + (t ? `[${t}]` : '');
      }),
    );

    expect(expected.length, `${route}: no focusable controls to tab through`)
      .toBeGreaterThan(0);

    const visited: string[] = [];
    for (let i = 0; i < expected.length; i++) {
      await page.keyboard.press('Tab');
      visited.push(
        await page.evaluate(() => {
          const el = document.activeElement as HTMLElement | null;
          if (!el || el === document.body) return '<body>';
          const t = el.getAttribute('type');
          return el.tagName.toLowerCase() + (t ? `[${t}]` : '');
        }),
      );
    }

    expect(
      visited,
      `${route}: tab order does not match document order — ` +
        `expected ${expected.join(' → ')}, got ${visited.join(' → ')}`,
    ).toEqual(expected);
  });

  test(`no positive tabindex overrides document order: ${route}`, async ({ page }) => {
    await gotoMounted(page, route);

    // A positive tabindex jumps an element ahead of everything with tabindex 0,
    // which reorders the page for keyboard users only — invisible in a
    // screenshot and in every server-side rendering test.
    const positive = await page.evaluate(() =>
      Array.from(document.querySelectorAll<HTMLElement>('[tabindex]'))
        .map((el) => ({
          tag: el.tagName.toLowerCase(),
          tabindex: el.getAttribute('tabindex') ?? '',
        }))
        .filter((e) => Number(e.tabindex) > 0),
    );

    expect(
      positive,
      `${route}: positive tabindex on ${positive.map((p) => `${p.tag}[tabindex=${p.tabindex}]`).join(', ')}`,
    ).toHaveLength(0);
  });
}
