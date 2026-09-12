import type { Page } from '@playwright/test';

/**
 * cesauth's public, unauthenticated HTML surface — the whole of it.
 *
 * Two paths, one page: `route-contracts.md` lists exactly these as the only
 * routes whose actor is `Anonymous`, and both call `login_page_for`. Every
 * other client-rendered route requires a Tenant admin, System admin, or
 * authenticated user, and R5 does not authenticate (handoff §7).
 *
 * Both are declared `server` in the catalogue while actually rendering
 * client-side — two of RFC 132 §8's three known conformance gaps. RFC 131 R3
 * converts them; until then they are what a browser can reach, and this suite
 * asserts them as they are rather than as the catalogue describes them.
 *
 * `/me/security` and the console screens arrive with R3, when there is
 * something for a browser to test.
 */
export const PUBLIC_ROUTES = ['/', '/login'] as const;

/**
 * Navigate to `path` and wait for the Leptos app to mount.
 *
 * "Mounted" means `<div id="root">` is non-empty. That is a real assertion as
 * of RFC 135 W4 and not before: the app previously mounted with
 * `mount_to_body`, which appends to `<body>` and leaves `#root` empty, so this
 * check would have failed against a working app. It is also the assertion that
 * fails when the WASM bundle cannot compile — the RFC 135 outage, where every
 * asset returned 200 and the page was blank.
 *
 * The timeout is deliberately generous: a cold `wrangler dev` compiles and
 * instantiates a ~750 KB WASM bundle on first request, and a timeout tuned to
 * a warm run would flake in CI for reasons that have nothing to do with the
 * code under test.
 */
export async function gotoMounted(page: Page, path: string): Promise<void> {
  await page.goto(path, { waitUntil: 'load' });
  await page.waitForFunction(
    () => (document.getElementById('root')?.innerHTML.trim().length ?? 0) > 0,
    undefined,
    { timeout: 30_000 },
  );
}

/**
 * Collect browser-side failures for the lifetime of a page.
 *
 * Must be called **before** navigating — listeners attached after `goto`
 * miss everything the page emitted while loading, which is precisely when a
 * WASM instantiation failure is thrown.
 *
 * `pageErrors` are uncaught exceptions and rejections (the RFC 135
 * `CompileError` was one of these, not a console message, which is why a
 * console-only check would have missed a total outage).
 */
export function collectFailures(page: Page): {
  consoleErrors: string[];
  pageErrors: string[];
} {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];

  page.on('console', (msg) => {
    if (msg.type() !== 'error') return;
    consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => pageErrors.push(String(err)));

  return { consoleErrors, pageErrors };
}
