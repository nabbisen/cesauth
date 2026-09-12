import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for cesauth's browser acceptance harness
 * (RFC 131 R5).
 *
 * **Requires `wrangler dev` on http://localhost:8787**, serving a current
 * frontend bundle:
 *
 * ```sh
 * make build-frontend
 * npx wrangler dev --port 8787
 * cd e2e && npx playwright test
 * ```
 *
 * No `webServer` block: starting `wrangler dev` from Playwright would hide
 * build and startup failures inside a test-runner timeout. The CI job starts
 * it explicitly and fails on the server's own output if it does not come up.
 *
 * **Unauthenticated, public pages only** (R5 handoff §7). A gate that needs a
 * session is a gate that gets disabled the first time session handling
 * changes — the same reasoning that keeps `runtime-smoke-check.sh` to 401
 * assertions rather than logging in.
 *
 * `retries: 0`, in CI too. RFC 131 R5's §8 buys one release of observation to
 * find out whether this suite flakes; retries would hide exactly the data
 * that window exists to collect.
 */
export default defineConfig({
  testDir: './specs',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',

  use: {
    baseURL: process.env.CESAUTH_BASE_URL ?? 'http://localhost:8787',
    trace: 'retain-on-failure',
  },

  // Chromium only for the first release. The suite has never run in CI; adding
  // engines multiplies unknown flake sources before the first one is
  // characterised. Firefox and WebKit are a deliberate follow-up, not an
  // oversight — see the R5e review request.
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
});
