# Developer Handoff — RFC 177 §4.1 / §4.2: stop the security centre leading with deletion

**Governing RFC.** [`rfcs/accepted/177-the-security-centre-leads-with-account-deletion.md`](../../accepted/177-the-security-centre-leads-with-account-deletion.md)
— accepted 2026-11-04. **Read §1 for how it was measured, §2 for the finding,
and §5.1 because it corrects §5's own cost estimate.**
**Builds on.** `main` at or after tag `0.92.5` (`eb94a78`).

**Target release.** **Patch — the next cut after 0.92.5**, alongside RFC 176
§6.1 if that lands first. Number at the cut.
**Trigger: none, argued.** Nothing gains capability. A destructive control
sitting first is a defect against the product's own standard, and reordering
sections fixes it.
**Tier.** **P2.** Nothing is exposed; the product invites a mistake it does not
need to.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-04.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. §4.1 — reorder `/me/security` least-destructive-first

`crates/frontend/src/pages/security_center.rs`. The `h2` sections in source
order today:

```
 91  "Account deletion scheduled"      (conditional — the pending state)
107  "Delete account"
129  "Primary sign-in method"
144  "Two-factor authentication"       (two branches, 144 and 160)
173  "Active sessions"
```

Measured in Chromium, that makes **"Request account deletion" the first control
in focus order** and `Delete account` the first heading a user reads, on the page
people visit to protect an account.

**Target order: constructive first, destructive last.**

1. `Primary sign-in method`
2. `Two-factor authentication`
3. `Active sessions`
4. `Delete account`

**`Account deletion scheduled` is a different case and is yours to judge.** It
is the *pending* state — a user who has already requested deletion needs to find
the cancel action quickly, and burying it last would be its own defect. **My
reading is that it should stay prominent, near the top, when it renders**,
because it is then the most important fact about the account. **If you disagree,
say which and why** — this is the one ordering decision in the cycle that is not
obvious.

**Sign-out is not an `h2`** and sits outside the section list; leave its
position alone unless the reorder makes it land somewhere absurd.

## 2. §4.2 — give the sessions page a heading structure

`crates/frontend/src/pages/sessions.rs` renders one `h1` ("Active sessions") and
**no `h2` at all** over a table plus a back-link. A screen-reader or zoomed user
has no landmark between the two. Add the minimum that makes the page navigable —
**do not invent sections that do not exist**; if the honest answer is one `h2`
over the table, that is the answer.

## 3. §5's gate: check the cost before you build it

RFC 177 §5 called this *"one Playwright assertion [that] runs in the existing
suite"*, and **§5.1 corrects that — it does not.** Verified before dispatch:

- `e2e/specs/support.ts` exports `PUBLIC_ROUTES = ['/', '/login']`, and **no
  spec signs in**;
- `/me/security` **302s without a session**;
- and **neither `security_center.rs` nor `sessions.rs` has a single
  `#[test]`**, so there is no host-test surface either.

**So: if a signed-in browser context is cheap in this suite, add the assertion**
— *the first focusable element of `/me/security` is not the deletion control* —
because this defect arrived by accretion and only a gate stops it arriving
again. **If it is not cheap, report what it would take and build nothing.**
Adding a credentialed path to the browser suite is a capability, not a test, and
0.92.2's `credentialed-flows.yml` already holds the pieces one would need
(migrated D1, seeded rows, the pinned wrangler). **That is a separate dispatch
and I would rather hear the estimate than receive a half-built one.**

## 4. How to verify the reorder without a gate

Drive it, the way the RFC was written: load `/me/security` in Chromium with a
real session and capture **the focus order and the heading order**, before and
after. The sign-in is a magic-link round trip — `POST /magic-link/request`, read
the OTP from the `wrangler dev` console (`DevConsoleMailer` is active because
`.dev.vars` sets `WRANGLER_LOCAL=1`), `POST /magic-link/verify`, keep the
`__Host-cesauth_session` cookie.

**Two notes from doing it**: a `__Host-` cookie cannot be injected through
Playwright's cookie jar over `http://localhost` (the prefix requires `Secure`
and the jar rejects the combination) — **pass it as an `extraHTTPHeaders.Cookie`
on the browser context instead**, which the server accepts and the jar never
validates. And clean up the `user_sessions` row afterwards.

**Capture both orders as text in the report.** A screenshot is not a focus
order.

## 5. Do not

- **Do not change any colour, font size or padding.** RFC 176 §6.1 owns colour
  and is in flight; §6.2/§6.3 are a minor and own typography and control height.
  **If the reorder tempts you to resize something, that is the other RFC.**
- **Do not answer RFC 177 §4.4.** `/login`'s passkey-first ordering is an open
  question with the owner. **Leave `/login` alone entirely.**
- **Do not add a `nav` landmark.** RFC 177 §6 names its absence and explicitly
  does not press it.
- **Do not measure the operator surfaces.** Separate work.

## 6. Stop conditions

- **The reorder requires restructuring the component**, not just moving
  sections — report what and why; a reorder that becomes a rewrite is a
  different size.
- **`Account deletion scheduled`'s placement turns out to matter more than §1
  allows** — report your reading rather than splitting the difference.
- **A signed-in browser context is not cheap** — report the estimate, build
  nothing (§3).
- The sessions page has no honest `h2` to add.

## 7. Baselines at tag `0.92.5` (`eb94a78`), each with its command

- host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,675 passed, 0 failed, 4 ignored, 12 lines**;
- `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
- `bash scripts/route-contracts-check.sh` → 192 routes; E4 `216 = 192 + 24 + 0`; E6 `92 = 83 + 9 + 0`; **E7 `156 = 8 + 31 + 117`**;
- `bash scripts/drift-scan.sh` → clean;
- `mdbook build docs` → clean, 82 pages;
- `npx playwright test` in `e2e/` → **20**, needs a warm `wrangler dev --port 8787`;
- `bash scripts/runtime-smoke-check.sh` → passed;
- bundle, `wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15 default** → **888,939 B** (878,238 wasm + 10,701 `shim.js`). **Expect a small move** — reordering a Leptos view changes the compiled wasm. Report it with the level named.

**Keep the report short.** `CHANGELOG.md` has under 1 KB of headroom and the
entry is mine to write at the cut.

**Measured focus order to beat, for the report's before/after:**
`1 Request account deletion · 2 Enable two-factor authentication · 3 Manage
sessions · 4 Sign out`, smallest focusable **17 px**, all four under 44 px.
