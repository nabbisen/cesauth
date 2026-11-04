# RFC 178 — The end-user app ships no stylesheet, and renders in Times New Roman

**Status.** **Accepted 2026-11-04.** Proposed the same day by the architect,
found while reviewing RFC 176 §6.1b. **Not quoted here**, same shape as
RFC 173/175: the owner's message named this file directly with `Follow:`
and no separate handoff, which this project's standing precedent treats as
real-time authorization — but it is not a literal "accepted" quotation, and
if one exists elsewhere this line should carry it. **§3's central question
— restoration or deferred-honesty-fix — is still open and this acceptance
does not answer it**; only §4's two gates, named as actionable "today,
whatever the answer," are dispatched by this acceptance.
**Tier.** **P1** for the question the owner asked. Nothing is exposed and
nothing errors. **The product's primary user-facing surface has no CSS at all**:
`/login` renders in **Times New Roman** at browser defaults, and six
hand-written class names — including `sr-only` — are referenced by markup that
nothing styles.
**Size.** **Unknown, and that is the honest answer.** It depends entirely on
§3's question, which is the owner's. Writing a stylesheet is a day; deciding
what the product should look like is not a sizing exercise.
**Touches.** `crates/frontend/` (a stylesheet where there is none), `Trunk.toml`
or the frontend build, `.github/workflows/trunk-release-build.yml`, and `e2e/`.
**Found by.** The architect, 2026-11-04, measuring the live DOM while checking
whether RFC 176's colour fix had reached the pages a user sees. **It had not,
and neither had any other styling.**
**Relates to.** [RFC 176](../accepted/176-the-ui-is-measurably-hostile-to-older-eyes.md)
and [RFC 177](../accepted/177-the-security-centre-leads-with-account-deletion.md) — both
measured and fixed real things, and §2 explains why neither reached this,
[RFC 131](../accepted/131-mockup-adoption-strategy.md) (the mockup adoption programme),
RFC 141 §10.2 (declared but never wired).

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Measured in Chromium against a running server

`GET /login`, after the Leptos app mounts:

```
stylesheets: 0      <style> tags: 0      <link rel=stylesheet>: 0
author CSS rules:  0
elements in #root: 14, of which 5 carry a class and 0 carry an inline style
body font-family:  "Times New Roman"
body background:   rgba(0, 0, 0, 0)
h1 font-size:      32px        (the browser default, not a choice)
```

**Class names present in the markup, styled by nothing:**
`login-page`, `login-card`, `sr-only`, `btn-primary`, `btn-passkey`, `muted`.

`crates/frontend/dist/` contains `cesauth-frontend_bg.wasm`,
`cesauth-frontend.js` and `webauthn.js`. **There is no `.css` file**, and
`trunk-release-build.yml` asserts the existence of exactly those three — so the
gate codifies the gap rather than catching it.

**`sr-only` is the detail that turns this from aesthetics into behaviour.** Its
only purpose is a CSS rule that hides content visually while leaving it to
assistive technology. With no stylesheet, **text intended only for screen
readers is rendered to everyone.**

## 2. Why RFC 176 and RFC 177 did not find this, and were not wrong

This project has **two** user-facing rendering paths, and the colour work landed
on the one that is styled:

| path | lives in | styled by | reaches |
|---|---|---|---|
| server-rendered | `crates/frontend/src/templates/` | `chrome.rs`'s `BASE_CSS` | the magic-link-sent page, TOTP pages, error pages |
| CSR (Leptos SPA) | `crates/frontend/src/pages/` | **nothing** | `/`, `/login`, `/me/security`, `/me/security/sessions` |

Both colour cycles were real fixes to the first path and to the admin frames.
**Neither could have reached the second, because there is nothing there to
apply a token to.** And RFC 177's measurements — 13.33 px text, 21 px controls —
were never a design that is too small: **they are Chrome's defaults in the
absence of a design.** That correction belongs on RFC 177 and is recorded there.

**The journey a new user actually takes** is the sharpest statement of the
problem: an **unstyled Times New Roman form** on `/login`, then — after
submitting an email — a **styled, tokenised, AAA-contrast "check your email"
page**. The second screen looks like a product; the first does not.

## 3. The question this RFC exists to ask, and it is not a technical one

**Was the SPA ever styled?** Six semantic class names written by hand, matching
a card-and-button layout, are not what someone writes when they intend browser
defaults. The markup expects a stylesheet. Whether one was lost, never written,
or deliberately deferred behind RFC 131's mockup-adoption programme **is not
something the code can tell me**, and the answer decides the work:

- **If it is missing**, this is a restoration: write the stylesheet the class
  names already describe, consume the existing tokens, and the typography and
  target-size work in RFC 176 §6.2/§6.3 lands in it naturally rather than being
  retrofitted across templates.
- **If it is deferred**, then RFC 131's programme owns it and the only thing
  owed now is honesty: the product's primary surface is unstyled today, and
  neither the docs nor any gate says so.

**I am not proposing a visual design.** That is the owner's, and §6.2's
typography tokens plus §6.1's colour tokens already give it a spine.

## 4. What can be gated today, whatever the answer

**One assertion, cheap, and it would have caught this years earlier**: the
mounted SPA has **at least one author stylesheet rule**. It runs in the existing
anonymous Playwright suite on `/login`, needs no session, and fails loudly the
day a build stops emitting CSS.

Second, narrower: **`trunk-release-build.yml` should assert the CSS artifact it
expects**, not only the three files that happen to exist. A gate that lists
what is there cannot notice what is not.

## 5. What this RFC does not claim

- **Nothing is broken or exposed.** The app works; it is undressed.
- **No user has reported it** — nobody has deployed this tree.
- **The server-rendered pages are fine** and getting better: RFC 176 §6.1 and
  §6.1b took them to AAA.
- **This is not a criticism of either colour cycle.** Both fixed what they were
  pointed at. **The scoping that pointed them at the styled half was the
  architect's**, in RFC 176 §2, which measured a token file and inferred a UI.
