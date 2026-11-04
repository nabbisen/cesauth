# RFC 177 — The security centre leads with account deletion, and other things only the running screens show

**Status.** **Accepted** 2026-11-04 by the owner (*"Accepted."*). Proposed the
same day by the architect, completing the half of the owner's frontend question
that RFC 176 §6 deliberately left unsized.

**§4.1, §4.2 and §5 dispatched 2026-11-04 as a patch.** §4.3's measurement
belongs to RFC 176 §6.3's minor and is not re-dispatched here.

**§4.4 is still open, and acceptance did not close it** — unlike RFC 174 §3,
this RFC offered two options and **picked neither**, so there was nothing in it
for an acceptance to carry. The question stands: does `/login`'s passkey button
move behind the email path until registration exists, or does registration get
built and the order stand?

**And §5 understated its own cost.** See §5.1: the browser suite is
anonymous-only — `PUBLIC_ROUTES = ['/', '/login']` — so the one assertion §5
asks for needs a signed-in session the suite has no path to.
**Tier.** **P2**, with one item arguing for higher: the most destructive control
an end user has is the **first** thing they read and the **first** thing they
reach by keyboard on `/me/security`. Nothing is exposed and nothing is broken;
the product invites a mistake it does not need to.
**Size.** **Small to medium.** §4's first three items are ordering and markup,
not new screens. The fourth is a judgement the owner has to make.
**Touches.** `crates/frontend/src/` templates for `/login`, `/me/security` and
`/me/security/sessions`; `e2e/` for the assertions in §5.
**Found by.** The architect, 2026-11-04, **by driving the running screens in
Chromium** rather than reading the stylesheet — which is what RFC 176 §6 said
this half required and refused to guess at.
**Relates to.** [RFC 176](../accepted/176-the-ui-is-measurably-hostile-to-older-eyes.md)
(the measured colour/typography/target half; §3 below confirms its §5 on real
rendered pages), [RFC 131](../accepted/131-mockup-adoption-strategy.md) (the operator
surfaces, not measured here), RFC 172 (why §2's first finding bites now).

**On 1.0:** not declared, not scoped, not dated.

---

## 1. How this was measured, and why it had to be

`/` and `/login` return a **1,432-byte CSR shell** — `<div id="root"></div>`
plus a wasm bootstrap. Every end-user surface is built by WebAssembly in the
browser, so **none of the owner's three questions about layout can be answered
from the source or from `curl`.** They were answered by loading each page in
Chromium, signing in through a real magic-link round trip, and measuring the
live DOM: focus order, heading structure, landmarks, rendered font sizes, and
the bounding box of every focusable element.

| page | focusables | headings | smallest focusable | under 44 px | ms to first text |
|---|---|---|---|---|---|
| `/login` | 3 | h1, h2, h2 | **21 px** | **3 of 3** | 167 |
| `/me/security` | 4 | h1 + four h2 | **17 px** | **4 of 4** | 80 |
| `/me/security/sessions` | 2 | h1 only | **17 px** | **2 of 2** | 51 |

**Three things are already right and should not be changed in the name of this
RFC**: heading levels are well-formed everywhere (no skipped levels), every
visible input is properly labelled, and the screens are genuinely sparse — three
controls on the sign-in page, four on the security centre. **The owner's "less
is more" instinct is already honoured.** What follows is about *order*, *size*
and *one unusable control*, not about volume.

## 2. The finding: the security centre leads with its most destructive action

On `/me/security`, measured focus order:

```
1.  button[submit]  "Request account deletion"
2.  a               "Enable two-factor authentication"
3.  a               "Manage sessions"
4.  button[submit]  "Sign out"
```

and heading order: **`Delete account`**, `Primary sign-in method`,
`Two-factor authentication`, `Active sessions`.

**So account deletion is the first section a user reads and the first control a
keyboard or screen-reader user reaches.** The routine, constructive tasks — add
a second factor, review your sessions — are second and third. I found no stated
rationale for the ordering in the template or in any RFC; it reads like each
section was added above the last.

**Why this is the item that matters most for the owner's question.** Older users
are over-represented among people who navigate by keyboard, who zoom, and who
scan the top of a page and act on what they find there. A 17-pixel-tall button
labelled *Request account deletion*, first in the tab order, on the page people
visit to **protect** their account, is an invitation to a mistake that no amount
of confirmation copy fully undoes. The control is not dangerous in itself — the
flow has a 30-day grace period — but **its position is the defect.**

**Least-destructive-first is the fix**, and it costs a reordering: sessions and
two-factor above, deletion last, under its own heading, after the constructive
options a worried user actually came for.

## 3. The sign-in page's first control is one no user can currently create

`/login`'s focus order is:

```
1.  button  "Sign in with passkey"
2.  input[email]
3.  button[submit]  "Send sign-in code"
```

**Tab stop 1 is a passkey sign-in, and as of 0.92.3 there is no way to register
a passkey.** RFC 172 fixed the registration route to require a session, RFC 174
confirmed no console affordance exists, and RFC 176 §6's note recorded that
RFC 131's passkey surface is unbuilt. So the first thing every user meets on the
sign-in page is a button for a credential they cannot have obtained, and the
working path — email code — is two stops behind it.

**This is not an argument for removing passkey-first.** *"Passkey first,
username-less first"* is the product's declared design and `introduction.md`
says so. It is an argument that **the order should follow what is actually
available today**, and flip back when registration exists. Whether to reorder or
to build registration is §4.4's question and it is the owner's.

## 4. Direction

1. **Reorder `/me/security` least-destructive-first.** Sessions, then two-factor,
   then sign-out, then deletion last. Markup and order only.
2. **Give the sessions page a section heading structure.** One `h1` over a table
   with no `h2` means a screen-reader user has no way to skip between the table
   and the back-link, and a zoomed user loses the page's shape. Small.
3. **Confirm RFC 176 §6.3's control-height floor against these numbers.**
   Every focusable on all three pages is under 44 px, the smallest **17 px** —
   measured on the rendered page, not inferred from padding, which is the
   evidence RFC 176 §5 was missing. **The floor belongs with RFC 176 §6.3's
   minor, not here**; this RFC supplies the measurement.
4. **The owner's call: `/login`'s order.** Either passkey moves behind the email
   path until registration exists, or registration gets built and the order
   stands. **Both are defensible and the choice is a product decision, not an
   implementation detail** — which is why this RFC asks rather than picks.

## 5. What a gate can hold, and what it cannot

**Can**: *the first focusable element of `/me/security` is not the deletion
control.* That is one Playwright assertion over the real page, it runs in the
existing suite, and it fails loudly if a future section is added on top again.
**Worth having** — this defect arrived by accretion and only a gate stops it
arriving again.

**Cannot**: whether an ordering is *good*. A gate can pin a decision once taken;
it cannot take it. §4.1's ordering should be asserted, §4.4's should not be
asserted until the owner has chosen.

## 5.1 Correction, 2026-11-04, before dispatch: §5's "one assertion" is not one assertion

§5 called the ordering gate *"one Playwright assertion over the real page [that]
runs in the existing suite."* **It does not run in the existing suite**, and
checking before dispatching is what found it:

- `e2e/specs/support.ts` exports `PUBLIC_ROUTES = ['/', '/login']` and **no
  spec signs in** — the only `magic-link` mention in the suite is a comment
  explaining that the route is POST-only.
- `/me/security` **302s without a session**, so the assertion needs a
  credentialed browser context the suite cannot currently produce.
- And **neither `pages/security_center.rs` nor `pages/sessions.rs` has a single
  `#[test]`**, so there is no host-test surface to pin the ordering in either.

**This is the same finding as RFC 176 §3 from the other side**: the browser
gate's coverage is two anonymous pages, which is why it sees neither the colour
tokens nor the focus order of any screen behind a login. **The ordering fix is
still small; the gate for it is not**, and 0.92.2's credentialed-flows job
already holds the pieces a signed-in browser path would need. Dispatched as
*report rather than build* if it proves more than small.

## 5.2 Correction, 2026-11-04: §1's sizes were browser defaults, not a design

§1's table reports 13.33 px text and 17–21 px controls as measurements of this
product's typography and targets. **They are measurements of Chrome's defaults.**
The CSR pages ship **no stylesheet at all** — 0 author rules, body font
`"Times New Roman"`, `h1` at the default 32 px, and six class names
(`login-page`, `login-card`, `sr-only`, `btn-primary`, `btn-passkey`, `muted`)
that nothing styles. See
[RFC 178](../accepted/178-the-end-user-app-ships-no-stylesheet.md).

**The findings in §2 and §3 stand unchanged** — focus order and heading order
are properties of the markup, not of CSS, and the reorder fixed a real defect.
**What does not stand is reading §1's numbers as evidence about a design.**
RFC 176 §6.3's control-height floor still wants doing, but it wants doing *in a
stylesheet that does not yet exist*, which is RFC 178's question and not a
retrofit across templates.

## 6. What this RFC does not claim

- **No user has reported any of this.** Nobody has deployed this tree.
- **The operator surfaces were not measured.** `/admin/**` needs a credentialed
  browser session; 0.92.2's job can now reach them, and that is a separate
  piece of work. **Everything above is the end-user surfaces only**, and the
  owner's question about menu position is answered for those: **there are no
  menus — there are links in prose, and no `nav` landmark on any of the three
  pages.** Whether that is right at this size is §4's smaller sibling and is not
  pressed here.
- **The CSR shell's blank first paint is a risk, not a measured defect.** First
  text arrived in 51–167 ms locally. `#root` is empty until wasm runs and the
  `<noscript>` fallback does not cover *slow* or *failed* wasm — only disabled
  scripting. On an old device that is a blank white page with no explanation.
  **Measuring it honestly needs throttling, which this cycle did not do**, so it
  is named and not sized.
