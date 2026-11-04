# RFC 176 — The UI is measurably hard for older eyes, and the a11y gate cannot see it

**Status.** **Proposed** 2026-11-04 by the architect, answering the owner's
question about layout, typography and colour for older users. **Not scheduled.
Needs the owner's acceptance.**
**Tier.** **P2.** Nothing is broken and nothing is exposed. The product is
measurably harder to read and to hit than it should be for the audience the
owner named, and **the gate that is supposed to catch this passes** — because it
only ever loads two pages.
**Size.** **Medium, in three clearly separable parts.** §5 orders them by
value-per-change; the first is small and fixes the worst of it.
**Touches.** `crates/frontend/src/design_tokens.rs` (which has no typography
tokens at all), the inline CSS in `crates/frontend/src/templates/**` and
`crates/backend/src/**`'s server-rendered frames, and `e2e/`.
**Found by.** The architect, 2026-11-04, measuring rather than reviewing, after
the owner asked *"are there some points to improve especially for elder people?"*
**Relates to.** RFC 105 (consolidated the colour tokens here), RFC 131 (the
operator surfaces this would also touch), RFC 166 (how a gate's coverage ends up
narrower than its claim).

**On 1.0:** not declared, not scoped, not dated.

---

## 1. What was measured, and the two things that are already right

**Zoom is not blocked.** No `maximum-scale`, no `user-scalable=no` anywhere —
all five `viewport` metas are plain `width=device-width, initial-scale=1`. That
is the single most common elderly-hostile pattern on the web and this project
does not have it. **And a skip-to-content link exists** (15 occurrences). Both
deserve saying before the rest.

## 2. Colour — five token pairs fail WCAG AA for normal text

Computed from `design_tokens.rs`, each semantic token against **its own `-bg`
partner**, which is how badges, flash banners and alert callouts actually
render:

| pair | ratio | normal-text verdict |
|---|---|---|
| **light `--success` `#1f9d55` on `#e8f5e9`** | **3.11** | **fails AA** |
| **light `--warning` `#b76e00` on `#fff7e6`** | **3.76** | **fails AA** |
| light `--danger` `#c92a2a` on `#fdecea` | 4.77 | AA |
| light `--info` `#1864ab` on `#e7f5ff` | 5.48 | AA |
| dark `--success` `#4ade80` on `#14532d` | 5.23 | AA |
| dark `--warning` `#fbbf24` on `#78350f` | 5.43 | AA |
| **dark `--danger` `#f87171` on `#7f1d1d`** | **3.62** | **fails AA** |
| **dark `--info` `#60a5fa` on `#1e3a8a`** | **4.07** | **fails AA** |
| **`--scope-tenant` `#1f9d55` on white** | **3.49** | **fails AA** |

**Five of nine fail AA (4.5:1) for normal-size text, in both themes. Only
`--scope-system` reaches AAA (7:1).**

**AA is the wrong target for this question.** Contrast sensitivity declines with
age; AAA's 7:1 is the level that reflects it, and it is the level a product
whose owner asks specifically about older users should be aiming at. **Today the
status colours do not reliably reach even AA.**

The `--success`/`--warning` failures are the worst in practice: those are the
colours that carry *"saved"*, *"active"*, *"expiring"* — the routine
reassurances a user reads most often and scrutinises least.

## 3. Why the a11y gate is green over this

`e2e/specs/accessibility.spec.ts` runs **axe `wcag2a`/`wcag2aa` and passes**,
20/20, on every push. It passes because **it loads `/` and `/login`** — and
these tokens render in flash banners, badges and callouts on the *admin and
operator* surfaces, which that suite never visits.

**So the gate's green is true and its scope is two pages.** Same shape as
RFC 166's finding one layer out: not a gate that stopped running, but a gate
whose coverage was narrower than the claim a reader takes from it. **A colour
contrast assertion over the token table itself — pure arithmetic, no browser —
would have caught all five, and is the cheapest part of §5.**

## 4. Typography — there is no typographic scale, and the common sizes are 12–13 px

**`design_tokens.rs` contains zero typography tokens.** It is colour-only, so
there is no single source of truth to answer "is the font size right", and
nothing keeps two screens consistent.

What is actually used: **13 distinct font-size values across four units.**
Ranked by frequency:

```
6 x 13px    6 x 12px    6 x 0.8em    6 x 0.85em    4 x 0.75em
3 x 0.9em   2 x 1em     2 x 1.2em    1 x each of 22px, 16px, 15px, 1.5rem, 1.1rem
```

**The most common sizes in this UI are 12px, 13px, and `em` values that compute
to roughly 12–13.6px** on a 16px base — and `em` compounds, so a `0.8em` inside
a `0.85em` block is smaller again. **Twelve declarations sit at or below 13px.**

**And `px` ignores the one setting an older user is most likely to have
changed.** Page zoom scales `px` text, but a browser's *default font size*
preference does not: a user who sets 20px as their default gets no benefit from
any `px`-declared text on these pages. `rem` honours it. That is not a style
preference — it is the difference between the product respecting an accessibility
setting and silently overriding it.

## 5. Interaction targets — the commonest control is about 18 px tall

`min-height` appears **nowhere** in the frontend or the server-rendered frames,
so control height is whatever padding plus line-height produces. The most common
paddings on controls:

```
7 x padding: 2px 8px     4 x padding: 4px 10px     2 x padding: 1px 4px
```

With a 12–13px font, `2px 8px` yields a control roughly **17–19 px tall** —
**under half** the 44×44 CSS px that WCAG 2.5.5 and both major platform
guidelines call a minimum. Some controls are fine (`12px 24px`, `8px 16px`,
`.5rem 1rem`); **the smallest are the most numerous.** Reduced fine-motor
precision is as age-correlated as contrast sensitivity, and this is the axis
where the product is furthest from guidance.

## 6. Direction, ordered by value per unit of change

1. **Fix the five failing colour pairs and add the arithmetic gate.** Pure token
   edits plus a contrast assertion over the token table — **no browser, no
   screens, runs on every push**, and it is the only part that closes a whole
   class rather than a list. **Target AAA (7:1) for text-on-`-bg`, not AA**, per
   §2's reasoning. Small.
2. **Introduce typography tokens and a minimum size.** `--text-sm` upward, in
   `rem`, with a floor — **no body or label text below 1rem**, and the `em`
   chains unwound so nothing compounds. This is the part that touches the most
   files and it is mechanical.
3. **A control-height floor.** `min-height: 2.75rem` (44px) on interactive
   controls, via one shared rule rather than per-template padding.

**Not in this RFC, and the owner should know why.** The first axis of the
question — *what is visible by default, the user flow, whether menu positions
are optimised* — **is not answerable from the stylesheet, and I will not
pretend otherwise.** It needs the real screens driven and a judgement about
information architecture. This project can now do that: Playwright drives the
end-user pages, and 0.92.2's credentialed job can reach the operator surfaces.
**That is its own piece of work with its own RFC**, and sizing it before looking
would repeat the mistake RFC 152 half B and half C each made in their first
draft.

## 7. What this RFC does not claim

- **No user has reported difficulty.** Nobody has deployed this tree; these are
  measurements against published guidance, not field evidence.
- **AA compliance is not claimed to be broken for the pages the gate covers.**
  `/` and `/login` pass axe today and this RFC does not contradict that.
- **"Elderly" is not a separate mode.** Everything in §6 is better for every
  user; the owner's question simply makes the cost of not doing it legible.
