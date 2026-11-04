# Developer Handoff — RFC 176 §6.1b: the end-user pages never got the fix

**Governing RFC.** [`rfcs/accepted/176-the-ui-is-measurably-hostile-to-older-eyes.md`](../../accepted/176-the-ui-is-measurably-hostile-to-older-eyes.md)
**Review.** `.git-exclude/reviewed/176-177-review.md` — **§1 and §2 are this
cycle's whole reason.**
**Builds on.** `be285c8` on `main`. **Nothing is reverted.**

**Target release.** **Patch — the same cut as `9b7dadd` + `be285c8`.** **The cut
is held for this**, because a release entry claiming the colour tokens reach AAA
would be false for every page a user visits.
**Tier.** **P2.** Same as RFC 176.
**Trigger: none** — the same fix, on the file that was wrongly scoped out.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-04.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. You flagged this and you were right; the scoping error was mine

`crates/frontend/src/templates/chrome.rs` carries its own copy of the four
semantic tokens at lines 27-34 (and the dark override from 46), **with the
pre-fix values**. It is consumed by `login.rs`, `security_center.rs` and
`totp.rs` — the end-user surfaces. `design_tokens.rs`, which you fixed, is
consumed only by the three admin frames.

Measured after `9b7dadd`:

```
operator surfaces:  success 7.08  warning 7.02  danger 7.01  info 7.02
end-user surfaces:  success 3.11  warning 3.76  danger 4.77  info 5.48
                            fails AA   fails AA
```

**My §6.1 handoff said "do not change any template's inline CSS", which excluded
by name the file carrying the half the owner asked about.** You reported instead
of widening, which is the standing rule and was the right call. This cycle
removes the instruction.

## 2. What to do

1. **Bring `chrome.rs`'s four semantic pairs to AAA**, light and dark, using the
   same method `9b7dadd` used — hue and saturation preserved, light mode moving
   the foreground, dark mode moving the background. **The values in
   `design_tokens.rs` are already computed and already reviewed**; if the same
   values are right here, use them and say so. If a pair renders differently in
   `chrome.rs`'s own context and wants a different number, **say which and
   why**.
2. **Widen the contrast gate to both files.** It must parse **`chrome.rs` as
   well as `design_tokens.rs`**, each against the background each token actually
   renders on, with the same `scanned = checked + declared_out + unclassified`
   arithmetic and `unclassified = 0`. **A gate over one of two token files is
   what let this through** — that is §2 of the review, and it is the durable
   half of this cycle just as it was of the last one.
3. **Report the new counts.** Today's line reads `14 = 11 + 3 + 0`.

## 3. The thing to decide and tell me, not to fix

**Two files define the same four tokens.** That is the actual defect behind both
cycles, and `design_tokens.rs`'s own module doc already acknowledges the split.
**Do not consolidate them here** — merging the end-user and admin token sources
changes what every page renders and is its own sized piece of work.

**But tell me what you find**: are the two copies meant to diverge (different
surfaces, different palettes) or is the duplication accidental? **Your reading,
with whatever the code shows.** That answer decides whether the follow-up is a
consolidation or a second gate entry, and I would rather have it from someone
who has just read both files.

## 4. Do not

- **No typography, no control sizing.** RFC 176 §6.2/§6.3 are a minor.
- **No `/login` reordering.** RFC 177 §4.4 is still open with the owner.
- **Do not touch the scope-badge dark-mode exclusion.** Your reasoning for
  declaring it out is accepted as written.
- **Do not consolidate the two token files** (§3).

## 5. Stop conditions

- **A `chrome.rs` pair cannot reach 7:1** without a value you think is wrong on
  screen — report the pair and the best ratio reached. A real trade-off is mine.
- **The gate cannot parse both files** without duplicating a table — stop; a
  duplicated table is worse than a narrow gate, and we already know what a
  narrow gate costs.
- **axe starts failing on `/` or `/login`.** It passes today over the *old*
  values; if raising contrast breaks a different axe rule, that is worth
  knowing before it ships.
- Any page's rendered text changes size or position. This cycle changes colour.

## 6. Baselines at `be285c8`

- host tests **1,675 / 0 / 4 / 12 lines**; `migration_chain` **35**;
- `route-contracts-check.sh` → 192 routes, **E7 `156 = 8 + 31 + 117`**, unchanged;
- `drift-scan.sh` → clean, including `colour contrast: scanned 14 -- 11 checked, 3 declared out, 0 unclassified -- 0 below threshold`;
- `mdbook build docs` → clean, 82 pages;
- `npx playwright test` in `e2e/` → **20**, warm server. **Expect 20 still** — and see §5;
- `runtime-smoke-check.sh` → passed;
- Worker bundle, gzip 1.15 default → **889,002 B**. **Expect it unchanged**: `chrome.rs` is CSR-only and does not compile into the Worker. **The artifact that will move is `crates/frontend/dist/assets/cesauth-frontend_bg.wasm`, 317,718 B gzip today** — report that one, and note that no gate currently budgets it (queued separately, not yours).
