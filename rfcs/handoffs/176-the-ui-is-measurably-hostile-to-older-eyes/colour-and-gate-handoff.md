# Developer Handoff — RFC 176 §6.1: make the colour tokens reach AAA, and gate the arithmetic

**Governing RFC.** [`rfcs/accepted/176-the-ui-is-measurably-hostile-to-older-eyes.md`](../../accepted/176-the-ui-is-measurably-hostile-to-older-eyes.md)
— accepted by the owner 2026-11-04. **§2 is the measurement, §3 is why the
existing a11y gate cannot see it, §6.1 is this cycle.**
**Builds on.** `main` at or after tag `0.92.5` (`eb94a78`).

**Target release.** **Patch — the next cut after 0.92.5.** Number at the cut.
**Trigger: none, argued.** No capability is added: these token pairs fail a
published standard and the change makes them pass. **§6.2 and §6.3 are a minor
and are not in this cycle.**
**Tier.** **P2.** Nothing is broken or exposed.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-04.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Two deliverables, and the gate matters more than the colours

1. **Every semantic pair in `crates/frontend/src/design_tokens.rs` reaches
   AAA (7:1)** against the background it actually renders on.
2. **A contrast check in `scripts/drift-scan.sh`** that recomputes every pair
   from the token source and fails below threshold.

**(2) is the durable half.** (1) is nine values; (2) is what stops the tenth
from arriving. `drift-scan.sh` is the right home — it already carries four
derived checks of this shape (docs coverage, link integrity, the `rfcs/` sweep,
release reconciliation), and this is arithmetic over a file, not a route
property.

## 2. The direction is settled by a constraint, not a preference

I computed the options rather than hand you a target. **Hue and saturation
preserved; only lightness moved.**

**Light mode: the foreground must darken. There is no alternative.**
`--success #1f9d55` and `--warning #b76e00` **cannot reach 7:1 against any
background, including pure white.** Candidates that do, at the existing `-bg`:

| token | now | candidate | ratio |
|---|---|---|---|
| `--success` on `--success-bg #e8f5e9` | `#1f9d55` 3.11 | **`#125d32`** | **7.08** |
| `--warning` on `--warning-bg #fff7e6` | `#b76e00` 3.76 | **`#7a4a00`** | **7.02** |
| `--danger` on `--danger-bg #fdecea` | `#c92a2a` 4.77 | `#9b2020` | 7.01 |
| `--info` on `--info-bg #e7f5ff` | `#1864ab` 5.48 | `#14548f` | 7.02 |
| `--scope-tenant` on white | `#1f9d55` 3.49 | **`#146637`** | **7.03** |

**Dark mode: darken the background and keep the foreground vivid.** Lightening
the foreground to 7:1 turns `--danger` into `#fdcccc` — a pale pink carrying the
word *danger*, which trades contrast for salience. Moving the background
instead preserves both:

| token | now | candidate `-bg` | ratio |
|---|---|---|---|
| `--danger` `#f87171` | bg `#7f1d1d` 3.62 | **`#1c0606`** | **7.04** |
| `--info` `#60a5fa` | bg `#1e3a8a` 4.07 | **`#0b1634`** | **7.01** |
| `--success` `#4ade80` | bg `#14532d` 5.23 | `#0f3d21` | 7.05 |
| `--warning` `#fbbf24` | bg `#78350f` 5.43 | `#5d290c` | 7.04 |

**These are candidates, not instructions.** If a value looks wrong on screen,
move it and say what you moved — **the constraint is the ratio, not my hex.**
But do not lighten a dark-mode foreground to buy contrast without saying why.

## 3. The gate

- **Parse the token values out of `design_tokens.rs` itself**, not a copy. A
  gate reading its own transcription of the thing it checks is the failure mode
  this project keeps finding.
- **Pair each token with the background it renders on.** The `-bg` partner for
  the four semantic tokens, in both the `:root` block and the
  `prefers-color-scheme: dark` override; **white** for the three scope badges.
  If a token has no determinable partner, **fail with its name** rather than
  skipping it — `unclassified` must be 0, the same discipline E4/E6/E7 use.
- **Threshold 7:1**, with the number printed per pair on failure so the fix is
  obvious, and the usual `ℹ️` summary line on success.
- **Use awk, not python3.** No script in this repo uses python3 and introducing
  it adds a CI dependency to a project that pins its tools deliberately
  (RFC 138). **I verified the arithmetic works in awk** and reproduces all three
  spot values exactly (3.11 / 5.48 / 7.67).
- **Parse hex POSIX-ly.** `strtonum()` is a gawk extension and **no script here
  uses one today** — though two 3-arg `match()` calls suggest CI's awk is gawk
  in practice. Use an `index()` lookup over `"0123456789abcdef"` instead; it is
  three lines and removes the question. **If you would rather rely on
  `strtonum`, say so and confirm it against a real CI run — do not assume it.**

## 4. Do not

- **Do not touch typography or control sizing.** §6.2 and §6.3 are a minor and
  are not dispatched.
- **Do not add axe rules or e2e specs.** §3's point is that the browser-based
  gate cannot see these pages; the fix is arithmetic over the token file, not
  more browser coverage.
- **Do not change any template's inline CSS.** The tokens are the single source
  (RFC 105) and the templates consume them.

## 5. Stop conditions

- **A pair cannot reach 7:1** without a change you think is wrong on screen —
  report the pair, the best ratio you reached, and why. **A real trade-off is
  mine to decide, not yours to split.**
- **A token has no determinable background** — report it; do not guess white.
- **The gate cannot read the values from the source file** without duplicating
  them — stop and report, because a duplicated table is worse than no gate.
- Any template needs editing to make a pair pass.

## 6. Baselines at tag `0.92.5` (`eb94a78`), each with its command

- host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,675 passed, 0 failed, 4 ignored, 12 lines**;
- `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
- `bash scripts/route-contracts-check.sh` → 192 routes; E4 `216 = 192 + 24 + 0`; E6 `92 = 83 + 9 + 0`; **E7 `156 = 8 + 31 + 117`**;
- `bash scripts/drift-scan.sh` → clean; docs coverage `80 = 78 + 2 + 0`; docs links `189 = 177 + 6 + 6 + 0`; `rfcs/` sweep **202 checked, 0 broken**;
- `mdbook build docs` → clean, 82 pages;
- `npx playwright test` in `e2e/` → **20**, needs a warm `wrangler dev --port 8787`. **Expect 20 still** — if axe's contrast rule starts failing on `/` or `/login`, a token moved further than it should have;
- `bash scripts/runtime-smoke-check.sh` → passed;
- bundle, `wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15 default** → **888,939 B** (878,238 wasm + 10,701 `shim.js`). **Expect a small move**: the token strings are compiled into the Worker, so changing hex values changes bytes. Report it with the level named.

**Keep the report short.** `CHANGELOG.md` is at 79 KB after 0.88 was archived,
with under 1 KB of headroom, and the entry is mine to write at the cut.
