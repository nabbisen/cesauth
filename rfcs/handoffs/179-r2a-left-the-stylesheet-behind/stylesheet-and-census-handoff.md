# RFC 179 — the import R2a left behind, and a census the import cannot satisfy vacuously

**Governing RFC.** [`rfcs/accepted/179-r2a-left-the-stylesheet-behind.md`](../../accepted/179-r2a-left-the-stylesheet-behind.md)
— **read §5, §6 and §6.1 before writing any code.** §6.1 is a refinement made
while writing this handoff and it changes the gate's polarity.

**Builds on.** `dc00a89` on `main` (tag `0.92.6` is `046ce28`). Nothing is
reverted.

**Target release.** **Patch — the next cut.** Number assigned at the cut.
**§4 and §5 ship together in one cycle**; §5 is not a follow-up. See §2 below
for why splitting them is worse than not starting.

**Tier.** **P2.** Six elements authored invisible render visible; one is an
operator's CSRF token. Not exploitable — see RFC 179 §2.3 and do not upgrade it.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-07.**

**On 1.0:** not declared, not scoped, not dated. Nothing here is a 1.0
requirement.

---

## 1. What this is, in one line

**Copy nine lines of CSS that already exist, then make sure copying them does
not silence the gate that found the gap.**

## 2. Why §4 and §5 are one cycle and not two

RFC 178's gate asserts `ruleCount > 0`. **A stylesheet containing only
`.sr-only` satisfies it.** So landing §4 alone would:

1. make both `KNOWN_NO_STYLESHEET` entries stale — the spec **fails** by its
   own §4b staleness rule, correctly;
2. force you to delete them, which flips the gate to **passing**;
3. leave **83 of 84** class names with no rule and **nothing reporting it**.

That is strictly worse than today, where the gap prints an `ℹ️` line on every
run. **If you can only do one half, do neither and say so** — §7.

## 3. §4 — the import

### 3.1 Where the rule comes from

`crates/ui/assets/base.css` lines **86-94** in the mockup repository at pin
**`df3d9d0`** (v0.14.0) — the same commit RFC 131 R2a imported the components
from in 0.82.0. On this machine that repository is at
`/home/nabbisen/Desktop/cesauth/cesauth-mockup-git`.

**Verbatim, 180 bytes, `sha256 42b849b2965687a22595f987b30253de3327b49663caeac895d08cfb4e722695`:**

```css
.sr-only {
  position: absolute !important;
  width: 1px; height: 1px;
  padding: 0; margin: -1px;
  overflow: hidden;
  clip: rect(0,0,0,0);
  white-space: nowrap;
  border: 0;
}
```

**Verify the provenance rather than trusting this block**: `sed -n '86,94p'`
over that file, piped to `sha256sum`, must give the hash above. If it does not,
**stop and report** — the pin moved, which is a finding, not a merge conflict to
resolve.

**Do not reformat it, do not "improve" it, do not drop `!important`.** The
`!important` is load-bearing: these elements carry other classes, and a later
`components.css` import must not be able to un-hide them.

### 3.2 Where it goes

- **New file `crates/frontend/static/base.css`**, holding that rule and a short
  header comment naming the source file, the pin and the governing RFC.
- Name it **`base.css`**, matching the mockup, so §8's later import of
  `tokens.css` / `components.css` / `screens.css` is additive rather than a
  rename.
- `Makefile:204` already copies `crates/frontend/static/*` into
  `crates/frontend/dist/assets/`, which Workers Static Assets serves at
  `/assets/`. **No Makefile change, no `wrangler.toml` change, no Trunk
  change.** `webauthn.js` reaches the browser by this exact path today.
- **One line** in `leptos_html_shell`'s `format!`
  (`crates/backend/src/routes/leptos_shell.rs`, in `<head>` beside the existing
  `<link rel="preload">`):
  `<link rel="stylesheet" href="/assets/base.css"/>`

**CSP needs no change.** `core/src/security_headers.rs:158` already declares
`style-src 'self'` with no `'unsafe-inline'`, so a same-origin stylesheet is
already permitted and an inline `<style>` is already forbidden. **Confirm the
rendered response still carries the unchanged CSP header** — do not take my word
for it, and do not add a `style-src` nonce.

### 3.3 Dev parity, and a measurement I could not make

`crates/frontend/index.html` is Trunk's **dev-only** shell (`trunk serve`);
production is `leptos_shell.rs`. Dev parity there is **optional and
lower-priority than not breaking the build.**

**I could not test any of this locally: `trunk` is not installed on this
machine, so `make build-frontend` cannot run here.** Every Trunk-side claim in
this handoff is read from `Makefile` and `index.html`, not executed. **You must
run `make build-frontend` and confirm the file lands at
`crates/frontend/dist/assets/base.css`.** If it does not, that is the finding
and the whole §3.2 serving story needs re-deriving — report it rather than
patching around it.

## 4. §5/§6 — the census gate

Replace `stylesheet-presence.spec.ts`'s single `ruleCount > 0` assertion.
**Read RFC 179 §6.1 first: declare the *styled* set, not the exempt one.**

### 4.1 The shape

- **Denominator**: distinct class names used by the CSR markup, derived from
  source **every run, no committed data file** — same discipline as E7 and the
  colour-contrast gate.
- **A dated declaration** names the selectors the stylesheet is expected to
  cover. After §4 that is **one entry, `sr-only`**, citing this RFC.
- **Not-yet-styled is computed as the remainder** and never written down. One
  dated exemption block covers it with its reason (RFC 179 §8's import).
- **Prints its census on every run**, with a live numerator:
  `96 = 1 declared-and-matching + 95 not-yet-styled + 0 unclassified`.
  **96, not 84** — RFC 179 §10.1 corrects its own figure. 84 is what a literal
  `class="…"` grep sees; resolving §4.2's computed sites adds 12 more.
- **Staleness, pointing outward**: a class with a matching rule that is **not**
  in the declared set **fails**, naming itself. A stylesheet cannot grow past
  what has been reviewed.
- `unclassified` must be **0**.

### 4.2 The nine sites a literal grep misses — do not skip these

`grep -rn 'class=[^"]'` over `pages/` and `components/` finds **9** sites that
compute their class in Rust. A census built only on `class="…"` would silently
omit them, and reporting a clean number while omitting them is the failure mode
this gate exists to prevent.

| shape | example | treatment |
|---|---|---|
| `match` over `&'static str` | `primitives/alert.rs:17` `fn class()`, 4 arms | **resolve the arms** — they are literals |
| inline `if` with literal branches | `entity_list.rs:70`, `scope_breadcrumb.rs:36`, `density_toggle.rs:17` | **resolve both branches** |
| `format!` over a caller-supplied prop | `badge.rs:13` `format!("badge {}", class)`; `metric_strip.rs:40` | **declare out by name, dated, with the reason** |

The last two are **not statically enumerable** — the suffix comes from callers.
`badge.rs`'s doc comment lists an intended set; **a doc comment is not a
constraint and must not be treated as the vocabulary.** Declaring them out is
correct and is the honest answer; inventing a resolution for them is not.

### 4.3 The workflow step

`.github/workflows/trunk-release-build.yml`'s stylesheet-presence step carries
a commented `exit 1` with a note saying to restore it the day a stylesheet
exists. **That day is this cycle. Restore it** — with a stylesheet present, a
`MISSING` result is a real regression again.

## 4.4 Three traps I fell into writing this. Each one produced a confident wrong number.

Read these before you write the matcher, not after.

**1. The denominator was wrong in the RFC I am handing you.** RFC 179 said 84.
It is **96**. 84 is the literal-grep figure; §4.2's computed sites contribute 12
names no literal grep can see. **The RFC that warns about matcher blind spots
shipped with one.** If your number is 84, you have reproduced my mistake, not
validated it.

**2. There is a third attribute form.** The server-rendered directories write
`class=\"…\"` **escaped inside `format!` strings** — 31 sites across `admin/`,
`tenant_admin/`, `tenancy_console/` and `templates/`. `class="[^"]*"` cannot
match it. **In scope (`pages/`, `components/`) there are zero such sites and I
verified that** — but check it yourself, and if your gate is ever pointed at the
other directories it must handle all three forms or it will under-report
silently.

**3. `comm` lies on locale-sorted input.** Comparing used-vs-defined with
`sort` under the ambient locale gave me **15/60**; under `LC_ALL=C` the truth is
**17/58**. Both partitions summed to the same total, so **the sum reconciling is
not validation**. Use `LC_ALL=C sort` for every set operation in this gate and
say in your report that you did.

**And the general rule, since it is three-for-three here:** a census number is
only as good as its matcher's vocabulary. State the matcher beside the number,
and when you find a form it misses, **sweep every grep over that same input** —
not just the one that failed.

## 5. Do not

- **Do not write a stylesheet.** Nine lines, imported. No typography, no
  colour, no spacing, no layout, no tokens.
- **Do not touch `templates/chrome.rs` or its 209-line `BASE_CSS`.** The
  consolidation question is RFC 179 §8's and it is a separate RFC.
- **Do not import `tokens.css`, `components.css` or `screens.css`.** They are
  §8's, and importing them here would make this a different release at a
  different level with an unresolved token-ownership question underneath.
- **Do not bring in RFC 176 §6.2/§6.3** (rem typography, 44 px control floor).
  Still a separate minor.
- **Do not add a `style-src` nonce or any CSP change.**
- **Do not reduce the gate to "skip when unstyled".** A skip is silent; §4.1's
  census reports.
- **Do not hand-list 95 exempt names.** RFC 179 §6.1 — wrong polarity.
- **Do not touch the server-rendered half.** RFC 179 §8.1: `admin/`,
  `tenancy_console/`, `tenant_admin/` and `templates/` use **75** distinct class
  names of which **58 have no rule anywhere**. Real, measured, and **its own
  ROADMAP row** — pulling it in here would turn a nine-line import into a
  three-stylesheet consolidation.
- **Do not rename `sr-only` to `visually-hidden` or vice versa.** RFC 179 §8.2:
  `BASE_CSS` already defines `.visually-hidden` with the **same rule** at
  `templates/chrome.rs:184-192`, and the server templates use it successfully.
  Converging the two names is a §8 deliverable, not this cycle's — but **neither
  rule may be changed without the other**, so if you touch one, stop and report.
- **Do not change any route, wire format, schema, cookie or permission slug.**

## 6. Evidence required

1. `sha256sum` of the imported range matching §3.1, and of the new file.
2. **The six elements verified invisible in a browser**, not inferred from the
   rule being present. RFC 179 §9.2. The browser suite is anonymous-only
   (`PUBLIC_ROUTES = ['/', '/login']`), so `login.rs:114` is reachable there and
   **the other five are not** — say which you drove how. If you can only reach
   one, say so plainly; a partial result stated is worth more than a complete
   one implied.
3. The census number **and its arithmetic reconciled**, with the command.
4. **Both directions on staleness**: forced to fail, and passing unforced —
   RFC 178 §4b's report is the model.
5. `make build-frontend` output showing `dist/assets/base.css`.
6. The unchanged CSP header on a real response.
7. Host tests, `migration_chain`, `route-contracts-check.sh`, `drift-scan.sh`,
   `mdbook`, Playwright — each with its command and count.
8. **Both bundles**, with `sha256sum` **and the gzip level stated** (default,
   not `-9` — a 4,221 B difference, RFC 133 §16). The frontend asset will grow;
   that is expected and is the first time a stylesheet is in it.

## 7. Stop conditions — report instead of improvising

- The `sha256` in §3.1 does not match: the pin moved.
- `make build-frontend` does not place the file in `dist/assets/`.
- The CSP blocks the stylesheet anyway: then `style-src 'self'` is not doing
  what `security_headers.rs:158` says and that is a bigger finding than this
  RFC.
- The census cannot reach `0 unclassified` without a rule you would have to
  invent: **stop.** Naming a tenth site you cannot resolve is a correct outcome;
  a number that hides it is not.
- Any of the six elements is still visible after the import.

## 8. Baselines at `dc00a89`, each with its command

| | value | command |
|---|---|---|
| `sr-only` sites | **6**, 5 files | `grep -rn "sr-only" crates/frontend/src/` |
| `.sr-only` rules | **0** | `grep -rn "\.sr-only" .` (excl. `target/`) |
| `.css` files | **0** | `find . -name "*.css"` (excl. `target/`, `docs/book`, `node_modules`, `dist/`) |
| distinct class names, literal only | **84** | `grep -rho 'class="[^"]*"' crates/frontend/src/pages crates/frontend/src/components \| sed 's/class="//;s/"$//' \| tr ' ' '\n' \| grep -v '^$' \| sort -u \| wc -l` |
| distinct class names, **true denominator** | **96** | the above ∪ §4.2's resolved values; the 12 additions are listed in RFC 179 §10.1 |
| computed `class=` sites | **9** | `grep -rn 'class=[^"]' crates/frontend/src/pages crates/frontend/src/components` |
| escaped `class=\"…\"` sites in scope | **0** | `grep -rn 'class=\\"' crates/frontend/src/pages crates/frontend/src/components` — **verify this is still 0**; §4.4 |
| Playwright | **22 passed** | `npx playwright test` |
| host tests | **1,675 / 0 / 4**, 12 result lines | the canonical five-crate command with `--features cesauth-frontend/csr`; **sum with awk over the full output, never by hand** |
| `migration_chain` | **35** | `cargo test -p cesauth-migrate-test` |
| `route-contracts-check.sh` | clean; E7 `156 = 8 + 31 + 117` | `./scripts/route-contracts-check.sh` |
| `drift-scan.sh` | clean; colour contrast `22 = 19 + 3 + 0` | `./scripts/drift-scan.sh` |
| `mdbook` | **82 pages** | `mdbook build docs` |
| Worker bundle | **888,972 B** gzip-default (878,272 wasm + 10,700 `shim.js`) | `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/` |
| frontend asset | **317,718 B** gzip — **dev team's figure, never verified by the architect** (no `trunk` locally) | `make build-frontend` |

## 9. The 84 literal names — a baseline to reconcile against, NOT the denominator (96)

```
alert alert-body alert-icon alert-text alert-title alert-warning b32-secret
badge badge-current badge-danger badge-ok badge-primary badge-warn btn
btn-danger btn-danger-small btn-ghost btn-passkey btn-primary btn-sm
card-title confirm-panel crumb danger-zone density-toggle dialog
dialog-backdrop disclosure disclosure-body disclosure-chevron
disclosure-summary empty empty-state empty-state-inline entity-card
entity-card-label entity-card-line entity-card-value entity-table
error-summary error-summary-list error-summary-title error-terminal field
field-hint field-input field-label field-required flash form-error hint
impact login-card login-page metric-chip-label metric-chip-value
metric-strip muted page-actions page-description page-h1 page-header
page-header-text qr-container row row-between scope-breadcrumb
secret-reveal-panel security-center security-status sep sessions-page
sr-only stat-grid status-ok status-warn step-num steps tab table-wrap tabs
text-muted text-small warning-box
```

**This list is 84 literal names and is deliberately NOT the denominator.** The
true denominator is **96**: these 84 plus the 12 that only appear once §4.2's
computed sites are resolved — `alert-info`, `alert-success`, `alert-danger`,
`step`, `step-done`, `step-current`, `col-secondary`, `crumb-current`,
`density-btn`, `active`, `metric-chip`, `metric-chip-link`. Derive yours from
source and reconcile against **96**. **If you get 84, you have reproduced the
error RFC 179 §10.1 corrects** — this list was produced by the very grep that
misses them, and is printed here so you can see the gap rather than inherit it.

**Keep the report short.** `CHANGELOG.md` has 17,625 B of headroom; the detail
belongs here and in `.git-exclude/reviewed/`, not in the release notes.
