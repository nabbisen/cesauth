# Developer Handoff — RFC 131, R2a + R5 (foundation import; browser harness)

**Governing RFC.** [`rfcs/accepted/131-mockup-adoption-strategy.md`](../../accepted/131-mockup-adoption-strategy.md)
**Scope.** **R2a and R5 only.** R2b, R3 and R4 are not in this unit — see §3.
**Target release.** 0.82.0 — **and why that level:** **minor.** Neither slice
fixes a defect. R5 introduces a new blocking CI gate, which changes what
"green" means for every future contributor, and R2a adds ~1,400 LOC of new
module surface inside `cesauth-frontend`. Added capability, so minor, and it
carries RFC 132's patch along with it.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing — but R5 has a report-and-stop gate that may end the
slice early, and that is a success condition, not a failure. See §5.

---

## 1. Purpose

Two things that stand on their own. **R2a** brings the mockup's
mechanism-free presentation foundation into `cesauth-frontend`, where R3 will
wire it to data. **R5** gives cesauth browser-level verification, which it has
never had at any point in 120 shipped RFCs: every gate in the project is
build-time, so a screen can compile, be named correctly, be served, and not
work.

R5 is deliberately first. Adopting the harness *before* screens change gives a
baseline to compare against; adopting it after means the first thing it ever
sees is already different.

## 2. Why this matters

RFC 130 shipped a bundle that builds and is correctly named. Whether the app
mounts in a browser is **unverified** — RFC 130 §10 raised it, RFC 127's
criterion 3 was reported unmet on it, and every review since has repeated the
same disclaimer. R5 is the thing that closes it, or proves it is worse than we
think.

## 3. Resolved decisions — do not re-open

**R2 is split; you are doing R2a.** Measuring the foundation before writing
this handoff found a locale mechanism inside it that collides with RFC 132.
The coupling map is in RFC 131 §5 R2. In short: `view_models` (651 LOC, 0/7
files) and `icons` (136 LOC, 0/1) have no i18n coupling; 17 of 19
`components/primitives` have none. The shells, nav and domain components call
`crate::i18n::{Msg, t}` and a Leptos-reactive `LocaleContext`/`use_locale()`,
which cesauth does not have — it resolves locale **per request** through
`cesauth_core::i18n::parse_accept_language` and a plain
`lookup(MessageKey, Locale)`, with 175 `MessageKey` variants against the
mockup's 263.

**R2a = `view_models` + `icons` + the 17 i18n-free primitives. Nothing else.**

**R2b is deferred, not delayed by you.** It needs RFC 132 §13 q1, which the
owner deferred on 2026-09-09 — `components/shells/auth_shell.rs` is a
pre-authentication shell calling `t`, and RFC 132 classifies pre-auth `server`,
where no Leptos reactive context exists. Do not import a second i18n catalog to
get a shell compiling. That is the duplication ADR-013 declined a whole crate
to avoid.

**Do not create a new crate.** Import as **modules inside
`crates/frontend/src/`**, not as `cesauth-ui` reborn under another name. RFC 131
is a *merge, not a port*; a second crate reintroduces the two-library condition
the programme exists to end, and ADR-013's own reasoning against a separate
`cesauth-i18n` crate applies unchanged. `cesauth-ui` is also a name
drift-scan now treats as stale (RFC 126).

**The mockup repository freezes, it does not get archived.** Read-only
reference pinned at **`df3d9d0`, v0.14.0** — the commit this import is taken
from. Record that hash in `DEPENDENCIES.md`. No commits to it; no fixing
anything there instead of here. R3 still needs to read its screens, so
archiving waits (RFC 131 §10 q3).

**Operator console language: Japanese.** Owner ruling 2026-09-09; ADR-013
amended. The mockup's own JA rule is inherited **deliberately** (RFC 131 §10
q4, resolved).

**Leptos pins stay `=0.8.19` / `=0.8.13`.** RFC 130's M2 verified 1.98.1
against them. Do not reconcile to the mockup's pins if they differ — report
the difference instead.

## 4. Facts already measured — do not re-derive

Mockup at `~/Desktop/cesauth/cesauth-mockup-git`, `df3d9d0`, v0.14.0.

| Area | Files using i18n | LOC |
|---|---|---|
| `crates/ui/src/view_models` | 0 / 7 | 651 |
| `crates/ui/src/icons` | 0 / 1 | 136 |
| `crates/ui/src/components/primitives` | 2 / 19 | 747 |
| `crates/ui/src/components/nav` | 1 / 3 | 101 |
| `crates/ui/src/components/domain` | 3 / 5 | 262 |
| `crates/ui/src/components/shells` | 4 / 5 | 341 |

Commands, so the numbers are re-runnable rather than trusted:

```sh
M=~/Desktop/cesauth/cesauth-mockup-git
grep -rlE 'crate::i18n|use_locale|LocaleContext' $M/crates/ui/src/<area>   # coupled files
find $M/crates/ui/src/<area> -name '*.rs' | xargs wc -l | tail -1          # LOC
```

`crates/ui/src/screens/mod.rs` is **6 lines and empty** — there is no screen
inventory to import. That is R3's work, from `mockup-workbench` (9,162 LOC),
not from here.

*If any of this fails to reproduce, that is a finding — report it.*

## 5. R5's report-and-stop gate — read before writing any code

**The harness is not portable as-is. It tests the mockup's route table.**

`e2e/specs/route-smoke.spec.ts` enumerates mockup routes. Checked against
`crates/backend/src/lib.rs`:

| Spec route | In cesauth |
|---|---|
| `/login`, `/accept-invite`, `/me/security` | **exist as `GET`** |
| `/magic-link/request` | exists **`POST`-only** — a GET smoke test fails |
| `/totp/verify`, `/auth/error`, `/me/sessions`, `/me/totp/enroll`, `/me/recovery-codes` | **do not exist.** cesauth uses `/me/security/sessions`, `/me/security/totp/enroll` |

Also: `baseURL` is `http://127.0.0.1:3000`; `wrangler dev` serves **8787**
(`Makefile:148`). And `hydration-smoke.spec.ts` "verifies that SSR output
hydrates" — **cesauth has no SSR and no hydration**; it is CSR-only in
production, which RFC 132 confirms per surface.

**M1 — establish the baseline before adapting anything.** Point Playwright at
`wrangler dev` on 8787 and run **one** spec: a route-smoke rewritten against
cesauth's real routes, checking only that each returns 200 and that
`client`-classified pages produce a **non-empty** root div.

**Stop and report M1's result before touching the other six specs.**

Three outcomes, all of them fine:
1. **Pages mount.** Proceed to §6 R5b. The 120-RFC open question closes.
2. **`client` pages serve an empty root div.** That is the RFC 130 §10 fear
   confirmed. **Stop.** It is a finding of the first order, it is not yours to
   fix, and it changes the whole programme's sequencing — mine to re-scope.
3. **`wrangler dev` cannot serve the bundle locally at all.** Also stop and
   report; do not spend the slice debugging the dev server.

Do not batch through this. RFC 029 was marked Implemented on a measurement
that had stopped being true, and that produced the 4,568-hunk `cargo fmt`
surprise.

## 6. Change scope

| # | Task | Files |
|---|---|---|
| M1 | Baseline: Playwright → `wrangler dev` :8787, one rewritten route-smoke spec | `e2e/` (new) |
| R5a | **Report M1. Stop.** | — |
| R5b | Adapt the portable specs: `accessibility`, `duplicate-ids`, `focus-trap`, `mobile-layout`. Rewrite `route-smoke` against cesauth's route table | `e2e/specs/` |
| R5c | **Drop** `hydration-smoke.spec.ts` — tests a mode cesauth does not have. Say so in the review; do not adapt it into something vacuous | — |
| R5d | **Invert** `devpanel-absent.spec.ts`: assert no `data-workbench-only` element reaches cesauth's output. It becomes an import-safety check | `e2e/specs/` |
| R5e | CI gate, non-blocking on the first landing — see §7 | `.github/workflows/` |
| R2a | Import `view_models`, `icons`, and the 17 i18n-free primitives as modules | `crates/frontend/src/` |
| R2b… | **NOT IN SCOPE.** | — |

Order: **M1 → report → R5b → R5c → R5d → R2a → R5e.**

R2a lands *after* the specs so the baseline is captured on an unchanged
frontend, and R5e — the gate — lands last so it lands green.

## 7. The one deliberate deviation from house rule, and its bound

Every gate in this project lands blocking. **R5e lands non-blocking for one
release**, then flips.

Why, and this is the whole argument: a browser suite's first contact with a
codebase produces flakes that are indistinguishable from findings — timing,
fonts, viewport, animation. Landing it blocking means the first flake either
stops the project or gets silenced with `continue-on-error`, and this project
has a rule against exactly that. One release of observation separates flake
from defect.

**The bound, which is not optional:**
- `continue-on-error: true` is **not** the mechanism. Use a separate
  non-required job so the result is *visible and recorded*, never swallowed.
- The workflow carries a dated comment naming the release that flips it.
- Flipping it to blocking is an acceptance criterion of the **next** slice, and
  I will check it. A non-blocking gate that stays non-blocking is decoration.

If you think it should land blocking immediately, say so in the review with
your flake data. I would rather be argued out of this with evidence.

## 8. Explicit non-change scope

- **No mock fixtures, at any intermediate step, however briefly.** RFC 131 §5
  R4's rule, and the owner's instruction verbatim: *"Don't take the actual
  security risk into the production codebase."* `view_models`, `icons` and
  the i18n-free primitives take props; they carry no fixtures. If a file you
  are importing contains sample data, **leave it and report it**.
- No screens. `screens/mod.rs` is empty; `mockup-workbench` is R3.
- No second i18n catalog. No `LocaleContext`. No shells, nav, or domain
  components.
- No `format!` template deletions — that is R4, and pre-auth templates are
  **kept** (RFC 132 classifies them `server`; they are why a user without JS
  can authenticate).
- No `render_context.rs` deletion — R4.
- Do not touch `/` or `/login`. R3, and it needs RFC 132 §13 q1.
- No new backend route. RFC 131 §6: if a component needs data no endpoint
  provides, that is a finding, not a licence.
- No Leptos version changes. No `cargo fmt`. No route-string changes.

## 9. Task detail worth stating explicitly

**R2a — the import is a rename-and-reparent, and the compiler is the check.**
Move the files, rewrite `crate::` paths to their new module positions, and let
`cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown`
find what you missed. **If a file you expected to be i18n-free turns out not to
be, do not import it** — add it to R2b's list and report. §4's coupling map is
a measurement, not a promise about every line.

**Silent-failure risk.** An imported component that compiles but is never
referenced is invisible until R3. Assert reachability mechanically (§10) rather
than assuming the module tree is wired.

**R5 — Playwright browser downloads.** This brings a new binary-download step
into CI. C1-130 required SHA-256 verification of the Binaryen download for
exactly this reason; be consistent. Pin `@playwright/test` and
`axe-playwright` to exact versions, commit the lockfile, and use Playwright's
own pinned browser revisions rather than "latest." If verifying the browser
download turns out to need more than that, **report it** — I would rather have
the question than an unverified download.

## 10. Assert the machine-checkable parts mechanically

```sh
# 1. no mock fixture reached the tree
grep -rniE 'doNotUse|example\.test|mock_|fixture|acme\.example' crates/frontend/src \
  && echo "REVIEW EACH HIT" || echo "clean"

# 2. every imported module is reachable from the crate root
cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown 2>&1 \
  | grep -E 'never used|unused' || echo "no dead imports"

# 3. no workbench-only markup reached the output (R5d's static twin)
grep -rn 'data-workbench-only' crates/frontend/src || echo "clean"

# 4. the stale crate name did not come along
grep -rn 'cesauth-ui\|cesauth_ui' crates/ docs/ || echo "clean"

# 5. LOC actually imported — state the number with this command, not from §4
find crates/frontend/src/{view_models,icons} -name '*.rs' | xargs wc -l | tail -1
```

Attach all five. #1 and #4 are the ones that matter most: #1 is the owner's
explicit constraint, and #4 is a drift-scan rule that will fail the build
anyway — better to find it here.

## 11. Required tests and evidence

```sh
cargo test -p cesauth-core -p cesauth-adapter-test \
           -p cesauth-migrate-test -p cesauth-frontend > evidence/cargo-test.log 2>&1
cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown > evidence/csr-check.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > evidence/wasm32-check.log 2>&1
cargo clippy -p cesauth-core -p cesauth-adapter-test -p cesauth-migrate-test \
             -p cesauth-frontend --all-targets -- -D clippy::correctness > evidence/cargo-clippy.log 2>&1
cargo deny check   > evidence/cargo-deny.log 2>&1
cargo audit        > evidence/cargo-audit.log 2>&1
bash scripts/route-contracts-check.sh > evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh            > evidence/drift-scan.log 2>&1
mdbook build docs                     > evidence/mdbook.log 2>&1
make build-frontend                   > evidence/make-build-frontend.log 2>&1
cd e2e && npx playwright test          > ../evidence/playwright.log 2>&1; cd ..
```

Expected: **1,233 passed, 0 failed** *plus* whatever `view_models` brings —
state the new total with the command, and if it is unchanged at 1,233 that is
itself a finding, because 651 LOC of view-models arriving with no tests is
worth knowing.

`make build-frontend` **will** change the bundle size — R2a adds modules. Record
what it measures with its command; do not compare against 751,711 or 751,714 as
if either were an invariant (RFC 133 §2.1).

Plus:

- **M1's result, stated plainly**, and before anything else.
- The five §10 assertions.
- **R5e fires:** break one spec's expectation → the non-required job reports
  red and is *visible in the run*; restore → green. A non-blocking gate still
  has to be shown to detect something, or it is theatre.

**Evidence policy.** Redirected output only. A hand-written summary line is
rejected: the v0.81.0 bundle shipped an 80-byte prose `cargo-fmt.log` asserting
a clean run no stable `rustfmt` could produce. **Counts in prose are
measurements** — attach the command for every number you state.

## 12. What must NOT be claimed

- That the frontend is verified in a browser. After this, **some** pages have
  smoke coverage under `wrangler dev` on one browser engine. That is enormously
  more than none and it is not the same as verified.
- That R2a changed anything a user can see. It imports dormant modules. No
  screen looks different; nothing is wired. If a screen *does* change, that is
  a bug, not progress.
- That the mockup is adopted. R2a is roughly 1,400 of the mockup's ~12,600 LOC,
  and none of its screens.

## 13. Prohibited shortcuts

- No committed mock fixtures, transiently or otherwise.
- No `continue-on-error: true` — §7's non-blocking job is a *visible*
  non-required job, which is a different thing.
- No `#[allow(...)]` or feature gate to hide an import error rather than fix it.
- No importing a shell "just to see if it compiles."
- No second i18n catalog.
- No `cargo fmt`.

## 14. Acceptance criteria

From RFC 131 §9, **only** items in this scope:

- **Item 2** — foundation imported under a non-colliding name, drift-scan
  clean. *Scoped to R2a.* Checked hardest, via §10 #4.
- **Item 5** — Playwright suite in CI, demonstrated to fire. *Amended by §7:*
  non-blocking for one release, with the flip as the next slice's criterion.
- **Item 6** — no `doNotUse` / `example.test` markers outside tests, gated.
  Checked hardest, via §10 #1 — this is the owner's constraint.
- **Item 7** — full gate set green.

Not in scope: items 1 (superseded by RFC 132), 3, 4, 8.

**Expected to be unmet, declared in advance:** nothing here demonstrates a
screen *works*, only that pages respond and mount. RFC 127's criterion 3 was
correctly reported unmet rather than quietly relaxed; that is the standard.

## 15. Known risks

| Risk | Mitigation |
|---|---|
| M1 reveals `client` pages do not mount | That is outcome 2 in §5 — stop and report. It is the most valuable thing this slice could produce |
| The import drags in i18n through a path §4 did not sample | §9: do not import it; add to R2b and report |
| A mock fixture rides along | §10 #1, and it is the owner's stated line |
| Playwright flake reads as defect | §7's one-release observation window, bounded |
| The non-blocking gate stays non-blocking | Flipping it is the next slice's acceptance criterion, and I will check |
| Bundle grows and looks like a regression | Expected; record with the command, cite RFC 133 §2.1 |

**If the work turns out materially larger than scoped, stop and report.**
Re-scoping is mine, not yours — and given §5, an early stop here is a good
outcome rather than a failed slice.

## 16. Review request

Write the package to `.git-exclude/review-request/`. It must include:

M1's result first · implementation summary · changed files · any deviation
from §6 · every log from §11 · all five §10 assertions · R5e's
fires/does-not-fire pair · the specs dropped or inverted, with reasons ·
anything added to R2b's list · the measured bundle figure and test total, each
with its command · what remains unverified (§12) · requested review focus.

Report the path only.
