# Developer Handoff — RFC 138, CI gate-set parity

**Governing RFC.** [`rfcs/accepted/138-ci-gate-set-parity.md`](../../accepted/138-ci-gate-set-parity.md) — read **§11** first. Two of its five items were inert as originally written.
**Target release.** The next release window. **Level: patch** — every item
closes a gap between what is claimed and what runs. **Independent of RFC 137**:
neither waits for the other; whichever is reviewed first ships first.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. Three report-and-stop measurements (§5).

---

## 1. Purpose

After this, the gate set the handoffs describe and the gate set CI runs are the
same set — or each difference is recorded as deliberate — and the tools CI
installs to run gates are pinned, with a gate checking the pins.

## 2. Why this matters

- **`mdbook build docs` has never run in CI, and as configured it cannot fail**
  on a broken chapter link: mdbook creates the missing file and exits 0 (§11.6).
- **wrangler** — the deploy tool, and the one that governs the Static Assets
  defaults behind RFC 131 C1-131's `/`-shadowing finding — **resolves the latest
  release on every CI run, at four sites**, and moved 4.131.1 → 4.131.2 in three
  days (§11.4).

## 3. Resolved decisions — do not re-open

All ruled in RFC 138 §11, with evidence.

- **mdbook lands blocking, with `[build] create-missing = false`** (§11.6, §11.7).
- **A root `package.json` pins wrangler** (§11.7) — and it pins nothing unless a
  root `npm ci` runs first in the same job (§11.3).
- **`wrangler-action` gets `wranglerVersion` explicitly**; do not rely on its
  detection (§11.3).
- **drift-scan reads workflows**: `.github/workflows` into `SCAN_PATHS`, `*.yml`
  into the includes (§11.5). Verified zero hits for the existing patterns.
- **The Trunk rule** is `install trunk( --locked)?\s*$` (§11.5, verified).
- **The wrangler guard** checks root `package.json` for an inexact version — it
  does **not** ban `npx wrangler`, which is correct once a lockfile exists
  (§11.5).
- **The Actions convention** is §11.8: major tag for orchestration actions,
  exact version for tool-installing gate actions.

## 4. Facts already measured — do not re-derive

| Fact | Where |
|---|---|
| mdbook: default creates missing chapters, exit 0 | RFC 138 §11.6 table |
| mdbook v0.5.4 locally; no preprocessors in `book.toml` | §11.6 |
| `npx wrangler` sites | `worker-build.yml:75`; `browser-tests.yml:97` (repo root); `scripts/runtime-smoke-check.sh:55` |
| `wrangler-action` without a version | `bundle-size.yml:34` |
| No root `npm ci` anywhere | `worker-build.yml` has none; `browser-tests.yml:81-82` runs it in `e2e/` only |
| Local wrangler is a bun global | `~/.bun/bin/wrangler` |
| Actions inventory | §11.1, with its command |
| Extending drift-scan to workflows: 0 hits | §11.5 |

*If any of this fails to reproduce, that is a finding — report it.*

## 5. Report-and-stop measurements

**M1 — the wrangler version to pin.** From a root `npm install wrangler`, not the
bun global: `node_modules/.bin/wrangler --version`. **Report it before pinning.**

**M2 — can drift-scan read root `package.json` without reading lockfiles?**
Add root `package.json` as a scanned file with a JSON include, lockfiles excluded,
and run every existing pattern. **If anything new fires, report it** before
adding the wrangler rule.

**M3 — the exact versions for the two tool-installing actions.** Resolve what
`EmbarkStudios/cargo-deny-action@v2` and `cloudflare/wrangler-action@v3` currently
point at (`git ls-remote --tags <repo>`). **Report the versions chosen and how you
determined them.**

## 6. Change scope

| # | Task | Files |
|---|---|---|
| D1 | `[build] create-missing = false`; a new blocking `docs.yml` running `mdbook build docs`, installing `cargo install mdbook --version 0.5.4 --locked`; a pin row | `docs/book.toml`, `.github/workflows/docs.yml`, `DEPENDENCIES.md` |
| D2 | Root `package.json` (`private`, `wrangler` exact, per M1) with its `package-lock.json` committed; root `node_modules/` ignored; `setup-node` + root `npm ci` before **every** `npx wrangler` — both `worker-build.yml` jobs and `browser-tests.yml`; `wranglerVersion` on `wrangler-action`; a pin row | root, `.gitignore`, three workflows, `DEPENDENCIES.md` |
| D3 | drift-scan reads `.github/workflows/*.yml`; the Trunk rule; the wrangler exact-pin rule (per M2) | `scripts/drift-scan.sh` |
| D4 | State the §11.8 convention; move `cargo-deny-action` and `wrangler-action` to exact versions (per M3) | `contributing.md`, two workflows |
| D5 | The parity table beside the gate list | `contributing.md` |

**Order:** M1 → D2 · D1 · M2 → D3 (after D1 and D2, so it lands green) · M3 → D4
· D5 last.

## 7. Explicit non-change scope

- No new gates beyond mdbook; no change to any gate's meaning.
- Not RFC 137 or RFC 139.
- Not flipping `browser-tests.yml` to blocking — that is 0.84.0's criterion.
- No SHA-pinning of Actions (RFC 138 §4).
- Not `cargo-fuzz`, not Node's own version (§11.9).
- No `cargo fmt`. No route strings.

## 8. The traps

**8.1 The docs gate that cannot fail.** Without `create-missing = false`, your
fires test passes vacuously and creates a stub file. The fires test must show a
**non-zero exit and no file created**.

**8.2 A lockfile that pins nothing.** A root `package-lock.json` does nothing for
a job that never runs a root `npm ci`. Every `npx wrangler` needs one earlier
**in the same job, at the root**. §9 asks you to show each.

**8.3 Measuring the wrong binary.** On a developer machine `npx wrangler`
resolves a bun global. Measure from a root install (M1).

**8.4 A workflow rule nobody reads.** The Trunk rule is inert unless drift-scan
reads `.github/workflows/*.yml`. The fires test must plant in a **workflow
file** — planting anywhere else proves nothing about workflows.

**8.5 Lockfiles in the scan.** They are large, full of version strings, and not
authored text. Never scan them (M2).

**8.6 Interference.** If a root `package.json` disturbs `crates/frontend`'s Trunk
build or `e2e/`'s install, **stop and report** — that is a layout question.

## 9. Mechanical assertions

```sh
grep -n 'create-missing' docs/book.toml                        # = false
grep -rln 'mdbook build' .github/workflows/                    # docs.yml present
grep -rhoE 'uses: [^ ]+' .github/workflows/*.yml | sort | uniq -c   # matches §11.8
grep -n 'wranglerVersion' .github/workflows/bundle-size.yml
npm ci && node_modules/.bin/wrangler --version                 # == the pin
# for each workflow: every `npx wrangler` preceded in its job by a root `npm ci`
grep -nE 'npm ci|npx wrangler|^  [a-z-]+:|working-directory' .github/workflows/{worker-build,browser-tests}.yml
```

## 10. Required tests and evidence

**Fires/does-not-fire, each both halves:**

1. **D1:** a `SUMMARY.md` entry to a missing chapter → the docs gate fails,
   **no file created**; restore → green.
2. **D3 Trunk rule:** remove `--version 0.21.14` from one workflow install →
   drift-scan red; restore → green.
3. **D3 wrangler rule:** change root `package.json`'s wrangler to `^<version>` →
   red; restore → green.

**Full gate set — you run it** and send it, per `contributing.md`. I re-run
drift-scan, mdbook with the new config, and the root `npm ci` version check.

**No YAML validator is available locally.** Say so rather than implying the
workflow edits were validated; GitHub's first run is the evidence, as it was for
RFC 131 R5 and C1-R5.

## 11. What must NOT be claimed

- **Not that these gates pass in CI.** None has executed there.
- Not that Node is pinned (§11.9).
- Not that every tool CI uses is pinned — only those this RFC names.

## 12. Prohibited shortcuts

- No `continue-on-error`; the docs gate is not landed non-blocking.
- No `create-missing = true`, no leaving it unset.
- No global `npm install -g wrangler` in CI as a substitute for the lockfile.
- No weakening a drift pattern to make it land green. If a hit appears, report it.
- No `cargo fmt`.

## 13. Acceptance criteria

RFC 138 §8, as amended by §11. Checked hardest: **D1 fires with no file created**
(the vacuous-pass trap), and **a root `npm ci` precedes every `npx wrangler` in
its job** (the pin-that-pins-nothing trap).

## 14. Known risks

| Risk | Mitigation |
|---|---|
| The docs gate finds existing breakage on first CI run | Local builds are clean with `create-missing = false` (§11.6); a CI failure would be real news |
| A root `package.json` disturbs Trunk or `e2e/` | §8.6 — stop and report |
| The wrangler pin is older than what the tree was tested against | M1 measures from a root install |
| A JSON include pulls in new drift hits | M2 — report before adding the rule |

**If the work turns out materially larger than scoped, stop and report.**

## 15. Review request

To `.git-exclude/review-request/`: M1, M2 and M3 results first · implementation
summary · changed files · every log from §10 · the §9 assertions · all three
fires/does-not-fire pairs · what remains unverified (§11) · requested review
focus.

**Do not cut a release, bump a version, or create a tag.** The tag is the
owner's alone.

Report the path only.
