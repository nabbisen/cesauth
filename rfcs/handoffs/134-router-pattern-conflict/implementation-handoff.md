# Developer Handoff — RFC 134, Router pattern conflict (P0)

**Governing RFC.** [`rfcs/accepted/134-router-pattern-conflict.md`](../../accepted/134-router-pattern-conflict.md)
**Target release.** 0.82.0 — **and why that level:** RFC 134 *itself* is a
**patch** (a fix; the three route strings it changes have never served a
request, so nothing depended on them). But it cannot ship alone: RFC 131 R2a is
already on `main` ahead of it, and importing 1,489 LOC of new module surface is
added capability. **A release mixing levels takes the higher one → minor →
0.82.0.** If R2a were reverted out, this would ship as 0.81.4.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. One report-and-stop gate (§5) and one feasibility
question that may end the slice early (§6) — both are success conditions.

---

## 1. Purpose

cesauth serves no requests. After this, it serves requests, and a gate exists
that would have caught it.

## 2. Why this matters

`worker`'s router is built inside `#[event(fetch)]` (`lib.rs:146-153`), so the
`matchit` rejection panics on **every request, before dispatch** — not on the
three offending routes, on all 188. Eight shipped releases carry it, every one
since 2026-07-07.

You found this. The reason it took two months is that no gate boots the runtime,
and the reason *that* went unfixed is architect prioritisation, recorded in
RFC 134 §3. Nothing about the finding is a reflection on the work that produced
the fix.

## 3. Resolved decisions — do not re-open

**The spelling is `detail.json`.** RFC 134 §11 q1 offered it as a proposal; the
owner accepted the RFC and raised no alternative, so it is ruled:

```
/admin/tenancy/tenants/:tid.json         →  /admin/tenancy/tenants/:tid/detail.json
/admin/t/:slug.json                      →  /admin/t/:slug/detail.json
/admin/t/:slug/organizations/:oid.json   →  /admin/t/:slug/organizations/:oid/detail.json
```

Verified collision-free: `grep -c 'detail.json'` is **0** in both
`crates/backend/src/lib.rs` and `docs/src/expert/route-contracts.md`.

**The "never change a route string" rule is suspended for exactly these three
strings.** Not relaxed generally. The justification is that they have never
successfully served a request in any release, so there is no contract to break.
**Any other route string you find yourself wanting to touch is out of scope —
stop and report.**

**Release level is settled** (see the header). Do not re-derive it at the cut.

**Owner-open, and it does not block you:** RFC 134 §11 q2 — whether the eight
broken releases get a dated note in `CHANGELOG.md`. That is a release-record
decision, it lands at release time, and I am carrying it. Do not write it.

## 4. Facts already measured — do not re-derive

Treat RFC 134 §2 as measured ground. The parts you will need:

- **The mechanism.** `worker-0.8.3/src/router.rs:4` uses `matchit`;
  `add_handler` at `:360-370` does
  `.insert(pattern, …).unwrap_or_else(|e| panic!(…))`. A rejected pattern is a
  panic, not a `Result` you can handle.
- **Exactly three routes** have the shape. `.json` on a *literal* segment
  (`/me/security.json` and ~20 siblings) is fine and stays.
- **Versions never moved.** `worker 0.8.3` + `matchit 0.7.3` are identical in
  `Cargo.lock` at tags 0.80.2, 0.81.0, 0.81.2 and HEAD.
- **The three handlers**, from `lib.rs:290,353,357`:
  `tenancy_console::tenant_detail::page_json`,
  `tenant_admin::overview::page_json`,
  `tenant_admin::organization_detail::page_json`.
- **All three return `401` before touching anything.**
  `tenant_detail.rs:31-37` — `resolve_admin` fails → `Response::error("Unauthorized", 401)`.
  This is the fact §7 builds the gate on, so check it holds for the other two.

*If any of this fails to reproduce on your run, that is a finding — report it
rather than working around it.*

## 5. Report-and-stop: T4 before T2

**Do not pin a `worker` version until the smoke gate passes on it.** Measure
first, report which version, then pin. RFC 029 was marked Implemented on a
measurement that had stopped being true, and RFC 131 C1-131 found `worker-build`
floating for the same reason `worker` is floating now (`Cargo.toml:42`,
`version = "0.8"`).

Start with the currently-resolved **0.8.3** — the fix is to the patterns, not
the crate, so there is no reason to move it. Pin what you verified.

## 6. Report-and-stop: can T3 run in CI at all?

The smoke gate needs `wrangler dev` (Miniflare, local, no Cloudflare
credentials). Determine the **minimum** environment for `GET /` and `GET /login`
to return HTML — whether `.dev.vars` secrets are needed at all for the shell
path, and whether D1 migrations must be applied.

**If `wrangler dev` cannot be made to run in GitHub Actions without Cloudflare
credentials or network access, stop and report.** A gate that only runs on a
developer's laptop is a different design problem and choosing what to do about
it is mine. Do not weaken the assertions to make it fit.

## 7. Change scope

| # | Task | Files |
|---|---|---|
| T1 | Reshape the three patterns to §3's spelling; update the three rows in the contracts table (`Rendering` stays `n/a`; audit/CSRF columns unchanged) | `crates/backend/src/lib.rs`, `docs/src/expert/route-contracts.md` |
| T4 | Measure: which `worker` version the smoke gate passes on. **Report before T2** | none (measurement) |
| T2 | Pin `worker` to the measured version, with a comment recording why — same reasoning as the `worker-build` pin | `Cargo.toml` |
| T3 | The runtime smoke gate — §8 | new `.github/workflows/` job (+ a script if cleaner) |

Order: **T1 → T4 → T2 → T3.** T3 last, so it lands green.

## 8. T3 — assert content and headers, never status alone

A status code cannot tell you a missing security header (RFC 131 C1-131's
finding) and a panic yields a 500 that looks like any other 500. So:

| Request | Assert |
|---|---|
| `GET /` | **200**, `content-type: text/html`, **non-empty body**, and a **`content-security-policy` header present** |
| `GET /login` | the same four |
| each of the three reshaped routes | **401** — which proves the route *resolved and reached its handler* (§4), with no session, no credentials and no dependence on migrations |
| `GET /definitely-not-a-route` | **404** — proves the matcher discriminates rather than answering everything |
| the console/`wrangler tail` output for the run | contains **no `Rust panic`** |

The 401 assertions are the cheap heart of this gate: they need nothing set up,
and under the current bug every one of them returns the runtime's plain-text
hang 500 instead. That is the discrimination that makes the gate real.

**Do not authenticate.** A gate that needs a session is a gate that will be
disabled the first time session handling changes.

## 9. Assert the machine-checkable parts mechanically

```sh
# 1. no route pattern puts a suffix on a parameter segment — the class, not the three
grep -oE '"/[^"]*:[a-z_]+\.[a-z]+"' crates/backend/src/lib.rs && echo "FOUND — must be empty" || echo "clean"

# 2. the literal-segment .json routes are untouched
grep -c '\.json"' crates/backend/src/lib.rs      # state the number with this command

# 3. the reshaped paths exist in both places, and agree
for p in /admin/tenancy/tenants/:tid/detail.json /admin/t/:slug/detail.json \
         /admin/t/:slug/organizations/:oid/detail.json; do
  grep -q "\"$p\"" crates/backend/src/lib.rs \
    && grep -q -- "$p" docs/src/expert/route-contracts.md \
    && echo "OK      $p" || echo "MISMATCH $p"
done
```

Assertion 1 is the one that matters: it forbids the **shape**, not the three
instances, so a fourth cannot arrive silently. Attach all three outputs.

## 10. Explicit non-change scope

- **No handler changes.** The three `page_json` functions are untouched; only
  the strings that route to them move.
- No schema, no `core::ports` trait, no config knob, no permission slug.
- No `worker`/`matchit` **upgrade** to make the old pattern legal — RFC 134 §4
  rules that out; the conflict is a genuine ambiguity.
- No `Accept`-header content negotiation. RFC 134 §4: its own RFC if ever.
- No other route string (§3).
- Nothing from RFC 132 (landed, awaiting release), RFC 131 R2b/R3/R5b–e, RFC
  129, or RFC 133.
- Do not fix the RFC 132 §8 conformance gaps (`/`, `/login`,
  `/me/security/totp/verify` rendering client-side). Those are R3. `/` returning
  HTML with a CSP header is this slice's bar; *how* it renders is not.
- No `cargo fmt`.

## 11. Required tests and evidence

```sh
cargo test -p cesauth-core -p cesauth-adapter-test \
           -p cesauth-migrate-test -p cesauth-frontend > evidence/cargo-test.log 2>&1
cargo check -p cesauth-backend --target wasm32-unknown-unknown > evidence/wasm32-check.log 2>&1
cargo check -p cesauth-frontend --features csr --target wasm32-unknown-unknown > evidence/csr-check.log 2>&1
cargo clippy -p cesauth-core -p cesauth-adapter-test -p cesauth-migrate-test \
             -p cesauth-frontend --all-targets -- -D clippy::correctness > evidence/cargo-clippy.log 2>&1
cargo deny check   > evidence/cargo-deny.log 2>&1
cargo audit        > evidence/cargo-audit.log 2>&1
bash scripts/route-contracts-check.sh > evidence/route-contracts.log 2>&1
bash scripts/drift-scan.sh            > evidence/drift-scan.log 2>&1
mdbook build docs                     > evidence/mdbook.log 2>&1
make build-frontend                   > evidence/make-build-frontend.log 2>&1
npx wrangler build                    > evidence/wrangler-build.log 2>&1
```

Expected: **1,233 passed, 0 failed**; route contracts **188**; everything else
exit 0. The bundle figure changes or does not — record it with its command and
do not compare it against 751,812 or 751,386 as an invariant (RFC 133 §2.1).

Plus:

- **T4's result**, stated plainly, before T2.
- **§6's feasibility answer**, stated plainly.
- The three §9 assertion outputs.
- **The full `curl -si` output for all six §8 requests** — headers included.
  This is the first evidence in the project's history that cesauth answers a
  request; capture it in full rather than summarising.
- **T3 fires:** restore one conflicting pattern, show the gate red with the
  panic; revert, show green. Both halves. **Eighth** time this project has
  asked for a pair, and the seventh caught a hole in a gate rather than in the
  code.

**Counts in prose are measurements** — attach the command for every number.

## 12. What must NOT be claimed

- **Not that cesauth works.** After this, the router constructs, six requests
  behave, and one gate watches it. Three of RFC 132 §8's rendering gaps remain
  open, `/me/security/totp/verify` still denies a no-JS TOTP user their second
  factor, no screen has ever been verified in a browser, and R5 has not run.
- **Not that the eight broken releases are fixed.** They shipped; they stay
  broken. This fixes `main`.
- **Not that it works on Cloudflare.** It will have been observed under
  Miniflare. Nobody has deployed this tree, and saying otherwise would repeat
  the mistake that produced RFC 134.

## 13. Prohibited shortcuts

- No `continue-on-error: true`; no weakening a §8 assertion to make CI pass. If
  it does not fit, §6 is the escape hatch.
- No authenticating in the smoke gate.
- No `#[allow(...)]`, no feature gate to hide an error.
- No merging T3 red.
- No changing a fourth route string.
- No `cargo fmt`.

## 14. Acceptance criteria

RFC 134 §9, items 1–8. Checked hardest: **item 2** (`/login` returning 200
*with* a `content-security-policy` header — the header half is what C1-131
proved a status check cannot see) and **item 6** (T3 blocking, with its pair).

Item 5 depends on T4; report the version rather than assuming 0.8.3.

## 15. Known risks

RFC 134 §8, plus:

| Risk | Mitigation |
|---|---|
| Fixing one conflict reveals a second | §9 assertion 1 forbids the whole shape; T3 proves the router *constructs*, not that one pattern was fixed |
| A further failure hides behind this one | Expected — `/` has failed for three distinct reasons in three cycles. §8 asserts content and headers precisely so the next layer surfaces now rather than in another two months |
| T3 is too expensive for CI | §6, stop and report |
| The 401 assertion breaks when auth changes | It asserts *routing*, not authorization. If a future change makes these routes return something else, the gate should be updated deliberately — say so in its comment |

**If the work turns out materially larger than scoped, stop and report.**
Re-scoping is mine.

## 16. Review request

Write the package to `.git-exclude/review-request/`. It must include:

T4's result and §6's feasibility answer **first** · implementation summary ·
changed files · any deviation from §7 · every log from §11 · the three §9
assertions · the six full `curl -si` captures · T3's fires/does-not-fire pair ·
the bundle figure with its command · what remains unverified (§12) · requested
review focus.

Report the path only.
