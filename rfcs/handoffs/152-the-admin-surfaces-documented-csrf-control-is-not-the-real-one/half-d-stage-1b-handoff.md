# Developer Handoff — RFC 152 half D stage 1b: the control stage 1 documented does not hold

**Governing RFC.** [`rfcs/accepted/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one.md`](../../accepted/152-the-admin-surfaces-documented-csrf-control-is-not-the-real-one.md)
— §"Half D stage 1 reviewed, 2026-11-03", added by this review.
**Review.** `.git-exclude/reviewed/152-half-d-stage-1-review.md` — **read §2
before you start.**
**Builds on.** `79e9090` on `main`. **Nothing to revert**: stage 1's decisions
all stand, including every cell it resolved. This corrects one check and two
cells.

**Target release.** **Patch, the same cut as stage 1** — the number is assigned
at the cut. **The cut is held for this.** I will not tag a release whose new
documentation claim fails the test this RFC exists to apply.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-03.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. What is wrong, measured

`csrf::is_json_content_type` decides with
`ct.to_ascii_lowercase().contains("application/json")`. The `.contains` is there
to tolerate `; charset=utf-8` — and **a parameter satisfies it too**:

```
POST /webauthn/authenticate/start
  application/json                      -> 200
  text/plain                            -> 400
  text/plain; x=application/json        -> 200     <-- past the control
  text/plain;charset=application/json   -> 200     <-- past the control

POST /me/security/delete-account        (400 = control held, 401 = control passed)
  text/plain                            -> 400
  text/plain; x=application/json        -> 401     <-- past the control
```

Captured by the architect against `wrangler dev` at `79e9090`.

**Why that matters and is not theoretical.** `text/plain; x=application/json`
parses to MIME **essence** `text/plain`, which is **CORS-safelisted**, so a
cross-site `fetch(…, {credentials:'include'})` sends it **without a preflight**.
The control the three `required (Content-Type)` cells now claim does not hold.

**`/me/security/delete-account` is pre-existing** — `deletions.rs` has carried
this check since RFC 149 §2 under a comment saying *"this check IS the CSRF
control"*. **Stage 1 did not introduce it**; it found the check, reused it, and
promoted it to a documented control, which is how it became visible. Not
exploitable today: `SameSite=Strict` holds, because nothing in this repo sets
`Access-Control-Allow-Origin`.

## 2. The fix

**Compare the MIME essence, not the whole header.** Split the value at the first
`;`, trim ASCII whitespace, lowercase, and require `== "application/json"`.
Nothing else changes about the control: the three routes keep it, `deletions.rs`
keeps sharing it, and the 400's wording stays.

**Host tests for the cases that matter**, extending the six that exist:

- `application/json` → true; `application/json; charset=utf-8` → true;
  `APPLICATION/JSON` → true; `  application/json  ` → true;
- **`text/plain; x=application/json` → false** — the bypass, as its own named
  test;
- **`text/plain;charset=application/json` → false** — the second captured shape;
- `application/jsonx` → false, and `xapplication/json` → false. The old
  `.contains` accepted both and nothing noticed.

**Negative-test it the way this project does**: revert the fix, confirm the new
tests fail, restore, byte-diff, re-run clean.

**Live capture** at the end: the same two routes, the same five header values,
the status lines — `text/plain; x=application/json` must answer **400** on both.

## 3. Two cells, paired inversely to what the code does

Stage 1 split the four webauthn rows on **caller presence**; the question is
**ambient credential**. Measured per handler — does it read the `cookie` header?

| route | reads `cookie`? | cell now | cell it should carry |
|---|---|---|---|
| `register/start` | no | `N/A (no ambient credential)` | unchanged |
| `register/finish` | **yes** — `extract_pending_handle` + `login_next` | `N/A (no ambient credential)` | **a real control** |
| `authenticate/start` | no | `required (Content-Type)` | **`N/A (no ambient credential)`** |
| `authenticate/finish` | **yes** — the identical two | `required (Content-Type)` | unchanged |

Both `finish` handlers capture `cookie_header` before consuming the body and
pass it to `post_auth::complete_auth`, so a cookie-borne pending-OAuth handle
steers where the resulting session lands. **That is an ambient credential, and it
is the same in both.**

**Do `authenticate/start` only** — drop its check and give it the honest cell.
**Leave `register/finish` alone in this cycle**: RFC 172 rewrites that file and
must touch those rows anyway, and two cycles editing one function is how a
conflict gets made. Say in your report that you left it and why.

**If you disagree with either reclassification, say so and do not do it.**
Stage 1's reading was defensible and twice before this team has departed from a
handoff and been right.

## 4. Stop conditions

- the essence comparison rejects a header a **real** caller sends — report it
  with the caller and the value, and change nothing;
- `register/finish` turns out to need its cell changed *in this cycle* to keep
  E6 closing — report it rather than editing a file RFC 172 is about to rewrite;
- E6's two arithmetics do not close, or `unclassified` is not 0;
- any of §2's new tests passes before the fix is applied — that means the test
  does not test what it says.

## 5. Not in this cycle

**`rfcs/proposed/172-passkey-registration-authenticates-nobody.md` — a P0 your
own stage 1 found.** Your justification for `register/*`'s cell, *"no ambient
credential is ever consulted"*, is the whole defect:
`POST /webauthn/register/start` takes the account it registers a passkey for
from the request body and authenticates nobody, and `register_finish` then
issues a session for it. **You wrote the fact down correctly and it is the
finding**; recognising what it implied was the architect's job, not a cycle's.
It needs the owner's acceptance first. **Do not touch `webauthn/register.rs`.**

## 6. Baselines at `79e9090`, each with its command

- host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,683 passed, 0 failed, 4 ignored, 12 lines**;
- `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
- `bash scripts/route-contracts-check.sh` → 194 routes; E4 `218 = 194 + 24 + 0`; E5 `17 = 17 + 0 + 0`; **E6 `94 = 84 claims + 10 declared + 0 unclassified`**, `84 = 66 + 0 + 18`;
- `bash scripts/drift-scan.sh` → clean;
- `npx playwright test` in `e2e/` → **20** — needs `node_modules/.bin/wrangler dev --port 8787` already serving;
- bundle, `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/`, **gzip 1.15 at its default level** → **896,558 B** (885,859 wasm + 10,699 shim), your own figure at `79e9090`. **Name the level with your figure**; `-9` reads ~4.2 KB lower and the project's progression is on the default.
