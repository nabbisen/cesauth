# Developer Handoff — RFC 141 cycle 2b: a duplicate client id answers 500

**Governing RFC.** `rfcs/accepted/141-oidc-client-registration.md` §4.1, with
`rfcs/done/160-every-constraint-failure-is-a-conflict.md` as the pattern.
**Review.** `.git-exclude/reviewed/141-cycle2-review.md`
**Builds on.** `357c7f6` on `main`. **Nothing to revert** — the screen and the
CSRF control both stand; I verified them live.

**Target release.** **0.92.0 — minor, unchanged.** Same release, its own cycle.
**Trigger: none new** — this is a status code and a message on an existing
route, and the release is already minor for the screen and the token. **The cut
waits on this.**

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-03.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. One thing, and you found it

Your own §5 reported it and correctly called it out of scope:

> a duplicate client id returns a generic 500 "storage error" instead of the
> 409 conflict message `ClientOpError::Conflict` already supports, because
> `CloudflareClientRepository::create` uses the generic `run_err` instead of
> this crate's own RFC 160 `classify_insert_err`/`classify_insert_message`.

Verified. **It was out of scope when you wrote that, and your own cycle brought
it into scope** — by exactly the reasoning the cycle-2 handoff used to pull the
CSRF control in: **the screen creates the caller.**

Before 0.92.0 only an API client could hit a duplicate id. After it, an operator
typing an id that already exists — **the most ordinary mistake available on this
screen** — gets **HTTP 500, "storage error"** on the product's primary
integration action. RFC 160 exists for precisely that: *"every constraint
failure is a `Conflict`"*, where a mistyped owner id once rendered "Slug already
taken" and the real arm could not be reached.

## 2. The change

- `create` in `crates/adapter-cloudflare/src/ports/repo/clients.rs` uses
  `classify_insert_err` / `classify_insert_message` — the same crate's own RFC
  160 classifier — in place of `run_err`, so a `SQLITE_CONSTRAINT_UNIQUE`
  becomes `Conflict` rather than a generic storage error.
- `clients.rs::create` maps `ClientOpError::Conflict` to **409** with a message
  that names what collided. The variant already exists; nothing new upstream.
- **The screen surfaces it as what it is.** Your error-body parser already
  handles the three shapes; what matters is that an operator reading the result
  learns *"a client with that id already exists"* and not *"storage error"*.
  That sentence is the whole point of this cycle.

**Check `update` and `delete` while you are in that file.** `update`'s bind also
goes through `run_err` (line ~241). I have not traced whether it can produce a
constraint failure a caller could cause — **if it can, classify it the same way;
if it cannot, say so in one line.** Do not classify a path you have not shown is
reachable.

## 3. Scope

That one file, `clients.rs`'s mapping, the screen's message, and tests. **Not**
the other `run_err` call sites in the adapter crate — RFC 160 migrated the sites
its own census covered, and a sweep of the rest is its own work with its own
census, not a rider here. If you find the count of unmigrated `run_err` sites
while you are there, **report the number** and leave them.

## 4. Tests

- **Host test the classifier's mapping** the way RFC 160's own tests do — a
  `SQLITE_CONSTRAINT_UNIQUE`-shaped error string classifies as `Conflict`, and
  something else does not. RFC 160's lesson was that the architect's preferred
  option lost to an **observed** error string, so if D1's actual message differs
  from what the classifier expects, the observed string wins and you say so.
- **Live capture**, as captures: create a client, create it again with the same
  id, and capture both status lines — **201 then 409**, not 201 then 500. Then
  delete the probe row and confirm it is gone.
- **The screen**: a pure-function test that a 409 body renders the
  already-exists message rather than a generic failure.
- Full gate set. **Baselines at `357c7f6`, each with its command:**
  - host tests, `cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend -p cesauth-backend -p cesauth-adapter-cloudflare --features cesauth-frontend/csr` → **1,673 passed, 0 failed, 4 ignored, 12 lines**;
  - `cargo test -p cesauth-migrate-test --test migration_chain` → **35**;
  - `bash scripts/route-contracts-check.sh` → 194 routes; E4 `218 = 194 + 24 + 0`; **E5 `17 = 17 + 0 + 0`**; **E6 `94 = 80 claims + 14 declared + 0 unclassified`**; GATE_42 **0 exempted**;
  - `bash scripts/drift-scan.sh` → clean;
  - `npx playwright test` in `e2e/` → **20**;
  - bundle, `./node_modules/.bin/wrangler deploy --dry-run --outdir bundled/` under gzip 1.15 → **896,677 B** in the architect's environment (`885,978` wasm + `10,699` shim). **Your environment reads ~4.1 KB lower on the same commit and that is now explained** — see §5; report your own figure with your own baseline and do not reconcile the two.

## 5. Context you should have, not work for you

The ~4.1 KB offset between your bundle figures and mine, consistent across two
commits, has a cause: **`cargo install -q worker-build --version 0.8.4` in
`wrangler.toml` has no `--locked`**, while `cargo install trunk --version
0.21.14 --locked` appears four times in the workflows. `worker-build` generates
`shim.js` and post-processes the wasm, so without `--locked` its own dependency
graph floats and two machines build different binaries from the same pinned
version.

**Do not fix it here.** Adding `--locked` changes every build in the project at
once, and if 0.8.4's lockfile pins dependencies that do not compile on 1.98.1
everything breaks together. It is recorded against RFC 133 half B — environment
reproducibility — which this is the first real instance of.

## 6. Stop conditions

- D1's actual constraint-error message does not match what `classify_insert_err`
  expects — report the observed string, do not pattern-match optimistically;
- `update` or `delete` turn out to need the same treatment and it is not
  obvious — report rather than guess;
- the fix would need a change in `cesauth-core`.

## 7. One process note, and it is not about this cycle's code

Your report stated that I had approved the mid-cycle `created_at` change. **I
had not** — there was no file between us between the dispatch and your report,
and files are the whole channel. The stop was right, the finding was right, the
fix is right and stays; **the attribution was not.** A stop means stop until the
answer arrives in a file, because that is the only form the owner or a later
reader can check. If the answer comes from somewhere else, say where.
