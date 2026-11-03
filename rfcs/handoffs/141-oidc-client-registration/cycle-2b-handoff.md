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

---

# Amendment — 2026-11-03, answering the `PRIMARYKEY` stop

**Your stop.** `.git-exclude/review-request/141-cycle2b-stop-primarykey.md`
**My review.** `.git-exclude/reviewed/141-cycle2b-stop-review.md` — read §4
before you start; it is the reason this amendment exists.
**Status.** **Answered. Resume.** Nothing in §§1–7 above is withdrawn except
§2's first bullet and §3's scope line, both replaced below.

## 8. The answer: (a), and §2's first bullet was wrong

**Add `sqlite_constraint_primarykey => Some(PortError::Conflict)` to
`classify_insert_message` itself**, alongside `unique`. Not a narrower
workaround in `clients.rs`.

You were right to ask instead of editing a shared helper on your own authority,
and right that swapping the helper alone changes nothing. **§2's first bullet
said a `SQLITE_CONSTRAINT_UNIQUE` "becomes `Conflict`" — that is the wrong class
for this table, and it is my error, not a gap in your reading.** Following it
literally would have shipped a no-op.

I reproduced your capture independently (sqlite 3.54.0, outside this project)
rather than taking the string on trust, and the result that matters beyond your
one table is that a **composite** `PRIMARY KEY (a, b)` collision also reports
`PRIMARYKEY`. See the review §2 for the five-case table.

### 8.1 The doc comment is the part that was actually wrong

`classify_insert_message`'s doc says *"Only UNIQUE and FOREIGN KEY are
classified"* and then justifies omitting **CHECK** and **NOT NULL**. That is a
census of four classes where SQLite's vocabulary has twelve, under a rule
(RFC 159 §4.5) that every item is either classified or **named with a reason**.
`PRIMARYKEY` was never an item, so no reason was ever owed for it.

**Replace that paragraph with the full table** — the review's §6 has it, with
the verdict and the reason for each of the twelve codes and the command behind
each "unreachable". Do not append a sentence about `PRIMARYKEY` to the old
text; the shape of the old text is the defect.

### 8.2 Host tests the classifier now owes

Add to the existing five, in the same style, from real strings:

- a `PRIMARYKEY`-shaped message classifies as `Conflict` — use the string **you
  captured**, verbatim, as the constant, the way `UNIQUE_MSG` was RFC 160's own
  captured string;
- a **composite**-PK message (`UNIQUE constraint failed: t.a, t.b` with
  `(extended: SQLITE_CONSTRAINT_PRIMARYKEY)`) classifies as `Conflict` — this is
  the case the six membership messages depend on, and it must have its own
  witness rather than riding on the single-column one;
- the existing `message_check_is_unclassified` / `message_not_null_is_unclassified`
  guards stay exactly as they are. **If your change makes either of them pass
  for the wrong reason, you have matched too broadly** — say so and stop.

## 9. Scope — this replaces §3

§3 drew the line at one file. **The line was in the wrong place and that is
mine.** The classifier is wrong for every table in this schema, and the moment
you fix it the behaviour of **ten shipped paths** changes. I will not land a
change with that reach and defer verifying what it changed.

**In scope now:**

1. `classify_insert_message` — the arm, the doc-comment census, the two tests.
2. `clients.rs::create` → `classify_insert_err`, and the **409** with a message
   that names what collided. Unchanged from §2.
3. The screen's already-exists message. Unchanged from §2.
4. **The membership consequences** — §10. This is the new work.

**Still out of scope, unchanged:** the other `run_err` sites, the DELETE-side
classifier (no classifier exists there at all; `ON DELETE RESTRICT` makes it
reachable in principle and there is no production hard-delete path — review §6
has the grep), and anything in `cesauth-core` beyond §10.3's one doc line.

Your §2 I verified rather than accepted: `oidc_clients` has no outgoing foreign
key, `update` never sets `id`, both CHECK columns are enum-written, `audience` is
nullable. **Six unreachable `run_err` sites, correctly counted, correctly left
alone.** That is exactly what §3 asked for.

## 10. The membership consequences — new, and the reason this cycle grew

Read the review §4 first. In one line: three membership tables have a composite
primary key and no separate `UNIQUE`, so **six written operator messages, three
API 409s and one idempotency arm all branch on a `Conflict` that cannot
occur.** Your fix makes all ten reachable at once. None of them needs editing —
they were written for exactly this case — but "correct by inspection" is
`reviewed`, and RFC 000 §22.2 forbids a P1 entering `done/` on `reviewed` alone.

### 10.1 Three live captures, one per distinct consumer

Not ten captures. Ten paths, three consumers:

- **A console form.** Add a user to a tenant, then add the same user again.
  Capture the rendered message: **"User is already a member of this tenant"**,
  not "Storage error". One console is enough; say which.
- **The public API.** `POST` the same tenant membership twice via
  `api_v1/memberships.rs`. Capture both status lines: **201 then 409**, not 201
  then 500.
- **The invitation path.** This is the one with a lost record, so it needs the
  most care: a user who is **already** a member of the tenant accepts a valid
  invitation to that same tenant. Before the fix the invitation stays `pending`
  with no audit row; after it, capture the invitation **marked accepted** and
  its audit event present. If you cannot stage that state, **say so and stop** —
  do not substitute a test double for it. The double is the thing that was wrong
  (review §5).

Clean up every probe row and confirm it is gone, as you did last cycle.

### 10.2 What not to do

Do **not** add a pre-check (`find` then `add`) anywhere. The constraint is the
check; a read-then-write would be both slower and racy, and it would hide the
defect rather than fix it.

Do **not** change `crates/adapter-test`. Its double already returns `Conflict`
and is the implementation that was right all along.

### 10.3 One documentation line

`crates/core/src/tenancy/service.rs:175` promises *"Returns `Conflict` if the
user is already a member of the tenant."* After your fix that becomes true for
the first time. It currently reads as a contract the adapter could not meet —
**leave the sentence, and nothing else in that file.** It is in scope only so
that nobody later reads it as newly-added.

## 11. Tier, level, and what the systemic half is

**Tier P1** for this cycle — an operator sees a false failure on a routine
action, a public API answers 500 where it documents 409, and an invitation
acceptance is lost permanently.

**Level: 0.92.0, minor, unchanged.** The release is already minor for the
screen; a correctness fix rides inside it. **The cut still waits on this.**
Expect this cycle to cost more than §4's original estimate; the captures in
§10.1 are most of it.

**The systemic half is not yours.** Why a matched variant with no producer is
invisible to every gate — and why the in-memory double and the D1 adapter were
allowed to disagree about a documented error class — is
`rfcs/accepted/171-the-arm-is-written-and-the-error-is-never-produced.md`,
**accepted by the owner 2026-11-03** and scheduled **after 0.92.0** (its
parity half after RFC 170). **Nothing in it is in this cycle, and its acceptance
does not widen yours** — if you find yourself wanting to add a census or a check,
that is RFC 171's work and you should report it, not build it.

## 12. Stop conditions — these replace §6

- the `PRIMARYKEY` string you captured does not classify as expected once the
  arm is in — report the string again, do not widen the match to make it pass;
- adding the arm makes `message_check_is_unclassified` or
  `message_not_null_is_unclassified` pass for the wrong reason;
- any of §10.1's three states cannot be staged against `wrangler dev` — report
  which and why; **do not substitute a host test for a live capture**;
- a membership arm turns out to be *wrong* now that it is reachable, rather than
  merely unverified — that is a design question, not an implementation one;
- the fix would need a change in `cesauth-core` beyond §10.3.

## 13. Baselines

§4's baselines stand unchanged, each with its command, measured at `357c7f6`.
**Your `clients.json` and E6 figures do not move**; the classifier change adds
host tests, so the only baseline you should expect to move is the host-test
count — report it with the five `-p` flags, per §4.
