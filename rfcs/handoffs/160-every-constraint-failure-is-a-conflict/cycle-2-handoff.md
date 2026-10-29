# Developer Handoff — RFC 160, cycle 2

**Governing RFC.** `rfcs/accepted/160-every-constraint-failure-is-a-conflict.md`
— **§4.8** and **§4.9**, both new.
**Review.** `.git-exclude/reviewed/160-implementation-review.md`
**Builds on.** `28b25b3`, which is accepted and stays.

**Target release.** **0.89.1 — patch**, unchanged, **not cut until this lands**:
one of the two items is this RFC's own defect at a site the census never saw.

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-10-29.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. `28b25b3` is accepted — revert nothing

Re-verified: **1,625** host tests / 0 failed, `migration_chain` 35, routes 193,
drift-scan clean, bundle 871,775 + 10,700 = 882,475 B reconciling at 33%, both
digests 64 characters, tree clean. All seven live items are in the log,
**including the half that matters most** — *"Slug already taken in this
deployment"* still renders for a genuinely taken slug, in the same walkthrough
as the new *"Owner user id not found"*. A fix to a wrong message that broke the
right one would have been no fix.

Two things worth saying. **§4.6's rule was applied as a check and produced a
"no change" answer** for the four `*_create.rs` forms, with the reasoning for
each — that is the harder outcome to report and you reported it. And you
**flagged the unconstructible test in one line instead of dropping it
silently**, which is the standing rule working as intended — see §3, where the
requirement turns out to have been constructible after all.

## 2. The ninth site — and the population was mine

`crates/adapter-cloudflare/src/ports/repo/users.rs:129`,
`UserRepository::create`:

    if msg.contains("UNIQUE") || msg.contains("constraint failed") {
        Err(PortError::Conflict)

`users.tenant_id` is a foreign key (`migrations/0016:46`), and `FOREIGN KEY
constraint failed` contains `constraint failed`. So a user created against a
nonexistent tenant comes back `Conflict`, and `admin/legacy.rs:94` renders that
as **"email already in use", 409** — a missing tenant reported as a duplicate
email, which is the same sentence as *"Slug already taken"* for a mistyped
owner id.

**This is not your miss.** RFC 160 §2's population came from my grep for the
literal `contains("constraint")` **with its closing `")`**, which cannot match
`contains("constraint failed")`. You inherited an eight-site population that
was wrong. §4.8 records it.

**Do:** route it through `classify_insert_err("users.create run", e)` like the
other nine.

**Do not** touch the other three variant-spelling sites — `anonymous.rs:94`
already distinguishes `FOREIGN KEY` explicitly (the one place that was right
all along), and `deletions.rs:91` / `invitations.rs:84` test `UNIQUE` only, so
a foreign-key failure falls through to a 500 rather than a wrong message, and
their callers pass tenants that exist. §4.8 records why they are left, so they
do not read as missed.

**Check the consumer, per §4.6**: `legacy.rs` matches `Conflict` then `Err(_)`.
After this change a foreign-key failure there becomes `NotFound` → *"storage
error", 500*. That is vague but **true**, where the current answer is false, and
`legacy.rs` passes `DEFAULT_TENANT_ID`, which always exists — so a `NotFound`
there is a storage inconsistency and the wildcard is the honest arm. **Confirm
that reading yourself and say so; do not add an arm on my say-so.**

## 3. The fallthrough needs a witness, and it is constructible

You flagged that asserting the fallthrough aborts the host binary, because
`run_err` calls `worker::console_error!`. Correct — and **the limit is in the
structure, not in the requirement.**

**Split the decision from the logging**: a pure function from the message to
`Option<PortError>` (`Some(NotFound)` / `Some(Conflict)` / `None`), with
`classify_insert_err` as the thin wrapper that calls `run_err` on `None`. All
three branches then test on the host — the same extraction this programme used
for `tenant_created_detail`, for `accept_invite_page`, and for every
`worker::Response` case since RFC 146 §2.

**Why this one matters more than a missing test usually would:** the
fallthrough is this RFC's **own regression guard**. Nothing currently pins that
an unrecognized constraint message does *not* become `Conflict` — exactly the
bug being fixed — and a future edit re-broadening the match would reintroduce
it with both existing tests staying green.

**Required cases**, all host tests over the recorded strings: UNIQUE →
`Conflict`; FOREIGN KEY → `NotFound`; **a CHECK string → `None`**; **a NOT NULL
string → `None`**; and a message with no constraint text at all → `None`. The
CHECK and NOT NULL strings are already in §0 of your decision report — use them
verbatim. **Do not re-run the production-code probes to get them again.**

## 4. Required evidence

1. **Live**: a duplicate email on the `legacy.rs` registration path still
   answers **"email already in use", 409** — the UNIQUE case this site was
   always right about must not regress. This is the same both-halves check that
   made cycle 1 convincing.
2. **The five classifier cases** above, as host tests, passing.
3. **Fires/does-not-fire** on the new pure function: revert the
   foreign-key arm, show the FOREIGN KEY case fail and the others pass; restore
   byte-identically; show all five pass.
4. **No live re-run of cycle 1's seven items** — they are in the record and
   nothing in this cycle touches those paths. Say that rather than repeating
   them.
5. **Full gate set with counts.** Host baseline **1,625**; `migration_chain`
   **35**; routes **193**; bundle with full 64-character digests copied from the
   log; 13 workflows against the manifest.
6. **An updated `Status` + `Evidence` back-fill line**, superseding the last.

## 5. Resolved — do not re-open

- The classifier's shape, the two classes, and §4.7's two API handlers.
- CHECK and NOT NULL stay **unclassified** — adding a `None` *test* for them is
  not adding a *branch* for them.
- `create_group`'s signature stays unchanged.
- **Still open, still not this RFC's**: the orphan tenant (visible again in
  your own step 2) and the API path's missing `via=` audit marker, both RFC 158
  §5.5. Also out of scope: RFC 159's nine; RFC 152 half B and §6; RFC 141
  cycle 2; RFC 123; RFC 120.

## 6. Report-and-stop

- `users.rs:129`'s UNIQUE behaviour cannot be preserved through the shared
  helper;
- the pure split turns out to need more than a function boundary;
- a site exists that §4.8's corrected population misses. **I have already run
  the loose grep** so you do not have to: `grep -rn "msg.contains("
  crates/adapter-cloudflare/src` gives **9 lines across 6 sites** after your
  consolidation, all named in §4.8, and `users.rs:129` is the only defective
  one. If you find a tenth line, that is a report-and-stop.

## 7. Review request

`.git-exclude/review-request/160-cycle-2-report.md`. Give me the commit.
