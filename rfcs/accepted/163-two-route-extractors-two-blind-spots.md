# RFC 163 — Two route extractors, two blind spots: the duplicate-route guard covers 105 of 193

**Status.** **Accepted** 2026-10-30. **Patch** — a test that covers 105 of 193
and a non-zero assertion, no capability added. **Fifth in the queue**, behind
RFC 162, RFC 161 §9(a), RFC 164 and RFC 165 §3; not dispatched. Patch number
assigned at dispatch. **§4's fork is decided at dispatch**: the recommendation is **1 now,
3 recorded** — the needle fix plus a non-zero-count assertion ships
immediately, the single-extractor end state is its own cycle, and **2 is
declined**, since reformatting 193 router lines to serve a grep is the tail
wagging the dog.
**Tier.** **P1** — not because anything is broken today (it is not), but because
the guard that is supposed to catch the failure cannot see the route it was
written for, and the failure it guards against is silent in production.
**Size.** Small to fix, and the fork in §4 is the whole reason this is an RFC
rather than a line in a handoff.
**Touches.** `crates/backend/src/lib.rs` (`#[cfg(test)] mod tests`),
`scripts/route-contracts-check.sh`.
**Found by.** Probing RFC 159's new E4 check for the comment-blindness recorded
as RFC 159 §4.4 — the probe passed for a reason that turned out to be a second,
unrelated blind spot in a different implementation of the same extraction.
**Relates to.** RFC 011 (the duplicate-route test, v0.50.3), RFC 027/125
(`route-contracts-check.sh`), RFC 159 §4.4, RFC 156 (*a gate that stops
covering something must fail*), RFC 125 T5 (*a zero count is a failure, not a
vacuous pass*).

**On 1.0:** not declared, not scoped, not dated. Nothing here is a 1.0
requirement.

---

## 1. Summary

`crates/backend/src/lib.rs`'s `no_duplicate_route_registrations` test searches
each line for the literal `.get_async("` / `.post_async("` / `.put_async("` /
`.delete_async("` — **no whitespace before the paren**. The registration block
is column-aligned, so 88 of the 193 routes are written `.get_async ("` and are
invisible to it:

```
$ python3  # extraction over crates/backend/src/lib.rs
registrations total:              193
matched by the test's needle:     105
invisible to the test:             88
```

`.post_async` 74 + `.get_async` 25 + `.delete_async` 6 are flush against the
paren; `.get_async ` 64, `.post_async  ` 13 and `.get_async   ` 11 are not.

**The route the test exists to protect is in the invisible 88.** Its own doc
comment: *"the second `/me/security/sessions` block was merge-conflict residue
from v0.35.0 and was removed; this test prevents it (or any future duplicate)
from re-appearing."* `lib.rs:228` is `.get_async ("/me/security/sessions"`.
Re-introduce that exact duplicate today and the test passes.

## 2. What is established

1. **No duplicates exist now.** A spacing-tolerant extraction of
   `(method, path)` over `lib.rs` gives **193 distinct / 193 total**. This is a
   guard that cannot guard, not a live defect.
2. **The coverage shortfall is silent.** The test has no "I found zero
   registrations" assertion and no coverage figure — it would pass identically
   if the needle matched nothing at all. That is the exact shape RFC 125 T5
   added to `route-contracts-check.sh` and RFC 156 generalised.
3. **Why it matters that it is silent:** `workers-rs`'s router is last-wins, so
   a duplicate `(method, path)` is invisible in production until someone edits
   one copy and not the other. That is the whole reason RFC 011 wrote the test.
4. **There are three implementations of "extract the registered routes from
   `lib.rs`" in this repository, with three different blind spots:**

   | Where | Spacing | Comments | Coverage reported |
   |---|---|---|---|
   | `route-contracts-check.sh`, E1 extraction (RFC 027/125) | tolerant (`\s*`) | **blind** (RFC 159 §4.4) | route count printed |
   | `route-contracts-check.sh`, E4 liveness grep (RFC 159) | n/a (greps the call, not the registration) | **blind** (RFC 159 §4.4) | coverage figure printed |
   | `lib.rs`'s `no_duplicate_route_registrations` (RFC 011) | **blind** | **blind** | **none** |

   RFC 159 §4.4 fixes the comment column for the two script rows. Nothing
   touches the test, and nothing keeps any of the three honest with the others.

## 3. Why the obvious fix is not obviously the right one

Changing `format!(".{method}(\"")` to a whitespace-tolerant match is three
characters and closes today's hole. It also leaves the third extractor in place
to diverge again — and the history here is that each of these three was written
correctly for the idiom in front of its author and then quietly stopped matching
the code. The needle fix buys the next divergence, not the last one.

Two things are worth noticing before choosing:

- **The idiom itself is the root cause.** 193 registrations, two spellings, and
  nothing enforces either. The aligned `.get_async (` form is a `rustfmt`
  survivor (`rustfmt` does not touch inside the method-chain alignment the block
  uses), so it will keep being produced.
- **The test and the script answer different questions** — "are any two
  registrations the same?" and "is every registration documented?" — but they
  need the *same list* to answer them, and only one of the two can be run on
  host without `wrangler`.

## 4. The fork

Three directions. I have a preference and state it, but this is a decision, not
a repair:

1. **Fix the needle only.** Whitespace-tolerant match plus a non-zero-count
   assertion (`assert!(seen.len() >= 150)` or similar, so a future idiom change
   fails loudly instead of silently). Cheapest; leaves three extractors.
2. **Normalise the idiom, then fix the needle.** Rewrite all 88 spaced
   registrations to the flush form in one mechanical commit, and add a check
   that the spaced form never returns. A large diff across the file every reader
   of the router opens, and it removes the class rather than the instance.
3. **One extractor, two consumers.** The registration list becomes one thing —
   either the test and the script both read a generated list, or the script's
   extraction becomes the single source and the duplicate check moves into it
   (where it would run in CI beside E1-E4 instead of in the crate's test suite).
   Most work; the only one of the three that makes the next divergence
   impossible rather than merely detected.

**Recommended: 1 now, 3 recorded.** The non-zero-count assertion is what turns
this from a silent subset into a loud one, and it is small enough to ship
without waiting on the fork; 3 is the right end state and is its own cycle
because moving the check out of `lib.rs`'s test module changes which gate owns
it. **2 I would not do** — a 193-line reformat of the router block to serve a
grep is the tail wagging the dog, and §2's table shows the spaced form is not
the defect, the three private extractors are.

## 5. What this does not claim

- Not that any duplicate route exists. 193 distinct of 193 total, checked.
- Not that `route-contracts-check.sh`'s E1 count is wrong. It is spacing-tolerant
  and reports 193 correctly; its separate comment-blindness is RFC 159 §4.4's.
- Not that this is the only vacuous test in the suite. One was found by probing
  one gate; the general question — *which other tests pass because their needle
  matches nothing?* — is RFC 156's territory and is not opened here.
