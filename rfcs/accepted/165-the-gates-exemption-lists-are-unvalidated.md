# RFC 165 — The gate's exemption lists are unvalidated, and the longest one need not exist

**Status.** **Accepted** 2026-10-30. **§3 — release 0.89.5, patch**: staleness
checks for the four unchecked lists, additive, no behaviour change to any
passing gate. **Queued behind RFC 162 (0.89.3) and RFC 164 (0.89.4)**; not
dispatched. **§4's reduction is release-unassigned** — it is a separate
decision about how much the gate should infer about code not yet written, and
it rides in on nothing. The §4 question is settled at that dispatch, not here.
**Tier.** **P2.** Nothing is wrong today — all three live entries check out.
The lists are what `route-contracts-check.sh` takes on trust, and four of its
five are trusted without being checked.
**Size.** Small for the staleness checks (one shared helper, four call sites).
Medium for §4's reduction, which deletes most of one list rather than
validating it.
**Touches.** `scripts/route-contracts-check.sh` only.
**Found by.** The architect, 2026-10-30, reviewing RFC 159 cycle 4 — applying
that cycle's own §4.5 argument to the four sibling lists it did not cover.
**Relates to.** RFC 159 §4.5 (the finding this generalises), RFC 156 (*a gate
that stops covering something must fail*), RFC 125 T5, RFC 163 (three private
extractors of the same fact), and the standing lesson from RFC 159 cycle 2 —
**a fix applied to one matcher is not a fix to the class**.

**On 1.0:** not declared, not scoped, not dated.

---

## 1. Summary

RFC 159 §4.5 established that a `NAMED_NON_HANDLERS` entry matching nothing
during a scan is a hard failure, because such an entry is **a pre-authorised
exemption for whatever is written at that key next, reviewed by nobody**. That
shipped in 0.89.2. The same script carries four more lists of exactly the same
kind, and **none of them is checked**:

| List | Entries | What an entry exempts | Staleness checked |
|---|---|---|---|
| `NAMED_NON_HANDLERS` | 22 | a `pub async fn` from being treated as a handler | **yes** (RFC 159 §4.5) |
| `E3_EXEMPT` | **2** — `GET /`, `GET /login` | a server-declared route from the Leptos-shell requirement | no |
| `GATE_42_EXEMPT` | **1** — `GET /admin/console/clients` | a route from its RFC 042 gate | no |
| `NONCE_EXEMPT` | 0 | a nonce call site | no |
| `E4_EXEMPT` | 0 | a handler from the reachability requirement | no |

**Not live today, checked:** all three exempted routes are still registered in
`lib.rs` (`grep -c '_async *("/"'` → 1, `"/login"` → 1,
`"/admin/console/clients"` → 2), and all 22 named entries resolve to a
`pub async fn` that exists at that path.

## 2. What is established

1. **The argument transfers without modification.** Remove `GET /login` from
   `lib.rs` and `E3_EXEMPT`'s entry stops matching anything; it then sits
   pre-clearing the next route registered at `/login` from the shell
   requirement. Nothing says so. This is §4.5's reasoning with one noun
   changed.
2. **Two of the four carry entries now**, so this is not a hypothetical about
   empty lists. `NONCE_EXEMPT` and `E4_EXEMPT` are empty *by design* and
   documented as such — which is precisely when a staleness check costs nothing
   and the first entry someone adds becomes self-policing.
3. **It is the fix-one-matcher pattern, for the fourth time in one RFC.**
   RFC 157's bare-name test could not see nine handlers; E4's first shape regex
   could not see eleven; the remainder list could rot unobserved (§4.5); and now
   §4.5's own remedy covers one list of five. Each step was a correct fix in the
   place the defect was found, and each time the siblings were not swept.
4. **The staleness question is one line per list**, because all five are already
   matched with the same idiom (`printf '%s\n' "$LIST" | grep -Fx "$key"`): the
   keys consulted during a run are already in hand at every call site, so a
   shared "every entry must have been consulted" helper needs the list and the
   set of keys it was asked about, nothing more.

## 3. Direction

1. **One shared helper**, used by all five lists: given a list and the keys
   actually tested against it this run, report any entry that was never matched
   as a **named, distinct hard failure** — the same message shape RFC 159 §4.5
   settled on (which of the three things is wrong, and whether to edit the list
   or the code).
2. **Fires/does-not-fire per list.** Four probes, one per list that is not
   already covered, each planting an entry that cannot match. The empty lists
   need the probe most: a check that has never seen a non-empty list is a check
   nobody has run.
3. **Then the counts in the coverage line**, so the lists' sizes are reported
   rather than inferred — `E3_EXEMPT` and `GATE_42_EXEMPT` print no figure
   today, which is why their contents were news when this was written.

## 4. The reduction: make the long list short rather than merely validating it

A list of 22 entries rots because it is long enough that nobody re-reads it. A
list of 3 does not. RFC 159's own by-value/by-reference insight is the tool:

- a **handler** owns its request (shapes A and B — it is the entry point);
- a **helper** borrows it, which is itself a classifier — call it **shape (C)**:
  `req`/`ctx`/`env` taken by reference.

Every one of the 22 named entries satisfies (C) or has **no** request-shaped
parameter at all. Verified at review, 22 of 22, and the dev team's cycle-4
report records independent agreement. Adding (C) as a structural classifier
leaves only the entries with no such parameter to name —
`api_v1/quota.rs::unwrap_storage`, `me/totp/disable.rs::decide_disable_post`,
`me/totp/verify.rs::decide_verify_get` — **22 entries down to 3**.

**The trade to weigh, and it is a real one.** (C) is laxer than a name: it
classifies *any* future by-reference `pub async fn` as a non-handler with no
review. Today that is correct for 19 of 19 and the project's idiom makes a
by-reference handler impossible (`workers-rs` hands the router an owned
`Request`). But a classifier is a standing promise about code not yet written,
and a name is a one-time judgement about code that exists. §3's staleness check
makes the *names* safe to keep; (C) makes most of them unnecessary. **These are
alternatives in emphasis, not in sequence** — §3 should land either way, and §4
is worth doing only if the (C)-is-always-right argument survives a second look.

**Recommended: §3 first and on its own.** It is small, it is purely additive,
and it makes every list self-policing including the two that are empty. §4 is a
separate decision about how much the gate should infer, and it should not ride
in on the back of a bug fix.

## 5. What this does not claim

- Not that any entry is stale today. Three live exempt entries, 22 named
  entries, all checked, all current.
- Not that these five are every list the gate trusts. They are every
  `*_EXEMPT`-style list in `route-contracts-check.sh`; other scripts were not
  enumerated, and **this RFC does not state a number for them** rather than
  quoting one it has not derived.
- Not that RFC 163's three route extractors are addressed. Different fact,
  different RFC, still the owner's fork.
