# Developer Handoff — RFC 171 §3 Q1: split E7's two shapes and green the gate

**Governing RFC.** [`rfcs/accepted/171-the-arm-is-written-and-the-error-is-never-produced.md`](../../accepted/171-the-arm-is-written-and-the-error-is-never-produced.md)
**Review.** `.git-exclude/reviewed/171-q1-check-review.md` — **§2 and §3 are
this cycle's whole reason.**
**Builds on.** `e6ab206` on `main`. **Nothing from it is reverted.**

**Target release.** **Patch — the same cut as `e6ab206`.** **The cut is blocked
until this lands**: `Route contracts check` is **failing on `main` right now**
(13/14), and a red release gate blocks every cut.
**Tier.** **P1** — not for the finding, for the red gate.
**Trigger: none.**

**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. **Dispatched 2026-11-04.**

**On 1.0:** not declared, not scoped, not dated.

---

## 1. First, what went wrong is mine

The check is right and stays. **My handoff said "build the check" and "do not
fix anything the check finds" and named no exemption mechanism** — three
instructions that cannot all hold in a green tree. The only possible outcome was
a red release gate. You built exactly what was asked.

**The project's answer already existed**: `E6_BEARER_LEGACY_EXEMPT` ships E6
with 18 known-unfixed rows — named, dated, each with a reason, staleness-checked
so an entry that stops matching is a hard failure, under a comment saying the
list **must shrink as each is actually fixed**. Copy that, not its absence.

## 2. Split the two shapes before exempting either

**Of the 31, 26 are credited with all five variants** —
`{Conflict, NotFound, PreconditionFailed, Serialization, Unavailable}` — because
`port_error_response` names every one. That is one structural fact, not 26
diagnoses: any method routed through it is a DEFECT unless its adapter produces
all five, and none does.

**And `port_error_response` maps `Unavailable` and `Serialization` to the same
`server_error()`** (`api_v1/auth.rs:76-83`), so for a method producing only
those two, every outcome it *can* reach is correct and the unreachable arms
promised nobody anything.

**The census drew this line and the check erased it** — it classed these as
*"`DEFECT (chokepoint)`, distinct from the `written` shape"*. Restore the
distinction **in the output**:

- **`chokepoint`** — every variant the caller matches comes from a shared
  dispatcher arm that maps it identically to another variant the producer *can*
  emit. No distinct outcome is lost.
- **`written`** — the caller has a **distinct** outcome (a different status, a
  different message, a different branch) for a variant the production adapter
  cannot produce. **These are the ones with a reader.** Today they are the five
  `ClientRepository` methods — `find`, `list`, `update`, `set_secret_hash`,
  `delete` — matching `{Conflict, NotFound}` through `ClientOpError`'s
  conversion, with distinct 404 and 409 behaviour.

**Print both counts.** `31 DEFECT` becomes something like
`5 written + 26 chokepoint`, and the arithmetic still closes to 156.

**If the split does not fall 5/26**, report what it falls at and why — my 5/26
came from counting which rows are credited with all five variants, which is a
proxy for the real test (*does the caller lose a distinct outcome?*), not the
test itself. **Yours is the real one; mine was the cheap one.**

## 3. Then exempt, by name, with reasons

Two lists, not one — the shapes have different futures:

- **`E7_WRITTEN_EXEMPT`** — the five. Each entry dated, with its reason, and a
  comment saying these are the ones that **should shrink first**, because each
  is a caller promising an outcome it cannot deliver.
- **`E7_CHOKEPOINT_EXEMPT`** — the twenty-six. Each named. One shared reason is
  enough here *provided it is the real one*: the caller's match comes from a
  shared dispatcher arm that maps the variant identically, so no distinct
  outcome is lost. **Say that the residual the census left open (~50 dispatcher
  sites, 3 traced) is now fully enumerated** — that is what this list is.

**Both staleness-checked**, per RFC 165 §3 and your own §2 discipline: an entry
that stops matching is a hard failure, not a silently-kept line. **The gate must
go green with the lists in place, and red again if any entry goes stale or a new
DEFECT appears outside them.** That last property is the whole point — a new
`written` defect must fail the build.

## 4. Stop conditions

- **The 5/26 split does not survive the real test** — report the true split and
  do not force mine.
- **Any of the 26 turns out to lose a distinct outcome** after all — then it is
  `written`, and say so; the classification matters more than the count.
- **The gate cannot be made green without exempting something that should fail**
  — stop. A gate that passes by exempting a real defect is worse than a red one.
- Exempting requires touching E3–E6 or any figure outside E7.

## 5. Not in this cycle

- **Fixing any of the 31.** Each is its own sizing decision (RFC 171 §4),
  RFC 175 the precedent.
- **Q2.** Untouched.
- **The `e6_mechanism_check` staleness extension**, still queued separately.

## 6. Baselines at `e6ab206`

Everything as at tag `0.92.4` (`4a4cdad`) except the gate itself:

- host tests **1,675 / 0 / 4 / 12 lines**; `migration_chain` **35**;
- `route-contracts-check.sh` → **exit 1**, E3–E6 unchanged, E7
  `156 = 8 resolved + 31 DEFECT + 117 no_caller`. **Exit 0 is this cycle's
  deliverable.**
- `drift-scan.sh` clean; `mdbook build docs` clean, 82 pages; Playwright **20**
  against a warm server; `runtime-smoke-check` passed;
- bundle **888,890 B** gzip 1.15 **default level** — **expect it unchanged**.

**Keep the report short.** `CHANGELOG.md` is one entry from RFC 028's guard and
the entry is mine to write at the cut; your report does not need to carry the
census's detail a second time.
