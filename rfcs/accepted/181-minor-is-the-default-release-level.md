# RFC 181 — Minor is the default release level; patch is the exception that must argue for itself

**Status.** **Accepted 2026-11-07** — the owner's own proposal, in the owner's
words: *"Wouldn't it be possible to just set the default release target to a
minor version at the time of scheduling or the scope of the next release, and
apply it in exceptional cases where it corresponds to a patch version or major
version update?"* Accepted the same day with *"Accepted. Proceed."*
**Tier.** **P2.** Nothing is broken at runtime. The project's release numbers
have twice stopped meaning what its own documentation says they mean.
**Size.** **Small.** Four documentation edits and one superseded ruling. No code.
**Touches.** `ROADMAP.md` §Versioning policy,
`docs/src/expert/contributing.md` §Choosing the version level,
`rfcs/handoffs/TEMPLATE.md`, RFC 168 §4.2.
**Found by.** The owner, 2026-11-07, asking *"Why 0.92.7? Why was it not 0.93?
I do not believe patch versions continue even seven times."*
**Target release.** The next cut, **as a minor under its own rule.**

---

## 1. The measurement that settles it

`contributing.md` §Choosing the version level already states the test —
*"was anything broken before, and is it now fixed? If the honest answer is
'nothing was broken; this is new,' it is a minor"* — and already carries a
worked example of this exact error:

> **The trap, recorded because it was walked into.** 0.81.2 was cut as a patch
> on the reasoning that RFC 130 changed no public API. It produced a deployable
> frontend bundle for the first time, pinned the toolchain, added a `wasm-opt`
> pipeline step and **added CI gates — new capability throughout**, and no part
> of it a fix. **It should have been 0.82.0.**

Audited against that test, the `0.92.x` run is **six misleveled releases out of
seven**:

| release | what it carried | correct |
|---|---|---|
| `0.92.1` | RFC 172 made `POST /webauthn/register/start` require a session **and** a `Content-Type` where it required neither — every caller must change or break | **minor** |
| `0.92.2` | added `credentialed-flows.yml`; workflow files **14 → 15** | **minor** |
| `0.92.3` | **removed two live URLs**, `POST /admin/console/config/log_level/{preview,apply}` — registered in `lib.rs` at `0.92.2`, absent after; `route-contracts.md` rows **194 → 192** | **minor** |
| `0.92.4` | RFC 175 — a fix, nothing added | **patch** ✓ |
| `0.92.5` | **E7**, a new blocking gate; its own defects were exempted, so the release shipped no fix | **minor** |
| `0.92.6` | colour fix **and** two new gates — mixed takes the higher level | **minor** |
| `0.92.7` | stylesheet fix **and** the census gate, plus a reporting step restored to blocking | **minor** |

Nothing else moved across the run: `wrangler.toml` **35** vars / **12**
sections unchanged, `cesauth-core` **28** `pub mod` unchanged, no migration
added, no permission slug added.

**And this is the second run, not the first.** `scripts/drift-scan.sh:730`
carries an exemption recording that **five patch releases, `0.79.1`–`0.79.6`,
added seventeen registered routes** during RFC 115 Phase C. Same error, eight
times larger, already on the record.

## 2. Why the rule cannot be fixed by writing it better

The rule is **already written, already correct, and already illustrated with
this precise mistake.** It still failed six times in seven, by an architect who
had read it, four days after accepting RFC 168 — an RFC whose entire subject is
that these release rules are unenforced.

So the variable is not the wording. It is **which way the rule fails when the
deciding step is skipped.** Today, deciding the level means scanning seven
triggers and concluding "none, therefore a patch." Skip it and you get a patch
— the harmful answer. The error costs are not symmetric:

- **Under-leveling** ships a caller-breaking change under a number that
  promises compatibility. It is silent, it reaches integrators, and it cannot
  be corrected afterwards because tags are immutable.
- **Over-leveling** spends a minor number. At `0.y.z`, where SemVer imposes no
  obligation at all (§4, scoped `x > 0`), that costs nothing but a digit.

**A default should fail toward the cheap error. Ours fails toward the expensive
one.** Inverting it is the whole fix.

## 3. The rule

**At scheduling time, the next release is a minor.** No argument required; no
trigger need be found.

**Patch is a claim that must be argued in writing, at scheduling, in the
dispatch handoff**: *everything in this release is a fix or internal-only, and
no caller must change anything.* Silence means minor.

**Major is unchanged** and stays the owner's: `1.0` is undeclared, unscoped and
undated, and this RFC neither moves toward it nor sets a condition for it.

**This rule is scoped to the `0.y.z` era and expires at `1.0`.** After `1.0` the
economics reverse — a minor bump then obliges a consumer to re-read, and the
asymmetry §2 relies on no longer holds. Stated here so a successor finds the
expiry written down rather than discovering it.

## 4. What this makes cheap, which was the point of RFC 168

RFC 168 has carried three unbuilt checks since 2026-10-31, through seven
releases. The reason they stayed unbuilt is that **detecting the old triggers
mechanically is hard**: "a new route surface", "a new permission slug" and above
all "caller obligation" are judgements, not greps.

Under this rule the check collapses to something a script can do:

> **Did the minor number increase? If not, is there a recorded patch argument
> for this release?**

Two conditions, both mechanical. The judgement moves to where a human is
already writing prose — the handoff — and the gate only has to check that the
prose exists when the number says it must. **That is the first version of this
check that is actually buildable**, and it is why this RFC is a prerequisite for
RFC 168's §4.2 check rather than a parallel idea.

It also retires an argument that should never have reached the owner. Whether
"a new blocking CI gate" is a minor trigger was **put to the owner on
2026-11-07 as a rubric decision**; `contributing.md`'s 0.81.2 trap had already
answered it, and under this rule the question cannot arise, because minor needs
no trigger.

## 5. Deliverables

1. **`ROADMAP.md` §Versioning policy** — invert the default. Keep the existing
   trigger list, demoted from *"what earns a minor"* to *"examples of what
   cannot be a patch"*, and keep the caller-obligation test as the patch
   argument's bar.
2. **`docs/src/expert/contributing.md` §Choosing the version level** — the same
   inversion, the 0.81.2 trap kept verbatim (it is the precedent), and the
   `0.92.x` audit added beside it as the second worked example.
3. **`rfcs/handoffs/TEMPLATE.md`** — the `Target release` field becomes *minor
   unless a patch argument is given here*. The template is the artifact a
   dispatch actually touches; RFC 168 §4.2 put the same requirement in an RFC
   and it was skipped four days later.
4. **RFC 168 §4.2 superseded in part** — its ruling that a handoff names the
   level and its trigger stands; *"none, therefore a patch is an argument to be
   made, not a default"* is replaced by this RFC, which removes the default it
   was guarding against.

## 6. Non-goals

- **No retagging.** `0.92.1`–`0.92.7` are shipped, signed, immutable artifacts.
  §Versioning policy already settles this class as historical debt, and RFC 168
  is forward-looking at the owner's direction — *"I care about ruling, workflow
  and guidelines for the future."*
- **No change to what a major means**, and no claim about when `1.0` happens.
- **No claim that SemVer requires this.** At `0.y.z` it requires nothing; this
  is the project's own rubric, held to its own account.
- **Not a throughput change.** The architect proposed pairing this with a rule
  about enforcement debt competing with feature work; the owner declined the
  broader framing, and this RFC is the narrow change that was asked for.

## 7. One interaction, noted not fixed

RFC 028 splits the CHANGELOG archive **by minor range**. Under a minor default
each minor is roughly one release, so archive files will group a handful of
releases rather than dozens, and names like `CHANGELOG-0.93-to-0.95.md` replace
the `CHANGELOG-0.88-to-0.88.md` shape the byte-driven split has started
producing. **Cosmetic, and tidier than the status quo.** No change proposed;
recorded so the next split is not read as a defect.
