# ADR-020: Security assurance posture — the Category taxonomy and the adopt/pilot/defer/reject direction

**Status**: Accepted
**RFC**: the security-critical assurance track (RFCs 116–124), ADR-019
**Date**: 2026-11-14

## Context

**This ADR exists because the content below was load-bearing in this repository
and stored outside it.** Audited 2026-11-14 on the owner's instruction that the
documentation be self-contained:

- `**Tier.** PN · Category X` is a **header field on 64 RFCs** — measured, 9 at
  P0, 32 at P1, 20 at P2, 3 at P3 (two carry a split tier) — and
  `rfcs/README.md` carries `Tier` and `Category` as **table columns** across its
  index.
- The definitions of Category A–D lived **only** in an architect instruction,
  `security-critical-assurance-strategy-v.0.80.2.md`, which is **not tracked by
  git** — `git ls-files` over its directory returns 0.
- Nine tracked documents cited it by name and section (`strategy §5.2`, `§5.5`,
  `§6`, `§8`, `§9`, `§12`), including this book, `rfcs/README.md`, `ROADMAP.md`
  and five RFCs.

So a reader of cesauth could see every RFC classified and **could not learn what
the classifications meant.** That is the defect this ADR closes.

**Nothing here is new policy.** §1 and §2 reproduce the strategy's own §6 and
§12; §3 reproduces its §9. What *is* new is §4, flagged as derived rather than
recovered, because no source document defines it.

**What was deliberately not copied**: the strategy's §5 target-area analysis
and §10–§11 deliverables, which are working material rather than definitions the
repo cites — **except the two §5 invariants that tracked RFCs cite as
authority**, which are in §5 below. The strategy remains private; the repository
no longer depends on reading it.

## Decision

### 1. The Category taxonomy (strategy §6)

Every assurance candidate is classified into exactly one:

| Category | Meaning | Examples as given |
|---|---|---|
| **A** | **Must implement now** — high-risk, high-value, low-to-moderate complexity | newtypes for tenant and subject IDs; private constructors for validated token objects; property tests for refresh-token rotation; DB uniqueness constraints for one-time code consumption |
| **B** | **Implement soon** — valuable, but needs more refactoring or sequencing | full state-machine tests for session lifecycle; tenant-scoped repository API redesign; audit-required operation wrappers |
| **C** | **Pilot only** — may be valuable, but must prove maintainability first | Kani for small pure authorization functions; a TLA+ model for refresh-token rotation; Flux for selected refinement-style checks |
| **D** | **Defer / do not adopt** — cost likely exceeds benefit at this stage | Verus across the whole codebase; typestate for all UI state; formal verification of repository/database logic; broad policy-engine migration without demonstrated need |

**A Category C item carries a verdict obligation**: adopt narrowly, defer, or
reject. ADR-019 is the worked instance, and records that **reject is a success**.

**The label is overloaded in one place**, noted so a reader is not misled:
`rfcs/done/104-audit-summary-index.md` uses "Category A–D" for an unrelated
code-hygiene taxonomy (duplicated logic / bloated files / boilerplate / dead
code). It predates this scheme and is not governed by this ADR.

### 2. The standing direction (strategy §12)

> Use Rust's type system and property-based testing as the primary assurance
> foundation. Use typestate only for security-critical lifecycle transitions.
> Use fuzzing for untrusted input boundaries. Use database constraints and
> transactions as part of the security design. Use lightweight
> formal/model-checking pilots only where the value is clear. Do not adopt broad
> formal verification unless the codebase later justifies it.

Default classification of techniques:

- **Adopt**: newtype, private constructor, smart constructor, typestate for
  selected lifecycle objects, `proptest`, state-machine tests, fuzzing, DB
  constraints.
- **Pilot**: TLA+, Kani, possibly Flux.
- **Defer**: broad Flux adoption, policy-engine migration.
- **Reject for now**: broad Verus adoption, whole-application formal
  verification.

**Verus's position is ADR-019**, which is a specialisation of this row and does
not reopen it.

### 3. Design guidance (strategy §9)

**Prefer** designs that keep the core domain model small; keep the authorization
core pure where possible; convert raw API inputs into validated domain types at
boundaries; avoid exposing raw strings for security-sensitive values; use
database constraints as part of the security model; use transactions for state
transitions that must be atomic; keep typestate localized to lifecycle-heavy
security objects; avoid typestate explosion; and **avoid making normal feature
development difficult.**

**Avoid** designs that encode every business rule in the type system; require
developers to understand advanced formal verification for routine changes; move
too much application behaviour into generic abstractions; make simple CRUD flows
unnecessarily complex; treat property-based tests as a replacement for normal
integration tests; or **treat formal methods as a substitute for threat
modeling or security review.**

The last item in each list is the one this project has had to invoke most often,
and the "ceremony creep on simple CRUD" warning is cited by name in RFC 123.

### 4. The Tier scheme — derived from usage, not recovered

**No document defines `P0`–`P3`.** It is absent from the strategy and absent
from this repository, while appearing on **64** RFC headers and in
`rfcs/README.md`'s index columns. **So this section is a derivation from how the
corpus actually uses it, and it is labelled as such rather than presented as
recovered policy.** If the owner intended different boundaries, this is the
place to correct them.

| Tier | As used | Count | Enumerated |
|---|---|---|---|
| **P0** | Security-critical, or blocks the assurance track; ships before the work that depends on it | **9** | 116, 117, 118, 120, 125, 127, 130, 155, 172 |
| **P1** | Important and scheduled; a real defect, or a policy the project needs | **32** | 119, 120, 121, 122, 123, 126, 128, 131, 132, 141–143, 145–150, 152–155, 158, 161–163, 166, 171, 173–175, 178 |
| **P2** | Valuable, not urgent; may wait on tooling or environment | **20** | 124, 133, 151, 156, 157, 159–161, 164, 165, 167–170, 174–177, 179, 181 |
| **P3** | Narrow or filler; recorded so it is not lost, scheduled when convenient | **3** | 144, 180, 183 |

Produced by `grep -rl '^\*\*Tier\.\*\*.*PN' rfcs/*/*.md`. **RFCs 120, 155, 161,
174 and 175 appear in two rows** — they carry split tiers (`P0/P1`, `P1/P2`) in
their own headers, which the scheme permits and which is itself evidence that
the boundaries are soft.

**Tier and Category are independent axes.** Tier is urgency; Category is whether
the *technique* is adopted, sequenced, piloted or declined. RFC 183 is the clear
illustration: **P3** (narrow, filler-scheduled) and **C** (pilot with a verdict
obligation).

### 5. Named invariants the corpus cites as authority

Two claims from the strategy's §5 are cited by tracked RFCs as the *reason* for
a design decision, so they belong here rather than in a file nobody can open.

- **Authorization ordering (strategy §5.5), cited by RFC 120**:
  > Tenant boundaries must be enforced before role-specific permissions.

  Also from §5.5, and load-bearing in the same place: system administrator,
  tenant administrator, resource owner and ordinary user roles **must not be
  confused**, and subject, action, resource, tenant and permission each get a
  newtype.

- **Refresh-token lifecycle (strategy §5.2), cited by RFC 118**: the listed
  important invariants are **typestate for `Active`, `Rotated`, `Revoked` and
  `Expired`**, plus an **optional** TLA+ model *if the lifecycle is complex or
  concurrency-sensitive*.

**Correction, 2026-11-14 — a citation that misreads its own source.**
`rfcs/done/118-refresh-rotation-assurance.md:83` declines a typestate wrapper
"(strategy §5.2 lists typestate as *optional*)". **It does not.** §5.2 lists
typestate among its important invariants; the word *optional* attaches to the
**TLA+ model**. RFC 118's decision is unaffected and stands on its own stated
reasoning — a host-side typestate would assert state the host cannot know,
because the lifecycle authority lives inside the Durable Object — but the
supporting citation was wrong, and **it was wrong for two releases with no way
for any reader of this repository to notice**, because the cited document was
not in it. That is the clearest argument for the rule in §Consequences.

## Consequences

Every `Tier · Category` header in this repository can now be resolved from
within it. `rfcs/README.md` carries the same definitions at the point of use.

**The standing rule this ADR is the first application of** — see
`docs/src/expert/contributing.md` §Documentation self-containment: **normative
content that tracked files depend on must live in a tracked file.** A citation
to untracked material is allowed only as a pointer to *evidence*, never as the
authority for a definition or a decision.

## See also

- ADR-019 — formal verification's position, a specialisation of §2's last row
- `rfcs/README.md` — the Tier/Category columns, defined at the point of use
- `docs/src/expert/contributing.md` §Documentation self-containment — the rule
