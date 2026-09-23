# RFC 144 — Introspection reveals that a token family exists

**Status.** Proposed
**Tier.** P3 · Category B — a narrow information leak to an authenticated caller.
**Size.** Small.
**Touches.** `crates/core/src/service/introspect.rs`, its tests.
**Found by.** The RFC 139 review, 2026-09-16.

## 1. Why this RFC exists at all

**Because the finding was already lost once.** It was recorded in the RFC 139
review as "for RFC 118", RFC 118 shipped without it, and the 2026-09-24 state
review found it homeless. "Recorded for a later RFC" is not a record. A number
is.

## 2. The finding

`introspect_refresh` classifies a family **before** comparing the presented
token id:

1. `expired` (stored, or computed from the lifetime policy);
2. `revoked`;
3. only then the jti comparison, which distinguishes `retired` from `unknown`.

So a caller presenting a **forged** token id against a **real** family id learns
`expired` or `revoked` — that the family exists — where a forged id against a
nonexistent family returns `unknown`. The jti-mismatch path already conflates
"family exists, wrong jti" with "no such family" **precisely to avoid this**
(`service/introspect.rs`, the `FamilyClassification::Unknown` branch and its
comment); the expiry and revocation paths do not.

**It is narrow.** The caller must be an authenticated confidential client
(`/introspect` authenticates before classifying), and must already know a
family id, which is a UUIDv4 obtainable only by having held one of its tokens.
It was true of `revoked` before RFC 139 and is now also true of `expired`.

## 3. Proposed design

Surface `expired` and `revoked` **only when the presented jti is the current one
or is in the retired ring** — the same test the mismatch path already applies.
Otherwise return `unknown`, as that path does.

The alternative — accept the leak and document it — is legitimate and cheaper,
and should be chosen deliberately rather than by default if the ordering turns
out to carry weight elsewhere.

## 4. Non-goals

- No change to what a *legitimate* holder sees: current and retired jtis keep
  their present classifications, including `revoked_at` and the reason.
- Not the `x_cesauth` extension's shape.

## 5. Testing strategy

- A forged jti against a real expired family, and against a real revoked
  family, return `unknown` with no `revoked_at`.
- A current jti and a retired jti are unchanged, with a test for each existing
  classification.
- The fires pair: restore the old ordering and show the tests go red.

## 6. Acceptance criteria

1. Existence is not distinguishable through classification for a caller who
   cannot present a jti the family has issued.
2. No existing introspection assertion is weakened.

## 7. Level

**Patch.**
