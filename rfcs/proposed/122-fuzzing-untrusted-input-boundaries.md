# RFC 122 — Fuzzing strategy for untrusted input boundaries

**Status.** Proposed
**Tier.** P1 · Category B
**Size.** Medium
**Tracks.** Strategy §5.8, §8 (RFC theme 7); audit G7. Extends RFC 005.
**Touches.** `fuzz/` (new targets + corpora), small refactors in
`core::oidc::authorization` / `core::magic_link` / `core::jwt::jwks`
only where a parse function needs a pure, fuzz-callable entry.

## 1. Summary

Grow the fuzz suite from one target (`jwt_parse`, RFC 005) to the full
set of hostile-input parsers: redirect-URI validation, `/token` request
body, Magic Link handle+OTP submission, JWKS/JWK parsing, OIDC
`/authorize` query parsing, and `Accept-Language` negotiation. Add
differential fuzzing for PKCE verification and a structure-aware
strategy for the challenge-handle alphabet.

## 2. Motivation

Every listed surface consumes bytes chosen by an unauthenticated
attacker before any auth decision. Panics in a Worker abort the request
but, worse, parser confusions (URI normalisation differences,
truncation, mixed encodings) become authorization bypasses — redirect
URI validation in particular guards the code-delivery step of OIDC.
The existing jwt_parse target proved the infrastructure (nightly,
out-of-workspace per Cargo.toml note); this RFC is scale-out, not
invention.

## 3. Background

`fuzz/` exists with cargo-fuzz layout and a corpus directory, excluded
from the stable workspace. Redirect-URI logic already has proptests
(RFC 003) — fuzzing complements them with coverage-guided, grammar-free
exploration and longer time budgets.

## 4. Target code areas

New targets under `fuzz/fuzz_targets/`:

| Target | Entry (pure fn) | Property checked |
|---|---|---|
| `redirect_uri_validate` | `oidc::authorization::validate_redirect_uri` | no panic; **never** accepts a URI that differs from a registered one under the documented exact-match rule (differential vs a byte-equality oracle) |
| `token_request_parse` | form-body → token-request DTO | no panic; parse-then-serialize stability |
| `magic_link_verify_input` | handle + OTP submission parsing | no panic; rejects out-of-alphabet handles before storage access |
| `jwks_parse` | `jwt::jwks` document parsing | no panic; only Ed25519 keys with valid lengths ever load |
| `authorize_query_parse` | `/authorize` query → PendingAuthorize fields | no panic; unknown params ignored, never field-bleed |
| `pkce_verify_differential` | `pkce::verify` | agreement with an independent 5-line S256 oracle; constant result regardless of where strings differ |
| `accept_language_negotiate` | i18n locale negotiation | no panic; result ∈ supported-locale set |

## 5. Security properties / invariants

1. No panic/abort on any input on any listed surface (Workers
   availability invariant).
2. Differential targets: implementation agrees with the simple oracle
   on accept/reject for all explored inputs.
3. Parsers reject before side effects: malformed input must not reach
   a port call (asserted with a panicking stub store inside the fuzz
   harness).

## 6. Non-goals

- Fuzzing the WebAuthn library internals (upstream's responsibility;
  we fuzz only our wrapping/parse layer if/when one exists).
- Fuzzing D1/SQL (parameterised queries; no string assembly to fuzz).
- CI-integrated continuous fuzzing infrastructure (OSS-Fuzz style) —
  out of scope; a `make fuzz-smoke` (60 s/target) is the regression
  gate, long runs are manual/nightly.

## 7. Proposed design

- One pure entry function per surface; where the current code couples
  parsing with port access, extract a `parse_*` function (refactor is
  behaviour-preserving and unit-test-pinned).
- Seed corpora from existing unit-test vectors (script:
  `scripts/fuzz-seed-corpus.sh` extracts string literals from the
  relevant `tests.rs`).
- Structure-aware mutators via `arbitrary` impls for the token-request
  and authorize-query DTOs, so the fuzzer spends time past the
  serde boundary.
- Findings workflow: every crash/divergence becomes (a) a regression
  unit test in the stable workspace, (b) a corpus seed — so the stable
  suite holds the line even though fuzz runs are nightly-only.

## 8. Data model impact

None.

## 9. API impact

None.

## 10. Testing strategy

`make fuzz-smoke`: each target 60 s, zero findings required. Manual
deep runs (≥ 1 h/target) before each minor release during this track;
results logged in the RFC closing note.

## 11. Migration strategy

Additive; small extractions noted in §7 land first with unit tests.

## 12. Rollout plan

After RFC 117 (pipeline gives clean pure entries for token parsing).
Findings ship as fixes in the same release, CHANGELOG security section.

## 13. Risks and mitigations

- **Nightly toolchain drift** breaking fuzz builds → fuzz dir already
  isolated from the stable lockfile; pin nightly in
  `fuzz/rust-toolchain.toml`.
- **Oracle wrong in differential targets** → oracles are ≤ 10 lines and
  quoted in full inside this RFC series' review.

## 14. Acceptance criteria

1. Seven targets build and run; smoke target green in `make`.
2. Each target's invariant assertions present (not just no-panic).
3. Corpus seeded; `DEPENDENCIES.md` notes the `arbitrary` dev-only
   addition.
4. At least one 1-hour run per target completed and logged before the
   RFC moves to `done/`.

## 15. Open questions

- Run fuzz smoke in CI? Depends on CI nightly availability — same
  env-blocked class as RFC 110a; smoke stays a local `make` target
  until resolved.
