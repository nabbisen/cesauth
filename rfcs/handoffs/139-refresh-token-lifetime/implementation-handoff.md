# Developer Handoff — RFC 139, refresh-token lifetime (P1)

**Governing RFC.** [`rfcs/accepted/139-refresh-token-lifetime.md`](../../accepted/139-refresh-token-lifetime.md). Read **§9 and §10**. They supersede §5, §7 and §8.
**Target release.** 0.84.0. **Level: minor.** Enforcing the configured absolute
lifetime is a fix, but the idle window and `REFRESH_TOKEN_IDLE_TIMEOUT_SECS`
are a new control, and a release mixing levels takes the higher one.
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. RFC 140 has landed on `main`, and this RFC builds on it.

---

## 1. Purpose

After this, a refresh family stops working at the earlier of two deadlines:

- **absolute:** `created_at + REFRESH_TOKEN_TTL_SECS`;
- **idle:** `last_rotated_at + REFRESH_TOKEN_IDLE_TIMEOUT_SECS`.

The store enforces both, atomically, and records which one ended the family.
Introspection reports the real lifetime from the family, never from the token,
which no longer carries an expiry.

## 2. Why this matters

A leaked refresh token works forever. The 30-day setting is written into an
unsigned field that rotation ignores and introspection echoes back as `exp`
(RFC §1–§3).

## 3. Resolved decisions — do not re-open

| Decision | Ruling (RFC §) |
|---|---|
| Model | Idle window **and** absolute cap (§9.1) |
| Boundary | Expired iff `now_unix >= deadline` (§9.1) |
| Defaults | Absolute stays `REFRESH_TOKEN_TTL_SECS` (30 d). Idle `REFRESH_TOKEN_IDLE_TIMEOUT_SECS` defaults to **1 209 600** (14 d). Idle `0` disables the idle check; absolute cannot be disabled (§9.1) |
| Config validation | Refused at startup if absolute ≤ 0, idle < 0, or idle > absolute (§9.1) |
| Where deadlines come from | Computed at check time from `created_at` and `last_rotated_at` with the **current** policy. **No deadline is stored** (§9.2) |
| One decision function | A pure function in core, used by the DO, the oracle and introspection (§9.2) |
| Enforcement | In `rotate`, in the store. Expiry sets `revoked_at` **and** `expired` in one write (§9.3, §10.1) |
| Check order in `rotate` | revoked → absolute → idle → jti match or reuse (§10.2) |
| Expired plus retired jti | **Expired**; reuse fields stay `None` (§10.2) |
| Wire | `invalid_grant`, the same as a revoked family (§9.3) |
| Token format | `base64url("{family_id}.{jti}")`. All three decoders accept **exactly two** parts (§9.4) |
| Introspection | `FamilyClassification::Expired`; read-only; `exp` = earlier deadline (§9.4, §10.3) |
| Audit | No new event kind (§10.4, RFC 123) |
| Existing families | No migration; they are governed from the first request (§9.2) |

## 4. Facts already measured — do not re-derive

| Fact | Where |
|---|---|
| `FamilyState` has `created_at`, `last_rotated_at`, `revoked_at`, and the `#[serde(default)]` reuse fields the new `expired` should sit beside | `core/src/ports/store.rs:163-204` |
| `RotateOutcome` has `Rotated`, `AlreadyRevoked`, `ReusedAndRevoked` | `ports/store.rs:236-262` |
| Port `rotate(family_id, presented_jti, new_jti, now_unix)` | `ports/store.rs:271-277` |
| The only production `rotate` caller | `core/src/service/token.rs:364`; peek and client check precede it (`:342-360`, RFC 137) |
| Service maps outcomes | `service/token.rs:369`, `:440`, `:443` |
| Oracle `rotate` | `adapter-test/src/store/refresh_token_family.rs:46-90` |
| DO `Command::Rotate` / adapter `FamilyCmd::Rotate` — **two separate enums** | `adapter-cloudflare/src/refresh_token_family.rs:21, :98`; `adapter-cloudflare/src/ports/store/refresh_token_family.rs:17, :84-91` |
| **Precedent to mirror**: session DO `Touch` checks revoked, then absolute, then idle, and revokes in the same write | `adapter-cloudflare/src/active_session.rs:73-97`; port `touch` at `ports/store.rs:357-363` |
| `encode_refresh` writes the expiry; `TokenConfig.refresh_ttl_secs` is its only use | `service/token.rs:470-475`, `:66`, `:213`, `:405`; set at `backend/src/routes/oidc/token.rs:96` |
| Three decoders | `service/token.rs:477` (ignores part 3), `service/introspect.rs:412` (**reads part 3 as `exp`**), `service/revoke.rs:333` |
| Introspection ignores `now` and passes the token's `exp` | `service/introspect.rs:285-289` (`_now`), `:397-405`; called at `:93`; backend builds its input at `backend/src/routes/oidc/introspect.rs:206` |
| Revoked families are classified by `reused_jti` only | `service/introspect.rs:333-350`; enums at `oidc/introspect.rs:233-274` |
| Config: `REFRESH_TOKEN_TTL_SECS` via `var_parsed`; session idle via `var_parsed_default` | `backend/src/config.rs:134`, `:142`; `wrangler.toml:128` |
| Test helpers build three-part tokens | `service/introspect/tests.rs:75`, `service/revoke/tests.rs:106` |
| Docs naming the TTL | `docs/src/expert/oidc-tokens.md:144`; `deployment/secrets.md:79, :101`; `runbook.md:235`; `disaster-recovery.md:369`; `wrangler.md:65`; `preflight.md:131`. The format comment is at `service/token.rs:464` |

*If any of this fails to reproduce, that is a finding. Report it.*

## 5. Change scope

| # | Task | Files |
|---|---|---|
| L1 | **Policy and decision function.** `RefreshLifetime { absolute_secs, idle_secs }` with a validating constructor (§3 rules). `LifetimeExpiry { Idle, Absolute }` (serde, snake_case). `FamilyState::lifetime(&self, now_unix, &RefreshLifetime) -> Lifetime { Live, Expired(LifetimeExpiry) }` and `FamilyState::deadline(&self, &RefreshLifetime) -> i64`, absolute checked before idle. **Unit tests at every boundary** (§9 tests 1–3) | `core/src/ports/store.rs` (or a new `core/src/refresh_lifetime.rs` re-exported there) |
| L2 | **Store contract.** `FamilyState.expired: Option<LifetimeExpiry>`, `#[serde(default)]`, set in `init` to `None`. `rotate` gains `lifetime: &RefreshLifetime`. `RotateOutcome::Expired(LifetimeExpiry)`. Contract doc states §3's order | `ports/store.rs` |
| L3 | **Oracle** implements the order using L1's function. **Contract tests** (§9 tests 4–7) | `adapter-test/src/store/refresh_token_family.rs`, `store/tests.rs` |
| L4 | **DO and adapter.** `Rotate` carries `absolute_secs` and `idle_secs` on **both** enums; the DO calls L1's function; the reply gains `Expired { kind }` | both `refresh_token_family.rs` files |
| L5 | **Service.** `TokenConfig.refresh_ttl_secs` becomes `refresh_lifetime: RefreshLifetime`. `rotate` receives it. `RotateOutcome::Expired(_)` becomes `InvalidGrant("refresh token expired")`. `encode_refresh(family_id, jti)`. `decode_refresh` requires exactly two parts | `service/token.rs`, `service/token/tests.rs` |
| L6 | **Introspection.** Input carries the policy. `decode_refresh_token` returns `(FamilyId, Jti)`, exactly two parts. Classification per §10.3. Active `exp` is `deadline()`. `FamilyClassification::Expired` added | `service/introspect.rs`, `oidc/introspect.rs`, introspection tests |
| L7 | **Revoke decoder** accepts exactly two parts | `service/revoke.rs`, `service/revoke/tests.rs` |
| L8 | **Config.** `REFRESH_TOKEN_IDLE_TIMEOUT_SECS` via `var_parsed_default(…, 1_209_600)`. Build `RefreshLifetime` once at load and fail startup on an invalid pair. Pass it to `/token` and `/introspect`. Add the var to `wrangler.toml` beside `:128` with a comment | `backend/src/config.rs`, `routes/oidc/token.rs`, `routes/oidc/introspect.rs`, `wrangler.toml` |
| L9 | **Docs.** Both vars with their real meaning (absolute cap, idle window, `0` disables idle) in `oidc-tokens.md` and `secrets.md`. The format comment at `token.rs:464`. Each of the other TTL mentions in §4 **read in context**: keep if still true of the absolute cap, correct if not. Report each disposition. Note the idle var in `wrangler.md` and `preflight.md` | as listed |

**Order: L1 → L2 + L3 (fires pair) → L4 → L5 → L6 → L7 → L8 → L9.** L1 is pure
and fully testable first. L2 breaks the oracle, the DO and the service at once;
the oracle is what proves the rule, so make it green before touching the DO or
the service.

## 6. Explicit non-change scope

- **Not RFC 117** (typestate), **not RFC 118** (rotation assurance), **not RFC
  123** (new audit kinds).
- No change to access-token or id_token lifetimes, rate limiting, reuse
  detection's existing forensics, RFC 137's client binding, or the challenge
  store (RFC 140).
- No cron sweep of expired families and no DO alarm. Expiry is enforced at
  rotation. Storage cleanup is a separate question, and it is not asked here.
- No signing or encrypting of the refresh token (RFC §4).
- **No browser-suite blocking flip.** It is also 0.84.0 content, but separate
  work.
- No route strings. No `cargo fmt`. **Do not open `.dev.vars`.**

## 7. The traps — each compiles and ships the defect

**7.1 One side of the DO wire.** `FamilyCmd::Rotate` and `Command::Rotate` are
separate types in separate crates. A policy field on one side only compiles
and fails at runtime. RFC 140 §7.3, same lesson. The live run in §9 is the
proof.

**7.2 A policy that silently disables the check.** Passing `0` for
`absolute_secs`, or a `RefreshLifetime` built without the validating
constructor, gives a family that never expires, which is today's defect. Make
the fields private; construct only through the validator. Tests use the
validator too.

**7.3 Re-implementing the arithmetic.** The DO, the oracle and introspection
must all call L1's function. A second `created_at + ttl <= now` anywhere is
a place the three can disagree. §8 checks it.

**7.4 Expiry decided in the service's peek.** The service peeks before rotating
(RFC 137). An expiry check there would race the rotation, and it would not
revoke. **Enforcement is the store's.** The service only maps the outcome.

**7.5 Introspection writing.** Reporting `Expired` for an unrotated family must
not call `revoke`. `/introspect` is read-only.

**7.6 A lenient decoder.** `split('.')` taking the first two parts accepts a
three-part token. "Exactly two" means a third part is malformed, on all three
decoders.

**7.7 `>` for `>=`.** The boundary is `>=`, the same as RFC 140. The session DO's
`<=` form (`created_at + ttl <= now`) is the same rule; do not change it to `<`.

## 8. Mechanical assertions

```sh
# the arithmetic lives in one place
grep -rnE 'created_at *\+|last_rotated_at *\+' crates --include='*.rs' | grep -v '/tests\|tests.rs'
#   → only L1's function (and the session DO, which is not this RFC)

# both sides of the wire carry the policy
grep -n 'Rotate {' crates/adapter-cloudflare/src/refresh_token_family.rs crates/adapter-cloudflare/src/ports/store/refresh_token_family.rs

# no decoder reads a third part
grep -n 'splitn(3\|parts.next()' crates/core/src/service/token.rs crates/core/src/service/introspect.rs crates/core/src/service/revoke.rs

# the unsigned expiry is gone from encoding
grep -n 'fn encode_refresh' -A5 crates/core/src/service/token.rs

# introspection does not revoke
grep -n 'revoke(' crates/core/src/service/introspect.rs || echo "clean"
```

## 9. Required tests and evidence

**New tests:**

*Decision function (L1)*
1. Absolute: `created_at + abs - 1` is Live; `created_at + abs` is `Expired(Absolute)`.
2. Idle: `last_rotated_at + idle - 1` is Live; `+ idle` is `Expired(Idle)`; idle `0` is never idle-expired.
3. Both past: `Absolute` wins. The validator rejects abs ≤ 0, idle < 0, idle > abs.

*Store contract, oracle (L3)*
4. Rotation inside both windows rotates; `last_rotated_at` advances, so the idle window moves.
5. Idle-expired `rotate` → `Expired(Idle)`; `revoked_at` and `expired` set; a later rotate → `AlreadyRevoked`.
6. Absolute-expired while recently rotated → `Expired(Absolute)`.
7. Expired family presented with a **retired** jti → `Expired`, reuse fields `None`.

*Service and introspection*
8. `/token` refresh on an expired family → `InvalidGrant`, same wire as revoked.
9. **Lowering the policy shortens a live family**: rotate under 30 d, then under 1 d past `created_at + 1 d` → expired (§9.2's incident property).
10. Introspection: live family → `active`, `exp` = the earlier deadline, **not** anything in the token.
11. Introspection: family past a deadline, never rotated → inactive `Expired`, and a later `peek` shows `revoked_at` still `None` (read-only).
12. Introspection: DO-expired family → `Expired`, not `Revoked`/`Explicit`.
13. All three decoders reject a three-part token.
14. Config: each invalid pair is refused; the defaults load. Test the pure validator, not `worker::Env`.

**Fires / does-not-fire:** remove the lifetime check from the **oracle** → tests 4–7 red (5, 6, 7 at least); restore → green. Separately, `StubFamilies` in `service/token/tests.rs` is a store too: it must follow the rule (RFC 137 §4.1, RFC 140 T3). Remove its check → test 8 red; restore → green.

**Existing tests.** They change only by passing a policy and building two-part
tokens. **Report any existing test whose `now` falls past a deadline under the
default policy**, before changing anything.

**Live, against `wrangler dev`** (pinned wrangler, `--var WRANGLER_LOCAL:1`, and
for the expiry run also `--var REFRESH_TOKEN_IDLE_TIMEOUT_SECS:5`
`--var REFRESH_TOKEN_TTL_SECS:60`):
- `first-oidc-flow.md` 4b → 4c → 5 still works under default policy;
- under the short policy: exchange, wait 7 s, refresh → `invalid_grant`, and
  `/introspect` on that token reports inactive `Expired`;
- the refresh token returned by 4c decodes to **two** parts (print the part
  count, never the token).

Unlike RFC 140, there is no alarm here to hide the check. This live run
**does** verify the DO's enforcement, and the package may say so.

**Evidence.** You run the full gate set:
- host tests (baseline **1,436**, plus the new ones, stated as the command and
  its summed `test result` lines);
- `migration_chain`, the wasm32 and csr checks, clippy over six crates;
- deny, audit, route-contracts, drift-scan `--verbose`, mdbook;
- `make build-frontend` with `du -b`, gzip **and `sha256sum`**;
- `make build-backend`, runtime smoke, the browser suite, each showing wrangler
  4.131.2.

I re-run the store and token tests, the introspection tests, runtime smoke and
the short-policy live run myself.

## 10. What must NOT be claimed

- Not that expired families are removed from storage. They are revoked and kept.
- Not that expiry is audited distinctly (RFC 123).
- Not that it works on Cloudflare. Miniflare only.
- Not that CI has run it.

## 11. Prohibited shortcuts

- No assertion changed in an existing test; only the policy passed and token
  construction.
- No `#[ignore]`, no `continue-on-error`, no `cargo fmt`.
- No expiry check in the service or a route (7.4).
- No public fields on `RefreshLifetime` (7.2).

## 12. Acceptance criteria

RFC 139 §6 as superseded by §9 and §10. Checked hardest: **test 9** (lowering
the policy takes effect), **test 11** (introspection read-only), **test 7**
(order), and the **short-policy live run** (both sides of the wire).

## 13. Known risks

| Risk | Mitigation |
|---|---|
| DO wire mismatch | 7.1; runtime smoke; live run |
| Arithmetic duplicated and drifting | 7.3; §8 first assertion |
| An operator sets idle > absolute | Startup refusal; test 14 |
| Existing local refresh tokens stop working (three parts) | Expected; no production use. Say so in the package |
| An existing test sat past a deadline | Report before changing (§9) |

**If the work turns out materially larger than scoped, stop and report.**

## 14. Review request

To `.git-exclude/review-request/`:
- implementation summary and changed files;
- the §9 existing-test report;
- every log from §9, and the §8 assertion output;
- both fires pairs;
- the L9 doc dispositions;
- the live output;
- what remains unverified (§10), and requested review focus.

**Do not cut a release, bump a version, or create a tag.**

Report the path only.
