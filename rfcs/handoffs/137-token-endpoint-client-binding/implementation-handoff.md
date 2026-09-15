# Developer Handoff — RFC 137, `/token` client authentication and binding (P0)

**Governing RFC.** [`rfcs/done/137-token-endpoint-client-binding.md`](../../done/137-token-endpoint-client-binding.md) — read **§12** first; it carries every ruling below with its evidence.
**Target release.** The next release, whose content RFC 137 is by the owner's
choice when shipping 0.83.0. **Level: patch** — controls RFC 6749 mandates were
missing on both grants; restoring them is a fix, and nothing new becomes
possible. If RFC 138 lands in the same window it rides along. **RFC 137 does not
wait for it.**
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing.

---

## 1. Purpose

After this, `/token` authenticates confidential clients and binds every
authorization code and every refresh token to the client it was issued to — on
**both** grants.

## 2. Why this matters

On the code grant, PKCE is today the only binding between a code and its
redeemer. On the refresh grant there is **nothing**: no PKCE, no client
authentication, and no comparison against the client the family was issued to.
A leaked refresh token is redeemable by any registered `client_id`, and the
access token it yields names the presenter as `aud`/`cid` while carrying the
victim's user and scopes.

## 3. Resolved decisions — do not re-open

All ruled in RFC 137 §12, with evidence.

**The refresh grant is in scope** (§12.1).

**A confidential client with no stored hash is rejected** (§12.2). No
documented setup creates one, and there is no production use.

**The discriminator is a fail-closed intersection** (§12.3):

```
public client  ⇔  client_type = Public  AND  client_secret_hash IS NULL
otherwise      →  must authenticate:
                    Authenticated                         → proceed
                    AuthenticationFailed | PublicOrUnknown → InvalidClient
```

**Extend `ClientAuthView` with `client_type`** (§12.3), so `/token` stays at one
client read, as `/introspect` does.

**Refresh-grant client mismatch revokes the family** (§12.4). Order:

```
authenticate client → peek family
  absent                        → InvalidGrant
  fam.client_id ≠ authenticated → revoke family, InvalidGrant
  otherwise                     → rotate exactly as today
```

**Code-grant client mismatch is checked after `take`** (RFC §5 T1), so the code
is consumed by the rejected attempt.

**Wrong-client and unknown-code/unknown-family return the same error** —
`InvalidGrant` — on both grants, so a probing client learns nothing.

**Fixtures are corrected; assertions are not** (§12.5).

**Out of scope** (§12.7): auth-method match (Basic vs post), requiring
`redirect_uri` when bound, `client_type`/`token_auth_method` consistency, and
refresh-token lifetime (**RFC 139** — do not start it).

## 4. Facts already measured — do not re-derive

| Fact | Where |
|---|---|
| Code grant discards the code's client | `service/token.rs:128-138` — `..` in the `Challenge::AuthCode` pattern |
| Code grant mints with the presented client | `service/token.rs:174` |
| Refresh grant: lookup only, `fam.client_id` never read | `service/token.rs:261` onward; the lookup is the only `client_id` use |
| `FamilyState.client_id` exists | `ports/store.rs:166` |
| `revoke` exists on the family port and DO | `ports/store.rs` (`rotate`/`revoke`); DO `Command::Revoke`, `adapter-cloudflare/src/refresh_token_family.rs:149-150` |
| `ClientAuthOutcome` semantics | `service/client_auth.rs:83-95`; `PublicOrUnknown` ⇔ hash is `None`, regardless of type |
| Constant-time secret check | `service/client_auth.rs:170` `check_client_credentials_from_view` |
| `ClientAuthView` has no `client_type` | `ports/repo.rs:96-101`; loaded by `find_auth_view` (`:85`) |
| Schema: `token_auth_method DEFAULT 'none'`, independent of `client_type` | `migrations/0001_initial.sql` |
| Both code mint sites bind the requesting client | `routes/oidc/authorize.rs:115`, `post_auth.rs:360` |
| `/token` reads its body as text | `routes/oidc/token.rs:22-25` — `req.text()` + `url::form_urlencoded` |
| Backend credential extraction | `backend/src/client_auth.rs` — `extract_from_basic` (`:51`), `extract_from_form(&worker::FormData)` (`:66`), `extract(headers, &worker::FormData)` (`:76-90`) |
| Token tests: 12, one client fixture, confidential with no hash | `service/token/tests.rs:58-62`, `:98`, `:102`; refresh tests `:307`, `:345`, `:385` |
| Documented flows use a public client and send no secret | `docs/src/beginner/first-local-run.md:119-135`; `first-oidc-flow.md:204-210`, `:280-284` |

*If any of this fails to reproduce, that is a finding — report it.*

## 5. Change scope

| # | Task |
|---|---|
| T1 | **Bind the code to its client.** Bind `client_id` out of `Challenge::AuthCode`; compare to the presented client **after** `take`; mismatch → `InvalidGrant` |
| T4 | **Bind the refresh family to its client.** Peek before rotate; mismatch → `revoke` then `InvalidGrant` (§3) |
| T2 | **Authenticate on the code grant.** Extend `ClientAuthView` with `client_type` — the D1 query behind `find_auth_view` and the adapter-test implementation; `ExchangeCodeInput` gains `client_secret: Option<&str>`; apply §3's discriminator |
| T3 | **Authenticate on the refresh grant.** Same discriminator; the refresh input gains `client_secret: Option<&str>` |
| T5 | **Correct the fixtures** — a confidential fixture with a real hash, plus a public fixture. Assertions unchanged |
| T6 | **New tests** — §9 |
| T7 | `docs/src/expert/route-contracts.md`: `/token`'s row states the authentication it performs |

**Order: T1 → T4 → T2 + T3 + T5 → T6 → T7.** The bindings first — they need no
fixture change if existing tests exchange codes as the client they minted for.
**If an existing test fails at T1 or T4, it was exchanging as a different client
— report which, do not adjust it.** Authentication and the fixture correction
land together, because the current fixture is exactly the case T2 rejects.

## 6. Explicit non-change scope

- **Not RFC 139.** Refresh tokens still never expire after this; do not add a TTL.
- Not RFC 117's typestate pipeline — it encodes these checks afterwards.
- No auth-method matching, no `redirect_uri`-required change, no
  `client_type`/`token_auth_method` reconciliation.
- No change to `/introspect` or `/revoke`, which already authenticate.
- No OAuth error wire-shape change beyond the new failure cases using the
  existing `InvalidClient`/`InvalidGrant` mappings.
- No route strings. No `cargo fmt`.

## 7. The traps — each would compile and ship the defect

**7.1 Reusing the helper the way `/introspect` does.**
`check_client_credentials_from_view` returns `PublicOrUnknown` for a confidential
client with no hash. `/introspect` rejects that outcome, so it is safe there.
`/token` must admit public clients, so `PublicOrUnknown` alone cannot mean
"proceed" — only `client_type = Public` with no hash can. Implement §3's
intersection; do not branch on the outcome alone.

**7.2 `client_auth::extract` cannot be called.** It takes `&worker::FormData`,
and `/token` has already consumed its body with `req.text()`. Use
`extract_from_basic(headers)` and read `client_secret` from the parsed form map,
**preserving `extract`'s precedence**: if an `Authorization` header is present,
Basic is the only path, and a malformed Basic header does **not** fall through to
the form.

**7.3 Two client identities in one request.** With Basic, the client comes from
the header. A form `client_id` that disagrees with it is a client presenting two
identities — reject with `InvalidClient` (RFC 6749 §2.3: a client MUST NOT use
more than one authentication method per request).

**7.4 Rotating before comparing on refresh.** If `rotate` runs first, a
mismatched client has already rotated the family before rejection. §3's order is
peek, compare, then rotate.

**7.5 A new `==` on secret material.** All secret comparison goes through
`check_client_credentials_from_view`'s constant-time path. If you find yourself
writing `==` on a secret or its hash, stop.

**7.6 Error responses.** Use the existing mappings. If `InvalidClient` does not
produce `401` with `WWW-Authenticate` when Basic was used (RFC 6749 §5.2),
**report it** — do not expand scope to fix it.

## 8. Mechanical assertions

```sh
# the code's client is bound, not discarded
grep -n -A12 'Challenge::AuthCode {' crates/core/src/service/token.rs | grep -n 'client_id'

# the refresh path reads the family's client
grep -n 'client_id' crates/core/src/service/token.rs | sed -n '1,40p'   # fam.client_id must appear in rotate_refresh

# the route reads client_secret beyond parsing it
grep -c 'client_secret' crates/backend/src/routes/oidc/token.rs         # must exceed 1

# the view carries client_type
grep -n -A8 'pub struct ClientAuthView' crates/core/src/ports/repo.rs | grep client_type

# no new equality on secrets
git diff -U0 | grep -nE '^\+.*(secret|hash)[^=]*==' && echo "REVIEW" || echo "clean"
```

## 9. Required tests and evidence

**New tests, in `crates/core`:**

*Code grant*
1. Code issued to A, redeemed by B — B holding valid credentials, correct
   verifier and redirect URI → `InvalidGrant`.
2. Then A redeems the same code correctly → **also fails**: consumed.
3. Confidential client, wrong secret → `InvalidClient`.
4. Confidential client, **absent** secret → `InvalidClient`.
5. **Confidential client with no stored hash** → `InvalidClient`.
6. Public client (`demo-cli` shape), no secret, matching code → succeeds.

*Refresh grant*
7. Family issued to A, rotated by B with valid credentials → `InvalidGrant`.
8. **The family is revoked**: A's subsequent correct refresh fails.
9. Confidential client, wrong secret → `InvalidClient`, family **untouched**
   (authentication precedes the family).
10. Public client, no secret, own family → rotates.

*Route*
11. Basic header and a disagreeing form `client_id` → `InvalidClient`.

**Evidence.** Per the split in `contributing.md`: **you run the full gate set**
and send it — host tests (expect 1,403 plus the new ones, stated with the
command), `migration_chain`, wasm32 and csr checks, clippy, deny, audit,
route-contracts, drift-scan, mdbook, `make build-frontend`, `wrangler build`,
runtime smoke, and the browser suite. I re-run the token tests, the runtime
smoke check and the browser suite myself.

**Fires/does-not-fire:** temporarily restore the `..` in T1's pattern → test 1
red; restore → green. Same for T4: remove the peek comparison → tests 7 and 8 red.

**The documented walkthrough still works.** Run
`docs/src/beginner/first-oidc-flow.md`'s code and refresh `curl` calls against
`wrangler dev` with the beginner guide's seeded public client, and attach the
output. That is the flow every new user runs first.

## 10. What must NOT be claimed

- **Not that refresh tokens are safe.** They still never expire — RFC 139.
- Not that the registered authentication method is enforced — out of scope.
- Not that it works on Cloudflare — Miniflare only; nobody has deployed.
- Not that CI has run it — `worker-build.yml`'s jobs have never executed in CI.

## 11. Prohibited shortcuts

- No weakening an assertion in an existing test — fixtures only (§12.5).
- No `#[ignore]`, no `continue-on-error`, no `cargo fmt`.
- No treating `PublicOrUnknown` as "proceed" on its own (7.1).
- No default-allow for a confidential client that cannot authenticate.

## 12. Acceptance criteria

RFC 137 §9, as amended by §12. Checked hardest: **refresh wrong-client revokes
the family** (tests 7–8), **confidential-with-no-hash is rejected** (test 5), and
**the public beginner client still works on both grants** (test 6, test 10, and
the walkthrough).

## 13. Known risks

| Risk | Mitigation |
|---|---|
| The helper silently admits confidential-without-hash | §7.1; test 5 |
| A test was exchanging as a different client | §5 — report, do not adjust |
| Refresh revoke-on-mismatch lets a token holder kill a family | Accepted, §12.4 — reuse detection already allows it |
| The walkthrough breaks | §9 requires running it |

**If the work turns out materially larger than scoped, stop and report.**

## 14. Review request

To `.git-exclude/review-request/`: implementation summary · changed files · any
test that failed at T1/T4 and why · every log from §9 · the §8 assertions · both
fires/does-not-fire pairs · the walkthrough output · what remains unverified
(§10) · requested review focus.

**Do not cut a release, bump a version, or create a tag.** The tag is the
owner's alone.

Report the path only.
