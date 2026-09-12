# RFC 137 — `/token` authenticates no client and binds no code

**Status.** Proposed — **needs owner authorization.**
**Author.** Architect · **Date.** 2026-09-12
**Priority.** **P0, security.** The authorization-code exchange is the highest-value
flow in an IdP, and two of the bindings RFC 6749 §4.1.3 mandates are absent.
**Target release.** The next one. **Ahead of RFC 117**, which assumed these checks
already existed.
**Found by.** Measuring `exchange_code` before writing RFC 117's handoff.

---

## 1. Summary

`POST /token`, authorization-code grant, does **neither** of the two things
RFC 6749 §4.1.3 requires of an authorization server:

1. **It does not authenticate the client.** `client_secret` is parsed from the
   form into `TokenRequest` at `crates/backend/src/routes/oidc/token.rs:33` and
   **never read again** — the string appears exactly once in the file.
   `ExchangeCodeInput` (`crates/core/src/service/token.rs:73-80`) has no
   `client_secret` field, so the service never receives it.
2. **It does not bind the code to the client it was issued to.**
   `Challenge::AuthCode` carries `client_id: String`
   (`crates/core/src/ports/store.rs:30`), and `exchange_code`'s destructure
   (`token.rs:128-138`) discards it via `..`. No comparison against the
   presented `client_id` exists anywhere in the service or the route.

The presented `client_id` is used only to *look up* a client
(`token.rs:114-118`) — proving it exists, not that the caller is it, and not
that the code belongs to it.

**PKCE is therefore the only thing binding an authorization code to whoever
redeems it.**

## 2. What is established

| Fact | Evidence |
|---|---|
| `client_secret` parsed and dropped | `routes/oidc/token.rs:33`; `grep -n client_secret` on that file returns **one** line |
| The service cannot see it | `ExchangeCodeInput` has five fields, none a secret (`service/token.rs:73-80`) |
| The code carries its client | `ports/store.rs:30`, `AuthCode { client_id: String, … }` |
| The exchange discards it | `service/token.rs:128-138` — `..` in the pattern; no `client_id` binding |
| No comparison anywhere | `grep client_id service/token.rs` shows lookup and mint-time use only; no `!=`/mismatch |
| Other endpoints do authenticate | `/introspect` — `routes/oidc/introspect.rs:105` `check_client_credentials_from_view(&view, &creds.client_secret)`; `/revoke` — `routes/oidc/revoke.rs:101` |
| The machinery exists | `crates/backend/src/client_auth.rs`; `ClientRepository::client_secret_hash` (`ports/repo.rs:76`); `ClientType { Public, Confidential }` (`types.rs:120-123`) |
| No test covers it | no test in `service/token/tests.rs` or `adapter-test` redeems a code with a different `client_id` |
| PKCE is mandatory and S256-only | `oidc/pkce.rs:23-29` — `plain` explicitly rejected |

**`/token` is the only client-credential-bearing endpoint that does not
authenticate.** The two that do sit beside it in the same directory, using a
helper written for the purpose.

## 3. Impact, stated precisely

**What an attacker needs:** the authorization code **and** its PKCE verifier.
S256 is mandatory, so the code alone is not redeemable — that is real
mitigation and it is why this has not produced an incident.

**What it costs when the verifier is not secret:**

- **Code injection / mix-up (RFC 9700 §4.4, §4.5).** Client binding is the
  standard defence against a code reaching the wrong client. cesauth has none.
- **Any co-leak of code and verifier** — they travel together in the same token
  request, so a client that logs its request body, a proxy, or a compromised
  client leaks both at once. Client authentication is the control that still
  stands in that case. Here nothing does.
- **Privilege transfer on success.** `service/token.rs:174` mints with
  `client_id: ClientId::from_storage(client.id.clone())` — the **presented**
  client. So a successful cross-client redemption yields tokens carrying the
  redeemer's `client_id`, the victim's `user_id`, and the scopes the user
  granted to a *different* client.

**Severity: high, not critical.** Exploitation requires the verifier. But the
specification's model is that client authentication is the primary control for
confidential clients and PKCE is defence-in-depth; cesauth has inverted it and
kept only the second layer. Two independent bindings are mandated; one exists.

**Not claimed:** that this has been exploited, or that a code alone suffices.
It does not.

## 4. Non-goals

- **Not the typestate pipeline.** That is RFC 117, and it should encode these
  checks *after* they exist — see §7.
- No change to code TTLs, DO storage layout, or OAuth error wire shapes beyond
  the two new failure cases (§5).
- Not `/introspect` or `/revoke`, which already authenticate.
- Not client authentication methods beyond what `client_auth.rs` implements
  today (`client_secret_post`, `client_secret_basic`). No `private_key_jwt`.

## 5. The change

**T1 — Bind the code to its client.** In `exchange_code`, bind `client_id` out
of `Challenge::AuthCode` instead of discarding it, and compare it to
`input.client_id`. Mismatch → `CoreError::InvalidGrant`, the same error the
redirect-URI mismatch returns, so a probing client cannot distinguish "wrong
client" from "unknown code".

**Order matters and is part of the fix:** the comparison goes **after**
`take` — a code presented by the wrong client is still consumed. Returning it
to the store would make the endpoint a code-validity oracle. This is RFC 117's
invariant 5 ("failure consumes") and it is satisfied for free by `take`'s
position, provided the check is not hoisted above it.

**T2 — Authenticate the client.** Reuse `client_auth.rs`, as `/introspect`
does. `ExchangeCodeInput` gains `client_secret: Option<&str>`; the service
verifies it against `client_secret_hash` for `ClientType::Confidential`.
Failure → `CoreError::InvalidClient`.

**Public clients:** a `Public` client presents no secret and must not be
required to. T1 is what binds a public client's code — which is precisely why
T1 is not optional and why PKCE alone was never the design.

**T3 — Tests, in `crates/core` where the logic lives.**
- A code issued to client A, redeemed by client B with B's valid credentials and
  the correct verifier and redirect URI → `InvalidGrant`.
- The same, and then A retries with the right credentials → **also fails**: the
  code was consumed by the rejected attempt.
- Confidential client with wrong/absent secret → `InvalidClient`.
- Public client with no secret and a matching code → succeeds.
- Every existing token-exchange test passes unchanged.

**T4 — `route-contracts.md`:** `/token`'s row records that the endpoint
authenticates confidential clients, which it does not say today.

Order: **T1 → T3 (T1's cases) → T2 → T3 (T2's cases) → T4.** T1 first because
it is the binding that protects public clients too, and it is three lines.

## 6. Why this was not found sooner

Four gates pass over this code and none could see it:

- `cargo test` — no test redeems a code with the wrong client. The absence of a
  test is not visible to the test runner.
- `cargo clippy`, `cargo deny`, `cargo audit` — none reason about protocol
  conformance.
- `route-contracts-check.sh` — checks that routes are *documented*, not that
  they authenticate.

It is the same shape as every finding in this programme: the gates measured a
layer above the property that mattered. The difference is that this one is a
missing *control*, not a stale sentence, and the only instrument that would
have caught it is a test nobody wrote — which is the gap RFC 117 and the
assurance track exist to close.

**And RFC 117 asserted it was already correct** — §7.

## 7. What this does to RFC 117

RFC 117 §2 states as fact:

> *"`exchange_code` currently performs the correct sequence (`take` →
> client/redirect binding checks → `pkce::verify` → mint), but the ordering is
> procedural."*

**The client binding check does not exist**, so the sequence RFC 117 set out to
make structurally unbreakable is missing one of its four steps. Its §5 invariant
3 — *"`client_id` … are those captured at code-mint time; the exchange compares,
never substitutes"* — describes behaviour cesauth does not have.

This does not weaken RFC 117; it sharpens it. Its `bind_client` transition was
going to be written as a no-op rename of an existing check. It now encodes a
control that RFC 137 introduces, and the typestate makes removing it again
impossible to express. **Fix first, then encode.** RFC 117 is re-sequenced
behind this RFC and its §2/§5 amended to say so.

## 8. Risks

| Risk | Mitigation |
|---|---|
| A real integration breaks because it was relying on the absent check | It would have to be redeeming codes as the wrong client, which is the defect. Any break is the fix working |
| Confidential-client auth rejects a client that worked yesterday | T2 applies only to `ClientType::Confidential`; T3 pins the public path. If a confidential client has no stored hash, that is a finding — **report, do not default to allow** |
| The wrong-client error leaks which codes exist | T1 returns the same `InvalidGrant` as an unknown code |
| Consuming the code on a wrong-client attempt looks like a DoS vector | It is the specified behaviour and prevents an oracle; a code is single-use by definition |

## 9. Acceptance criteria

1. A code issued to client A cannot be redeemed by client B — asserted by test,
   with B holding valid credentials, the correct verifier and redirect URI.
2. The code is **consumed** by the rejected attempt; A's subsequent correct
   attempt also fails.
3. A confidential client presenting a wrong or absent secret gets
   `InvalidClient`.
4. A public client presenting no secret still succeeds.
5. Every pre-existing token test passes unchanged (wire compatibility).
6. `/token`'s `route-contracts.md` row states the authentication it performs.
7. Full gate set green, including the runtime smoke check.

## 10. Release level

**Patch** — a fix. It closes a conformance gap and adds no capability. Per
`contributing.md` §"Choosing the version level".

## 11. Open questions

1. **Should an existing confidential client with no stored `client_secret_hash`
   be rejected or treated as public?** My recommendation: **rejected**, and the
   condition reported — a confidential client that cannot authenticate is a
   provisioning defect, and defaulting to allow would reintroduce this RFC. The
   owner decides, because it can lock out a client that works today.
2. **Should `/token` also require `redirect_uri` when the code was issued with
   one?** It compares when present (`token.rs:144`). Whether absence should be
   rejected is adjacent and not in this scope; raising it so it is a decision
   rather than an omission.
