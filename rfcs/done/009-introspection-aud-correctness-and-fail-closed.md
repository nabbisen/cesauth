# RFC 009: Introspection access-token `aud` correctness + audience-gate fail-closed

**Status**: Implemented (v0.50.3)
**ROADMAP**: External codebase review v0.50.1 — High + High findings
**ADR**: ADR-014 (Token introspection); §Q1 was marked Resolved in v0.50.0 but the underlying introspection was already broken on access tokens — this RFC closes the gap and tightens §Q1's gate
**Severity**: **P0 + P1 — ship in same release as RFCs 008, 010**
**Estimated scope**: Small/medium — ~50 LOC code change + significant test fixture update + ~10 new tests + ADR-014 §Q1 amendment
**Source**: External Rust+Cloudflare codebase review attached to v0.50.1 conversation. Independently verified.

## Background

### The introspection bug

Access tokens are minted with `aud = client.id`:

```rust
// crates/core/src/service/token.rs:115-123, 274-281
let claims = AccessTokenClaims {
    iss: signer.issuer().to_owned(),
    sub: user_id.clone(),
    aud: client.id.clone(),     // ← aud is the client_id
    // ...
};
```

`/introspect` verifies them with `expected_aud = issuer`:

```rust
// crates/worker/src/routes/oidc/introspect.rs:202-208
let resp = introspect_token(
    &families,
    &key_views,
    &cfg.issuer,
    &cfg.issuer,        // ← passed as expected_aud
    30,                 // leeway_secs
    &IntrospectInput { token: &token, hint, now_unix: now },
).await?;
```

**Result**: every production access-token introspection
returns `{"active": false}` for valid, unexpired,
non-revoked tokens. The verifier rejects on `aud`
mismatch before any other claim is evaluated.

### Why no test catches this

`crates/core/src/service/introspect/tests.rs:78-79`:

```rust
const ISS: &str = "https://cesauth.example";
const AUD: &str = "https://cesauth.example";
```

The test fixture sets `ISS == AUD`. The verifier's
`expected_aud=ISS` happens to match the signer's
`aud=AUD`. Production minting uses `aud=client.id`,
which is never equal to the issuer URL. The test
suite's all-green status is misleading.

v0.41.0, v0.46.0, and v0.50.0 each extended the
introspect test surface without surfacing the
regression — the fixture has masked it since the
v0.38.0 introspect ship.

### Why P0

- **`/introspect` is broken in production** for any
  RP performing token validation against an access
  token. Depending on RP fallback (some accept the
  token without introspection if introspection
  returns inactive — silent acceptance; some reject
  outright — availability outage), the symptom is
  either correctness regression or DoS.
- **The v0.50.0 audience gate never fires.** The gate
  in `apply_introspection_audience_gate` checks
  `response.active && response.aud != requesting_audience`.
  If `response.active` is always false (the bug),
  the gate never runs. The privilege-escalation
  defense ADR-014 §Q1 promised is silently absent.
- **Discovery doc lies.** Cesauth advertises an
  `introspection_endpoint` that produces wrong
  results.

### The companion P1 — audience-gate fail-open

Lines 97-117 of `introspect.rs`:

```rust
let requesting_client = match clients.find(&creds.client_id).await {
    Ok(Some(c)) => Some(c),
    Ok(None) => {
        // race with admin DELETE → unscoped
        None
    }
    Err(_) => {
        worker::console_warn!("introspect: client repo lookup failed (audience scope unavailable)");
        None       // ← storage outage → unscoped (fail-open)
    }
};
```

For a deployment that has *deliberately* enabled
audience scoping, a transient D1 outage silently
disables the security boundary. This is fail-open
behavior on the security gate.

For deployments with NO audience scoping configured
(`oidc_clients.audience IS NULL` for every client),
this fail-open has no effect — the gate is
unscoped anyway. But for the deployments that
opted into ADR-014 §Q1's gate, fail-open defeats
the entire feature.

**Both bugs ship in the same RFC** because they're
tightly coupled: the gate becomes meaningful only
after the verifier returns `active`, and the
verifier fix surfaces the gate. Fixing one without
the other leaves a half-broken state.

## Requirements

1. Access-token introspection MUST validate based on
   the token's actual `aud` claim, not against the
   issuer URL.
2. The test fixture MUST exercise `ISS != AUD` to
   prevent regression.
3. The audience-gate client lookup MUST be
   fail-closed on storage error (HTTP 503).
4. The audience-gate client lookup MUST be
   fail-closed on `Ok(None)` (HTTP 401, with a new
   `IntrospectionRowMissing` audit kind).
5. ADR-014 §Q1 MUST be amended to reflect the
   tightened gate semantics.

## Design

### Step 1 — Decide the verification semantics

Two viable approaches:

**Option A — verifier accepts any `aud`, exposes
the value, audience gate is the canonical check.**

The pure-service `introspect_token` no longer takes
an `expected_aud` parameter. It verifies signature
+ `iss` + `exp` + `nbf`, builds the response with
the token's `aud` claim populated on
`IntrospectionResponse.aud`. The worker handler's
audience gate (already implemented in v0.50.0)
compares `response.aud` against the requesting
client's `audience` config — the gate becomes the
authoritative audience check.

**Option B — verifier checks `aud == client.id`
where `client.id` is the requesting client.**

`introspect_token` keeps `expected_aud` but the
worker handler passes the requesting client's id.
This works only for self-introspection (RS checking
its own tokens). RS_A introspecting a token minted
for RS_B (legitimate cross-RS use case in audience-
scoped deployments) would fail the verifier check
even before the audience gate runs.

**Decision: Option A.** Reasoning:

- ADR-014 §Q1 (v0.50.0) explicitly designed the
  audience gate to be the per-client policy point.
  Making the verifier also enforce `aud` duplicates
  the policy in two places — drift hazard.
- Option B forces the verifier to know which client
  is asking, which breaks the pure-service
  abstraction (the verifier shouldn't know about
  caller identity).
- The wire-format outcome is identical: a
  mis-audience token returns `{"active":false}` in
  both options (Option B at the verifier; Option A
  at the gate).

### Step 2 — Verifier signature change

`cesauth_core::service::introspect::introspect_token`:

Before:

```rust
pub async fn introspect_token<FS>(
    families:    &FS,
    keys:        &[IntrospectionKey<'_>],
    iss:         &str,
    expected_aud: &str,
    leeway_secs: u64,
    input:       &IntrospectInput<'_>,
) -> CoreResult<IntrospectionResponse>
```

After:

```rust
pub async fn introspect_token<FS>(
    families:    &FS,
    keys:        &[IntrospectionKey<'_>],
    iss:         &str,
    leeway_secs: u64,
    input:       &IntrospectInput<'_>,
) -> CoreResult<IntrospectionResponse>
```

The `expected_aud` parameter is removed. The
verifier validates signature + `iss` + `exp` + `nbf`
+ structural well-formedness, returns the response
with `aud` populated from the token's claim. The
caller (worker handler) applies the audience gate.

`IntrospectionResponse.aud: Option<String>` already
exists in v0.50.0; this RFC changes it from
"populated when verifier checks pass" to "always
populated when token is active".

### Step 3 — Update the test fixture

`crates/core/src/service/introspect/tests.rs:78-79`:

```rust
const ISS: &str = "https://cesauth.example";
- const AUD: &str = "https://cesauth.example";
+ const AUD: &str = "client_X";    // matches token's aud=client.id
```

Every test that mints an access token via the test
helper should use `AUD = "client_X"` (or another
non-issuer string). This is the production-realistic
shape.

### Step 4 — New tests pinning the contract

In `service/introspect/tests.rs`:

1. **`access_token_with_aud_equal_to_client_id_introspects_active`** — happy path. Catches future regression to the v0.50.0 bug.
2. **`access_token_with_aud_equal_to_issuer_string_introspects_active_if_token_otherwise_valid`** — confirm verifier doesn't itself reject on aud=iss (it stops doing aud-equality at all).
3. **`introspect_response_aud_field_equals_token_aud`** — wire-shape pin.
4. **`access_token_with_no_aud_claim_introspects_inactive`** — defensive: a token missing `aud` is malformed, not introspectable.
5. **`access_token_with_array_aud_claim_rejected`** — cesauth historically mints string-form `aud` only (per v0.44.0 verifier comment). Reject array form. Pin.

### Step 5 — Audience-gate fail-closed

`crates/worker/src/routes/oidc/introspect.rs:97-117`:

```rust
let requesting_client = match clients.find(&creds.client_id).await {
    Ok(Some(c)) => c,
    Ok(None) => {
        // Auth succeeded but the row is gone. Anomalous —
        // admin DELETE race, or auth path divergence from
        // repo. Fail-closed on the assumption that an
        // operator who removed the client did so for a
        // reason.
        log::emit(&cfg.log, Level::Error, Category::Auth,
            "introspect: client row missing post-auth (race?)",
            Some(&creds.client_id));
        audit::write_owned(
            &ctx.env, EventKind::IntrospectionRowMissing,
            None, Some(creds.client_id.clone()),
            None,
        ).await.ok();
        return unauthorized();
    }
    Err(_) => {
        // Storage outage. Without the client row we
        // cannot apply audience scoping. **Fail-closed**:
        // a deployment that opted into scoping must not
        // see it disabled by a transient hiccup.
        log::emit(&cfg.log, Level::Error, Category::Storage,
            "introspect: client repo lookup failed",
            Some(&creds.client_id));
        return Response::error("storage error", 503);
    }
};
```

Two key changes:

- `Ok(None)` is now an explicit failure — HTTP 401,
  audited as new kind `IntrospectionRowMissing`.
- `Err(_)` is now HTTP 503 (operator-visible
  transient error), not silent fall-through to
  unscoped behavior.

Compatibility with deployments that have NEVER
configured audience scoping: those deployments hit
the same code path. `Ok(None)` is impossible in
healthy operation (the auth check just succeeded
against a row); only the admin-DELETE race produces
it, and that race is a real anomaly worth surfacing
either way. `Err(_)` is a real D1 outage; surfacing
it as 503 is more correct than silent
"continue-with-unscoped" — operators investigating
intermittent introspection failures can tie them to
storage incidents.

### Step 6 — New audit kind `IntrospectionRowMissing`

Add to `crates/worker/src/audit.rs`:

```rust
/// **v0.50.2 (RFC 009)** — `/introspect` was called
/// by an authenticated client whose client row is
/// missing from the repository (admin DELETE race,
/// repo divergence). Fail-closed response is HTTP
/// 401. Distinct from `IntrospectionAudienceMismatch`
/// (audience mismatch with row present) and
/// `TokenIntrospected` (successful authenticated
/// introspection).
IntrospectionRowMissing,
```

Snake-case kind: `introspection_row_missing`.

### Step 7 — ADR-014 §Q1 amendment

ADR-014 §Q1 currently reads:

> **Q1**: Resource-server-typed clients. ... ✅
> Resolved in v0.50.0.

Add a Resolved-amendment paragraph noting RFC 009:

> **Tightened in v0.50.2 (RFC 009)**: the v0.50.0
> design assumed introspection's verifier was
> producing correct `active` responses for access
> tokens. In practice the verifier was passing
> `aud=issuer` while tokens were minted with
> `aud=client.id` — every access-token
> introspection returned `inactive`, and the
> audience gate consequently never fired. v0.50.2
> removes the verifier's `expected_aud`
> enforcement, makes the audience gate the sole
> aud-policy point, and tightens the gate's
> client-lookup to fail-closed on storage error
> (HTTP 503) and on row-missing (HTTP 401, new
> audit kind `IntrospectionRowMissing`). The §Q1
> design is now actually in effect.

### Step 8 — Worker handler tests

`crates/worker/src/routes/oidc/introspect/tests.rs`
(or extending existing test surface):

6. **`introspect_returns_503_when_client_repo_errors`**
7. **`introspect_returns_401_when_client_row_missing`**
8. **`introspect_audits_row_missing_kind_on_401_path`**

### Step 9 — End-to-end integration

9. **`mint_then_introspect_self_returns_active`** —
   mint an access token via `/token`, introspect it
   via `/introspect` from the issuing client (same
   client_id used as `aud`), assert response is
   `{"active": true, "aud": "<client_id>", ...}`.
   Catches the full regression.

## Test plan

Items 1-9 above are the new tests; items 1-5 in
`crates/core/src/service/introspect/tests.rs`,
items 6-8 in
`crates/worker/src/routes/oidc/introspect/tests.rs`
or equivalent worker test harness, item 9 as an
integration test.

Existing tests that depended on the
`expected_aud=issuer` shape need updating:

- Any test passing `&cfg.issuer` as the audience
  parameter is calling the old signature; remove
  the parameter.
- Any test fixture setting `AUD = ISS` should
  switch to a distinct value (`AUD = "client_X"`).

Total test diff: ~50 LOC of test code, with
fixture updates rippling across ~10 existing tests.

## Security considerations

**Verifier weakening**. Removing `expected_aud`
enforcement from the pure verifier widens the set
of token shapes that pass verification. This is
**only safe** because the audience gate (RFC 014
§Q1, v0.50.0) replaces it as the authoritative
audience check.

Pin the dependency: a worker handler test asserts
`apply_introspection_audience_gate` is called on
every code path through `/introspect`. If a future
edit introduces a path that bypasses the gate, the
verifier's relaxation becomes a vulnerability —
the test catches the regression.

**Other endpoints that validate access tokens**.
`/userinfo` (when shipped) and any future
access-token-consuming endpoint inside cesauth
itself need the **strict** `aud = client.id` check
— those endpoints answer "is this token meant for
me?", which IS an aud-equality question. The
strict verifier remains the default; only
`/introspect` uses the relaxed variant.

Make this explicit: a separate strict-verify
function in `cesauth_core::jwt::verify` that
existing internal callers continue to use, and a
new `verify_for_introspection` (or similar) that
omits the aud check. Distinct names prevent
accidental cross-use.

**Side-channel via `IntrospectionRowMissing` audit**.
The new audit kind reveals to a log-reading
attacker that a client_id existed at auth time but
not at lookup time. This is a marginal
side-channel (operator's admin DELETE timing),
not secret material. Acceptable.

**Wire-format change**. Strictly additive: the
response gains a populated `aud` field on the
active-access-token path; nothing is removed. RPs
that ignored the field continue working. RPs that
were depending on `inactive` responses for valid
tokens — i.e., were *relying on the bug* — get
correct behavior at upgrade. Release notes call
this out under "Behavior change at upgrade".

**Fail-closed availability cost**. Storage outages
on the client lookup now return 503 instead of
silent fall-through. Cost: introspection
availability tracks D1 availability rather than
gracefully degrading. Trade-off is correct: the
operator's signal that scoping is not working is
worth more than transparent fall-through.

## Open questions

**Should the relaxed verifier reject array-form
`aud`?** Yes (test 5). Cesauth has historically
emitted string-form only; an inbound array-form
`aud` is anomalous (operator-side modification or
forgery attempt against a third-party token).
Keep the rejection.

**Is there a case where two different clients
share an `aud`?** Per ADR-014 §Q1's design,
`oidc_clients.audience` is a free-form operator-
controlled string. Two clients with the same
`audience` config can both introspect the same
token. This is intentional — multiple resource
servers fronting the same logical audience. No
change for this RFC.

**Backward compat for the `expected_aud`
parameter**. Removing it breaks any external
caller of the pure service. There are no external
callers today (cesauth-core is unpublished). No
deprecation cycle needed; rip the band-aid.

## Implementation order

1. **PR 1 — Pure service signature change.**
   `introspect_token` loses `expected_aud`.
   Verifier path adjusted. ~15 LOC. Tests will
   fail until PR 2.
2. **PR 2 — Test fixture update + 5 pure-service
   tests.** ~80 LOC. Mergeable jointly with PR 1
   if reviewers prefer.
3. **PR 3 — Worker handler audience-gate
   fail-closed + `IntrospectionRowMissing` audit
   kind.** ~30 LOC + 3 tests.
4. **PR 4 — End-to-end integration test.** ~30
   LOC.
5. **PR 5 — ADR-014 §Q1 amendment + CHANGELOG
   entry under v0.50.2.**

PRs 1 + 2 land together; PR 3 follows; PR 4 is the
proof; PR 5 closes.

## Notes for the implementer

- Coordinate with RFC 008 (audit OTP fix) and RFC
  010 (mailer port). All three ship as v0.50.2.
  PR ordering across RFCs: RFC 008 PR 1 first
  (stop the bleed); RFCs 009 and 010 in parallel.
- Add a comment at the top of the introspection
  verifier explicitly rejecting future `iss==aud`
  conflation: "introspect's verifier deliberately
  does NOT enforce `aud` — see RFC 009. The
  audience gate is the canonical check."
- The "behavior change at upgrade" warning in the
  CHANGELOG matters: operators whose RPs were
  silently treating `inactive` as "fall through to
  some other validation" might be surprised.
  Frame the change as "introspection now works
  correctly for the first time" — accurate and
  unambiguous.
- Test 9 (end-to-end mint → introspect) is the
  single most important regression-catcher for
  this whole class of bug. It exercises the bug's
  exact production shape. Keep it.
