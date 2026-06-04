# RFC 026: `/introspect` hot path consolidation

**Status**: Implemented
**ROADMAP**: External codebase review v0.50.1 — P2 finding on duplicated D1 reads in the introspection hot path
**ADR**: N/A — query consolidation, not new design
**Severity**: **P2 — adds latency under load; resource servers commonly introspect on every incoming request and the path runs O(N_RS × QPS_per_RS)**
**Estimated scope**: Small — one new repository method + handler refactor + ~30 LOC of test fixture changes
**Source**: External codebase review attached to the v0.50.1 conversation, §"具体的な最適化例"

## Background

The current `/introspect` handler
(`crates/worker/src/routes/oidc/introspect.rs`)
performs two D1 reads of the same `oidc_clients`
row per request:

1. `verify_client_credentials(&clients,
   &creds.client_id, &creds.client_secret)` —
   fetches the client to compare `client_secret_hash`.
2. `clients.find(&creds.client_id)` — fetches
   the client again to read `audience` for the
   audience-scoping gate (RFC 009 / v0.50.0).

Each read is a D1 query. D1 queries are billed and
counted against the per-invocation D1 query budget
(50 on Free, 1000 on Paid). For a deployment with
multiple resource servers each introspecting on
every request, the duplicate read multiplies traffic.

The codebase review proposes consolidating the two
reads into a single `ClientAuthView` query:

```rust
struct ClientAuthView {
    client_id:         String,
    client_secret_hash: Option<String>,
    audience:          Option<String>,
    token_auth_method: TokenAuthMethod,
}

async fn find_client_auth_view(id: &str)
    -> PortResult<Option<ClientAuthView>>;
```

Beyond the latency win, consolidation produces a
stronger property: client authentication and
audience policy come from the **same row read at
the same instant**, eliminating a TOCTOU window
where the audience could change between the auth
read and the gate read.

Companion observation: v0.50.0's audience read
treats a storage failure as fail-open by design
(letting requests proceed under pre-v0.50.0
behavior). Consolidating means that storage failure
fails the *authentication* read too, which is
already fail-closed. This shifts the gate to
fail-closed by virtue of co-location with auth,
which is what RFC 009 §"Audience-gate fail-closed"
intended.

## Requirements

The fix must:

1. `/introspect` issues at most one read of
   `oidc_clients` per request for the
   authentication + audience-scope check, plus the
   existing reads for token verification (signing
   keys, family DO, refresh decoder).
2. The wire form of `/introspect` is unchanged.
3. The audit emission shape is unchanged
   (`token_introspected`, `introspection_audience_mismatch`,
   `introspection_rate_limited` all still fire as
   they do now).
4. Storage failure on the consolidated read fails
   closed — the request returns the standard
   "authentication failed" response, not a
   stale-cached pre-v0.50.0 fallback.

## Decision / Plan

### Step 1 — New port method `find_auth_view`

Add to `cesauth_core::ports::repo::ClientRepository`:

```rust
/// Atomic read of the data needed to authenticate
/// a client AND enforce its audience-scoping
/// policy. Returns `None` if the client doesn't
/// exist; an error if the storage layer can't
/// answer.
///
/// The returned view is a snapshot at one instant,
/// so the auth check and the audience check
/// observe consistent values — closing the TOCTOU
/// window between two separate reads.
async fn find_auth_view(
    &self,
    client_id: &str,
) -> PortResult<Option<ClientAuthView>>;
```

`ClientAuthView` is a new public type:

```rust
#[derive(Clone, Debug)]
pub struct ClientAuthView {
    pub client_id:          String,
    pub client_secret_hash: Option<String>,
    pub audience:           Option<String>,
    pub token_auth_method:  TokenAuthMethod,
}
```

`token_auth_method` already exists in the codebase
as a column on `oidc_clients`; surfacing it in the
view is forward-looking (the introspect handler
checks it to choose between `client_secret_basic`
and `client_secret_post`).

### Step 2 — Cloudflare D1 adapter implementation

```rust
async fn find_auth_view(&self, client_id: &str)
    -> PortResult<Option<ClientAuthView>>
{
    let row = self.db
        .prepare("SELECT id, client_secret_hash, audience,
                         token_auth_method
                  FROM oidc_clients
                  WHERE id = ?1
                  LIMIT 1")
        .bind(&[client_id.into()])?
        .first::<ClientAuthRow>(None).await
        .map_err(...)?;

    Ok(row.map(|r| ClientAuthView {
        client_id:          r.id,
        client_secret_hash: r.client_secret_hash,
        audience:           r.audience,
        token_auth_method:  parse_token_auth_method(&r.token_auth_method)?,
    }))
}
```

Single SQL prepare + bind + first; one D1 query.

### Step 3 — In-memory adapter parity

`cesauth-adapter-test`'s in-memory `ClientRepository`
gains the same method, returning a `ClientAuthView`
constructed from the `Client` it already stores.
The two existing read paths in tests (find +
verify_credentials) collapse into one new read
in the test fixture too, exercising the same
contract.

### Step 4 — Service-layer consolidation

`cesauth_core::service::client_auth::verify_client_credentials`
gains a sibling that takes a pre-read view:

```rust
pub fn check_client_credentials_from_view(
    view: &ClientAuthView,
    presented_secret: &str,
) -> ClientAuthOutcome {
    // existing constant-time comparison logic; just no I/O.
}
```

The legacy `verify_client_credentials` (which does
the lookup + check) stays for callers like
`/revoke` that don't need the audience field; it
can be re-implemented as `find_auth_view`
followed by `check_client_credentials_from_view`,
keeping the old surface stable.

### Step 5 — Worker handler rewrite

```rust
// crates/worker/src/routes/oidc/introspect.rs

let creds = client_auth::extract(...)?;

// Single read of the row.
let auth_view = clients.find_auth_view(&creds.client_id).await
    .map_err(handle_storage_error_fail_closed)?
    .ok_or(invalid_client_response())?;

// Authentication.
match check_client_credentials_from_view(&auth_view, &creds.client_secret) {
    Authenticated => {},
    _ => return invalid_client_response(),
}

// Rate limit (unchanged).
let limit = check_introspection_rate_limit(...).await?;
if let Denied { retry_after_secs } = limit { return rate_limited(retry_after_secs); }

// Token introspection (unchanged).
let resp = introspect_token(&families, &keys, &cfg.issuer, /* aud unused here */, leeway, &input).await?;

// Audience gate now reads from the in-memory view.
let outcome = apply_introspection_audience_gate(resp, auth_view.audience.as_deref());

match outcome {
    PassedThrough(r) => return ok(r),
    AudienceDenied { ... } => {
        emit_audience_mismatch_audit(...);
        return ok(IntrospectionResponse::inactive());
    }
}
```

Storage failure on `find_auth_view` is now a
fail-closed `invalid_client` response — exactly
what RFC 009 §"Audience-gate fail-closed"
specified for the audience read. The merge makes
the fail-closed behavior unconditional rather
than "fail-closed for auth, fail-open for
audience".

### Step 6 — Test updates

- `cesauth-adapter-test::client_auth::tests`
  gains tests against the new view (round-trip,
  None-on-missing, secret-hash present,
  audience optional).
- The existing introspection tests in
  `cesauth_core::service::introspect::tests` are
  unchanged shape but now exercise the
  consolidated path through fixture wiring.
- A new test pins the fail-closed behavior:
  storage error on `find_auth_view` produces the
  standard `invalid_client` response, and
  emits no `introspection_audience_mismatch`
  audit (because the auth check fails first).

## Test plan

Per Step 6. Existing /introspect integration tests
must continue to pass with no wire-form change.

## Security considerations

The TOCTOU closure is the security gain. Pre-RFC,
in the unlikely event that an admin updated
`oidc_clients.audience` between the two reads
within a single request, the auth check would
observe the old value and the audience gate the
new value (or vice versa). This is *theoretical*
in scope — admin updates on individual rows are
infrequent and the read window is microseconds —
but the consolidation eliminates it for free.

The fail-closed alignment is the second gain:
v0.50.0 documented the fail-open audience read as
a "transient hiccup" tolerance. RFC 026 reasons
that auth and audience read from the same row
should fail or succeed together — there is no
sensible state where auth succeeded but audience
read failed. Treating any storage failure on
this path as fail-closed is operationally safer.

## Performance considerations

Measurement target: drop one D1 query from the
hot path. At default Paid budget (1000 D1 queries
/ invocation), the saving is a fraction of a
percent per request. The compounding gain is
across many invocations under load — Cloudflare's
D1 backend has a per-database serialization
property; reducing query count reduces contention.

Real-world impact will vary by deployment; the
measurement post-deploy should track:

- D1 queries per `/introspect` invocation
  (admin dashboard counter; cesauth's ops log
  at `Info` for sample requests).
- p50 / p95 / p99 of `/introspect` end-to-end
  latency.

If the saving is below noise threshold, the
consolidation is still worth it for the TOCTOU /
fail-closed reasons; the latency claim becomes a
bonus, not the headline.

## Open questions

1. **Should the same consolidation be applied to
   `/revoke`?** Yes, eventually — `/revoke`'s
   client-auth path could benefit from the same
   view (and surface `audience` if a future
   revoke-scoping feature wants it). Out of
   scope for RFC 026; revoke's hot path is much
   colder than introspect, and the change is
   mostly mechanical.

2. **Should we cache `ClientAuthView` per Worker
   isolate?** The codebase review suggests it.
   Caching has correctness implications: an admin
   updating `oidc_clients.audience` would not
   take effect until cache invalidation. Defer
   this to a separate RFC if/when measurement
   shows the single-query path is still a hot
   spot. The TOCTOU concern from Step 5 cuts
   harder against an isolate-local cache than
   against two same-instant reads.

## Implementation order

1. Add `ClientAuthView` and `find_auth_view` to
   the port trait + in-memory adapter.
2. Add the D1 implementation.
3. Add `check_client_credentials_from_view`.
4. Refactor the introspect handler.
5. Run existing tests; add new fail-closed test.
6. Single PR.

## Notes for the implementer

- The legacy `verify_client_credentials` should
  remain. `/revoke` uses it; deleting it is a
  separate cleanup. The RFC's invariant is "no
  duplicate reads on the introspect path"; it
  is silent about `/revoke`.
- `ClientAuthView` must NOT include
  `redirect_uris` or other large columns —
  introspection doesn't need them and including
  them bloats every call.
- The `parse_token_auth_method` helper exists in
  `cesauth-adapter-cloudflare`; reuse it rather
  than duplicating.
- Storage error mapping in the handler should
  emit a generic `client_auth_storage_error`
  audit event (using the existing
  `error_kind` field on TokenIntrospected if
  fired, or a new short-lived event); the spike
  signal is operator-meaningful.
