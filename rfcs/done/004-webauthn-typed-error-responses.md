# RFC 004: WebAuthn error → typed client responses

**Status**: Implemented (v0.51.1)
**ROADMAP**: `## Planned (0.x) / Next minor releases` — "WebAuthn error → typed client responses"
**ADR**: N/A
**Estimated scope**: Small — new enum + error mapping + 8 tests + JSON wire field, ~150 LOC

## Background

cesauth's `CoreError::WebAuthn(&'static str)` carries
diagnostic strings like `"rpIdHash mismatch"`,
`"signature invalid"`, `"counter regression"`, etc. The
HTTP response collapses all these into a generic 400.
The client sees a flat error and can't render specific
guidance — but UX research consistently shows that
WebAuthn UX requires **specific** guidance (the user
needs to know whether to try again, switch authenticators,
or contact support; "registration failed" alone is
useless).

This RFC introduces a small typed error category that
clients can branch on, while preserving the existing
diagnostic strings for server-side logs (the *category* is
new; the *detail* stays in logs).

## Requirements

1. The HTTP error response on a failed WebAuthn ceremony
   MUST carry a typed `kind` field with one of a
   closed enum of values, allowing client-side
   branching.
2. The existing `&'static str` diagnostic message MUST
   remain in server-side logs (audit + console). Do
   **NOT** surface it to clients.
3. The change MUST NOT cause any existing test to fail
   beyond the deliberate response-shape extensions
   covered below.
4. The typed enum MUST be conservative — start with a
   small set of meaningful categories; add more only
   when a real client-side action differs.

## Design

### `WebAuthnErrorKind` enum

In `cesauth_core::webauthn::error`:

```rust
/// Client-actionable category for a WebAuthn failure.
/// Distinct from the diagnostic detail string, which
/// stays in server-side logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebAuthnErrorKind {
    /// The credential the user attempted with isn't
    /// registered for this user. Client should prompt
    /// to try another authenticator or to register
    /// this one. Examples: `"credential not found"`,
    /// `"unknown credentialId"`.
    UnknownCredential,

    /// The relying-party ID the user's authenticator
    /// signed against doesn't match what this cesauth
    /// instance expects. Almost always a deployment
    /// misconfiguration (subdomain mismatch, wrong
    /// `RP_ID`). Client renders an "ask your admin"
    /// message; this is not a user-recoverable error.
    /// Examples: `"rpIdHash mismatch"`.
    RelyingPartyMismatch,

    /// User cancelled or aborted the ceremony at the
    /// browser/OS prompt. Client retries by re-issuing
    /// the ceremony. Examples: `"user cancelled"`,
    /// `"NotAllowedError"`.
    UserCancelled,

    /// The signature failed verification, OR the
    /// signature counter regressed (replay defense).
    /// Distinguishing these two from the client side
    /// doesn't help — both surface as "this
    /// authenticator may be cloned or compromised; try
    /// a different one". Server logs distinguish via
    /// the diagnostic detail.
    SignatureInvalid,

    /// The challenge presented by the client doesn't
    /// match what cesauth issued. Most often the
    /// ceremony took too long (challenge expired) and
    /// the client should re-issue.
    ChallengeMismatch,

    /// Anything else — unknown or unmapped underlying
    /// failure. Client renders a generic "something
    /// went wrong" message. The server log carries
    /// the exact detail.
    Other,
}
```

The enum is **conservative**: 6 variants. Each variant
maps to a **distinct user action** (try another, contact
admin, retry, abandon, retry-after-refresh, give-up).
Adding a 7th variant requires a new distinct user
action.

### Mapping diagnostic string → kind

Centralized in `cesauth_core::webauthn::error::classify`:

```rust
pub fn classify(detail: &str) -> WebAuthnErrorKind {
    match detail {
        "rpIdHash mismatch"          => WebAuthnErrorKind::RelyingPartyMismatch,
        "credential not found"       => WebAuthnErrorKind::UnknownCredential,
        "unknown credentialId"       => WebAuthnErrorKind::UnknownCredential,
        "signature invalid"          => WebAuthnErrorKind::SignatureInvalid,
        "counter regression"         => WebAuthnErrorKind::SignatureInvalid,
        "user cancelled"             => WebAuthnErrorKind::UserCancelled,
        "NotAllowedError"            => WebAuthnErrorKind::UserCancelled,
        "challenge mismatch"         => WebAuthnErrorKind::ChallengeMismatch,
        "challenge expired"          => WebAuthnErrorKind::ChallengeMismatch,
        _                            => WebAuthnErrorKind::Other,
    }
}
```

This keeps the mapping in one place, exhaustively
testable. New diagnostic strings introduced anywhere in
`webauthn-rs-core`'s error path must be added here OR
they fall through to `Other` — which is a deliberate
default (over-classifying as `Other` is fine; the
specific category is an enhancement, not a correctness
condition).

### Wire response shape

Failed WebAuthn ceremonies currently return:

```json
{ "error": "webauthn_failed", "error_description": "..." }
```

After this RFC:

```json
{
  "error": "webauthn_failed",
  "error_description": "...",
  "kind": "unknown_credential"
}
```

`error_description` stays a generic value (e.g.
`"WebAuthn ceremony failed"`); the **detail string
does not appear on the wire**. Clients that ignore the
new `kind` field continue working unchanged.

### Worker-glue change

In `crates/worker/src/routes/webauthn/...`, the error path
that currently formats `CoreError::WebAuthn(detail)` adds
one extra step: call `classify(detail)`, render `kind`
into the JSON. Audit log gets both `detail` and `kind`.

## Test plan

In `crates/core/src/webauthn/error/tests.rs`:

1. `classify_rp_id_hash_mismatch_to_relying_party_mismatch`
2. `classify_credential_not_found_to_unknown_credential`
3. `classify_signature_invalid_to_signature_invalid`
4. `classify_counter_regression_to_signature_invalid`
   (pin the deliberate conflation)
5. `classify_user_cancelled_to_user_cancelled`
6. `classify_challenge_expired_to_challenge_mismatch`
7. `classify_unknown_string_falls_to_other`
8. `classify_empty_string_falls_to_other`

Pin tests in worker layer
(`crates/worker/src/routes/webauthn/tests.rs` or
extending existing):

9. `webauthn_failure_response_includes_kind_field`
10. `webauthn_failure_response_does_not_leak_detail_string`
    — pin the privacy invariant: the `&'static str`
    detail must NOT surface on the wire.
11. `webauthn_audit_event_includes_both_kind_and_detail`
    — pin the asymmetry: server-side observability gets
    both.

## Security considerations

**Information leak via `kind`**. The categories were
chosen to avoid leaking sensitive state. In particular:
- `UnknownCredential` doesn't reveal whether the user
  exists (the WebAuthn flow is bound to a session-bound
  challenge; an attacker without the session cookie
  can't trigger this code path).
- `RelyingPartyMismatch` reveals a deployment-side
  misconfiguration but not user-side state.
- `SignatureInvalid` is the deliberate conflation of
  "wrong sig" and "replay-counter regression"; an
  attacker who could distinguish these would learn
  whether their authenticator was previously known to
  the server, which is useful intelligence in cloning
  scenarios.

The pin tests above (10, 11) lock the
detail-stays-in-logs invariant.

**Backward compatibility**. Clients ignoring unknown
JSON fields (the well-behaved default) see no change.
Clients that explicitly reject unknown fields (rare; bad
practice) would break. cesauth's own UI templates do
not fall in this category.

## Open questions

**Should the wire response also be HTTP-status-coded
differently per kind?** No. RFC 6749 / 7591 don't
suggest 401 vs 403 vs 400 by WebAuthn-failure category;
keep it 400 across the board. The `kind` field is the
discriminator. (HTTP status is for the protocol layer;
ceremony failure is application-layer.)

## Notes for the implementer

- Keep `classify` exhaustively tested (the 8 unit tests
  above), and treat new diagnostic strings as a checklist:
  whenever `webauthn-rs-core` adds an error category, the
  PR doing the upgrade audits `classify` for new
  mappings.
- Don't expose `WebAuthnErrorKind` through any non-error
  path. It's an error-classification enum; using it for
  anything else dilutes the meaning.
- Document `kind` in the OpenAPI/OpenID-style API
  reference at `docs/src/api/`. Pin the closed set so
  client implementers can branch confidently.
