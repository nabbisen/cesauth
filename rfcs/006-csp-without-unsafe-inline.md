# RFC 006: CSP without `'unsafe-inline'` (per-request nonces)

**Status**: Ready
**ROADMAP**: `## Planned (0.x) / Later` — "CSP without `'unsafe-inline'`"
**ADR**: ADR-007 §Q3 documents the v0.23.0 limitation
**Estimated scope**: Medium — touches every HTML template render path; ~400 LOC + significant test churn

## Background

ADR-007 (Accepted, v0.23.0) shipped HTTP security
response headers. Per-route CSPs were tightened, but the
inline-CSS / inline-`<script>` shape of cesauth's
templates required `'unsafe-inline'` to keep the
templates rendering. ADR-007 §Q3 documented this as a
known limitation with two paths to remove:

- **Extract inline content to same-origin files** —
  workable, but requires multiple sub-requests per
  HTML page (a Workers cost).
- **Per-request nonces on every inline block** — the
  modern best practice. CSP v2+, well-supported across
  current browsers.

This RFC chooses the nonce path.

## Requirements

1. Every per-route CSP MUST drop `'unsafe-inline'` for
   `script-src` and `style-src`.
2. Every inline `<script>` and `<style>` block in
   `cesauth-ui` templates MUST receive a unique
   per-request nonce attribute.
3. The nonce MUST be cryptographically unguessable
   (CSPRNG, ≥128 bits) and bound to a single response
   (no caching, no reuse across requests).
4. The change MUST NOT cause any rendered template to
   visually regress (test via the existing UI tests).
5. The change MUST NOT add latency on the HTML render
   path beyond the nonce-generation cost (a single 16-
   byte CSPRNG read + base64-encode; negligible).

## Design

### Nonce generation

A single nonce is generated **per HTTP response** in
the worker layer. Pure helper:

```rust
// crates/core/src/security_headers/nonce.rs
pub struct CspNonce(String);
impl CspNonce {
    pub fn generate(rng: &mut impl rand_core::RngCore) -> Self {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        Self(base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}
```

In the worker, generate one `CspNonce` per request that
will return HTML, plumb it through the template render
call AND the CSP header builder.

### Template signature change

Every template function that emits inline `<script>` or
`<style>` gains a `nonce: &CspNonce` parameter. The
templates render `<style nonce="{nonce}">...</style>`
or `<script nonce="{nonce}">...</script>`.

This is a **wide-touch** change — every template
function in `cesauth-ui` is in scope. The mechanical
diff is large but structurally trivial. Doing it via
sed-then-cargo-check is fine.

For templates that have a `_for(.., locale)` shorthand
(see development directives), the shorthand also takes
the nonce. To minimize call-site churn, consider
introducing a `RenderContext` that bundles
`(locale, nonce)` and passing that single value through
every template signature. Decision: yes, do this.
The signature becomes `xxx_page(args..., ctx:
RenderContext)`. Saves repeated parameter additions
across the codebase and matches the trajectory of i18n
work.

### CSP header builder

`cesauth_core::security_headers::build_csp_for(route, nonce)` —
existing function gains `nonce` parameter. The output
gains:

- `script-src 'self' 'nonce-{nonce}'` (replaces
  `'unsafe-inline'`)
- `style-src 'self' 'nonce-{nonce}'` (replaces
  `'unsafe-inline'`)

`'unsafe-inline'` is dropped entirely. The legacy
fallback `'unsafe-inline'` next to nonces (which CSP v2
ignores when nonces are present) is also dropped — it
was a v1-vs-v2 transition affordance; cesauth has only
ever shipped v2 syntax.

### Routes that don't render HTML

JSON / 302 / 304 responses bypass nonce generation.
The worker's response-builder layer detects HTML by
content-type and inserts nonces only on that path.

### env knob

`SECURITY_HEADERS_CSP` operator override (already
exists per ADR-007 §SECURITY_HEADERS_CSP) gains a
documented placeholder syntax: operators may use
`{nonce}` in their override to receive cesauth's
generated nonce, e.g.

```
SECURITY_HEADERS_CSP="default-src 'self'; script-src 'self' 'nonce-{nonce}'"
```

cesauth substitutes `{nonce}` at render time. Operators
who don't include the placeholder accept whatever CSP
they wrote — no nonce subscription, but also no
inline-script support.

### Internal `unsafe-inline` audit

Before removing `'unsafe-inline'`, audit every
template for any block that **currently relies on
`'unsafe-inline'` accidentally**. The risk: a template
embeds an inline event handler (`onclick="..."`) which
CSP nonces don't cover. If any such handler exists,
refactor to attach via `<script nonce="...">document.
querySelector(...).addEventListener(...)</script>` in a
nonce'd block.

## Test plan

### Unit (in `cesauth-core`)

1. `nonce_generates_unique_per_call` — 1000 calls
   produce 1000 unique values.
2. `nonce_is_url_safe_base64_no_pad` — pin format.
3. `nonce_is_at_least_128_bits_of_entropy` — pin
   the byte length post-decode.
4. `csp_header_includes_nonce_for_script_src`.
5. `csp_header_includes_nonce_for_style_src`.
6. `csp_header_does_not_include_unsafe_inline`.
7. `csp_header_substitutes_operator_placeholder`.
8. `csp_header_without_placeholder_passes_through_unchanged`.

### Template integration

Re-run every existing UI template test against the
new signature. The expected diff: every test gains
`(locale, nonce)` (via `RenderContext`) and asserts
the `nonce` attribute appears in every `<script>` and
`<style>` block. Add per-template:

9. `<template>_emits_nonce_attribute_on_inline_style`
10. `<template>_emits_nonce_attribute_on_inline_script`
11. `<template>_does_not_emit_inline_event_handler` —
    pin the audit decision.

### Worker integration

12. `html_response_includes_nonce_in_csp_header`.
13. `json_response_does_not_include_csp_nonce_header`.
14. `nonce_in_csp_header_matches_nonce_in_html_body` —
    critical pin: the nonce in the response header MUST
    equal the nonce in every inline-script / inline-style
    in the body.
15. `two_concurrent_requests_get_different_nonces` —
    pin per-request uniqueness.

## Security considerations

**Nonce reuse**. Reusing a nonce across requests
defeats the security model — an XSS that finds a stale
nonce can inject script. Test 15 pins per-request
uniqueness. Implementation: nonce is a stack-local
generated at request entry, never cached, never
written to KV.

**Nonce predictability**. 128 bits from `getrandom`
is the lower bound. Test 3 pins this. Don't use any
PRNG that's not CSPRNG.

**`'unsafe-eval' is unaffected**. cesauth doesn't use
`eval()`; CSP `'unsafe-eval'` was already absent. This
RFC doesn't change that. Future template/script work
that does `JSON.parse` (legitimate) is fine; `eval()`
for any reason is a refactor target.

**Header / body desync**. The response is assembled
in two paths: the CSP header (built in the response
hardening middleware) and the body (built by the
template). Both must read the same nonce instance. The
implementation MUST pass the nonce as a value, not
re-generate. Test 14 pins this.

**Operator misconfiguration**. An operator who
overrides `SECURITY_HEADERS_CSP` without `{nonce}`
placeholder turns off cesauth's CSP for inline
content. The behavior is "their CSP wins"; this is
documented in ADR-007 (operator-knows-best). The
warning is in `docs/src/deployment/security-headers.md`.

## Open questions

**Should we add a CSP `'strict-dynamic'` directive?**
`'strict-dynamic'` lets nonce'd scripts spawn
non-nonce'd scripts dynamically. Safer for SPAs that
load script trees; cesauth's templates are server-
rendered with no script trees. Decision: don't add.
Re-evaluate if cesauth ever ships a real SPA front-end.

**Migration plan for the change**. The change is
wire-compatible (clients see CSP they could already
have received) but is a significant refactor.
Recommend shipping in a dedicated minor release with
no other features, so any visual regression is
isolatable.

## Notes for the implementer

- This is a **3-day refactor**, not an afternoon
  patch. Plan accordingly.
- The `RenderContext` introduction is the bulk of
  the diff. Consider it a separate first PR; the
  CSP-tightening PR rides on top.
- Audit any operator-side documentation that
  references `'unsafe-inline'` and update.
- Don't ship without confirming every template's
  visual rendering on at least one real browser run.
  CSP errors are silent in HTTP; only the browser
  reports them.
