# RFC 141 — OIDC client registration has no API

**Status.** Accepted — approved by the owner 2026-09-24.
**Tier.** P1 · Category A — the product's primary integration action.
**Size.** Medium–large.
**Touches.** `crates/backend/src/routes/admin/`, `crates/core/src/service/`,
`crates/core/src/ports/repo.rs`, the console, `docs/`.
**Depends on.** RFC 116 (newtypes), RFC 137 (what `/token` now requires of a
client record).
**Found by.** The 2026-09-24 state review.

## 1. Summary

Registering an OIDC client — the thing every integrator must do first — has
**no API, no console screen and no usable documentation**. It is performed by
hand-writing a row into D1, including a hash the operator must compute
themselves, in a production database.

## 2. What is established

- **No route.** `grep 'clients' docs/src/expert/route-contracts.md` matches
  nothing across all 188 documented routes. One *field* of an existing client is
  editable — `audience`, via the tenant admin editor (RFC 017) — and nothing
  else.
- **The production guide elides the statement itself**
  (`docs/src/deployment/production.md:72-75`):

  ```
  wrangler d1 execute cesauth-prod --command "
    INSERT INTO oidc_clients (…) VALUES (…);
  "
  ```

- **What the operator must get right unaided** (`migrations/0001_initial.sql`):
  `client_secret_hash` is `sha256_hex(secret)` of a **server-minted 256-bit**
  secret; `redirect_uris` and `allowed_scopes` are **JSON arrays** in `TEXT`
  columns; `client_type` and `token_auth_method` are CHECK-constrained enums;
  `require_pkce` defaults to 1.
- **The failure mode is opaque.** A `confidential` client with a NULL hash is
  rejected by `/token` with `401 invalid_client` and no detail (RFC 137 §12.2) —
  correct, and indistinguishable from a wrong secret. A plaintext secret stored
  instead of its hash never authenticates and says nothing about why.

## 3. Why it matters under the project's standard

An identity provider is adopted by *integrators*. This is the first thing one
does, it is unsupported, and every way of getting it wrong surfaces later as an
authentication failure that names no cause. It is simultaneously an **API gap**,
a **UX gap** and a **documentation defect**.

## 4. Proposed design

### 4.1 Surface

Follow the existing system console exactly (`/admin/console/*`: system-admin
auth, CSRF on writes, an audit event per write, `client` rendering class):

| Method | Route | Purpose |
|---|---|---|
| GET | `/admin/console/clients` | list page |
| GET | `/admin/console/clients.json` | list + `csrf_token` |
| POST | `/admin/console/clients` | **create**; mints the secret |
| POST | `/admin/console/clients/:id` | update the editable fields |
| POST | `/admin/console/clients/:id/rotate-secret` | mint a new secret |
| POST | `/admin/console/clients/:id/delete` | delete |

### 4.2 The secret is minted, shown once, and never retrievable

The server generates 256 bits, returns the plaintext **once** in the create (or
rotate) response, and stores only `sha256_hex`. No route ever returns it again;
the console says so at the point of display. This removes the operator's hashing
step, which is the error the current instructions invite.

### 4.3 Validation, using the code that enforces it later

- **`redirect_uris`** are validated by the **same matcher `/authorize` uses**
  (`core/src/oidc/authorization.rs`, which has property tests). Registration and
  authorization must not have two opinions about what a valid redirect URI is.
- **`client_type` ↔ `token_auth_method` are coupled**: `public` ⇒ `none` and no
  secret; `confidential` ⇒ `client_secret_basic` or `client_secret_post` **and**
  a secret. The combination RFC 137 §12.2 rejects at `/token` becomes
  unrepresentable at registration.
- **`allowed_scopes`** are validated against the scopes cesauth issues.
- **`require_pkce`** cannot be set to 0: PKCE is mandatory and S256-only. Either
  omit it from the API or reject 0 explicitly — silently accepting a value the
  product ignores is the defect class this project keeps finding.

### 4.4 Enforce the registered authentication method

Registration is where `token_auth_method` is chosen, so this RFC is where it
starts meaning something. Today (RFC 137 §13.4, recorded and unfixed) a
**public** client is accepted whatever secret it presents, and a confidential
client may use either method regardless of what it registered. `/token` should
enforce the registered method.

**This is a behaviour change at `/token`** and the reason this RFC is not purely
additive. It is in scope because leaving it out means shipping a registration
API for a field that is still ignored.

### 4.5 Documentation

- **A new "Integrating an application" chapter**: the discovery document, the
  scopes and claims cesauth issues, how to register a client and what each field
  means, redirect-URI rules, token lifetimes to assume, and what each error at
  `/token` means for the integrator's code.
- **`production.md`'s elided `INSERT` is replaced** by the API.
- The console screen is documented in the admin guide.

## 5. Non-goals

- **Not Dynamic Client Registration (RFC 7591).** A different problem, and an
  open registration endpoint is a liability without a policy for it.
- **Not per-tenant client ownership** beyond what exists today.
- **Not consent-screen or connected-apps work.**

## 6. Testing strategy

- Service-level tests for every validation rule, including the couplings in
  §4.3 and the unrepresentable combinations.
- The minted secret authenticates at `/token`; the stored value is the hash;
  the plaintext appears in exactly one response and never again.
- Rotation invalidates the previous secret.
- §4.4: a public client presenting a secret, and a confidential client using the
  method it did not register, are refused — with the fires pair.
- A live walkthrough: register a client through the API, then complete the
  documented OIDC flow with it.

## 7. Acceptance criteria

1. A client can be registered, rotated and deleted without SQL.
2. `route-contracts.md` documents every new route; the check passes.
3. No document instructs anyone to write `oidc_clients` by hand.
4. The integrator chapter exists and its flow has been executed end to end.
5. §4.4 enforced, with tests.

## 8. Level

**Minor** — new capability, plus one behaviour change at `/token` (§4.4).

## 9. Open questions

1. ~~**System console, tenant console, or both?**~~ **Closed 2026-09-24 — the
   system console.** See §10; the question was built on two false premises of
   mine.
2. ~~Should deletion be soft?~~ **Closed at the handoff, 2026-10-24: hard
   delete.** `grants` and `consent` already cascade
   (`migrations/0001_initial.sql`); a soft-delete column would need a migration
   **and** a check in every client lookup including `find_auth_view`, which is on
   the authentication path. Refresh stops immediately, because `rotate_refresh`
   loads the client first; **issued access tokens remain valid until they
   expire** (self-contained JWTs, ten minutes by default), which the
   documentation must state.

## 10. §9 q1 closed, and two defects found closing it

The question assumed clients are tenant-scoped and that a tenant-admin client
editor already exists. **Neither is true**, measured 2026-09-24.

### 10.1 Clients are global; there is no tenant column

`grep -rn 'oidc_clients' migrations/*.sql`: the table is created in `0001` and
altered exactly once, by `0010`, which adds `audience`. **There is no
`tenant_id`, and there never has been.**

**Ruling: the system console**, `/admin/console/clients`, as §4.1 proposes. A
per-tenant creation surface would imply an ownership model the schema does not
have, and inventing one in a registration API is the wrong place to decide it.

**If clients should be tenant-owned, that is a data-model change and belongs to
RFC 119** (tenant-scoped repository APIs), not here. Explicit non-goal.

### 10.2 The "tenant admin editor" does not exist

`crates/backend/src/audit.rs:186-191` documents an event kind
`OidcClientAudienceChanged` — *"An admin changed `oidc_clients.audience` via the
tenant admin editor"* (RFC 017). Measured:

- `grep -rn 'OidcClientAudienceChanged' crates/ docs/` → **two hits**: the enum
  variant and its wire string. **Nothing writes it.**
- `grep -rn 'UPDATE oidc_clients|update_audience|set_audience' crates/` →
  **nothing**.

**No route modifies an `oidc_clients` row at all.** Not `audience`, not any
field. So the situation is worse than §1 states: it is not only that a client
cannot be *created* without SQL — it cannot be *changed* without SQL either, and
`audience`, which ADR-014 makes the introspection scoping control, is settable
only by hand-editing the database.

**Consequences for this RFC:**

- §4.1's `POST /admin/console/clients/:id` is not a convenience; it is the only
  way any client field will ever be editable.
- It gives `OidcClientAudienceChanged` its **first writer**. Editing `audience`
  must emit it, with before/after as its doc already specifies.
- If any other declared event kind has no writer, say so rather than adding one
  quietly — a declared-but-never-written audit event is a promise the audit
  trail does not keep.

### 10.3 A false comment found on the way, homed elsewhere

`migrations/0020_authenticator_tenant_id.sql` justifies its scope with: *"consent
and grants are already indirectly tenant-scoped via `oidc_clients`"*. Since
`oidc_clients` has no `tenant_id` (§10.1), **they are not**, and that sentence is
the stated reason those two tables were left alone. Recorded in **RFC 119**,
which owns tenant scoping. Not this RFC's to fix.

## 11. Found while writing the handoff: the storage layer already exists (2026-10-24)

`ClientRepository::create(&OidcClient, secret_hash)` is **declared and
implemented in both adapters** — the Cloudflare one writes all eleven columns,
JSON-serialising `redirect_uris` and `allowed_scopes` and handling the nullable
`audience` and secret hash — and **nothing calls it**
(`grep -rn 'clients\.create('` → no hits).

With `AdminClientCreated` and `OidcClientAudienceChanged` (§10.2), that makes
**three capabilities in this one area that were declared, implemented, carried,
and never wired.** The knowledge the production guide elides — the column list,
the JSON encoding — has been in the codebase the whole time.

So this RFC is **mostly wiring**: the service layer, the routes and the
documentation are what is missing. It also means the cycle must not extend the
pattern: every port method and audit kind it adds gets a caller in the same
cycle, or is not added.

## 12. Cycle 1 reviewed; C1-141 (2026-10-25)

T1–T7 landed in `464b4f5` and are accepted: 1,539 host tests, 194 documented
routes, the secret exposed at exactly two sites, and `/token` checking the
registered method **before** any secret comparison. §11's prediction held — the
cycle was wiring, and nothing unwired was added.

### 12.1 `token_auth_method` is updatable; `client_type` is not

The implementer made both immutable, reasoning that an update would re-run the
coupling check "at a second enforcement site". **That premise does not hold**:
the handoff required the coupling to live in the service, so an update calls the
same validator again rather than duplicating it.

- **`client_type` stays immutable** — public ⇔ confidential implies minting or
  destroying a secret, which is a different operation; delete and re-register.
- **`token_auth_method` becomes updatable** between `client_secret_basic` and
  `client_secret_post`: only the transport changes, the secret is untouched, and
  the coupling rule is unaffected.

**This is also the remedy for §12.2**, and that is what decided it.

### 12.2 The backward-compatibility finding: no backfill

`token_auth_method` was written by default and never read before this RFC, so a
confidential client registered by hand may say `none` and will now be refused at
`/token` before its secret is compared. **No backfill migration**: guessing
`client_secret_basic` for every such row could be wrong for an integrator who
uses POST, and a migration that guesses credentials-adjacent configuration is
worse than one that does not run. Nobody has deployed this tree, so nothing real
is affected — and with §12.1 the remedy is one API call rather than SQL, which is
the whole point of this RFC. Documented in the integrator chapter and in the
release notes.

### 12.3 A documented CSRF control that does not exist

Found by the reviewer while checking the implementer's §4 flag.
`routes/admin/console/audit_export.rs` reads `req.form_data()` and contains **no
CSRF code**, while `route-contracts.md:96` claims CSRF for
`POST /admin/console/audit/export`. The console authenticates with a session
cookie, so CSRF applies. Severity is low-to-moderate — a forged POST forces an
export and an audit event, but the CSV reaches the victim's own browser, not an
attacker — and it is still a control the contract claims and the code lacks.
Fixed in C1-141.

### 12.4 RUSTSEC-2026-0387 accepted, with a measured justification

`crypto-bigint` 0.5.5, timing variability in constant-time-intended operations,
reached via `p256`/`ecdsa`/`elliptic-curve`. No compatible update exists; the fix
needs the whole stack bumped, which touches WebAuthn verification.

**Measured:** JWT signing is **Ed25519 only** (`jwt/signer.rs`), and `p256` is
reached **only** by `webauthn/cose.rs`, which does `VerifyingKey` +
`verify` on an ECDSA-P256 assertion. There is no `SigningKey` and **no secret
key material on that path** — the authenticator holds the private key.

A timing side-channel leaks information about secret inputs; on cesauth's only
path into that crate every input is public. **Accepted with that reasoning
recorded beside the id, and an explicit revisit trigger: if cesauth ever signs
with P-256 — ES256 JWT support or any ECDSA signing path — the acceptance is void
and the stack must be upgraded first.** The upgrade remains a recorded
candidate, not a mid-feature decision.
