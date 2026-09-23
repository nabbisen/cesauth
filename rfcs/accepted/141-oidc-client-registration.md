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
2. Should deletion be soft (revoking grants) rather than a row delete? Grants
   and refresh families reference `client_id`. **Open**; decide at the handoff.

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
