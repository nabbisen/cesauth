# Developer Handoff — RFC 141 cycle 1, the client-registration API and its documentation

**Governing RFC.** [`rfcs/accepted/141-oidc-client-registration.md`](../../accepted/141-oidc-client-registration.md) — read **§10 first**: it closes §9 q1 and records two defects found closing it.
**Target release.** 0.85.0. **Level: minor** — new capability, plus one
behaviour change at `/token` (§3.6).
**Prepared by.** Architect · **Implemented by.** Mid-capability model
**Blocked on.** Nothing. `0.84.3` is tagged. **Work on `main`**, no branch.
**Scope.** The **API and the documentation**. The console *screen* is cycle 2
(§7) — it is real frontend work and splitting keeps this reviewable.

---

## 1. Purpose

After this, an OIDC client can be registered, listed, updated, have its secret
rotated and be deleted **through an API**, with the secret minted server-side
and shown once. No operator ever hand-writes `oidc_clients` again, and the
integrator documentation describes the product rather than a SQL placeholder.

## 2. Read this first: most of the storage layer already exists, unused

| Thing | State |
|---|---|
| `ClientRepository::create(&OidcClient, secret_hash: Option<&str>)` | **declared and implemented in both adapters** — `adapter-cloudflare/src/ports/repo/clients.rs:152` writes all eleven columns, JSON-serialising `redirect_uris` and `allowed_scopes` and handling the nullable `audience` and secret hash; `adapter-test/src/repo/clients.rs:38` mirrors it |
| Callers of it | **none.** `grep -rn 'clients\.create('` → nothing |
| `AdminClientCreated` audit kind (`admin_client_created`) | **declared, no writer** (`backend/src/audit.rs:92, :328`) |
| `OidcClientAudienceChanged` audit kind | **declared, no writer** (RFC 141 §10.2) |

**So this is mostly wiring, not building.** The missing pieces are the service
layer, the routes, and the documentation. **Do not write a second `INSERT`** —
the existing one already encodes the column list and the JSON handling that
`production.md` elides.

**And note the pattern, because this cycle must not extend it.** Three
capabilities in this one area were declared, carried, and never called. Every
port method and audit kind you add here gets a caller **in this cycle**, or it
does not get added.

## 3. Resolved decisions — do not re-open

| # | Decision |
|---|---|
| 3.1 | **System console**, `/admin/console/clients` (RFC §10.1). `oidc_clients` has no `tenant_id` and never has, so clients are global. **Do not add a tenant column** — that is RFC 119's question |
| 3.2 | **The secret is minted server-side**: 256 bits from the platform RNG, base64url, stored as `sha256_hex` via the existing `service::client_auth::sha256_hex`, and **returned exactly once** in the create/rotate response. No route ever returns it again, and it is never logged |
| 3.3 | **`redirect_uris` are validated by the matcher `/authorize` already uses** (`core/src/oidc/authorization.rs`, which has property tests). Registration and authorization must not hold two opinions about what is valid |
| 3.4 | **`client_type` ↔ `token_auth_method` are coupled**: `public` ⇒ `none` and no secret; `confidential` ⇒ `client_secret_basic` or `client_secret_post` **and** a secret. The combination RFC 137 §12.2 rejects at `/token` becomes unrepresentable at registration |
| 3.5 | **`require_pkce` cannot be set false.** Reject it explicitly; accepting a value the product ignores is the defect class this project keeps finding |
| 3.6 | **`/token` enforces the registered method** (RFC §4.4). This is the behaviour change: today a public client is accepted whatever secret it presents, and a confidential client may use either method regardless of registration |
| 3.7 | **Deletion is a hard delete** — §9 q2, decided here. See §4 |
| 3.8 | **The existing audit kinds get their first writers**: `AdminClientCreated` on create, `OidcClientAudienceChanged` on an audience change (with `before`/`after`, as its doc already specifies). Add kinds for update, delete and secret rotation |

## 4. §9 q2 closed — hard delete, with its consequences documented

**Hard delete.** `grants` and `consent` already declare
`FOREIGN KEY (client_id) REFERENCES oidc_clients(id) ON DELETE CASCADE`
(`migrations/0001_initial.sql`), so they go with it. A soft-delete column was
rejected: it would require a migration **and** a check in every client lookup,
including `find_auth_view`, which is on the authentication path — a security
surface this RFC has no reason to touch.

**What deletion does and does not stop, and the documentation must say both:**

- **Refresh stops immediately.** `rotate_refresh` loads the client first, so a
  deleted client's refresh tokens fail with `invalid_client`. **Prove it with a
  test.**
- **Issued access tokens remain valid until they expire** — they are
  self-contained signed JWTs, and `/introspect` does not check that the client
  still exists. With `ACCESS_TOKEN_TTL_SECS` at its default that is ten minutes.
  **Do not claim deletion revokes access**, and say so in the docs.

## 5. Change scope

| # | Task | Where |
|---|---|---|
| T1 | **Port**: add `list`, `update`, `delete` and `set_secret_hash` beside the existing `create`, implemented in **both** adapters | `core/src/ports/repo.rs`, both adapters |
| T2 | **Service**: validation (§3.3–§3.5), secret minting (§3.2), and the operations. Pure where it can be; the RNG is the only impure part | `core/src/service/` (new module) |
| T3 | **Routes**, mirroring the existing console shape exactly — system-admin auth, CSRF on writes, an audit event per write: `GET /admin/console/clients`, `GET /admin/console/clients.json`, `POST /admin/console/clients`, `POST /admin/console/clients/:id`, `POST /admin/console/clients/:id/rotate-secret`, `POST /admin/console/clients/:id/delete` | `backend/src/routes/admin/` |
| T4 | **`/token` enforces the registered method** (§3.6), with the fires pair | `core/src/service/token.rs` or `client_auth.rs` |
| T5 | **`route-contracts.md`** documents all six routes; the check must pass | `docs/src/expert/route-contracts.md` |
| T6 | **The integrator chapter** — new: the discovery document, the scopes and claims cesauth issues, how to register a client and what every field means, redirect-URI rules, token lifetimes to assume, and what each `/token` error means for the integrator's own code. Add it to `SUMMARY.md` | `docs/src/` |
| T7 | **`production.md`'s elided `INSERT` is replaced** by the API, and the local-run guide too if it hand-writes a client | `docs/src/deployment/production.md`, `beginner/first-local-run.md` |

**Order: T1 → T2 → T3 → T4 → T5–T7.** T2 before T3 so the validation has tests
that do not need a route.

## 6. The traps

**6.1 Returning the secret twice.** It appears in exactly one response. Not in
the list, not in the detail, not in a log line, not in an audit payload. The
audit event records *that* a secret was minted, never the secret.

**6.2 A second definition of "valid redirect URI".** §3.3. If the matcher's
signature does not fit, change the call, not the rule.

**6.3 Making the unrepresentable representable.** §3.4's coupling must be
enforced in the **service**, not only in the route, so a future caller cannot
bypass it.

**6.4 Enforcing the auth method too early.** T4 changes `/token`. RFC 137's
order is: load the client, authenticate, *then* touch the code or family. The
method check belongs with authentication, and a mismatch is `invalid_client`
with the existing mapping — no new wire shape.

**6.5 Breaking the documented walkthrough.** `demo-cli` is a **public** client
with `token_auth_method = none`, and the beginner guide signs in with it. T4
must leave that flow working — run it.

**6.6 Adding another unwired capability.** §2. If a port method or audit kind
ends the cycle with no caller, remove it.

## 7. Explicit non-change scope

- **Not the console screen.** Cycle 2. This cycle's surface is the API and the
  `.json` endpoints.
- **Not Dynamic Client Registration (RFC 7591)**, not per-tenant ownership
  (RFC 119), not consent or connected-apps screens.
- **Not a soft-delete column** (§4). **Not** a change to `find_auth_view`'s
  shape beyond what T1 needs.
- No `cargo fmt`. **Work on `main`**; no branch.

## 8. Mechanical assertions

```sh
# the secret appears in exactly one response path
grep -rn 'secret' crates/backend/src/routes/admin/ --include='*.rs' | grep -v tests

# nothing added is unwired: every new port method has a caller
for m in list update delete set_secret_hash; do echo -n "$m: "; grep -rn "\.$m(" crates/backend/src crates/core/src --include='*.rs' | grep -c clients; done

# the existing INSERT is the only one
grep -rn 'INSERT INTO oidc_clients' crates/ --include='*.rs' | wc -l      # must stay 1

# the audit kinds that had no writer now have one
grep -rn 'AdminClientCreated\|OidcClientAudienceChanged' crates/backend/src --include='*.rs' | grep -v 'audit.rs'
```

## 9. Required evidence

- **A test per validation rule**, including each unrepresentable combination
  from §3.4 and `require_pkce = false`.
- **The secret round-trip**: the minted secret authenticates at `/token`; the
  stored value is its hash; rotation invalidates the previous one.
- **Deletion**: refresh fails afterwards (§4), and the grant and consent rows
  are gone.
- **T4 fires pair**: a public client presenting a secret, and a confidential
  client using the method it did not register, are refused; restore and they
  are not.
- **A live walkthrough**: register a confidential client **through the API**,
  then complete `first-oidc-flow.md` with it, and run the existing `demo-cli`
  flow unchanged (§6.5). Never print a secret — write it to the scratchpad as
  RFC 139's package did.
- **The full gate set**, baseline **1,509** host tests stated with its command,
  and the bundle with `du -b`, gzip and `sha256sum`.

I re-run the validation tests, T4's fires pair, and the live walkthrough.

## 10. What must NOT be claimed

- **Not that deletion revokes access** (§4).
- **Not that the registered method is enforced anywhere but `/token`**;
  `/introspect` and `/revoke` already authenticate and are out of scope.
- **Not that the console can manage clients** — that is cycle 2.
- Not that it works on Cloudflare; not that CI enforces anything (it reports).

## 11. Acceptance criteria

RFC 141 §7, minus the console screen (§7 here). Checked hardest: **the secret
is returned exactly once and never logged**, **§3.4's couplings are
unrepresentable**, **the `demo-cli` walkthrough still works**, and **nothing
unwired is added** (§2).

## 12. Review request

To `.git-exclude/review-request/`: implementation summary, changed files, the §8
assertions, the §9 evidence, T7's doc dispositions, and §10's list.

**Do not cut a release, bump a version, or create a tag.**

Report the path only.
