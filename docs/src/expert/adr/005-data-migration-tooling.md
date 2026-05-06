# ADR-005: Data migration tooling for server-to-server moves

**Status**: Accepted (v0.21.0)
**Decision**: A standalone host-side CLI binary `cesauth-migrate`
in a new `crates/migrate/` workspace member, **operator-mediated**
(not Worker-self-export). Two data formats:
- **`.cdump`** = full structured snapshot for cross-account moves
  (preserves invariants, secrets coordinated separately).
- **`.cdump.redacted`** = same structure with profile-driven PII
  scrubbing for prod → staging refresh.
Manifest signed with a per-export Ed25519 key generated at export
time; the importer must be told the public key out-of-band.
**Rejected**:
- Self-export endpoint at `/admin/migrate/*` (server holds export
  state, attack surface, complicates revocation).
- Reusing `wrangler d1 export` raw SQL dumps as the canonical
  format (loses schema invariants, no PII redaction, no
  versioning).
- Bundling secrets (`JWT_SIGNING_KEY` etc.) in the dump (a
  compromised dump would forge tokens).
- ZIP-of-CSV format (no signed manifest, no schema versioning).

## Context

cesauth deployments occasionally need to move between Cloudflare
accounts: M&A events, regional separation for data residency,
isolating a compromised account from the new clean one, or
operator preference shifts. The
[Backup &amp; restore](../../deployment/backup-restore.md) chapter
in v0.18.1 documents `wrangler d1 export` + manual restore as the
current state. This works for same-account moves but has four
gaps that operators have flagged:

1. **No PII redaction**. Prod → staging refresh needs sanitized
   data; today operators write hand-rolled `sed` scripts. Each
   such script is a chance to leak.
2. **No schema-invariant preservation**. `wrangler d1 export`
   produces SQL with FK relationships expressed only via
   constraint declarations, not via export ordering. A naive
   restore can fail mid-way and leave the destination half-
   populated.
3. **No tampering protection**. The dump is plain SQL. Anyone
   between source and destination can edit it before the
   importer runs — no operator-detectable signal of corruption.
4. **No secrets coordination**. The operator handles secrets
   "by remembering" — fragile. A move where new secrets are
   minted at the destination and old tokens grace-rotated
   needs choreography the docs do not currently provide.

The use case is also clear: a cesauth operator wants to
**move 1+ tenants' worth of data** (or sometimes the whole
deployment) from source-account to destination-account, with:

- Short maintenance window (target: < 4 hours from
  "stop writing source" to "destination is the new source").
- Verifiable destination state ("did everything import
  cleanly?").
- Optional PII redaction for staging-bound dumps.
- Reasonable defense against accidental or malicious
  tampering of the dump in transit.

The threat model is bounded: the operator has root on both
sides, this is not a privacy-against-the-operator product. But
"the operator" is often "an operations team" plural, and the
in-transit dump may pass through email, file shares, CI
artifacts. So the tool defends against **modification in
transit**, not against **the operator themselves being malicious**.

## Decision

### Q1: What is being migrated — data, not secrets

A `cesauth-migrate` dump contains everything in cesauth's D1
schema: users, tenants, organizations, groups, memberships,
role assignments, OIDC clients (with secret hashes), JWT
signing key **public** halves, audit references (the audit
events themselves stay in R2). It does **NOT** contain:

- JWT signing key **private** halves.
- `SESSION_COOKIE_KEY`, `ADMIN_API_KEY`.
- Active sessions (DO state — short-lived, regenerable).
- Auth challenges, refresh-token families (DO state).
- Pre-v0.32.0 R2 audit objects (separate concern, separate
  tooling). v0.32.0+ audit events live in the `audit_events`
  D1 table and ARE included in dumps; the chain hashes
  travel intact, so a re-import of a dump produces a
  database whose chain verifies identically (ADR-010).

Rationale: a stolen `.cdump` should not be capable of forging
tokens. The operator coordinates secret regeneration as a
separate runbook step (see Q6). The dump format declares which
`kid` was active at export time so the importer knows what
keys it will need to provision at the destination.

### Q2: Source-side trust boundary — operator-mediated, not server-self-export

**Operator-mediated**: the operator runs `cesauth-migrate
export` on a host machine that has D1 read credentials (a
Wrangler API token with `Workers D1:Edit` scope, the same
credential `wrangler d1 export` already needs). The CLI
queries D1 via the Cloudflare D1 HTTP API, transforms the
result into the structured dump format, and writes the file.

**Rejected**: a `/admin/migrate/export` HTTP endpoint that
the Worker itself serves. Reasons:

- **Revocation is hard.** A leaked credential that lets the
  attacker hit the export endpoint produces a full-database
  dump. Revoking the credential requires admin-token rotation;
  the dump is already exfiltrated.
- **Attack surface.** A new admin endpoint that can dump the
  whole DB is exactly the kind of surface that wants
  scrutiny. CLI-driven export uses credentials that already
  exist (D1 API tokens) and produces no new surface.
- **State management.** A multi-MB export streamed over HTTP
  needs incremental progress, retries, resumption — all
  server-side state. CLI-driven runs locally, retries are
  the operator's problem.

**Rejected**: an "operator-runs-it-on-the-Worker" helper
endpoint that triggers a one-shot export to R2. Adds two
attack surfaces (the trigger + the R2 object) and a new R2
bucket binding. CLI is simpler.

### Q3: Destination-side trust boundary — signed manifests, verification handshake

The exporter:

1. Generates a **fresh Ed25519 keypair** at export time (used
   only for this dump).
2. Produces the dump payload (Q4 below describes the format).
3. Signs the payload's SHA-256 hash with the private key,
   embeds the signature + public key in the manifest at the
   head of the file.
4. **Discards the private key.** Single-use.

The importer:

1. Reads the manifest, extracts the public key.
2. **Asks the operator out-of-band** to confirm the public-key
   fingerprint (`SHA-256` of the public key, displayed as a
   short hex). The operator compares it to the value the
   exporter printed at export time. This is the
   "verification handshake" — it stops dumps replaced in
   transit.
3. If fingerprint matches, verifies the signature, then
   imports.

**Rejected**: long-lived signing keys in cesauth's secret
store. Increases the key-management surface for marginal
benefit; per-export keys are simpler.

**Rejected**: PGP / X.509 / GPG. cesauth doesn't currently
manage operator-PKI; introducing it for this one use case is
disproportionate.

**Rejected**: no signature at all. A dump that travels
through CI artifacts or email is reasonably likely to be
modified accidentally (e.g., line-ending normalization);
we want to catch that. And a signed dump is what
operators expect from a "data migration tool" — meeting the
expectation is cheaper than explaining why we don't.

### Q4: CLI shape vs library shape — both, layered

The implementation is two layers:

- **`cesauth-core::migrate`** — the library. Defines the
  dump format types (`Manifest`, `TableSnapshot`,
  `RedactionProfile`), serialization, signature primitives,
  invariant verification. Pure functions; no I/O. Testable
  on the host without a D1.
- **`cesauth-migrate`** — the CLI binary in
  `crates/migrate/`. Wires the library to D1 (via
  Cloudflare's HTTP API for export, via wrangler-shaped SQL
  execution for import), implements `clap`-style command
  parsing, owns the operator UX (progress bars, prompts).

Rationale: the library has tests; the CLI has no tests beyond
"compiles". This is the same shape as `crates/core` vs
`crates/worker` already established.

### Q5: Schema invariants — verify-on-import, not assume-correct

D1 raw SQL dumps trust the source schema to be consistent.
cesauth-migrate doesn't. After every table import, the
importer:

1. **Runs the schema-invariant checks** for that table — same
   checks `cesauth-core` types use to validate boundary
   crossings (e.g., `tenants.slug` matches the slug regex,
   `users.tenant_id` references an existing `tenants.id`,
   memberships' (user_id, group_id) tuples are valid).
2. **Surfaces violations as a structured report** — the
   importer doesn't abort on the first violation; it
   completes the import in a transaction, reports all
   violations, and asks the operator to confirm before
   committing.
3. **Refuses commit** unless the operator explicitly waves
   the violations off (`--accept-violations` flag for
   recovery scenarios where partial integrity is acceptable;
   refused by default).

This costs round-trips at import time. The expected dataset
size (tens of thousands of users at most for the deployments
this tool targets) makes the cost acceptable.

**Rejected**: dump-time invariant guarantees. Source-side
guarantees that every export is consistent are theoretically
appealing but require holding the database in a quiescent
state during export, which isn't always possible. Verify
on the receiving side; it's the side that owns the resulting
state.

### Q6: Secrets coordination — runbook task with tool support

The CLI does NOT export, transport, or import secrets. It
DOES:

- **Print at export time**: a list of every secret the
  destination will need to mint fresh (`JWT_SIGNING_KEY`,
  `SESSION_COOKIE_KEY`, `ADMIN_API_KEY`, plus optional
  `TURNSTILE_SECRET`, `MAGIC_LINK_MAIL_API_KEY`). For each:
  the recommended generation command and the kid/handle
  the destination should use.
- **Print at import time**: a checklist of "before this
  destination is operational, do these steps in this order"
  — generate keys, push to `wrangler secret`, update
  `wrangler.toml` `JWT_KID`, etc.
- **Refuse `import --commit`** unless the destination has
  `JWT_SIGNING_KEY` set (the importer reads the binding to
  check).

**Rejected**: tool-managed secret transport. Secrets
encryption, secrets-in-vault integration, etc. Out of scope
— operators have their own secret management; the tool just
points at it.

## Consequences

- **New crate**: `crates/migrate/` is a workspace member.
  Different from existing crates: it's a `[[bin]]` target,
  not a library or `cdylib`. CI runs `cargo build -p
  cesauth-migrate` on host targets only.
- **New core module**: `cesauth_core::migrate`. Adds dump
  format types, invariant checks, signing primitives.
  Touches no existing modules.
- **New file format**: `.cdump` (raw structured) and
  `.cdump.redacted` (PII-scrubbed). Format spec lives in the
  module documentation.
- **No schema migration**. The exporter reads existing
  tables as-is; the importer writes existing tables as-is.
  The format itself carries a schema-version number so
  future schema changes don't break old dumps.
- **Documentation**: new
  `docs/src/deployment/data-migration.md` chapter. The
  Backup &amp; restore chapter from v0.18.1 gains a pointer
  to this for the cross-account-move case.
- **Operator runbook**: new section in the Day-2 runbook
  on "Pre-flight before invoking `cesauth-migrate`" and
  "Post-import verification".

## Implementation phases

The ADR settles the design; landing it across releases follows
the v0.16.0 → v0.17.0 → v0.18.0 model (foundation → CLI →
polish):

1. **0.19.0 (this ADR + foundation)**: ADR-005 written,
   `cesauth_core::migrate` module skeleton with the
   `Manifest`, `TableSnapshot`, `RedactionProfile` value
   types, signature primitives, invariant-check trait. New
   `crates/migrate/` workspace member with the CLI's
   `clap` skeleton — accepts subcommands but has no
   implementation behind them yet. Type-level tests cover
   the format round-trip and the redaction profile lookup.
   Targeted scope: ADR + types, no actual export or import
   logic yet.
2. **0.20.0 (export path + redaction profiles)**: Real
   `cesauth-migrate export` against a live D1 (or a
   tested-against-in-memory mock for host tests).
   Redaction profile registry. Signed manifest emission.
   Documentation: format spec finalized, walkthrough.
3. **0.21.0 (import path + invariant verification)**: Real
   `cesauth-migrate import` against a live D1, the
   verification handshake (operator prompt + fingerprint
   confirmation), invariant-check execution, the
   `--accept-violations` recovery escape hatch. Docs:
   day-2 runbook section, disaster-recovery integration.
4. **0.22.0 (polish)**: Resume support for interrupted
   imports, progress reporting, multi-tenant filtered
   exports (`--tenant slug,slug`), staging refresh as a
   first-class workflow command (combines export +
   redaction + import in one invocation).

This phasing trades release count for risk: each phase is
independently shippable and testable; problems surface in
isolation rather than as a single multi-thousand-line drop.
The same approach worked for ADR-001 through ADR-004.

## Format sketch (informal)

A `.cdump` is a single file:

```
+-----------------------------------+
| Manifest (JSON, line-delimited)   |
|   - format_version: 1             |
|   - cesauth_version: "0.19.0"     |
|   - schema_version: 6             |
|   - exported_at: 1714287000       |
|   - source_account_id: "abc..."   |
|   - source_d1_database_id: "..."  |
|   - signature_alg: "ed25519"      |
|   - signature_pubkey: "base64..." |
|   - signature: "base64..."        |
|   - payload_sha256: "hex..."      |
|   - tables: [{name, row_count,    |
|              sha256}, ...]        |
|   - redaction_profile: null|"..." |
+-----------------------------------+
| Payload (newline-delimited JSON)  |
|   {table: "tenants", row: {...}}  |
|   {table: "tenants", row: {...}}  |
|   {table: "users",   row: {...}}  |
|   ...                             |
+-----------------------------------+
```

The signature covers the SHA-256 of the payload; the manifest
itself sits before the signature in file order, so it must
be parsed first to retrieve the public key + signature.
Tables are dumped in topological order (parents before
children) — `tenants` before `users`, `users` before
`memberships`, etc. This makes a streaming importer possible
without holding the whole file in memory.

The full format spec lives in `crates/core/src/migrate.rs`
module documentation; this sketch is for design-discussion
purposes.
