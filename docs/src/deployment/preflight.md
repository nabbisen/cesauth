# Pre-flight checklist

This is the consolidated "did I forget anything" list before
deploying cesauth to production for the first time, or before
promoting a major version bump.

It exists because the rest of the Deployment section is organized
by topic (Wrangler, Secrets, Cron, etc.) and an operator
mid-deploy doesn't want to read each in full to confirm one
missing step. Use this page as a cross-cutting confirmation;
follow the linked chapter for the actual procedure.

**This page assumes you've read [Migrating from local to
production](./production.md) at least once.** It does not repeat
the rationale — only the checks.

## A — Cloudflare account & billing

- [ ] Cloudflare account created with the Workers Paid plan
      (Durable Objects require it).
- [ ] R2 enabled on the account (cesauth uses two R2 buckets:
      audit + assets).
- [ ] Account-level API token issued for Wrangler with
      `User:User Details:Read`, `Workers Scripts:Edit`,
      `Workers KV Storage:Edit`, `Workers R2 Storage:Edit`,
      `Workers D1:Edit`, `Account Settings:Read`.
- [ ] Billing alerts configured (Cloudflare dashboard →
      Manage Account → Billing). v0.32.0+: D1 row growth
      (especially `audit_events`) is the surface to watch on
      a small account; D1 free-tier ceiling is 500 MB.

## B — Resources provisioned

Each item below corresponds to one binding in `wrangler.toml`. See
[Wrangler configuration → Bindings](./wrangler.md#bindings) for the
full table.

- [ ] **D1 database** created (`wrangler d1 create cesauth-prod`).
      Database ID copied into `wrangler.toml` under
      `[[d1_databases]]`.
- [ ] **KV namespace** created
      (`wrangler kv namespace create CACHE`). ID copied under
      `[[kv_namespaces]]`.
- [ ] **R2 assets bucket** created (`cesauth-assets-prod`).
      v0.32.0+: only the assets bucket is needed; the v0.31.x
      audit bucket binding was removed when audit moved to D1
      (ADR-010).
- [ ] Durable Objects: nothing to provision; the four classes
      are declared in `wrangler.toml` and provisioned on first
      deploy.

## C — Schema applied

- [ ] All migrations applied to remote D1:
      ```sh
      wrangler d1 migrations apply cesauth-prod
      ```
      (No `--local`.)
- [ ] Verify migration count matches the `migrations/` directory:
      ```sh
      ls migrations/ | wc -l
      wrangler d1 execute cesauth-prod --remote \
        --command="SELECT count(*) FROM d1_migrations;"
      ```
      The two numbers must match.

## D — Secrets set

Run `wrangler secret list --env production` and confirm each:

- [ ] `JWT_SIGNING_KEY` — Ed25519 PKCS#8 PEM. Generate with
      `openssl genpkey -algorithm ed25519`.
- [ ] `SESSION_COOKIE_KEY` — 48 random bytes, base64.
- [ ] `ADMIN_API_KEY` — opaque bearer for `/admin/*`.
- [ ] `TURNSTILE_SECRET` — only if Turnstile is enabled (see
      [Turnstile integration](../expert/turnstile.md)).
- [ ] `MAGIC_LINK_MAIL_API_KEY` — only if a real mail provider
      is wired (see [`production.md` Step 6](./production.md)).

The first three are non-negotiable — every deploy fails closed
without them.

## E — `[vars]` set

Run `cat wrangler.toml | grep -A50 '\[vars\]'` and confirm:

- [ ] `ISSUER` is set to your **production** issuer URL
      (e.g. `https://auth.example.com`). Must match the
      `iss` claim every client validates.
- [ ] `JWT_KID` matches a row in `jwt_signing_keys` whose
      `retired_at` is NULL.
- [ ] `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_RP_ORIGIN`
      set to your production origin.
- [ ] `WRANGLER_LOCAL = "0"`. Never `"1"` in any deployed env.
- [ ] `LOG_EMIT_SENSITIVE = "0"` unless a specific incident
      response says otherwise.
- [ ] TTLs (`ACCESS_TOKEN_TTL_SECS`, `REFRESH_TOKEN_TTL_SECS`,
      etc.) reviewed against your security posture.

## F — Cron Triggers

- [ ] `wrangler.toml` has the `[triggers]` block:
      ```toml
      [triggers]
      crons = ["0 4 * * *"]
      ```
      Without this, the v0.18.0 anonymous-trial retention sweep
      never runs and anonymous users accumulate indefinitely.
      See [Cron Triggers](./cron-triggers.md).

## G — Custom domain & TLS

- [ ] Custom domain configured for the Worker (Cloudflare
      dashboard → Workers & Pages → cesauth → Triggers →
      Custom Domains, NOT Routes — see
      [Custom domains & DNS](./custom-domains.md) for why).
- [ ] TLS edge certificate active for that domain.
- [ ] DNS A/AAAA/CNAME pointed at Cloudflare and proxied
      (orange cloud).

## H — Mail provider

- [ ] `MAGIC_LINK_MAIL_API_KEY` set if production users will
      authenticate via Magic Link (the most common case).
- [ ] The mail-delivery code path no longer logs the OTP
      plaintext into the audit channel — see
      [`production.md` Step 6](./production.md). The dev
      shortcut is a release blocker.

## I — Dependency hygiene

- [ ] `cargo audit` runs clean against the latest advisory
      database:
      ```sh
      cargo install cargo-audit
      cargo audit
      ```
- [ ] `.github/workflows/audit.yml` is on the repo's main
      branch and green.

## J — Smoke tests

After `wrangler deploy`:

- [ ] Discovery doc resolves and `issuer` matches:
      ```sh
      curl -s https://auth.example.com/.well-known/openid-configuration \
        | jq -r .issuer
      ```
- [ ] JWKS resolves and contains the expected `kid`:
      ```sh
      curl -s https://auth.example.com/jwks.json \
        | jq -r '.keys[].kid'
      ```
- [ ] Magic-link delivery actually delivers (issue an OTP, watch
      it arrive in the inbox, NOT in `wrangler tail`).
- [ ] Anonymous trial begin works:
      ```sh
      curl -sS -X POST https://auth.example.com/api/v1/anonymous/begin
      ```
- [ ] (24h+ after deploy) Cron Trigger fired at least once —
      check Workers & Pages → cesauth → Settings → Triggers.

## K — Backup baseline

- [ ] First D1 export captured and stored in safe long-term
      storage (NOT in the same Cloudflare account):
      ```sh
      wrangler d1 export cesauth-prod --remote --output cesauth-baseline.sql
      ```
      See [Backup & restore](./backup-restore.md).

## L — Communication

- [ ] On-call schedule defined; runbook URL bookmarked
      (see [Day-2 operations runbook](./runbook.md)).
- [ ] Status page or incident-comms channel chosen.
- [ ] Disaster-recovery contact list (Cloudflare support tier,
      DNS registrar, mail provider) in a place that survives
      cesauth itself being down.

---

## Tier-by-tier readiness

If you cannot tick everything in this list, here's how cesauth
degrades:

| Missing | Effect |
|---|---|
| Section A | Deploy fails (no Workers Paid → no DOs → no `wrangler deploy`). |
| Section B | Deploy fails or runtime crashes on first request to a missing binding. |
| Section C | Schema-shaped errors at runtime; users cannot register. |
| Section D | Token verification fails; sessions cannot start. |
| Section E | `WRANGLER_LOCAL` accidents leak dev surfaces; `ISSUER` mismatch breaks every client. |
| Section F | Anonymous trials accumulate; storage grows unboundedly. |
| Section G | Browsers refuse the origin; WebAuthn / cookies break. |
| Section H | Magic-link "delivers" via the audit log — operator can read every user's OTP. **Critical incident posture.** |
| Section I | Deploying with known-CVE deps. **Critical incident posture.** |
| Section J | Silent failure invisible until users complain. |
| Section K | First incident has no recovery path. |
| Section L | First incident is reactive instead of routine. |

The first deploy that fails any of A–E is normal and recoverable.
A deploy that fails H or I in production is a **postmortem-grade
event** — write it up.
