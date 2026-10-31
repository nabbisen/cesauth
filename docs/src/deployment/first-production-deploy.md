# Your first production deployment

This page is the one ordered pass from an empty Cloudflare account to a
tenant completing an OIDC flow. Fifteen chapters in this section already
cover every individual procedure in depth; what was missing was the
**order** — this page is that order, nothing more. Each step below is a
short paragraph saying what you are doing and why it comes here, then a
link to the chapter that owns the actual commands. Follow the links; do
not expect the commands here, because a second copy of them is a second
thing that can drift from the first.

The companion to this page is
[Your first OIDC flow with curl](../beginner/first-oidc-flow.md) — once
you have deployed, that chapter is what proves the deployment actually
works, and its closing step is this page's closing step too.

## 0 — Before you provision anything

Read [Pre-flight checklist § A](./preflight.md#a--cloudflare-account--billing)
first. cesauth needs the **Workers Paid plan** — the daily cron
maintenance passes alone exceed Free-plan subrequest and D1-query
limits — and confirming billing is live is the one prerequisite this
page cannot discover for you by walking it. Everything from here on
assumes it.

## 1 — Provision real resources

Create the D1 database, the KV namespace, and the R2 bucket, and copy
each generated id into `wrangler.toml`. [production.md, Step
1](./production.md#step-1--provision-real-resources).

## 2 — Apply migrations `--remote`

Run the schema migrations against the database you just created — not
`--local`, which only ever touches your own machine's simulation.
[production.md, Step 2](./production.md#step-2--apply-migrations-remotely).

## 3 — Seed production rows

Register the public half of your production JWT signing key in
`jwt_signing_keys`, so `/jwks.json` can serve it once you deploy.
[production.md, Step 3](./production.md#step-3--seed-production-rows).

## 4 — Set production secrets

`wrangler secret put` for `JWT_SIGNING_KEY`, `SESSION_COOKIE_KEY`, and
`ADMIN_API_KEY` — fresh values, never reused from local development.
`ADMIN_API_KEY` is your first admin credential; you will use it as the
bearer token for every step below that calls an `/admin/*` endpoint.
[production.md, Step 4](./production.md#step-4--set-production-secrets).

## 5 — Confirm `WRANGLER_LOCAL` is off

One line in `wrangler.toml`, and it is not optional: `WRANGLER_LOCAL="1"`
in production exposes `/__dev/audit` and `/__dev/stage-auth-code` — two
routes built for exactly the kind of scripted walkthrough this page
describes — on your public surface. [production.md, Step
6](./production.md#step-6--confirm-wrangler_local-is-off).

## 6 — Configure Cron Triggers

Without the `[triggers]` block, the anonymous-trial retention sweep and
the other daily maintenance passes compile into the Worker but
Cloudflare never calls them. [production.md, Step
8.5](./production.md#step-85--configure-cron-triggers) (also its own
chapter: [Cron Triggers](./cron-triggers.md)).

## 7 — Deploy

```sh
wrangler deploy
```

[production.md, Step 9](./production.md#step-9--deploy), which also
covers the discovery-document smoke test to run immediately after.

## 8 — Register your first OIDC client

**This step comes after deploy here, even though
[production.md, Step 5](./production.md#step-5--register-your-oidc-clients)
numbers it before Step 9's deploy.** That chapter's Step 5 curls your
production domain — there is nothing there to curl until Step 7 above
has run. The dependency it already states correctly (clients are
registered once `ADMIN_API_KEY` exists, Step 4) is right; its position
relative to deploy is not. This page orders it correctly instead of
reproducing the inversion.

Registering a client is one `POST` to `/admin/console/clients`,
bearing `ADMIN_API_KEY`; the response's `client_secret` is shown
exactly once. See production.md's Step 5 for the full command and
payload shape.

## 9 — Observability

Before you need it, not after: know where the audit trail lives, what
`wrangler tail` shows you, and what cesauth does **not** do today (it
does not push audit events to an external SIEM). [Observability](./observability.md).

## 10 — Day 2

Bookmark this one. [Day-2 operations runbook](./runbook.md) covers
secret rotation, the cron passes' expected behavior, and what to do
when one of them reports a problem.

## Prove it works

Deploying is not the finish line — a tenant completing an OIDC flow is.
Run [Your first OIDC flow with curl](../beginner/first-oidc-flow.md)
against your production domain instead of `localhost:8787`, using the
client you registered in step 8 instead of that chapter's `demo-cli`,
and your own real user instead of `bob@example.com`. If every step in
that chapter succeeds against your deployment, the sequence above held
end to end.

Two adjustments the tutorial's own commands need for a real deployment:

- **No `/__dev/*` routes.** Step 4b's dev-only auth-code staging helper
  is gated on `WRANGLER_LOCAL="1"` (step 5 above turned it off, on
  purpose) and does not exist in production. A real client drives
  `/authorize` through an actual browser redirect instead — the
  "A real browser would render the login page here" paragraph in that
  chapter's Step 4b is what actually happens; the dev helper was only
  ever a substitute for not having one.
- **A confidential client authenticates differently.** If you
  registered a `confidential` client (the production.md Step 5
  example), `/token` takes its credentials via HTTP Basic auth
  (`client_id:client_secret`), not a bare `client_id` form field — the
  tutorial's `demo-cli` is a `public` client, which is why its examples
  omit a secret.
