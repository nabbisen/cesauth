# Terms of Use

cesauth is a free and open-source identity service, published under
the [Apache License 2.0](LICENSE). The software itself is governed
by that license; this document covers the additional expectations
that come with cesauth being **built exclusively on the Cloudflare
Workers platform**.

We want cesauth to contribute positively to the Cloudflare developer
ecosystem. This file exists to make sure that both (a) visitors
have a clear picture of what cesauth is and is not, and (b) nothing
about how cesauth is used creates trouble for Cloudflare or for the
wider community.

By using, cloning, forking, or deploying cesauth, you agree to the
terms below in addition to the license.

## 1. Platform dependency

cesauth is designed exclusively for **Cloudflare Workers**, and
relies on Workers-native primitives:

- **Durable Objects** — for the single-consumption and
  serialized-rotation guarantees that underpin authentication
  security.
- **D1** — for the relational state (users, clients,
  authenticators, grants).
- **KV** — as a cache.
- **R2** — for append-only audit logs.
- **Turnstile** — for risk escalation.

There is no self-hosted, Docker, or alternative-cloud build target.
Porting cesauth off Cloudflare would require re-implementing the
contents of `crates/adapter-cloudflare` against a different set of
primitives with equivalent consistency guarantees — the domain
layer (`crates/core`) is deliberately portable, but no such adapter
exists today. We do not support, troubleshoot, or accept
responsibility for attempts to run cesauth outside the Cloudflare
ecosystem.

If you want a drop-in, any-cloud identity service, cesauth is not
it — and we want to be upfront about that, so nobody is surprised
later.

## 2. Compliance with Cloudflare's terms

Deploying cesauth means deploying to Cloudflare, which means you
are bound by Cloudflare's published policies. In particular:

- **[Cloudflare Terms of Service](https://www.cloudflare.com/terms/)**
- **[Cloudflare Acceptable Use Policy](https://www.cloudflare.com/website-terms/)**
- **[Cloudflare Self-Serve Subscription Agreement](https://www.cloudflare.com/terms/)**
  (or the applicable enterprise agreement for larger deployments)

These documents are authoritative. Nothing here supersedes them; if
a provision here conflicts with a Cloudflare term, the Cloudflare
term governs your Cloudflare account.

### Prohibited uses

You agree not to use cesauth, or any deployment of it, for any
activity that would violate Cloudflare's terms, including:

- Distributed denial-of-service (DDoS) attacks, traffic amplification,
  or any activity that deliberately consumes network or compute
  resources to degrade service for others.
- Hosting illegal content, malware, phishing kits, or credential-theft
  infrastructure.
- Spam, unsolicited bulk messaging, or abuse of the Magic Link flow
  to enumerate or harass email addresses.
- Circumvention of Cloudflare's rate limits, abuse protections, or
  billing controls.
- Any activity prohibited by Cloudflare's Acceptable Use Policy,
  whether or not it is specifically enumerated above.

cesauth's Magic Link flow can in principle send email to
user-supplied addresses. It is your responsibility to ensure that
flow is gated against abuse (rate limits are built in; configure
them appropriately) and that email delivery respects the recipient's
expectations and applicable anti-spam law.

## 3. Resource limits and cost responsibility

cesauth is intended for **educational use, prototyping, and
small-to-moderate-traffic deployments**. It runs on standard
Cloudflare Workers primitives — there is no special allocation
or committed-use quota behind it.

- **You are responsible for any costs** incurred on your Cloudflare
  account from running cesauth. The software does not meter its own
  usage against your billing plan.
- **Rate limits are your defense line.** cesauth ships with
  rate-limit buckets on the abuse-prone endpoints (Magic Link
  request/verify, WebAuthn authenticate, admin user create). The
  defaults in `wrangler.toml` are a starting point, not a guarantee.
  Tune them for your expected traffic.
- **Free-tier limits are Cloudflare's, not ours.** If your deployment
  exceeds the free-tier allowance for D1 rows, KV reads, R2 storage,
  DO requests, or Workers invocations, the overage shows up on your
  bill — or the Worker fails — depending on your plan.
- **Scalability is not guaranteed.** cesauth is not performance-tested
  against large-scale workloads. If you are planning a deployment of
  significant size, load-test it yourself and budget for tuning.

## 4. Abuse reporting

If you believe a deployed cesauth instance is being operated in
violation of these terms, Cloudflare's AUP, or applicable law:

- **Report abuse of the deployment's operator** via Cloudflare's
  abuse channel: <https://abuse.cloudflare.com>. The operator is
  the party running that specific instance; they are identifiable
  via the domain the Worker is served under.
- **Report a security vulnerability in cesauth itself** (as opposed
  to a misuse of a deployment) via
  [`.github/SECURITY.md`](.github/SECURITY.md), not here. The two
  channels have different scopes and different timelines.

We, the cesauth maintainers, do not operate any specific deployment
of cesauth. We cannot remove content, suspend accounts, or
investigate abuse on a deployment we did not create. Cloudflare can
act on deployments on their platform; deployment operators can act
on their own instances; we act on the source code.

## 5. No warranty

cesauth is provided **"as is"**, without warranty of any kind,
express or implied, including but not limited to the warranties of
merchantability, fitness for a particular purpose, and
noninfringement. See the [Apache License 2.0](LICENSE) for the full
disclaimer and the limitation of liability.

This is particularly relevant for an identity service: cesauth aims
for correctness and has test coverage for the documented behaviors,
but it is **in active development** and **has not undergone
independent security audit or FIDO Alliance conformance
certification**. Deploy it in a context appropriate to that
posture — and see
[`docs/src/expert/security.md`](docs/src/expert/security.md) and
[`ROADMAP.md`](ROADMAP.md) for the current posture in detail.

## 6. Contributing back

cesauth is an open-source project, and contributions that improve
it — for anyone running it on Cloudflare — are welcome. If you fix
a bug, add a feature, or harden a rough edge during your
deployment, please consider upstreaming the change so the broader
ecosystem benefits. A formal contribution guide is planned; in the
meantime, opening an issue to discuss the approach before writing
code is appreciated.

## 7. Updates to these terms

These terms may be updated as cesauth evolves. Material changes
will be called out in [`CHANGELOG.md`](CHANGELOG.md); the current
version is always in the repository's `main` branch. If a change
materially affects your deployment's compliance posture, we
recommend re-reading this document after any cesauth upgrade.

---

*Last updated: 2026-04-24*
