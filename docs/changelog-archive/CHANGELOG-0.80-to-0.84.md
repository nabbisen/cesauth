# cesauth — CHANGELOG (archive: v0.80–v0.84)

> This file is part of the changelog archive.
> Current releases are in the root [`CHANGELOG.md`](../../CHANGELOG.md).

## [0.84.3] - 2026-10-24

### The build produces the same artifact for the same input — RFC 133 half A

`make build-frontend` applied its WebAssembly optimizer **in place**, reading
and writing one path, over a directory whose previous contents it never
cleared. The optimizer is not idempotent, so the artifact was a function of
the build's history rather than of the source alone.

Now: the output directory is cleared before the build, so a failed build
leaves nothing stale rather than a previous artifact; the optimizer writes to
a scratch path **outside** the deployed asset directory and is moved into
place only on success, so no partial file is ever created where assets are
served from; and a build that produces no WebAssembly fails with a message
saying so, instead of handing the optimizer a file named `*_bg.wasm`. A loop
that reported only its last iteration's status was corrected in the same
lines.

**`wasm-bindgen` was measured deterministic** — two runs over identical
compiler output produced identical bytes — which eliminates it as a cause of
the remaining variation.

**This does not make the build reproducible.** Recompiling unchanged source
can still produce different bytes, and this release contains new evidence of
exactly that: the *pre-optimizer* WebAssembly changed over a month with no
source change, which places the variation in the compiler rather than in
anything downstream. Environment reproducibility — the same commit on another
host yielding an identical hash — remains deferred.

### CI had been running all along, and four of its gates were red — RFC 142

The premise this work started from was wrong, and it is worth stating plainly:
cesauth's workflows had run roughly 1,650 times since April, not never. What
was true is that **nothing was required**, so every failure had been advisory.

Four gates were red and are now green:

- **Fuzzing had never run at all.** The fuzz crate was never excluded from the
  workspace, so it could not build. It now runs — 11.7 million executions in
  60 seconds.
- **The bundle-size gate had never once passed** — 149 consecutive failures —
  because it never built the frontend whose directory it needs. Once fixed, it
  measured the *loader*, 10,698 bytes, and reported 0% usage for an artifact
  that is 98.7% something else. It now sums every uploaded module and fails
  outright if the Worker module is absent. **The budget it has guarded since
  RFC 025 has been evaluated for the first time: 811,575 bytes gzipped, 30% of
  2.5 MiB.**
- **The runtime smoke check and the browser suite** both died at their
  readiness deadlines while `wrangler dev` performed a 214-second cold compile.
  Both now build the Worker in a prior step; warm startup is about ten seconds,
  and the deadlines are unchanged. Raising them would have required roughly four
  times the real startup time and would have measured nothing.

**`wrangler dev` serves the public sign-in surface on a clean runner with no
secrets configured.** Routes that sign or verify tokens were not exercised.

### A dependency advisory, fixed rather than accepted

`cargo deny` turned red on **RUSTSEC-2026-0386**, an unsoundness in `tokio`'s
`AsyncFd` constructors. Upgraded **1.52.3 → 1.54.1**, a two-line lockfile
change. The unsound API appears nowhere in cesauth, and the advisory was **not**
added to any ignore list: a patched release existed, so there was nothing to
accept.

### Documentation that asserted things the code did not do

Four corrections, each dated and each stated as a measurement rather than a
promise:

- `BUNDLE_SIZE_BUDGET.md` said the build was "run-reproducible". It is not, and
  the single observation that produced that belief is now described as one
  occasion rather than a property.
- Three sentences said gates had "not yet executed in CI". They had executed
  hundreds of times.
- `browser-tests.yml` and the contributor gate table said the browser suite
  **is** a required status check. Nothing is required; both now say what
  blocking would need and that the setting is absent.
- The gate table now records that running the browser suite locally needs
  `npx playwright install` first — CI installs browsers itself, and the local
  gate list had no equivalent step, so the symptom (every test failing
  instantly) had no explanation anywhere.

### What this release does NOT claim

- **Not that any CI gate is enforced.** `main` has no branch protection, so no
  check is required. Thirteen checks are green and could be. This is the fourth
  consecutive release that has had to say so.
- **Not that the newly fixed checks are proven on pull requests.** They are
  proven on pushes; branch protection acts on pull requests.
- **Not that the build is reproducible**, and not that the bundle figures are
  invariants.
- **Not that 60 seconds of fuzzing is meaningful coverage**, and not that
  fuzzing has found anything. It runs; that is the claim.
- **Not that `wrangler dev` needs no secrets in general** — only for the public
  surface those gates exercise.
- **Not that the advisory affected cesauth's own code.**
- **Still true:** nobody has deployed this tree; the registered client
  authentication method is not enforced; some rejected authentications write no
  audit event; refresh tokens issued before 0.84.0 no longer decode; the
  frontend is verified by 20 tests on one unauthenticated, unstyled page.

## [0.84.2] - 2026-09-24

### The refresh-token family lifecycle has an executable specification — RFC 118

Rotation with reuse detection is cesauth's strongest response to a stolen
refresh token: present a token that has already been rotated out and the
entire family is revoked. Until now its correctness rested on hand-written
example tests, and the bugs that matter in rotation schemes are *sequence*
bugs — a token accepted twice, a revoked family resurrected by a late
rotation, an expired family rotating because the checks ran in the wrong
order. Examples do not find those.

The lifecycle is now written down as a small reference model, derived from
the port's contract and RFC 9700 §4.14.2 rather than from any
implementation, and the real store is run against it in lockstep over
generated adversarial sequences: replayed retired tokens, rotation after
revocation, tokens never issued, clock jumps past both deadlines, and
sequences long enough to overflow the 16-entry memory of retired tokens.
**Every outcome and the whole resulting state are compared after every
operation** — an outcome-only comparison misses a corrupted history until
some later operation happens to read it.

Alongside the model: 20 named invariant tests, a coverage test that fails if
the generator stops reaching a category, normative wording on the rotation
outcome type, and two rules the implementations already agreed on that
nothing had written down (what happens to a family that was never created,
and an explicit revocation of a family that has silently expired).

**Nothing about shipped behaviour changed.**

### A test-support defect, found by the new tests on their first run

The generated sequences immediately found that the **in-memory test double**
for refresh-token families discarded the original sign-in timestamp, where
the real Cloudflare implementation and `cesauth-core`'s own stub both store
it. The contract states the rule twice; three of the four implementations
followed it.

- It is a **test-support fidelity defect**, in a crate that is never
  published and reaches no shipped code path.
- **No shipped behaviour was affected**, and no existing test could observe
  it: every one of them constructed the value as zero, which is why it
  survived unnoticed.
- **This is not a security fix.**
- It is the third instance of the same class — a test double that quietly
  simplifies the contract it stands in for — after the ones found during
  RFC 137 and RFC 140, and the first found by a machine rather than a
  reviewer.

### What this release does NOT claim

- **Not that the Durable Object is verified.** The harness runs against the
  in-memory store; the Durable Object cannot be exercised off the Workers
  runtime, and doing so under miniflare remains deferred.
- **Not that concurrency is proven.** Generated *sequences*, single-threaded.
  A Durable Object executes sequentially, so interleaving reduces to
  ordering — but no memory-model property is established.
- **Not that reuse detection is newly correct.** It is newly *pinned*.
- **Not that any CI gate is enforced.** `main` has **no branch protection**,
  so no status check is required — including the browser suite, whose
  workflow says blocking.
- **Not that any of it has run in CI**, and the workflow YAML is unvalidated.
- **Not that it works on Cloudflare. Nobody has deployed this tree.**

## [0.84.1] - 2026-09-22

### Minting a token before its checks is now a compile error — RFC 117

The authorization-code exchange performed the right sequence — authenticate
the client, consume the code, check it was issued to that client, match the
redirect URI, verify PKCE, then mint — but that sequence was held by the
order of lines in one function. Every control in it was one edit from being
reordered or dropped, and only example-based tests would have noticed. Two
of this project's recent security fixes were exactly that: a check that was
never written (RFC 137) and one enforced nowhere (RFC 140).

The exchange is now a typestate pipeline. Each step consumes the previous
value and produces the next, and the data a token is minted from exists only
at the end of the chain. The compiler rejects, rather than a test:

- minting before PKCE verification, or before either binding;
- consuming the code before the client has authenticated;
- constructing the mint input, or the "mint license", by hand;
- using either twice, so one code cannot mint two token sets.

Alongside it: the first property-based tests for PKCE verification and for
the challenge store's contract, generating operation sequences rather than
examples. The store contract also now states what `put` does when a handle
holds an entry that has expired but was never taken — it is still occupied,
and `put` is refused.

**Nothing about behaviour changed.** Every response, error code and message
is what 0.84.0 returned, and no existing test was edited.

### What this release does NOT claim

- **Not that the refresh path is protected.** Refresh-token rotation still
  mints procedurally; that is RFC 118.
- **Not that one-time use is newly guaranteed.** The store already
  guaranteed it. The new property test pins it against arbitrary operation
  sequences in the in-memory store; the Durable Object cannot be tested off
  the Workers runtime.
- **Not that the types prove the client authenticated against its true
  stored record.** They prove the order and that no step is skipped.
- **Not that any CI gate is enforced.** `main` still has **no branch
  protection**, so no status check is required — including the browser
  suite, whose workflow says blocking.
- **Not that any of it has run in CI**, and the workflow YAML is unvalidated.
- **Not that it works on Cloudflare. Nobody has deployed this tree.**

## [0.84.0] - 2026-09-22

### Refresh tokens never expired — RFC 139

`REFRESH_TOKEN_TTL_SECS` (30 days) was written into the refresh token
itself, ignored on rotation, and enforced by nothing. A refresh family
rotated forever, so a leaked refresh token was a permanent credential
unless reuse detection happened to fire. Introspection compounded it: it
read the expiry **out of the token** and reported it as `exp`, so the
lifetime a resource server saw was whatever the presenter had written.

A family now ends at the **earlier** of two deadlines, both enforced by the
family store at rotation:

- **absolute cap** — `created_at + REFRESH_TOKEN_TTL_SECS`, however often
  the family is rotated;
- **idle window** — `last_rotated_at + REFRESH_TOKEN_IDLE_TIMEOUT_SECS`,
  which moves with every rotation.

`REFRESH_TOKEN_IDLE_TIMEOUT_SECS` is **new**, defaults to 1209600
(14 days), and `0` disables the idle check; the absolute cap cannot be
disabled. An idle window longer than the cap, a negative idle window or a
non-positive cap is refused.

Also:

- **Expiry revokes, atomically**, and records which deadline ended the
  family. `/token` answers `invalid_grant`, the same as for a revoked
  family.
- **No deadline is stored.** Both are computed from the family's own
  timestamps against the *current* configuration, so lowering a lifetime
  after an incident shortens every live family at once, and families
  created before this release are governed from their next request. No
  migration.
- **The refresh token no longer carries an expiry.** Its format is
  `base64url("{family_id}.{jti}")`, and all three decoders accept exactly
  two parts. **Refresh tokens issued before this release stop working.**
  Nobody has deployed this tree, so this affects local development only.
- **Introspection reads the family, never the token.** `exp` is the real
  deadline; an expired family reports inactive with an `expired` state, and
  introspection never writes.

**Upgrade note.** If an invalid pair of lifetime variables is deployed, the
deployment still succeeds: configuration is read per request, and every
request that loads it then fails with `500` until the variables are
corrected — the Worker's log names the variable. Measured under an invalid
pair: the discovery document, `/authorize`, `/token`, `/introspect`,
`/revoke`, `/userinfo` and `/magic-link/request` returned `500`, while
`/`, `/login`, JWKS and unregistered routes answered normally. Check the
pair before deploying; nothing checks it at deploy time.

### Login challenges outlived their expiry — RFC 140

The `AuthChallengeStore` contract required implementations to treat an
entry past `expires_at` as absent. Neither implementation did. Expiry was
left to a Durable Object alarm, and that alarm discarded its own failed
delete and reported success — so a failed delete left the entry usable
indefinitely. Four of the six challenge kinds had no other check:
authorization codes (60 s), WebAuthn registration and authentication
nonces (60 s), the TOTP second-factor gate (5 min) and parked
authorization requests. The TOTP gate additionally re-parked an already
expired challenge with 60 more seconds.

Now: `peek`, `take` and the magic-link attempt counter take the caller's
clock, and an entry at or past `expires_at` is absent. An expired `take`
deletes the entry and returns nothing, so it cannot be used even once.
`peek` stays read-only. The alarm propagates a failed delete instead of
swallowing it, and is cleanup only — correctness no longer depends on it
having run.

An expired authorization code is refused as `invalid_grant`, identical to
an unknown code.

### The browser suite's grace period ends — RFC 131 R5f

The 20 Playwright tests over `/` and `/login` were non-blocking for exactly
one release, 0.83.0, to tell first-contact flakes from findings. They
produced none. The workflow and the documented gate set now describe the
suite as blocking, with a standing rule: a flake is diagnosed and fixed, or
the test is deleted — the gate is never made non-blocking again. It carries
no `continue-on-error` and must not.

**This is not in force yet.** See below.

### What this release does NOT claim

- **Not that any CI gate is enforced.** `main` has **no branch protection
  at all**, so no check is required — not the browser suite, not the docs
  build, not the others. Making the browser suite blocking needs
  `browser-tests` added to required status checks; the repository setting
  is outstanding.
- **Not that the new or changed CI gates have ever run in CI.** They have
  not, and the workflow YAML is unvalidated.
- **Not that the Durable Object's read-time expiry check is verified
  live.** An alarm due at the same moment may delete the entry first, so a
  live expired-code run answers the same either way. It rests on the code,
  on the rule shared with the tested store, and on a live check that the
  Durable Object command wire decodes.
- **Not that WebAuthn challenge expiry is tested.** Those routes have no
  host-side harness; they share the store rule with the tested kinds.
- **Not that expired refresh families are removed from storage**, or that
  expiry writes a distinct audit event.
- **Not that an invalid lifetime pair is prevented** — only that it is
  never applied.
- **Not that the registered client authentication method is enforced**, and
  not that every rejected authentication is audited.
- **Not that it works on Cloudflare. Nobody has deployed this tree.** Every
  runtime observation is Miniflare.
- **Still true from 0.83.0:** the frontend is verified by 20 tests on one
  unauthenticated page, in one engine, with no interaction beyond Tab, and
  it renders unstyled.

## [0.83.1] - 2026-09-15

### `/token` authenticated no client — RFC 137

Until this release, `/token` **never checked a confidential client's
secret**, and neither an authorization code nor a refresh family was bound
to the client it was issued to, as RFC 6749 §4.1.3 requires. PKCE was the
only binding between an authorization request and the client redeeming it.
0.83.0's notes named this gap as open. **It is closed.**

What holds now, on both the `authorization_code` and `refresh_token` grants:

- **A confidential client must authenticate.** A missing or wrong secret is
  `401 invalid_client`.
- **A client with no stored secret counts as public only if it is registered
  as public.** A confidential registration with no stored hash is rejected,
  not waved through.
- **Authentication happens before a code is consumed.** A failed
  authentication neither burns the code nor touches the refresh family, so
  holding a code without the secret cannot destroy it or probe whether it is
  valid.
- **A wrong-client redemption consumes the code and is refused.**
- **A wrong-client refresh revokes the family.**
- **One authentication method per request** (RFC 6749 §2.3). HTTP Basic plus
  a form `client_secret` is rejected, as is a Basic identity that disagrees
  with the body's `client_id`, and a malformed Basic header does not fall
  back to the form.
- **A client authenticating with Basic needs no body `client_id`** (RFC 6749
  §4.1.3). Before this, a standards-conforming Basic-only client was refused
  with `invalid_request`.
- **`invalid_client` challenges.** When the request carried an
  `Authorization` header, the 401 includes `WWW-Authenticate: Basic
  realm="cesauth"` (RFC 6749 §5.2), as `/introspect` already did.

The public beginner client, `demo-cli`, still completes the documented
first OIDC flow unchanged.

### The gates CI runs now match the ones we describe — RFC 138

- **CI runs `mdbook build`**, in a new `docs.yml` on every pull request.
  `create-missing = false` means a missing chapter now fails the build
  instead of being silently created.
- **wrangler is pinned exactly (4.131.2)** by a committed root lockfile, and
  every invocation — CI jobs, `make build-backend`, `make dev-backend`, the
  runtime smoke check — runs `node_modules/.bin/wrangler`. Without a root
  `npm ci` it **fails with a message saying so**. `npx wrangler` was not
  enough: without the install it silently ran a cached copy or fetched the
  latest release.
- **The tool-installing Actions are pinned to exact versions.**
- **drift-scan reads the workflows** (and the root `package.json`), so a pin
  loosened there, or an `npx wrangler` reintroduced, fails the scan.
- **Clippy covers all six crates.** `cesauth-backend` and
  `cesauth-adapter-cloudflare` had been excluded on the belief that they need
  the wasm32 target; they lint on the host with zero correctness errors.

### Open, and stated rather than omitted

- **RFC 139 is open: refresh tokens never expire.** The configured lifetime
  is written into the token and then enforced nowhere, so a stolen refresh
  token stays valid until reuse detection fires, which needs the legitimate
  client to refresh afterwards. The owner chose to ship 0.83.1 first.

### What this release does NOT claim

- **Not that refresh tokens are safe.** They never expire (RFC 139).
- **Not that the registered authentication method is enforced.** A public
  client is accepted whatever secret it presents, and a confidential client
  may use Basic or the form body regardless of its registration.
- **Not that every rejected authentication is audited.** A malformed Basic
  header, or a request carrying two identities, writes no audit event; a
  wrong secret does.
- **Not that the new or changed CI gates have run in CI.** `docs.yml` is new,
  `worker-build.yml`'s jobs have never executed, and clippy's two added
  crates have not run there. **The workflow YAML is unvalidated.**
- **Not that every tool is pinned.** Node, `cargo-bloat` and `cargo-fuzz` are
  not.
- **Not that the operations docs call the pinned wrangler.** Operator pages
  still write bare `wrangler …`; a documentation follow-up is scheduled.
- **Not that it works on Cloudflare. Nobody has deployed this tree.** Every
  runtime observation in this release is Miniflare.
- **Still true from 0.83.0:** the frontend is verified by 20 tests on one
  unauthenticated page and nothing more, it renders unstyled, and the browser
  suite is non-blocking until 0.84.0.

---

## [0.83.0] - 2026-09-13

### The application could not run — RFC 135

Every client-rendered surface served a **blank page**. The shell was
served, the bootstrap script ran under its nonce, every asset returned
200, `init()` was called — and the browser then refused to compile the
WebAssembly module:

```
CompileError: WebAssembly.instantiateStreaming(): Compiling or instantiating
WebAssembly module violates the following Content Security Policy directive
because 'unsafe-eval' is not an allowed source of script in the following
Content Security Policy directive: "script-src 'nonce-…'".
```

WebAssembly compilation is a **separate CSP capability**,
`'wasm-unsafe-eval'`. A nonce authorises the bootstrap *script*; it does
not authorise the *module* that script instantiates. cesauth's policy had
never granted it, so `<div id="root">` stayed empty on `/` and `/login`.

**Ten `curl` assertions rated this healthy** — 200 HTML, CSP header
present, every referenced asset resolving, no panic. All true. `curl` does
not execute WebAssembly. Only a browser decides this, and until this
release nothing had opened one; the defect was found by RFC 131 R5's first
browser probe.

Not a regression: no route resolved at all before 0.82.0 (RFC 134), so
nobody could have observed it.

- **`'wasm-unsafe-eval'` added to the Leptos shell's own CSP, and nowhere
  else.** The scope follows by construction rather than by convention:
  only routes calling `leptos_html_shell` receive the directive, and
  RFC 132's E3 gate asserts that no `server`-declared route calls it. The
  default CSP is unchanged, so the JSON API and every `format!`-templated
  HTML page carry no WASM directive. When RFC 131 R3 converts the
  remaining client-rendered pages to server rendering they stop calling
  the shell and fall back to the strict policy automatically.
- **`'unsafe-eval'` remains barred.** The two are distinct directives, and
  tests now assert both directions — present, absent — in the quoted form,
  because unquoted `unsafe-eval` is a substring of `'wasm-unsafe-eval'`
  and an unquoted assertion conflates them.
- **ADR-007 amended** (owner-approved) to record the distinction, the
  scope, and that RFC 115 introduced a WebAssembly frontend under a policy
  written for a server-rendered application without amending the ADR.
- **Leptos now mounts into `#root`** via `mount_to(…).forget()`. It used
  `mount_to_body`, which appends to `<body>` — so the shell's own comment
  ("Leptos mounts into this div"), and the frontend's doc comment saying
  the same, had both been false since they were written.
- `runtime-smoke-check.sh` gained two checks (10 → 12): `/login`'s served
  CSP grants the WASM directive and bars `'unsafe-eval'`, and a
  server-rendered route carries no WASM directive at all.

### 159 tests in the deployed crate did not compile — RFC 136

`cargo test -p cesauth-backend` failed with 36 errors. The crate has
**159 `#[test]` functions across 16 files**, and none of them had been
compiled — let alone run — by any gate, for at least two months.

The exclusion was documented, with a reason that was false: the workflow
and the contributing guide both said the crate "requires the
wasm32-unknown-unknown target and worker-build toolchain". That reason
covered **two** of the 36 errors, and on inspection neither of those two
was an error at all — both were `worker::` type names quoted as *context*
inside ordinary type-mismatch messages. **No test in either excluded crate
is wasm-only.** All 36 were ordinary API drift: `AuthChallengeStore`'s
methods had moved to a `ChallengeHandle` newtype, `csrf::mint()` had
started returning a `Result`, `Jti` had lost `From<&str>`, and
`log::Record` had gained a field.

- **The tests were repaired to current signatures, not rewritten to
  pass.** 199 backend tests now run and pass.
- **`cesauth-adapter-cloudflare`** was excluded by the same false
  sentence; its one test module needed a `tokio` dev-dependency.
- **Both crates are now in CI**, and `--lib` was dropped from the host
  test step so **doc-tests and integration targets are gated too**. That
  restored two more things nothing had been running: two failing
  doc-tests in the adapter (prose fenced blocks that rustdoc compiles as
  Rust), and `cesauth-frontend`'s 4-test `acceptance_harness`. Host tests
  counted by CI went from 1,198 to **1,403**.
- **The RFC 008 audit-secret invariant had never once executed.** The test
  pins that no `audit::write*` call passes token material. Written in
  v0.50.2, it looked for `crates/` **two directories above the repository
  root**, so it could not have found its own inputs even had it compiled;
  and its scan window was a fixed eight lines, which reads past the end of
  the call into the *next* statement. Both are fixed — the window is now
  bounded to the call expression — and the invariant is **measured to
  hold** across 413 files. It also proves its own scanner on every run.

### drift-scan could not see the largest directory in the repository — RFC 129

The stale-phrase gate's four crate-rename rules all excluded `crates/`,
so the gate that catches renamed-away names could not see them in the
source. 19 dead pointers were fixed, 6 true historical statements
rephrased to stay true without the stale token (a blanket rename would
have turned accurate history into fiction), and one broken
copy-pasteable command corrected. `ROADMAP.md` was added to the scan.

This is the first time that gate has ever been able to fire inside
`crates/`.

### The first browser-level verification in this project's history — RFC 131 R5

**20 Playwright tests**, asserting the layer `curl` structurally cannot
reach: that the WASM bundle instantiates, that Leptos mounts into a
non-empty `#root`, that the browser threw no uncaught exception, that axe
reports no critical or serious WCAG 2 A/AA violation, that no `id` is
duplicated, that keyboard focus reaches every control in document order,
that the page does not scroll sideways at 375 px, and that no
workbench-only markup from the imported mockup reaches served output.

Three of the mockup's seven specs did not survive contact with cesauth
and were dropped or replaced rather than adapted into something vacuous:
its hydration spec (cesauth has no SSR to hydrate), its dialog
focus-trap spec (there are no dialogs on the public surface — the
property was kept as a tab-order spec, the mechanism dropped), and its
pixel-screenshot spec (no stylesheet exists to photograph, and a
screenshot gate passes its own first run by *creating* the baseline).

CI also gained a Trunk install step in the two jobs that invoked Trunk
without installing it, and Trunk is now pinned at all four install sites.

### Open, and stated rather than omitted

- **RFC 137 is open.** `/token` **authenticates no client**, and binds no
  authorization code to the client it was issued to — both mandated by
  RFC 6749 §4.1.3. PKCE is currently the only binding between an
  authorization request and the client redeeming it. The owner chose to
  ship 0.83.0 first; RFC 137 ships in the next release.

### What this release does NOT claim

- **Not that the frontend works.** 20 tests over **one rendered page**
  (`/` and `/login` are the same page, and they are the entire
  unauthenticated HTML surface), one browser engine, unauthenticated, with
  no interaction beyond Tab.
- **Not that it is styled.** No stylesheet exists anywhere in the tree;
  the page renders in browser defaults. Axe's zero violations therefore
  say **nothing** about contrast, focus-visible or target size — untested
  by construction, not passing. Both are RFC 131 R3.
- **Not that it works on Cloudflare. Nobody has deployed this tree.**
  Every runtime observation in this release is Miniflare.
- **Not that RFC 134's deploy-path gate or RFC 135's runtime smoke gate
  have run in CI.** They could not start — nothing installed Trunk. This
  release makes their first execution possible; it has not happened yet.
- **Not that `mdbook build docs` is gated.** It is in no workflow at all
  (RFC 138), despite being required in every handoff and review.
- **Not that the browser suite is blocking.** It is non-blocking for one
  release; flipping it is an acceptance criterion of 0.84.0.
- **Not that the rendering policy is satisfied.** Three named exemptions
  remain (RFC 132 §8), including `/me/security/totp/verify`, which still
  denies a no-JS user their second factor.
- **Not that the backend is well-tested.** 199 passing tests match today's
  code; coverage is unmeasured.

---

## [0.82.0] - 2026-09-10

### cesauth serves a request — RFC 134

Every release since **0.79.6** (2026-07-07) shipped a Worker whose router
panicked on construction, on every request, before any handler ran — see
the dated note further down this file for the full history. This release
fixes it.

Three route patterns put a `.json` suffix on a **parameter** segment
(`/admin/tenancy/tenants/:tid.json`, `/admin/t/:slug.json`,
`/admin/t/:slug/organizations/:oid.json`). `matchit`, the matcher inside
the `worker` crate, rejects such a pattern when the bare `:param` sibling
is already registered, and `worker` turns that rejection into a Rust
panic rather than a recoverable error. The router is built inside
`#[event(fetch)]`, so the panic fired per request, ahead of dispatch, on
**every** route — not only the three conflicting ones.

- **Reshaped the three patterns** so `.json` sits on a literal segment
  instead (`.../:tid/detail.json` and siblings). This is the one place
  this project has ever changed a route string outside a minor-version
  contract change: justified because these three strings never
  successfully served a request in any release, so there was no
  contract to break. No handler changed — only the strings that route to
  them moved.
- **`worker` pinned** `=0.8.3` (was floating on `"0.8"`) — the same class
  of gap C1-131 closed for `worker-build` last release, left open here
  until now.
- **New runtime smoke gate.** Every prior gate proved compilation,
  artifact production, or documentation consistency; none of them booted
  the runtime and issued a request, which is why this went undetected for
  eight releases. `scripts/runtime-smoke-check.sh` now boots `wrangler
  dev` (no Cloudflare credentials, no secrets, no D1 migrations needed)
  and asserts **content and headers**, never status alone: `GET /` and
  `GET /login` return HTML with a `content-security-policy` header
  present, the three reshaped routes resolve (401, proving they reached
  their handler), an unregistered route 404s, and no panic appears in the
  console.
- **The shell's own assets now resolve.** Fixing the router surfaced a
  second, independent defect: `leptos_shell.rs` has always requested its
  JS/wasm bundle at `/assets/...`, but `make build-frontend` placed the
  built files at `dist/`'s root, where Cloudflare Workers Static Assets
  served them unprefixed — so every asset 404'd, `init()` never ran, and
  Leptos never mounted, on every client-rendered surface. Built output
  now nests under `crates/frontend/dist/assets/`, matching what the shell
  already asked for; this also bounds a shadowing risk this release found
  independently (see below) to `/assets/*` instead of leaving it open
  against `dist/`'s root. The smoke gate now parses every asset URL out
  of the served HTML and asserts each resolves, rather than only checking
  that the shell itself renders.
- **Trunk's dev-only `index.html` is no longer shipped.** It was being
  served directly at `/` by Cloudflare Workers Static Assets — ahead of
  the Worker script, with none of the Worker's security headers (no CSP,
  nothing) applied, a live regression against RFC 006. `make
  build-frontend` now deletes it after the build; `trunk serve` is
  unaffected.

**Not claimed:** that the app mounts in a browser. `init()` is now
reached rather than throwing on a 404, but nothing here has run
JavaScript — whether Leptos renders into `<div id="root">` is
unverified and belongs to RFC 131 R5. Not claimed for Cloudflare either:
everything above was observed under Miniflare (`wrangler dev`) only;
nobody has deployed this tree.

### View rendering policy — RFC 132

cesauth had a stated rendering policy — External Design v2 §4, "server-side
rendering only (no client framework)" — that RFC 115's migration to Leptos
CSR silently abandoned without amendment. The result was internally
inconsistent: `/` and `/login` rendered client-side and failed without
JavaScript, while `/magic-link/*` next door rendered server HTML and
worked fine, with no rule governing which was which.

- **The rule.** Rendering mode is derived per surface, not chosen
  globally: can the user route around a failure (Q1), is it
  pre-authentication (Q2), does it need client interactivity server HTML
  can't express (Q3), is it machine-facing (Q4). Recorded in
  `docs/src/expert/view-rendering-policy.md`.
- **Enforcement.** All 188 routes in `route-contracts.md` now declare a
  `Rendering` value (`server` | `client` | `n/a`); a missing value fails
  the same way an undocumented route does. A `server`-declared route's
  handler must not call the Leptos shell — checked by resolving the
  handler to its actual defining function (not just a name match), which
  catches re-exports a naive scan would miss.
- **Three named conformance gaps**, each an exemption naming the RFC that
  removes it: `GET /`, `GET /login`, and `GET /me/security/totp/verify`
  all declare `server` but currently render client-side. The third is on
  the *only* path a no-JS user with TOTP enabled has to complete sign-in
  — RFC 131 R3 must fix it in the same slice as `/login`, not as an
  afterthought.
- External Design v2 §4 amended to record the new rule and that the old
  statement was abandoned rather than superseded.

**Not claimed:** that the rendering policy is satisfied. It is stated and
enforced, with three known violations still open.

### Mockup foundation imported (dormant) — RFC 131 R2a

`view_models`, `icons`, and 17 of 19 i18n-free `components/primitives`
files imported from the `cesauth-mockup` reference repository (pinned at
`df3d9d0`, v0.14.0) as modules inside `crates/frontend/src/` — a merge,
not a new crate. ~1,489 LOC, gated behind the existing `csr` feature,
referenced by nothing yet; a future RFC wires them to real data. Two
files excluded (`permission_denied.rs`, `suspended_notice.rs`) pending a
locale-mechanism decision.

No mock data, no `cesauth-ui` name collision, no new crate dependency.

### Notes

No wire format, D1 schema, Durable Object payload, cookie, or permission
slug changed. `core::ports` traits unchanged. MSRV unchanged at 1.85.
**Minor**, not patch: RFC 134 and RFC 132 are each fixes on their own, but
RFC 131 R2a adds new module surface and RFC 134's smoke gate is new
blocking CI capability — a release mixing levels takes the higher one.

---

## [0.81.3] - 2026-09-08

### Audit architecture corrected in the observability guide — RFC 128

`docs/src/deployment/observability.md` told operators that audit events
are R2 objects with R2 query patterns and R2-lifecycle-managed cost.
Audit events have been rows in the D1 `audit_events` table with a
SHA-256 hash chain since **v0.32.0** (ADR-010) — roughly 49 versions.
Two of the three "query patterns" the chapter gave were unactionable:
there is no audit bucket to list, and cesauth does not push audit
events to a SIEM.

- **The audit-trail section is rewritten** against source, not
  restated prose: the real 14-column `audit_events` shape (migration
  `0008_audit_chain.sql`), the three real indexes, and the four real
  query surfaces — the admin console browser (with its actual filter
  semantics: `kind`/`subject` are **substring** matches, `event` is
  the one **exact** match, and an invalid `from`/`to` bound is
  **dropped silently** rather than rejected), the export endpoint
  (itself an audited event, though that write is best-effort, and
  capped at `AUDIT_EXPORT_MAX_ROWS` — 10,000 rows by default), chain
  status/verify, and `wrangler d1 execute` for anything the console
  can't express. Links out to `docs/src/expert/audit-log-hash-chain.md`
  for chain mechanics rather than duplicating it.
- **The cost-management line no longer points at a fictional
  mechanism.** cesauth's Worker makes **no R2 API calls at all** — the
  `ASSETS` R2 binding is declared in `wrangler.toml` but unused; the
  frontend bundle is served by Workers Static Assets, a different
  product. Audit-log growth is bounded by the daily
  `audit_retention_cron` job, configured by the deployment-wide
  `AUDIT_RETENTION_DAYS` / `AUDIT_RETENTION_TOKEN_INTROSPECTED_DAYS`
  operator env vars (defaults 365 / 30 days) — not an R2 lifecycle
  rule.
- **`ip` and `user_agent` are documented as always NULL**, because
  they are: the builder methods that would populate them
  (`with_ip`/`with_user_agent`) have zero callers anywhere in the
  tree, and `write_owned` — the helper every call site actually
  uses — hardcodes both to `None`. Populating them is recorded as a
  0.82.0 candidate; this release only documents the code as it
  stands.
- **"Useful audit queries" rewritten in syntax that exists** —
  `wrangler d1 execute` SQL plus the console's real filter fields —
  replacing pseudo-syntax that matched neither, including an
  `admin_*` glob that doesn't exist in the codebase (the real
  substring match already does what it implied).
- **New drift-scan.sh rules** catch the two core stale claims ("Each
  audit event is one R2 object", "R2 doesn't have SQL") should they
  reappear, excluded on ADRs and the changelog archive so legitimate
  historical descriptions don't trip them.

Two corrections landed before this shipped, both to unshipped work and
not separately noted here: the R2/cost rewrite itself introduced five
new inaccuracies (wrong service named for the R2 bullet, inverted
filter-exactness claims, missing export caveats, a masked-IP note on
the wrong column), all caught in review and corrected against source
before release; a second pass then found the `admin_*` enumeration
undercounted the real kinds (five listed, ten actual — the two missing
were the ones a reader asking about admin token use most needed) and
a mislabeled reason-string example, both also fixed before this tag.

### Notes

No wire format, D1 schema, Durable Object payload, cookie, permission
slug, or public `cesauth-core` type changed. Documentation only — no
code, route, or schema changed. MSRV unchanged at 1.85. Drop-in for
0.81.2 consumers.

---

## [0.81.2] - 2026-09-08

### Frontend bundle is deployable — RFC 130

`trunk build --release` failed at `wasm-opt`, and the artifact names Trunk
emits did not match what `crates/backend/src/routes/leptos_shell.rs` asks the
browser to load. Both are fixed; `make build-frontend` now produces a bundle
that can actually be deployed.

- **`wasm-opt` failure.** rustc 1.98 enables `bulk-memory` by default on
  wasm32; Trunk's pinned Binaryen rejects those instructions and exposes no
  way to pass the enabling flags. Pinning a newer Binaryen (version 132) was
  measured first and produces the identical error, so Trunk's optimize step is
  disabled (`data-wasm-opt="0"`) and `wasm-opt` runs from the `Makefile` with
  the required flags.
- **Artifact naming.** Trunk names output after the Cargo *package* and
  appends a content hash, so the hardcoded constants could never match in any
  spelling. The build now passes `--filehash false` — a CLI flag; the
  `data-filehash` HTML attribute is silently ignored — and the constants are
  corrected to the hyphenated names Trunk actually emits.
- **Toolchain pinned.** New `rust-toolchain.toml` at **1.98.1**, measured
  rather than assumed. Every CI workflow reconciled to it; `test.yml` and
  `clippy.yml` moved from apt to `dtolnay/rust-toolchain`, since apt carries no
  arbitrary patch release and could never honour the pin. `fuzz.yml` stays on
  nightly for cargo-fuzz. `Cargo.toml`'s `rust-version` stays at 1.85 — the
  MSRV is a promise to consumers and a codegen default does not justify
  raising it.
- **New blocking CI gate** `trunk-release-build.yml` runs `make
  build-frontend` and re-asserts that every filename constant resolves to a
  real file.
- **Binaryen download is verified.** The `Makefile` pins the SHA-256 of all
  four platform assets and refuses to extract on mismatch, removing the
  partial download. Previously an 18 MB binary was downloaded and executed
  unverified on every clean checkout and CI run — and that binary transforms
  the wasm artifact serving the authentication UI.
- **Bundle measurements — corrected (C1-0.81.2, C2-0.81.2).** RFC 130 S4 first
  recorded 879,980 B pre-opt → 750,151 B post-`-Oz` → 262,744 B gzipped
  (default `gzip` level) in `BUNDLE_SIZE_BUDGET.md`. Rebuilding this same
  commit on a different host (rustc 1.98.1, Trunk 0.21.14, Binaryen
  `version_123` — all unchanged; `git diff --stat -- crates/` between the two
  measurements is empty) produces **881,519 B pre-opt → 751,714 B
  post-`-Oz`** instead — a fixed ~1.5 KB shift, confirmed non-random by three
  consecutive builds (incremental, incremental, and after a forced
  `cargo clean -p cesauth-frontend`) all yielding a byte-identical artifact on
  the rebuilding host. The build is run-reproducible but not
  environment-reproducible; RFC 133 is opened to close that gap.
  **Gzip: 261,502 B**, measured as `gzip -9 -c <file> | wc -c` — the original
  figure's level was never stated, so it is not directly comparable to this
  one; only the raw sizes are. These are the figures that reproduce at this
  commit, with their measurement command stated, and are recorded as
  environment-sensitive, not as invariants — see `BUNDLE_SIZE_BUDGET.md` for
  the full note.

**The frontend screens are not yet confirmed working.** Every check in this
release is build-time. The bundle builds, is verified, is correctly named, and
is addressable by the shell; whether it mounts in a browser is unverified.

### Notes

No wire format, D1 schema, Durable Object payload, cookie, permission slug, or
public `cesauth-core` type changed. MSRV unchanged at 1.85. Drop-in for
0.81.1 consumers.

---

## [0.81.1] - 2026-09-03

### Release-gate integrity — RFC 125 (+ condition C1)

Four of nine CI workflows had been failing at invocation since the RFC 114
crate rename (`cesauth-ui` → `cesauth-frontend`, `cesauth-worker` →
`cesauth-backend`), which the rename never reached. The "full host suite
green" gate that RFCs 117–124 each name as their step boundary was not
running at all.

- `test.yml` / `clippy.yml`: corrected the package names, and added
  `cesauth-frontend` to the host-test job. It had **no CI coverage** since the
  rename; the real suite is **1,233 tests**, not the 953 previously reported.
- `clippy.yml`: `-D warnings` → `-D clippy::correctness`, aligning CI with the
  declared advisory-clippy policy while keeping genuine defects blocking.
- `scripts/route-contracts-check.sh`: now reads `crates/backend/src/lib.rs`,
  fails with a named diagnostic when its input is missing, and treats a zero
  route count as a failure rather than a vacuous pass.
- **`fmt.yml` removed.** `cargo fmt --check` had never passed on this tree —
  447 of 498 files differ, and the hand-aligned columns it would collapse
  cannot be produced by any stable `rustfmt` (`struct_field_align_threshold`
  is nightly-only). Hand-alignment is now documented house style in
  `docs/src/expert/code-style.md`, amending RFC 029's conclusion.
- Fixed a deny-level `clippy::never_loop` in
  `crates/core/src/migrate/tests/import_pipeline.rs`.
- `crates/core/src/types/ids.rs`: module doc described `mint()` and
  `from_storage()` as `pub(crate)`; both are `pub`. Since `from_storage()`
  **bypasses validation**, the doc understated the reach of the one
  constructor that skips input checks.
- **Condition C1:** documented the 23 routes the repaired contract gate found
  undocumented — 22 `.json` API views plus `GET /admin/login`. Route contracts
  are now 188/188.

### Frontend bundle buildability — RFC 127

The Leptos CSR crate had **never compiled**. `cargo check -p cesauth-frontend
--features csr --target wasm32-unknown-unknown` failed with 79 errors, and no
gate covered it.

- `wasm-bindgen` was used in the source but was not a dependency; the `csr`
  feature omitted it.
- 26 `<Route path="…"/>` elements passed a bare `&str`; `leptos_router` 0.8.13
  requires `PossibleRouteMatch` via `path!()`. All 26 production route strings
  verified byte-identical.
- 18 `Resource` → `LocalResource` conversions (`Resource` requires
  `Send + Sync`, which `gloo-net`'s `JsFuture`-based fetch cannot satisfy on a
  single-threaded wasm32 target), plus a self-referential crate import, a
  missing `JsCast` import, three `Result::and_then(async …)` chains that could
  never have compiled, and one `Children` → `ChildrenFn` prop fix.
- Trunk now passes `data-cargo-features="csr"`. Without it the feature was
  never enabled — which is why the two defects above went unnoticed for two
  release cycles.
- New blocking workflow `.github/workflows/csr-bundle-check.yml`.

**The frontend screens are still not functional.** `trunk build --release`
fails at `wasm-opt`, and the artifact names Trunk emits do not match what the
backend expects. RFC 127's acceptance criterion 3 was formally not met.
RFC 130 addresses both.

### Documentation rename sweep — RFC 126

The RFC 114 rename changed the code but never reached the documentation: 56
stale references across 19 files, including `docs/src/deployment/wrangler.md`
documenting a build path that no longer exists — an operator following it
would have misconfigured the deploy.

- `scripts/drift-scan.sh` gains an optional per-pattern exclude-path field and
  four crate-name rules. ADRs and archived changelogs are excluded as
  historical records.
- **Known gap:** `crates/` is excluded from those rules, hiding 25 stale
  doc-comments in Rust source. Deliberate and disclosed; a follow-up RFC owns
  it.
- D5 (adding `ROADMAP.md` to the scan paths) is **not** included — it would
  surface an unresolved scope contradiction and ship a knowingly red gate.

### Security — dependency advisories

- **RUSTSEC-2026-0221** (`event-listener` unsoundness): patched, 5.4.1 →
  5.4.2. Net −2 crates.
- **RUSTSEC-2026-0190** (`anyhow` unsoundness): patched, 1.0.102 → 1.0.104.
- **RUSTSEC-2024-0436** (`paste`) and **RUSTSEC-2026-0173**
  (`proc-macro-error2`): accepted, not fixed. Both unmaintained, both
  compile-time only via Leptos proc-macros, neither reachable at runtime in
  the Worker binary or the browser bundle. Recorded in `.cargo/audit.toml`
  and `DEPENDENCIES.md`, each with a revisit trigger.

### Project governance

- RFC 000's RFC lifecycle adopted in its **5-folder variant**
  (`proposed/ accepted/ done/ archive/`). Supersedes RFC 019, now archived.
- Release procedure documented for the first time, including the tag format
  (bare `X.Y.Z`, no `v` prefix) and the requirement that a tag and a CHANGELOG
  entry exist together.
- `rfcs/handoffs/TEMPLATE.md` added.

### Notes

No wire format, D1 schema, Durable Object payload, cookie, permission slug, or
public `cesauth-core` type changed. Drop-in for 0.81.0 consumers.

---

## [0.81.0] - 2026-06-05

### Security hardening — RFC 116 (type-modeling baseline, Phase 2)

**RFC 116** is the foundational security-assurance release: identifier
newtypes and secret-material types throughout the authentication core.

#### RFC 116 Phase 1 — Identifier and secret newtypes (additive)

New types in `cesauth_core::types`:

- **`TenantId`, `UserId`, `ClientId`, `SessionId`, `FamilyId`, `Jti`,
  `ChallengeHandle`, `RoleId`** — domain identifier newtypes with a
  private inner field. Entry points: `parse()` (attacker-controlled
  input, shape-validated), `from_storage()` (trusted storage reads,
  validation bypassed), `mint()` (internal UUID generation).
  `#[serde(transparent)]` — all wire formats, D1 rows, DO payloads,
  and JWT claims are byte-identical to v0.80.x.

- **`RawSecret`** — wraps live secret material (`client_secret`,
  OTP material) in a `zeroize::Zeroizing<String>`. No `Clone`, no
  `Serialize`. `Debug` prints `RawSecret(REDACTED)`. The only read
  point is `.expose()` — greppable.

- **`HashedSecret`** — a stored digest (sha-256 hex). No `PartialEq`
  derived; equality is `ct_eq` (constant-time) only. `Debug` prints
  `HashedSecret(REDACTED)`. `RawSecret::sha256()` is differential-
  tested against the pre-existing `sha256_hex` helper to confirm
  every existing `clients.client_secret_hash` row stays valid.

- **`RedactedSecret`** — zero-size display placeholder for audit
  `before`/`after` deltas.

New dependency: `zeroize = "1"` (production, cesauth-core only).

#### RFC 116 Phase 2 — RefreshTokenFamilyStore conversion

Eliminates the three-adjacent-`&str` swappable-parameter hazard in
`RefreshTokenFamilyStore::rotate`:

```rust
// Before (any two &str args silently transposable):
async fn rotate(&self, family_id: &str, presented_jti: &str, new_jti: &str, …)

// After (distinct types, transposition is a compile error):
async fn rotate(&self, family_id: &FamilyId, presented_jti: &Jti, new_jti: &Jti, …)
```

`FamilyInit`, `FamilyState`, `RotateOutcome`, `RevokeOutcome` fields
converted to `FamilyId`, `UserId`, `ClientId`, `Jti`. All adapters
(`cesauth-adapter-test`, `cesauth-adapter-cloudflare`), all services
(`token`, `revoke`, `introspect`), and all backends updated. 931 host-
side tests + wasm32 `cargo check` remain green throughout.

#### wasm32 build recovery

Pre-existing wasm32 `cesauth-backend` breakage introduced during the
v0.79/v0.80 RFC 115 migration is resolved:

- `totp/enroll.rs`: orphaned post-handler block (dead code from the
  template→Leptos migration) removed.
- `totp/verify.rs`: `VerifyPostDecision` enum head (including
  `CsrfFailure` variant) reconstructed from surviving enum body.
- `backend`: stale import paths for `CloudflareTenantRepository` /
  `CloudflareOrganizationRepository`; `ActiveSession` → `SessionState`;
  duplicate `primary_method_for`; wrong `list()` / `list_for_tenant()`
  arities — all corrected.

`cargo check -p cesauth-backend --target wasm32-unknown-unknown` now
passes cleanly for the first time at this version line.

### Security assurance planning — RFCs 116–124 proposed

Full RFC set for the security-critical assurance strategy deposited in
`rfcs/proposed/` (RFCs 116–124) and indexed in `rfcs/README.md`.
Codebase audit report at `docs/src/expert/security-assurance-audit-v0.80.2.md`.
Security assurance track added to `ROADMAP.md`.

---

## [0.80.2] - 2026-05-21

### Dependency upgrades

Applied from `cargo update --dry-run --verbose` audit (see `DEPENDENCIES.md`).

**Applied (compatible minor/patch):** `either 1.16.0`, `num-conv 0.2.2`,
`pin-project 1.1.13`, `worker + macros + sys 0.8.3`, `zerofrom 0.1.8`.

**Leptos upgraded:** `=0.8.2` → `=0.8.19` (with `leptos_router =0.8.13`).
Host-side `cargo check` passes. The original hold (RFC 115 §2 — getrandom
0.3/uuid 1.18 on Workers wasm32) is considered resolved because the workspace
already carries `getrandom 0.4.2` via `uuid = { features = ["js"] }`, making
the `wasm_js` feature globally available. Full wasm32 / Trunk build
verification required in CI before production use.

**RustCrypto suite — blocked:** `sha2`, `sha1`, `hmac`, `crypto-common`,
`pkcs8`, `rand_core` are all pinned by `ed25519-dalek 2.2.0`.
`ed25519-dalek 3.0.0` (in pre-release) unblocks the suite; upgrade as
a coordinated batch when it ships. See `DEPENDENCIES.md`.

**`rusqlite` — deferred:** 0.32.1 → 0.39.0 (7 major versions); test-only
crate; upgrade separately. See `DEPENDENCIES.md`.

**New file:** `DEPENDENCIES.md` — living document tracking held
dependencies, upgrade blockers, and upgrade procedures.

1,211 / 1,211 tests pass.

---

## [0.80.1] - 2026-05-21

### Dependency update patch

Applied compatible updates from `cargo update --dry-run`:
`either 1.16.0`, `num-conv 0.2.2`, `pin-project 1.1.13`,
`worker + macros + sys 0.8.3`, `zerofrom 0.1.8`.

---


## Note — 0.79.6 through 0.81.3 could not serve a request

**Added 2026-09-10, discovered by RFC 134.** Every release from `0.79.6`
through `0.81.3` — the eight entries below this note, all the way up to
(but not including) `0.82.0` — shipped a Worker whose router panicked on
construction on **every** request, before any handler ran. Three route
patterns (`.json` suffixed onto a parameter segment) collided with
sibling routes in `matchit`, the matcher `worker` uses; `worker` turns a
rejected pattern into a Rust panic rather than a recoverable error, and
the router was built inside `#[event(fetch)]` — so the panic fired per
request, on the very first line of routing, regardless of which path was
requested. See [RFC 134](../../rfcs/done/134-router-pattern-conflict.md) for
the full mechanism, the fix, and the new gate that would have caught it.

These eight releases are not corrected retroactively — they shipped, and
they stay as they were tagged. `0.82.0` is the first release since
`0.79.5` capable of serving a request.

---

## [0.80.0] - 2026-05-20

### RFC 115 — Phase C complete: old string templates removed

Completion release for the Leptos frontend migration (RFC 115).

**Template functions deleted** (replaced by Leptos components):
`login_page_for`, `login_page`, `security_center_page_for`,
`security_center_page`, `security_center_page_with_flash`,
`sessions_page_for`, `sessions_page`, `totp_disable_confirm_page_for`,
`totp_disable_confirm_page`.

**Retained** (still used by POST handler error re-renders):
`magic_link_sent_page_for`, `error_page_for`, `totp_enroll_page_for`,
`totp_recovery_codes_page_for`, `totp_verify_page_for`.

**79 template tests removed** — tests that existed solely to pin the
deleted functions. Total test count: 1,211 (was 1,290).

**PoC infrastructure removed**: `GET /__leptos` route, `PocCounter`
component, `poc_handler`.

**`oidc/authorize.rs` fixed**: `GET /authorize` cold path now redirects
to `302 /login` with the pending-AR cookie pre-set, instead of rendering
the login template directly. Correct behaviour under Leptos CSR.

**Orphaned backend code removed** from `me/security.rs`, `me/sessions.rs`,
`routes/ui.rs` — old GET handler bodies left by the Phase C migration that
were invisible to host-side `cargo check` (backend is wasm32-only).

**`drift-scan.sh`** updated: RFC 108 check exempts `crates/frontend/src/pages/`
and `app.rs` (Leptos CSR files). Follow-up RFC will decide on centralised
route constants.

---

