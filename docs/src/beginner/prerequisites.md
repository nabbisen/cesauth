# Prerequisites

This chapter covers the tools you need before cesauth will build or run.
If you already work with Rust and Cloudflare Workers, skim the version
table and skip to the next chapter.

## Tools

| Tool                     | Why                                      | Tested with |
|--------------------------|------------------------------------------|-------------|
| Rust 1.85+               | Required by the `worker-rs` dep graph    | 1.85, 1.86  |
| `wasm32-unknown-unknown` | WASM build target                        | —           |
| `wrangler` (pinned)      | Runs the Worker and manages CF resources | 4.131.2, from the root `package.json` |
| Node.js with `npm`       | Installs the pinned `wrangler`           | 22          |
| `worker-build`           | Rust → JS+WASM glue                      | auto-installed by the build command |
| `curl`                   | Exercise endpoints                       | any         |
| `jq`                     | Pretty-print JSON                        | any         |
| `openssl`                | Generate Ed25519 signing keys            | 3.x         |

## Install Rust

```sh
rustup install stable
rustup target add wasm32-unknown-unknown --toolchain stable
```

## Install Wrangler

cesauth pins wrangler in the repository root's `package.json`. Once you have
cloned the repository (next section), install it from the repository root:

```sh
npm ci
node_modules/.bin/wrangler --version
```

Do not install wrangler globally, and do not call it through `npx`. Either
one bypasses the pin: a global runs whatever version is installed, and `npx`
without the root install silently runs its cache's copy or the latest release.
The local binary does not run at all without `npm ci`, which is the point
(RFC 138).

Later chapters write commands as `wrangler …`. They mean the pinned binary. To
type them as written, put it on your shell's `PATH` from the repository root:

```sh
export PATH="$PWD/node_modules/.bin:$PATH"
```

## Verify the host build

Clone the repository and run the host-only test suite. This does not
touch Cloudflare at all — it exercises the pure-Rust `core`,
`adapter-test`, `frontend`, and `migrate`/`migrate-test` crates that
make up cesauth's domain layer. A bare `cargo test` tries every
workspace member, including `adapter-cloudflare` and `backend`, which
are wasm32-only and fail to compile on the host — scope the command to
the host-buildable crates:

```sh
git clone https://github.com/cesauth/cesauth.git   # or extract the tarball
cd cesauth
cargo test -p cesauth-core -p cesauth-adapter-test -p cesauth-frontend
cargo test -p cesauth-migrate-test --test migration_chain
```

You should see the full host test suite pass. If it does not, fix the
domain layer before reaching for Cloudflare-specific setup — none of
it will work otherwise.

## Host-only iteration (no Cloudflare)

If you only want to hack on `core`, `adapter-test`, `frontend`, or
`migrate`/`migrate-test`, the setup ends here. Those crates target the
host toolchain and have no Workers runtime dependency:

```sh
cargo test -p cesauth-core
cargo test -p cesauth-adapter-test
cargo test -p cesauth-frontend
cargo test -p cesauth-migrate-test --test migration_chain
```

The adapter-test crate's in-memory port implementations exercise the
same contracts the Cloudflare adapter must satisfy — that parity is
what lets you develop offline with confidence. The
[Ports & adapters](../expert/ports-adapters.md) chapter explains why.

Continue to the [next chapter](./first-local-run.md) when you want to
boot the Worker against Miniflare's local Cloudflare simulator.
