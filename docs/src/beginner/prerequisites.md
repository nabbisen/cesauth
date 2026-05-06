# Prerequisites

This chapter covers the tools you need before cesauth will build or run.
If you already work with Rust and Cloudflare Workers, skim the version
table and skip to the next chapter.

## Tools

| Tool                     | Why                                      | Tested with |
|--------------------------|------------------------------------------|-------------|
| Rust 1.85+               | Required by the `worker-rs` dep graph    | 1.85, 1.86  |
| `wasm32-unknown-unknown` | WASM build target                        | —           |
| `wrangler` 3.x or 4.x    | Runs the Worker and manages CF resources | 3.76+, 4.x  |
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

Via npm, which is Cloudflare's preferred distribution:

```sh
npm install -g wrangler
wrangler --version
```

## Verify the host build

Clone the repository and run the host-only test suite. This does not
touch Cloudflare at all — it exercises the pure-Rust `core`,
`adapter-test`, and `ui` crates that make up cesauth's domain layer:

```sh
git clone https://github.com/cesauth/cesauth.git   # or extract the tarball
cd cesauth
cargo test
```

You should see the full host test suite pass. If it does not, fix the
domain layer before reaching for Cloudflare-specific setup — none of
it will work otherwise.

## Host-only iteration (no Cloudflare)

If you only want to hack on `core`, `adapter-test`, or `ui`, the setup
ends here. Those three crates target the host toolchain and have no
Workers runtime dependency:

```sh
cargo test -p cesauth-core
cargo test -p cesauth-adapter-test
cargo test -p cesauth-ui
```

The adapter-test crate's in-memory port implementations exercise the
same contracts the Cloudflare adapter must satisfy — that parity is
what lets you develop offline with confidence. The
[Ports & adapters](../expert/ports-adapters.md) chapter explains why.

Continue to the [next chapter](./first-local-run.md) when you want to
boot the Worker against Miniflare's local Cloudflare simulator.
