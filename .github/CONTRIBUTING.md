# Contributing to cesauth

Thank you for considering a contribution. cesauth is a small,
opinionated codebase and the maintainer is solo, so this guide is
practical rather than ceremonial — it tells you what shape of
contribution lands smoothly, and what to expect once you open a
pull request.

## Before you start

- Read the [README](../README.md) for what cesauth is and isn't.
- Skim [`ROADMAP.md`](../ROADMAP.md) — it lists what's planned and
  what is explicitly out of scope.
- Check the [CHANGELOG](../CHANGELOG.md) and existing release
  bundles in the repository tags to see the project's pace.

If you're proposing a substantial change, please open an issue
first so we can agree on the shape before you write code.
Substantial means: a new public API, a new dependency, a new
crate, or a refactor that touches more than a handful of files.

## Working with the codebase

cesauth is a Cargo workspace targeting both host (`cargo test`) and
`wasm32-unknown-unknown` (`wrangler deploy`). The recommended local
flow:

```sh
# Build and test on host. This is the fastest feedback loop and
# covers the bulk of the codebase.
cargo check --workspace
cargo test --workspace --lib

# Build for wasm32 to confirm the worker still compiles.
cd crates/worker
wrangler dev --local
```

The host test suite must pass with zero warnings before a PR is
considered for review. The wasm32 path is verified by maintainers
during release (the bundles in `outputs/` are produced from
machines that have wrangler set up).

### Code style

cesauth uses the standard Rust toolchain conventions:

- `rustfmt` with the `edition = "2024"` config in
  `rustfmt.toml`. Run `cargo fmt --all` before committing.
- `clippy` warnings should be fixed or explicitly allowed with a
  comment explaining why. We don't run clippy in CI, but reviewers
  may flag issues clippy would catch.

Beyond those, cesauth's code review priorities are:

1. **Make invalid states unrepresentable.** Use the type system
   wherever it can carry an invariant. New ports, new domain
   types, and new error enums should narrow the possible values,
   not widen them.
2. **Pure decision in core, side effects at the edge.** Domain
   logic lives in `cesauth-core` as pure functions; storage and
   network calls live at the adapter or worker boundary. If a new
   port or service crosses this line, call it out in the PR.
3. **Test what changed.** Most PRs land with tests in the same
   commit. Aim for tests that exercise the boundary you changed
   (a new port → an in-memory adapter test; a new HTTP route →
   a host-side smoke test or a wasm32 manual verification note).

### Commit messages

Reasonable English (or Japanese — both are fine) sentences that
explain what changed and why. A line or two of body for
non-trivial changes. We don't enforce conventional-commits, but
clarity is appreciated.

## Pull-request checklist

Before opening a PR:

- [ ] `cargo check --workspace` passes with zero warnings.
- [ ] `cargo test --workspace --lib` passes.
- [ ] `cargo fmt --all` has been run.
- [ ] New public APIs are documented with `///` doc-comments.
- [ ] If the change is user-facing or breaks something, the
      `[Unreleased]` section of `CHANGELOG.md` has been updated.
- [ ] If the change opens a new design question or affects the
      tenant-scoped admin surface, a relevant ADR has been
      drafted under `docs/src/expert/adr/`.

## What lands smoothly

- Bug fixes with a regression test.
- Documentation improvements (typos, clarifications, missing
  examples).
- Test-suite additions covering edge cases.
- Small refactors that reduce duplication or improve naming,
  with no behavior change.
- New adapter implementations (e.g., a new database backend) that
  follow the existing port shape.

## What might need discussion first

- New crates, new top-level dependencies, new platform targets.
- Changes to the wire format (`/api/v1/...`, audit-event JSON,
  `wrangler.toml` variable names).
- Schema migrations.
- Substantial UI changes to the admin or SaaS console.
- Anything in `cesauth-core::ports` (the port surface should
  shrink or stay flat, not grow).

## Reporting issues

Use the issue templates under `.github/ISSUE_TEMPLATE/`. If you're
not sure which template applies, the blank template is fine.

For security-sensitive reports, follow the
[security policy](SECURITY.md) instead of opening a public issue.

## Code of conduct

Participation in this project is subject to our
[Code of Conduct](CODE_OF_CONDUCT.md). In short: be respectful,
be welcoming, focus on the work.

## License

By contributing, you agree that your contribution will be licensed
under the [Apache License, Version 2.0](../LICENSE), the same
license as the rest of the project.
