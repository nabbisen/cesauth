# `nodejs_compat` Investigation

**RFC 025 — Step 2**

## Summary

`wrangler.toml` line 12 enables
`compatibility_flags = ["nodejs_compat"]`.
A static review of the codebase found **no Node API call sites** — no
`require()`, no `process.*`, no `Buffer`, no Node-specific modules.

The investigation below records a structured experiment to determine
whether the flag is safe to remove.

## Hypothesis

`nodejs_compat` was added at project init (possibly a wrangler scaffold
default) and is dead weight.  Removing it should:

1. Reduce bundle gzip size (Node polyfills no longer bundled).
2. Not break any worker functionality.
3. Pass all existing tests unchanged.

## Experiment protocol

### Step 1 — baseline measurement

```bash
# With nodejs_compat enabled (current state)
wrangler deploy --dry-run --outdir bundled-with-compat/
gzip -c bundled-with-compat/*.js | wc -c
# Record result: __ bytes
```

### Step 2 — remove the flag

```diff
# wrangler.toml
-compatibility_flags = ["nodejs_compat"]
+# nodejs_compat removed — see docs/src/expert/nodejs-compat-investigation.md
```

### Step 3 — build without the flag

```bash
wrangler deploy --dry-run --outdir bundled-no-compat/
gzip -c bundled-no-compat/*.js | wc -c
# Record result: __ bytes
# Delta: __ bytes (__ %)
```

If the build **fails**, capture the error and record the root-cause crate
below.

### Step 4 — smoke tests

```bash
# Run host-testable tests (unchanged either way — these don't touch
# the wasm target or Node polyfills)
cargo-1.91 test -p cesauth-core -p cesauth-adapter-test -p cesauth-ui --lib

# Optionally run wrangler dev and exercise /authorize + /token manually
# to confirm the hot path is unaffected.
```

## Results

> **TODO**: Record measurement results here when the experiment is run.

| Configuration | Gzip size (bytes) | Build result |
|---|---|---|
| With `nodejs_compat` | _TBD_ | passes |
| Without `nodejs_compat` | _TBD_ | _TBD_ |
| Delta | _TBD_ | — |

## Decision

- If the build passes without the flag **and** the size reduction is
  ≥ 5% (or ≥ 50 KiB), remove the flag and update `wrangler.toml`.
- If the build fails, identify the dependency that requires the polyfill
  and record it in the "Root cause" section below.
- If the build passes but the size reduction is negligible (< 5%),
  retain the flag for compatibility with any tooling that may depend on
  it and record the finding here.

## Root cause (if removal fails)

> _TBD — fill in if Step 3 build fails, naming the crate and the
> specific Node API it calls._

## References

- RFC 025 `§"Step 2 — nodejs_compat measurement"`
- Cloudflare docs: [Node.js compatibility](https://developers.cloudflare.com/workers/runtime-apis/nodejs/)
- `wrangler.toml` line 12
