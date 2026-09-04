# cesauth — build orchestration
#
# Two WASM targets are compiled separately:
#
#   crates/frontend  → Trunk (+ a manual wasm-opt pass, see below)
#                       → dist/*.{js,wasm}  (browser, CSR)
#   crates/backend   → worker-build → build/     (Cloudflare Workers)
#
# Workers Static Assets serves the dist/ contents at /assets/*.
# The backend Worker handles all other routes.
#
# The Rust toolchain is pinned in `rust-toolchain.toml` (RFC 130 M2) —
# rustup picks it up automatically for every command in this repo.
#
# Prerequisites:
#   rustup target add wasm32-unknown-unknown
#   cargo install trunk
#   npm install -g wrangler   (or use npx wrangler)
#   curl, tar                 (fetches wasm-opt; see wasm-opt-fetch below)
#
# Usage:
#   make build       — full production build (frontend then backend)
#   make dev         — concurrent Trunk watch + wrangler dev
#   make test        — run host-side tests (cargo test, no WASM target)
#   make clean       — remove all build artefacts

.PHONY: build build-frontend build-backend dev dev-frontend dev-backend \
        test clean wasm-opt-fetch

# ── Build ────────────────────────────────────────────────────────────────────

## Full production build: frontend first, then backend.
## The backend wrangler.toml [assets] section reads crates/frontend/dist/,
## so the frontend must be built first.
build: build-frontend build-backend

# RFC 130 S1 (M1 measured: even Binaryen 132, the newest release as of
# writing, still rejects the module — the target-feature auto-detection
# RFC 130 §M1 hoped for does not happen in practice). Trunk's own
# `data-wasm-opt` release-mode optimize step fails wasm-validation: rustc's
# wasm32-unknown-unknown target now emits bulk-memory instructions by
# default (`rustc --print cfg --target wasm32-unknown-unknown`), and Trunk
# has no attribute to pass wasm-opt the `--enable-bulk-memory` flags that
# accepting them requires.
#
# `index.html` sets `data-wasm-opt="0"`, so Trunk skips its own (broken)
# optimize step and just stages the wasm-bindgen output. This target then
# runs the real wasm-opt — fetched directly from the upstream Binaryen
# release, not through Trunk's cache, so this works on a clean checkout
# without depending on Trunk ever having been asked to optimize anything —
# with the flags Trunk cannot pass, over whatever file Trunk staged.
#
# Pinned to version_123: the version this was verified against (RFC 130 §2).
# Re-verify before bumping; M1 already showed version_132 does not remove
# the need for this step.
BINARYEN_VERSION := version_123
BINARYEN_DIR     := target/binaryen-$(BINARYEN_VERSION)
BINARYEN_OS      := $(shell uname -s)
BINARYEN_ARCH    := $(shell uname -m)
ifeq ($(BINARYEN_OS),Linux)
  BINARYEN_ARCH := $(if $(filter aarch64,$(BINARYEN_ARCH)),aarch64,x86_64)
  BINARYEN_ASSET := binaryen-$(BINARYEN_VERSION)-$(BINARYEN_ARCH)-linux.tar.gz
else ifeq ($(BINARYEN_OS),Darwin)
  BINARYEN_ARCH := $(if $(filter arm64,$(BINARYEN_ARCH)),arm64,x86_64)
  BINARYEN_ASSET := binaryen-$(BINARYEN_VERSION)-$(BINARYEN_ARCH)-macos.tar.gz
else
  $(error RFC 130 S1: no Binaryen release mapping for OS "$(BINARYEN_OS)" — add one or fetch wasm-opt manually)
endif
BINARYEN_URL := https://github.com/WebAssembly/binaryen/releases/download/$(BINARYEN_VERSION)/$(BINARYEN_ASSET)

## Fetch wasm-opt directly from the upstream Binaryen release, cached
## under target/ so `make clean` removes it. No-op if already present.
wasm-opt-fetch:
	@if [ ! -x "$(BINARYEN_DIR)/bin/wasm-opt" ]; then \
		echo "Fetching Binaryen $(BINARYEN_VERSION) ($(BINARYEN_ASSET))..."; \
		mkdir -p target; \
		curl -sSL -o target/$(BINARYEN_ASSET) "$(BINARYEN_URL)"; \
		tar xzf target/$(BINARYEN_ASSET) -C target; \
		rm -f target/$(BINARYEN_ASSET); \
	fi

## Compile the Leptos CSR bundle with Trunk + copy static assets to dist/.
## Output: crates/frontend/dist/
##
## Trunk's own optimize step is disabled (see wasm-opt-fetch above); the
## wasm-opt invocation below applies the flags Trunk cannot pass. Runs
## against whatever `_bg.wasm` Trunk staged, name-agnostically (glob, not
## a fixed name) as a second line of defence even though --filehash false
## (RFC 130 S2) makes the name deterministic — a `data-filehash` *HTML*
## attribute does not exist on Trunk's `rust` asset (tested: silently
## ignored, hash still applied); `--filehash false` must be a CLI flag.
##
## --filehash false: deterministic `cesauth-frontend.js` /
## `cesauth-frontend_bg.wasm`, matching crates/backend/src/routes/
## leptos_shell.rs's LEPTOS_JS / LEPTOS_WASM constants (RFC 130 S2).
build-frontend: wasm-opt-fetch
	cd crates/frontend && trunk build --release --filehash false
	for f in crates/frontend/dist/*_bg.wasm; do \
		"$(CURDIR)/$(BINARYEN_DIR)/bin/wasm-opt" \
			--enable-bulk-memory --enable-bulk-memory-opt -Oz \
			-o "$$f" "$$f"; \
	done
	cp crates/frontend/static/* crates/frontend/dist/

## Compile the Cloudflare Workers backend.
## Output: crates/backend/build/worker/shim.mjs + *.wasm
build-backend:
	wrangler build

# ── Development ──────────────────────────────────────────────────────────────

## Run both the Leptos frontend and the wrangler dev server concurrently.
## The frontend watcher rebuilds the WASM bundle on file changes.
## The backend dev server hot-reloads on its own file changes.
##
## Ports:
##   http://localhost:8787  — wrangler dev (full app with backend routes)
##   http://localhost:8080  — trunk serve  (frontend-only, no backend routes)
##
## Typical workflow: open localhost:8787 for full-stack testing.
## Use localhost:8080 only when iterating on frontend component layout
## without needing backend calls.
dev: build-frontend
	$(MAKE) -j2 dev-frontend dev-backend

dev-frontend:
	cd crates/frontend && trunk watch

dev-backend:
	wrangler dev

# ── Tests ────────────────────────────────────────────────────────────────────

## Run all host-side tests (no WASM target required).
## Matches the CI test command documented in CONTRIBUTING.md.
test:
	cargo test -p cesauth-core \
	           -p cesauth-frontend \
	           -p cesauth-adapter-test \
	           -p cesauth-migrate-test \
	           --tests --lib

# ── Utilities ────────────────────────────────────────────────────────────────

## Remove build artefacts from both Trunk and wrangler.
clean:
	rm -rf crates/frontend/dist
	rm -rf crates/backend/build
	rm -rf .wrangler/state
	rm -rf target/binaryen-*
	cargo clean -p cesauth-backend -p cesauth-frontend
