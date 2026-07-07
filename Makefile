# cesauth — build orchestration
#
# Two WASM targets are compiled separately:
#
#   crates/frontend  → Trunk → dist/*.{js,wasm}  (browser, CSR)
#   crates/backend   → worker-build → build/     (Cloudflare Workers)
#
# Workers Static Assets serves the dist/ contents at /assets/*.
# The backend Worker handles all other routes.
#
# Prerequisites:
#   rustup target add wasm32-unknown-unknown
#   cargo install trunk
#   npm install -g wrangler   (or use npx wrangler)
#
# Usage:
#   make build       — full production build (frontend then backend)
#   make dev         — concurrent Trunk watch + wrangler dev
#   make test        — run host-side tests (cargo test, no WASM target)
#   make clean       — remove all build artefacts

.PHONY: build build-frontend build-backend dev dev-frontend dev-backend \
        test clean

# ── Build ────────────────────────────────────────────────────────────────────

## Full production build: frontend first, then backend.
## The backend wrangler.toml [assets] section reads crates/frontend/dist/,
## so the frontend must be built first.
build: build-frontend build-backend

## Compile the Leptos CSR bundle with Trunk.
## Output: crates/frontend/dist/cesauth_frontend{,_bg}.{js,wasm}
build-frontend:
	cd crates/frontend && trunk build --release

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
	cargo clean -p cesauth-backend -p cesauth-frontend
