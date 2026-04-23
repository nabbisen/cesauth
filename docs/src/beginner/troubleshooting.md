# Troubleshooting

Common failure modes from the beginner chapters, consolidated so you
can jump directly to your symptom.

## `/__dev/audit` returns 404

`WRANGLER_LOCAL` is not set to exactly `"1"`. Check:

```sh
grep WRANGLER_LOCAL .dev.vars
# WRANGLER_LOCAL="1"   ← correct
```

If missing, add the line, then restart `wrangler dev`. `.dev.vars` is
read once at boot.

## `/magic-link/verify` returns `status=500`

Look at `wrangler tail`. Two common causes:

- **`SESSION_COOKIE_KEY secret is not set`** — the tutorial's secret
  step was skipped. Add the key to `.dev.vars` and restart:

  ```sh
  echo "SESSION_COOKIE_KEY=\"$(openssl rand -base64 48 | tr -d '\n')\"" >> .dev.vars
  ```

- **Rust panic mentioning `CryptoProvider`** — the build is missing
  the `rust_crypto` feature on `jsonwebtoken`. The shipped
  `Cargo.toml` already enables it; if you have a fork, ensure:

  ```toml
  jsonwebtoken = { version = "10", default-features = false,
                   features = ["use_pem", "rust_crypto"] }
  ```

## `/token` returns `400 Bad Request` with `invalid_grant`

The staged auth code is gone. Causes, in order of likelihood:

1. **TTL expired.** Auth codes live for 5 minutes.
2. **Already redeemed.** Codes are single-use.
3. **Worker restarted between stage and redeem.** The DO lost the
   entry.

Re-run the stage step with a fresh `$CODE_HANDLE`.

## `/token` returns `500 Internal Server Error`

Check `wrangler tail`. The token handler now emits a structured log
line on every 500 path:

```
{"lvl":"error","cat":"config","msg":"load_signing_key failed: ..."}
{"lvl":"error","cat":"crypto","msg":"JwtSigner::from_pem failed: ..."}
{"lvl":"warn", "cat":"auth",  "msg":"exchange_code failed: <CoreError>"}
```

- `load_signing_key` — `JWT_SIGNING_KEY` missing from `.dev.vars`.
- `JwtSigner::from_pem` — the PEM is malformed. Usually an
  `openssl genpkey` step that was interrupted, or a truncated copy.
- `exchange_code failed: ClientNotFound` — the `oidc_clients` row
  was not seeded.
- `exchange_code failed: PreconditionFailed("invalid_grant")` — see
  the `invalid_grant` section above.

## `/magic-link/verify` returns `status=200` instead of `302`

Old docs showed `status=200`; the real success signal since
`post_auth::complete_auth` landed is `302`. 200 means you are
running an old build. Pull, rebuild, retry.

## `wrangler d1 execute ... '.tables'` fails

`.tables`, `.schema`, `.indexes` are `sqlite3` interactive-shell
meta-commands. `wrangler d1 execute` only takes real SQL. See the
[Inspecting state](./inspecting-state.md) table for equivalents.

## `POST /admin/users` returns `storage error: Unavailable`

D1's `bind()` rejects JavaScript BigInt — and `wasm_bindgen` produces
BigInt from Rust `i64.into()`. The shipped adapter already uses a
`d1_int(v: i64) -> JsValue::from_f64(v as f64)` helper. If you wrote
a new INSERT/UPDATE path and are hitting this, use `d1_int` for every
integer bind site. See
[Ports & adapters](../expert/ports-adapters.md) for the pattern.

## `wrangler r2 object list ... --local` fails

That subcommand does not exist in Wrangler v3 or v4 — only `get`,
`put`, and `delete`. Use `/__dev/audit` for listing audit objects, or
look directly at `.wrangler/state/` for other R2 buckets.

## Nothing works and I want to start over

```sh
rm -rf .wrangler/state
wrangler d1 migrations apply cesauth --local
# re-register the signing key
# re-seed the OIDC client
wrangler dev
```

See [Resetting between runs](./resetting.md) for details.
