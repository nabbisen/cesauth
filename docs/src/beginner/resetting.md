# Resetting between runs

If local state gets confusing (a half-migrated D1 schema, a stale
refresh-token family, a seed row you want to re-insert), the fastest
recovery is a clean slate:

```sh
# Stop wrangler dev first (Ctrl-C), then:
rm -rf .wrangler/state
wrangler d1 migrations apply cesauth --local
```

The `.wrangler/state/` directory holds every piece of local
Cloudflare state — D1 rows, Durable Object storage, KV entries, R2
objects. Deleting it is a full reset.

After a reset you have to re-seed the three rows the tutorial assumes:

1. Re-register the signing key (Step 3 of
   [First local run](./first-local-run.md)).
2. Re-seed the OIDC client (Step 4 of the same).
3. Re-create any tutorial users you had.

Then start the Worker and re-run whichever part of the
[OIDC flow](./first-oidc-flow.md) you were working on.

## Not a full reset — just one row

For narrower recovery, use `wrangler d1 execute`:

```sh
# Drop a specific user so you can recreate them
wrangler d1 execute cesauth --local \
  --command "DELETE FROM users WHERE email='bob@example.com';"

# Clear all grants (refresh-token families)
wrangler d1 execute cesauth --local \
  --command "DELETE FROM grants;"

# Clear the audit log (R2 objects are keyed by day; a full reset is easiest)
# — there is no wrangler r2 object list, so either nuke .wrangler/state
# or use the `wrangler r2 object delete` command per-key.
```

## Durable Object state

DO storage is the one thing `wrangler d1` cannot reach. `AuthChallenge`
(single-use auth codes, magic-link handles), `RefreshTokenFamily`,
and `ActiveSession` all live there. They respect their own TTLs and
alarm callbacks, so they normally self-clean. If you need to force
the issue, `rm -rf .wrangler/state` is still the hammer.
