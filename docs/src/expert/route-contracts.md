# Route contracts

Every browser-facing and machine-facing route in `crates/worker/src/lib.rs`
is recorded here with the six fields identified in the v0.50.1 UI/UX
design deck (p.13): **actor**, **audit kind**, **view** (MessageKey or
template), **rendering test reference**, and **CSRF requirement**.

This table is the contract.  Adding a route to `lib.rs` without a
corresponding row here fails CI (see `scripts/route-contracts-check.sh`,
RFC 027).

The CI check verifies presence only; the content of each row is a
code-review responsibility.

---

## End-user auth routes

| Method | Path | Actor | Audit kind | View / template | Rendering test | CSRF |
|---|---|---|---|---|---|---|
| GET | `/userinfo` | RP / end user | none (read) | JSON (UserInfoClaims) | n/a | N/A (Bearer) |
| POST | `/userinfo` | RP / end user | none (read) | JSON (UserInfoClaims) | n/a | N/A (Bearer) |
| GET | `/.well-known/openid-configuration` | RP / public | none | JSON | n/a | N/A (GET, JSON) |
| GET | `/jwks.json` | RP / public | none | JSON | n/a | N/A (GET, JSON) |
| GET | `/authorize` | Anonymous | none (read) | `authorize_login_page` | `templates::tests::authorize_*` | N/A (GET) |
| POST | `/token` | RP | `token_issued` / `token_refresh_rejected` / `refresh_token_reuse_detected` / `refresh_rate_limited` | JSON | n/a | N/A (CORS preflight) |
| POST | `/revoke` | RP | `revocation_requested` | JSON | n/a | N/A (RFC 7009) |
| POST | `/introspect` | RS (confidential) | `token_introspected` / `introspection_audience_mismatch` / `introspection_rate_limited` | JSON | n/a | N/A (Authorization-only) |

## WebAuthn routes

| Method | Path | Actor | Audit kind | View / template | Rendering test | CSRF |
|---|---|---|---|---|---|---|
| POST | `/webauthn/register/start` | End user | none | JSON (challenge) | n/a | N/A (JSON) |
| POST | `/webauthn/register/finish` | End user | `passkey_registered` | JSON | n/a | N/A (JSON) |
| POST | `/webauthn/authenticate/start` | Anonymous | none | JSON (challenge) | n/a | N/A (JSON) |
| POST | `/webauthn/authenticate/finish` | Anonymous | `passkey_login_succeeded` / `passkey_login_failed` | JSON | n/a | N/A (JSON) |

## Magic Link routes

| Method | Path | Actor | Audit kind | View / template | Rendering test | CSRF |
|---|---|---|---|---|---|---|
| POST | `/magic-link/request` | Anonymous | `magic_link_issued` | `magic_link_sent_page_for` | `templates::tests::magic_link_sent_page_*` | required |
| POST | `/magic-link/verify` | Anonymous | `magic_link_verified` | `complete_auth` redirect | n/a | required (form path) |

## User self-service routes (`/me`)

| Method | Path | Actor | Audit kind | View / template | Rendering test | CSRF |
|---|---|---|---|---|---|---|
| GET | `/me/security` | Authenticated user | none (read) | `security_center_page_for` | `templates::tests::security_center_*` | N/A (GET) |
| GET | `/me/security/sessions` | Authenticated user | none (read) | `sessions_page_for` | `templates::tests::sessions_page_*` | N/A (GET) |
| POST | `/me/security/sessions/revoke-others` | Authenticated user | `session_revoked_by_user` (bulk) | redirect + flash | n/a | required |
| POST | `/me/security/sessions/:session_id/revoke` | Authenticated user | `session_revoked_by_user` | redirect + flash | n/a | required |
| GET | `/me/security/totp/enroll` | Authenticated user | none (read) | `totp_enroll_page_for` | `templates::tests::totp_enroll_page_*` | N/A (GET) |
| POST | `/me/security/totp/enroll/confirm` | Authenticated user | `totp_enrolled` | `totp_recovery_codes_page_for` | `templates::tests::totp_recovery_codes_*` | required |
| GET | `/me/security/totp/verify` | End user mid-auth | none (read) | `totp_verify_page_for` | `templates::tests::totp_verify_*` | N/A (GET) |
| POST | `/me/security/totp/verify` | End user mid-auth | `totp_verified` / `totp_verify_failed` | `complete_auth` redirect | n/a | required |
| POST | `/me/security/totp/recover` | End user mid-auth | `totp_recovered` | `complete_auth` redirect | n/a | required |
| GET | `/me/security/totp/disable` | Authenticated user | none (read) | `totp_disable_confirm_page_for` | `templates::tests::totp_disable_*` | N/A (GET) |
| POST | `/me/security/totp/disable` | Authenticated user | `totp_disabled` | redirect + flash | n/a | required |

## Top-level UI routes

| Method | Path | Actor | Audit kind | View / template | Rendering test | CSRF |
|---|---|---|---|---|---|---|
| GET | `/` | Anonymous | none (read) | `login_page_for` | `templates::tests::login_page_*` | N/A (GET) |
| GET | `/login` | Anonymous | none (read) | `login_page_for` | `templates::tests::login_page_*` | N/A (GET) |
| POST | `/logout` | Authenticated user | `session_revoked_by_user` | redirect | n/a | required (Origin check) |

## Admin — system console (`/admin/console`)

| Method | Path | Actor | Audit kind | View / template | Rendering test | CSRF |
|---|---|---|---|---|---|---|
| POST | `/admin/users` | System admin (bearer) | `user_created` | JSON | n/a | N/A (bearer) |
| DELETE | `/admin/sessions/:id` | System admin (bearer) | `session_revoked_by_admin` | JSON | n/a | N/A (bearer) |
| GET | `/admin/console` | System admin | none | overview page | `admin::tests::console_*` | N/A (GET) |
| GET | `/admin/console/cost` | System admin | none | cost page | n/a | N/A (GET) |
| GET | `/admin/console/safety` | System admin | none | safety page | n/a | N/A (GET) |
| POST | `/admin/console/safety/:bucket/verify` | System admin | `bucket_verified` | redirect | n/a | required |
| GET | `/admin/console/audit` | System admin | none | audit search page | n/a | N/A (GET) |
| GET | `/admin/console/audit/chain` | System admin | none | chain status page | n/a | N/A (GET) |
| POST | `/admin/console/audit/chain/verify` | System admin | `audit_chain_verified` | redirect | n/a | required |
| GET | `/admin/console/config` | System admin | none | config page | n/a | N/A (GET) |
| POST | `/admin/console/config/:bucket/preview` | System admin | none | config preview | n/a | required |
| POST | `/admin/console/config/:bucket/apply` | System admin | `config_applied` | redirect | n/a | required |
| POST | `/admin/t/:slug/invitations` | Tenant admin | `invitation_issued` | redirect | CSRF | required |
| GET  | `/admin/t/:slug/invitations` | Tenant admin | none | HTML | n/a | required |
| GET  | `/accept-invite` | public (invite link) | none | HTML | n/a | N/A |
| POST | `/accept-invite` | public (invite link) | `invitation_accepted` | redirect | n/a | N/A |
| POST | `/me/security/delete-account` | authenticated user | `deletion_requested` | redirect | CSRF | session |
| GET  | `/admin/t/:slug/deletion-requests` | Tenant admin | none | HTML | n/a | required |
| POST | `/admin/t/:slug/deletion-requests/:id/cancel` | Tenant admin | `deletion_cancelled` | redirect | CSRF | required |
| POST | `/admin/t/:slug/deletion-requests/:id/execute` | Tenant admin | `deletion_executed` | redirect | CSRF | required |
| POST | `/admin/console/config/log_level/preview` | System admin | `operation_previewed` | preview page | n/a | required |
| POST | `/admin/console/config/log_level/apply` | System admin | `operation_applied` | redirect | n/a | required |
| GET | `/admin/console/alerts` | System admin | none | alerts page | n/a | N/A (GET) |
| POST | `/admin/console/thresholds/:name` | System admin | `threshold_set` | redirect | n/a | required |
| GET | `/admin/console/config/:bucket/edit` | System admin | none | edit form | n/a | N/A (GET) |
| POST | `/admin/console/config/:bucket/edit` | System admin | `config_edited` | redirect | n/a | required |
| GET | `/admin/console/tokens` | System admin | none | token list | n/a | N/A (GET) |
| GET | `/admin/console/tokens/new` | System admin | none | new-token form | n/a | N/A (GET) |
| POST | `/admin/console/tokens` | System admin | `admin_token_created` | redirect | n/a | required |
| POST | `/admin/console/tokens/:id/disable` | System admin | `admin_token_disabled` | redirect | n/a | required |

## Admin — system tenancy console (`/admin/tenancy`)

| Method | Path | Actor | Audit kind | View / template | Rendering test | CSRF |
|---|---|---|---|---|---|---|
| GET | `/admin/tenancy` | System admin | none | tenancy overview | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:id/suspend` | System admin | `tenant_status_changed` | redirect | CSRF | required |
| POST | `/admin/tenancy/tenants/:id/restore` | System admin | `tenant_status_changed` | redirect | CSRF | required |
| GET | `/admin/tenancy/tenants` | System admin | none | tenant list | n/a | N/A (GET) |
| GET | `/admin/tenancy/tenants/:tid` | System admin | none | tenant detail | n/a | N/A (GET) |
| GET | `/admin/tenancy/tenants/:tid/subscription/history` | System admin | none | subscription history | n/a | N/A (GET) |
| GET | `/admin/tenancy/organizations/:oid` | System admin | none | org detail | n/a | N/A (GET) |
| GET | `/admin/tenancy/users/:uid/role_assignments` | System admin | none | role assignments | n/a | N/A (GET) |
| GET | `/admin/tenancy/tenants/new` | System admin | none | new-tenant form | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/new` | System admin | `tenant_created` | redirect | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/status` | System admin | none | status form | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/status` | System admin | `tenant_status_changed` | redirect | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/organizations/new` | System admin | none | new-org form | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/organizations/new` | System admin | `organization_created` | redirect | n/a | required |
| GET | `/admin/tenancy/organizations/:oid/status` | System admin | none | status form | n/a | N/A (GET) |
| POST | `/admin/tenancy/organizations/:oid/status` | System admin | `organization_status_changed` | redirect | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/groups/new` | System admin | none | new-group form | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/groups/new` | System admin | `group_created` | redirect | n/a | required |
| GET | `/admin/tenancy/organizations/:oid/groups/new` | System admin | none | new-group form | n/a | N/A (GET) |
| POST | `/admin/tenancy/organizations/:oid/groups/new` | System admin | `group_created` | redirect | n/a | required |
| GET | `/admin/tenancy/groups/:gid/delete` | System admin | none | delete confirm | n/a | N/A (GET) |
| POST | `/admin/tenancy/groups/:gid/delete` | System admin | `group_deleted` | redirect | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/subscription/plan` | System admin | none | plan form | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/subscription/plan` | System admin | `subscription_plan_changed` | redirect | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/subscription/status` | System admin | none | status form | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/subscription/status` | System admin | `subscription_status_changed` | redirect | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/memberships/new` | System admin | none | add-member form | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/memberships/new` | System admin | `membership_added` | redirect | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/memberships/:uid/delete` | System admin | none | remove-member confirm | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/memberships/:uid/delete` | System admin | `membership_removed` | redirect | n/a | required |
| GET | `/admin/tenancy/organizations/:oid/memberships/new` | System admin | none | add-member form | n/a | N/A (GET) |
| POST | `/admin/tenancy/organizations/:oid/memberships/new` | System admin | `membership_added` | redirect | n/a | required |
| GET | `/admin/tenancy/organizations/:oid/memberships/:uid/delete` | System admin | none | remove confirm | n/a | N/A (GET) |
| POST | `/admin/tenancy/organizations/:oid/memberships/:uid/delete` | System admin | `membership_removed` | redirect | n/a | required |
| GET | `/admin/tenancy/groups/:gid/memberships/new` | System admin | none | add-member form | n/a | N/A (GET) |
| POST | `/admin/tenancy/groups/:gid/memberships/new` | System admin | `membership_added` | redirect | n/a | required |
| GET | `/admin/tenancy/groups/:gid/memberships/:uid/delete` | System admin | none | remove confirm | n/a | N/A (GET) |
| POST | `/admin/tenancy/groups/:gid/memberships/:uid/delete` | System admin | `membership_removed` | redirect | n/a | required |
| GET | `/admin/tenancy/users/:uid/role_assignments/new` | System admin | none | grant-role form | n/a | N/A (GET) |
| POST | `/admin/tenancy/users/:uid/role_assignments/new` | System admin | `role_assignment_created` | redirect | n/a | required |
| GET | `/admin/tenancy/role_assignments/:id/delete` | System admin | none | revoke confirm | n/a | N/A (GET) |
| POST | `/admin/tenancy/role_assignments/:id/delete` | System admin | `role_assignment_deleted` | redirect | n/a | required |
| GET | `/admin/tenancy/users/:uid/tokens/new` | System admin | none | mint-token form | n/a | N/A (GET) |
| POST | `/admin/tenancy/users/:uid/tokens/new` | System admin | `admin_token_minted` | redirect | n/a | required |

## Admin — tenant-admin console (`/admin/t/:slug`)

| Method | Path | Actor | Audit kind | View / template | Rendering test | CSRF |
|---|---|---|---|---|---|---|
| GET | `/admin/t/:slug` | Tenant admin | none | tenant overview | n/a | N/A (GET) |
| GET | `/admin/t/:slug/organizations` | Tenant admin | none | org list | n/a | N/A (GET) |
| GET | `/admin/t/:slug/organizations/:oid` | Tenant admin | none | org detail | n/a | N/A (GET) |
| GET | `/admin/t/:slug/users` | Tenant admin | none | user list | n/a | N/A (GET) |
| GET | `/admin/t/:slug/users/:uid/role_assignments` | Tenant admin | none | role assignments | n/a | N/A (GET) |
| GET | `/admin/t/:slug/subscription` | Tenant admin | none | subscription | n/a | N/A (GET) |
| GET | `/admin/t/:slug/organizations/new` | Tenant admin | none | new-org form | n/a | N/A (GET) |
| POST | `/admin/t/:slug/organizations/new` | Tenant admin | `organization_created` | redirect | n/a | required |
| GET | `/admin/t/:slug/organizations/:oid/status` | Tenant admin | none | status form | n/a | N/A (GET) |
| POST | `/admin/t/:slug/organizations/:oid/status` | Tenant admin | `organization_status_changed` | redirect | n/a | required |
| GET | `/admin/t/:slug/organizations/:oid/groups/new` | Tenant admin | none | new-group form | n/a | N/A (GET) |
| POST | `/admin/t/:slug/organizations/:oid/groups/new` | Tenant admin | `group_created` | redirect | n/a | required |
| GET | `/admin/t/:slug/groups/:gid/delete` | Tenant admin | none | delete confirm | n/a | N/A (GET) |
| POST | `/admin/t/:slug/groups/:gid/delete` | Tenant admin | `group_deleted` | redirect | n/a | required |
| GET | `/admin/t/:slug/users/:uid/role_assignments/new` | Tenant admin | none | grant-role form | n/a | N/A (GET) |
| POST | `/admin/t/:slug/users/:uid/role_assignments/new` | Tenant admin | `role_assignment_created` | redirect | n/a | required |
| GET | `/admin/t/:slug/role_assignments/:id/delete` | Tenant admin | none | revoke confirm | n/a | N/A (GET) |
| POST | `/admin/t/:slug/role_assignments/:id/delete` | Tenant admin | `role_assignment_deleted` | redirect | n/a | required |
| GET | `/admin/t/:slug/memberships/new` | Tenant admin | none | add-member form | n/a | N/A (GET) |
| POST | `/admin/t/:slug/memberships` | Tenant admin | `membership_added` | redirect | n/a | required |
| GET | `/admin/t/:slug/memberships/:uid/delete` | Tenant admin | none | remove confirm | n/a | N/A (GET) |
| POST | `/admin/t/:slug/memberships/:uid/delete` | Tenant admin | `membership_removed` | redirect | n/a | required |
| GET | `/admin/t/:slug/organizations/:oid/memberships/new` | Tenant admin | none | add-member form | n/a | N/A (GET) |
| POST | `/admin/t/:slug/organizations/:oid/memberships` | Tenant admin | `membership_added` | redirect | n/a | required |
| GET | `/admin/t/:slug/organizations/:oid/memberships/:uid/delete` | Tenant admin | none | remove confirm | n/a | N/A (GET) |
| POST | `/admin/t/:slug/organizations/:oid/memberships/:uid/delete` | Tenant admin | `membership_removed` | redirect | n/a | required |
| GET | `/admin/t/:slug/groups/:gid/memberships/new` | Tenant admin | none | add-member form | n/a | N/A (GET) |
| POST | `/admin/t/:slug/groups/:gid/memberships` | Tenant admin | `membership_added` | redirect | n/a | required |
| GET | `/admin/t/:slug/groups/:gid/memberships/:uid/delete` | Tenant admin | none | remove confirm | n/a | N/A (GET) |
| POST | `/admin/t/:slug/groups/:gid/memberships/:uid/delete` | Tenant admin | `membership_removed` | redirect | n/a | required |

## REST API v1 (`/api/v1`)

| Method | Path | Actor | Audit kind | View / template | Rendering test | CSRF |
|---|---|---|---|---|---|---|
| POST | `/api/v1/tenants` | System admin (bearer) | `tenant_created` | JSON | n/a | N/A (bearer) |
| GET | `/api/v1/tenants` | System admin (bearer) | none | JSON | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid` | System admin (bearer) | none | JSON | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/status` | System admin (bearer) | `tenant_status_changed` | JSON | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/organizations` | System admin (bearer) | `organization_created` | JSON | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/organizations` | System admin (bearer) | none | JSON | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/organizations/:oid` | System admin (bearer) | none | JSON | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/organizations/:oid/status` | System admin (bearer) | `organization_status_changed` | JSON | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/groups` | System admin (bearer) | `group_created` | JSON | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/groups` | System admin (bearer) | none | JSON | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/memberships` | System admin (bearer) | `membership_added` | JSON | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/memberships` | System admin (bearer) | none | JSON | n/a | N/A (bearer) |
| POST | `/api/v1/organizations/:oid/memberships` | System admin (bearer) | `membership_added` | JSON | n/a | N/A (bearer) |
| GET | `/api/v1/organizations/:oid/memberships` | System admin (bearer) | none | JSON | n/a | N/A (bearer) |
| POST | `/api/v1/groups/:gid/memberships` | System admin (bearer) | `membership_added` | JSON | n/a | N/A (bearer) |
| GET | `/api/v1/groups/:gid/memberships` | System admin (bearer) | none | JSON | n/a | N/A (bearer) |
| POST | `/api/v1/role_assignments` | System admin (bearer) | `role_assignment_created` | JSON | n/a | N/A (bearer) |
| GET | `/api/v1/users/:uid/role_assignments` | System admin (bearer) | none | JSON | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/subscription` | System admin (bearer) | none | JSON | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/subscription/plan` | System admin (bearer) | `subscription_plan_changed` | JSON | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/subscription/status` | System admin (bearer) | `subscription_status_changed` | JSON | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/subscription/history` | System admin (bearer) | none | JSON | n/a | N/A (bearer) |
| POST | `/api/v1/anonymous/begin` | Anonymous | `anonymous_session_started` | JSON | n/a | N/A (JSON) |
| POST | `/api/v1/anonymous/promote` | Anonymous user | `anonymous_session_promoted` | JSON | n/a | N/A (JSON) |
| DELETE | `/api/v1/tenants/:tid/memberships/:uid` | System admin (bearer) | `membership_removed` | JSON | n/a | N/A (bearer) |
| DELETE | `/api/v1/organizations/:oid/memberships/:uid` | System admin (bearer) | `membership_removed` | JSON | n/a | N/A (bearer) |
| DELETE | `/api/v1/groups/:gid` | System admin (bearer) | `group_deleted` | JSON | n/a | N/A (bearer) |
| DELETE | `/api/v1/groups/:gid/memberships/:uid` | System admin (bearer) | `membership_removed` | JSON | n/a | N/A (bearer) |
| DELETE | `/api/v1/role_assignments/:id` | System admin (bearer) | `role_assignment_deleted` | JSON | n/a | N/A (bearer) |

## Dev-only routes (`/__dev`)

| Method | Path | Actor | Audit kind | View / template | Rendering test | CSRF |
|---|---|---|---|---|---|---|
| POST | `/__dev/stage-auth-code/:handle` | Dev only | none | JSON | n/a | N/A (dev only) |
| GET | `/__dev/audit` | Dev only | none | audit browser | n/a | N/A (dev only) |

---

## Checklist for adding a new route

When adding a route to `crates/worker/src/lib.rs`, update this table with:

1. **Actor** — who makes this request (anonymous, end user, authenticated user, tenant admin, system admin, RS, RP)
2. **Audit kind** — the `EventKind` emitted on success (or "none" if the route never emits)
3. **View** — the template function or response type
4. **Rendering test** — a reference to an existing or new test that pins the HTML/JSON shape
5. **CSRF** — "required", "N/A (GET)", "N/A (bearer)", "N/A (JSON)", etc.

The CI check will fail until this table has a row for the new route.
