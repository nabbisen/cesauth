# Route contracts

Every browser-facing and machine-facing route in `crates/backend/src/lib.rs`
is recorded here with the six fields identified in the v0.50.1 UI/UX
design deck (p.13): **actor**, **audit kind**, **view** (MessageKey or
template), **rendering test reference**, and **CSRF requirement** — plus a
seventh field added by RFC 132, **rendering mode**.

This table is the contract.  Adding a route to `lib.rs` without a
corresponding row here fails CI (see `scripts/route-contracts-check.sh`,
RFC 027).

**Rendering** (RFC 132) is `server` | `client` | `n/a`, per
[the view rendering policy](./view-rendering-policy.md). A route declared
`server` must not have its handler call `leptos_html_shell` — the script
checks that mechanically. A missing value fails the check the same way an
undocumented route does.

The CI check verifies presence only; the content of each row is a
code-review responsibility.

---

## End-user auth routes

| Method | Path | Actor | Audit kind | View / template | Rendering | Rendering test | CSRF |
|---|---|---|---|---|---|---|---|
| GET | `/userinfo` | RP / end user | none (read) | JSON (UserInfoClaims) | n/a | n/a | N/A (Bearer) |
| POST | `/userinfo` | RP / end user | none (read) | JSON (UserInfoClaims) | n/a | n/a | N/A (Bearer) |
| GET | `/.well-known/openid-configuration` | RP / public | none | JSON | n/a | n/a | N/A (GET, JSON) |
| GET | `/jwks.json` | RP / public | none | JSON | n/a | n/a | N/A (GET, JSON) |
| GET | `/authorize` | Anonymous | none (read) | `authorize_login_page` | n/a | `templates::tests::authorize_*` | N/A (GET) |
| POST | `/token` | RP | `token_issued` / `token_refresh_rejected` / `refresh_token_reuse_detected` / `refresh_rate_limited` | JSON | n/a | n/a | N/A (CORS preflight) |
| POST | `/revoke` | RP | `revocation_requested` | JSON | n/a | n/a | N/A (RFC 7009) |
| POST | `/introspect` | RS (confidential) | `token_introspected` / `introspection_audience_mismatch` / `introspection_rate_limited` | JSON | n/a | n/a | N/A (Authorization-only) |

## WebAuthn routes

| Method | Path | Actor | Audit kind | View / template | Rendering | Rendering test | CSRF |
|---|---|---|---|---|---|---|---|
| POST | `/webauthn/register/start` | End user | none | JSON (challenge) | n/a | n/a | N/A (JSON) |
| POST | `/webauthn/register/finish` | End user | `passkey_registered` | JSON | n/a | n/a | N/A (JSON) |
| POST | `/webauthn/authenticate/start` | Anonymous | none | JSON (challenge) | n/a | n/a | N/A (JSON) |
| POST | `/webauthn/authenticate/finish` | Anonymous | `passkey_login_succeeded` / `passkey_login_failed` | JSON | n/a | n/a | N/A (JSON) |

## Magic Link routes

| Method | Path | Actor | Audit kind | View / template | Rendering | Rendering test | CSRF |
|---|---|---|---|---|---|---|---|
| POST | `/magic-link/request` | Anonymous | `magic_link_issued` | `magic_link_sent_page_for` | server | `templates::tests::magic_link_sent_page_*` | required |
| POST | `/magic-link/verify` | Anonymous | `magic_link_verified` | `complete_auth` redirect | server | n/a | required (form path) |

## User self-service routes (`/me`)

| Method | Path | Actor | Audit kind | View / template | Rendering | Rendering test | CSRF |
|---|---|---|---|---|---|---|---|
| GET | `/me/security` | Authenticated user | none (read) | `security_center_page_for` | client | `templates::tests::security_center_*` | N/A (GET) |
| GET | `/me/security.json` | Authenticated user | none (read) | JSON (`SecurityCenterState`) | n/a | n/a | N/A (GET) |
| GET | `/me/security/sessions` | Authenticated user | none (read) | `sessions_page_for` | client | `templates::tests::sessions_page_*` | N/A (GET) |
| GET | `/me/security/sessions.json` | Authenticated user | none (read) | JSON (`sessions`, `current_session_id`, `csrf_token`) | n/a | n/a | N/A (GET) |
| POST | `/me/security/sessions/revoke-others` | Authenticated user | `session_revoked_by_user` (bulk) | redirect + flash | client | n/a | required |
| POST | `/me/security/sessions/:session_id/revoke` | Authenticated user | `session_revoked_by_user` | redirect + flash | client | n/a | required |
| GET | `/me/security/totp/enroll` | Authenticated user | none (read) | `totp_enroll_page_for` | client | `templates::tests::totp_enroll_page_*` | N/A (GET) |
| GET | `/me/security/totp/enroll.json` | Authenticated user | none (read) | JSON (`qr_svg`, `secret_b32`, `csrf_token`) | n/a | n/a | N/A (GET) |
| POST | `/me/security/totp/enroll/confirm` | Authenticated user | `totp_enrolled` | `totp_recovery_codes_page_for` | server | `templates::tests::totp_recovery_codes_*` | required |
| GET | `/me/security/totp/verify` | End user mid-auth | none (read) | `totp_verify_page_for` | server | `templates::tests::totp_verify_*` | N/A (GET) |
| GET | `/me/security/totp/verify.json` | End user mid-auth | none (read) | JSON (`csrf_token`, `totp_handle`) | n/a | n/a | N/A (GET) |
| POST | `/me/security/totp/verify` | End user mid-auth | `totp_verified` / `totp_verify_failed` | `complete_auth` redirect | server | n/a | required |
| POST | `/me/security/totp/recover` | End user mid-auth | `totp_recovered` | `complete_auth` redirect | server | n/a | required |
| GET | `/me/security/totp/disable` | Authenticated user | none (read) | `totp_disable_confirm_page_for` | client | `templates::tests::totp_disable_*` | N/A (GET) |
| GET | `/me/security/totp/disable.json` | Authenticated user | none (read) | JSON (`csrf_token`) | n/a | n/a | N/A (GET) |
| POST | `/me/security/totp/disable` | Authenticated user | `totp_disabled` | redirect + flash | client | n/a | required |

## Top-level UI routes

| Method | Path | Actor | Audit kind | View / template | Rendering | Rendering test | CSRF |
|---|---|---|---|---|---|---|---|
| GET | `/` | Anonymous | none (read) | `login_page_for` | server | `templates::tests::login_page_*` | N/A (GET) |
| GET | `/login` | Anonymous | none (read) | `login_page_for` | server | `templates::tests::login_page_*` | N/A (GET) |
| POST | `/logout` | Authenticated user | `session_revoked_by_user` | redirect | n/a | n/a | required (Origin check) |

## Admin — system console (`/admin/console`)

| Method | Path | Actor | Audit kind | View / template | Rendering | Rendering test | CSRF |
|---|---|---|---|---|---|---|---|
| POST | `/admin/users` | System admin (bearer) | `user_created` | JSON | n/a | n/a | N/A (bearer) |
| DELETE | `/admin/sessions/:id` | System admin (bearer) | `session_revoked_by_admin` | JSON | n/a | n/a | N/A (bearer) |
| GET | `/admin/login` | System admin (bearer, pre-cookie) | none | login form (no `?token=`) / 302 redirect to `/admin/console` + sets `__Host-cesauth_admin` cookie (valid `?token=`) | server | n/a | N/A (GET) |
| GET | `/admin/console` | System admin | none | overview page | client | `admin::tests::console_*` | N/A (GET) |
| GET | `/admin/console.json` | System admin | none | JSON (`csrf_token`) | n/a | n/a | N/A (GET) |
| GET | `/admin/console/cost` | System admin | none | cost page | client | n/a | N/A (GET) |
| GET | `/admin/console/safety` | System admin | none | safety page | client | n/a | N/A (GET) |
| POST | `/admin/console/safety/:bucket/verify` | System admin | `bucket_verified` | redirect | client | n/a | required |
| GET  | `/admin/console/operations` | System admin | none | HTML | client | n/a | required |
| GET  | `/admin/console/operations.json` | System admin | none | JSON (`csrf_token`) | n/a | n/a | required |
| POST | `/admin/console/audit/export` | System admin | `audit_exported` | CSV/JSONL download | n/a | CSRF | required |
| GET | `/admin/console/audit` | System admin | none | audit search page | client | n/a | N/A (GET) |
| GET | `/admin/console/audit/chain` | System admin | none | chain status page | client | n/a | N/A (GET) |
| POST | `/admin/console/audit/chain/verify` | System admin | `audit_chain_verified` | redirect | client | n/a | required |
| GET | `/admin/console/config` | System admin | none | config page | client | n/a | N/A (GET) |
| POST | `/admin/console/config/:bucket/preview` | System admin | none | config preview | client | n/a | required |
| POST | `/admin/console/config/:bucket/apply` | System admin | `config_applied` | redirect | client | n/a | required |
| POST | `/admin/t/:slug/invitations` | Tenant admin | `invitation_issued` | redirect | client | CSRF | required |
| GET  | `/admin/t/:slug/invitations` | Tenant admin | none | HTML | client | n/a | required |
| GET  | `/admin/t/:slug/invitations.json` | Tenant admin | none | JSON (`csrf_token`) | n/a | n/a | required |
| GET  | `/accept-invite` | public (invite link) | none | HTML | server | n/a | N/A |
| POST | `/accept-invite` | public (invite link) | `invitation_accepted` | redirect | server | n/a | N/A |
| POST | `/me/security/delete-account` | authenticated user | `deletion_requested` | redirect | client | CSRF | session |
| GET  | `/admin/t/:slug/deletion-requests` | Tenant admin | none | HTML | client | n/a | required |
| GET  | `/admin/t/:slug/deletion-requests.json` | Tenant admin | none | JSON (`csrf_token`) | n/a | n/a | required |
| POST | `/admin/t/:slug/deletion-requests/:id/cancel` | Tenant admin | `deletion_cancelled` | redirect | client | CSRF | required |
| POST | `/admin/t/:slug/deletion-requests/:id/execute` | Tenant admin | `deletion_executed` | redirect | client | CSRF | required |
| POST | `/admin/console/config/log_level/preview` | System admin | `operation_previewed` | preview page | client | n/a | required |
| POST | `/admin/console/config/log_level/apply` | System admin | `operation_applied` | redirect | client | n/a | required |
| GET | `/admin/console/alerts` | System admin | none | alerts page | client | n/a | N/A (GET) |
| POST | `/admin/console/thresholds/:name` | System admin | `threshold_set` | redirect | client | n/a | required |
| GET | `/admin/console/config/:bucket/edit` | System admin | none | edit form | client | n/a | N/A (GET) |
| POST | `/admin/console/config/:bucket/edit` | System admin | `config_edited` | redirect | client | n/a | required |
| GET | `/admin/console/tokens` | System admin | none | token list | client | n/a | N/A (GET) |
| GET | `/admin/console/tokens.json` | System admin | none | JSON (`csrf_token`) | n/a | n/a | N/A (GET) |
| GET | `/admin/console/tokens/new` | System admin | none | new-token form | client | n/a | N/A (GET) |
| POST | `/admin/console/tokens` | System admin | `admin_token_created` | redirect | client | n/a | required |
| POST | `/admin/console/tokens/:id/disable` | System admin | `admin_token_disabled` | redirect | client | n/a | required |

## Admin — system tenancy console (`/admin/tenancy`)

| Method | Path | Actor | Audit kind | View / template | Rendering | Rendering test | CSRF |
|---|---|---|---|---|---|---|---|
| GET | `/admin/tenancy` | System admin | none | tenancy overview | client | n/a | N/A (GET) |
| GET | `/admin/tenancy.json` | System admin | none | JSON (`tenant_count`) | n/a | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:id/suspend` | System admin | `tenant_status_changed` | redirect | client | CSRF | required |
| POST | `/admin/tenancy/tenants/:id/restore` | System admin | `tenant_status_changed` | redirect | client | CSRF | required |
| GET | `/admin/tenancy/tenants` | System admin | none | tenant list | client | n/a | N/A (GET) |
| GET | `/admin/tenancy/tenants.json` | System admin | none | JSON (`tenants`) | n/a | n/a | N/A (GET) |
| GET | `/admin/tenancy/tenants/:tid` | System admin | none | tenant detail | client | n/a | N/A (GET) |
| GET | `/admin/tenancy/tenants/:tid.json` | System admin | none | JSON (`csrf_token`) | n/a | n/a | N/A (GET) |
| GET | `/admin/tenancy/tenants/:tid/subscription/history` | System admin | none | subscription history | client | n/a | N/A (GET) |
| GET | `/admin/tenancy/organizations/:oid` | System admin | none | org detail | client | n/a | N/A (GET) |
| GET | `/admin/tenancy/users/:uid/role_assignments` | System admin | none | role assignments | client | n/a | N/A (GET) |
| GET | `/admin/tenancy/tenants/new` | System admin | none | new-tenant form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/new` | System admin | `tenant_created` | redirect | client | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/status` | System admin | none | status form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/status` | System admin | `tenant_status_changed` | redirect | client | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/organizations/new` | System admin | none | new-org form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/organizations/new` | System admin | `organization_created` | redirect | client | n/a | required |
| GET | `/admin/tenancy/organizations/:oid/status` | System admin | none | status form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/organizations/:oid/status` | System admin | `organization_status_changed` | redirect | client | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/groups/new` | System admin | none | new-group form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/groups/new` | System admin | `group_created` | redirect | client | n/a | required |
| GET | `/admin/tenancy/organizations/:oid/groups/new` | System admin | none | new-group form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/organizations/:oid/groups/new` | System admin | `group_created` | redirect | client | n/a | required |
| GET | `/admin/tenancy/groups/:gid/delete` | System admin | none | delete confirm | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/groups/:gid/delete` | System admin | `group_deleted` | redirect | client | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/subscription/plan` | System admin | none | plan form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/subscription/plan` | System admin | `subscription_plan_changed` | redirect | client | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/subscription/status` | System admin | none | status form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/subscription/status` | System admin | `subscription_status_changed` | redirect | client | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/memberships/new` | System admin | none | add-member form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/memberships/new` | System admin | `membership_added` | redirect | client | n/a | required |
| GET | `/admin/tenancy/tenants/:tid/memberships/:uid/delete` | System admin | none | remove-member confirm | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/tenants/:tid/memberships/:uid/delete` | System admin | `membership_removed` | redirect | client | n/a | required |
| GET | `/admin/tenancy/organizations/:oid/memberships/new` | System admin | none | add-member form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/organizations/:oid/memberships/new` | System admin | `membership_added` | redirect | client | n/a | required |
| GET | `/admin/tenancy/organizations/:oid/memberships/:uid/delete` | System admin | none | remove confirm | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/organizations/:oid/memberships/:uid/delete` | System admin | `membership_removed` | redirect | client | n/a | required |
| GET | `/admin/tenancy/groups/:gid/memberships/new` | System admin | none | add-member form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/groups/:gid/memberships/new` | System admin | `membership_added` | redirect | client | n/a | required |
| GET | `/admin/tenancy/groups/:gid/memberships/:uid/delete` | System admin | none | remove confirm | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/groups/:gid/memberships/:uid/delete` | System admin | `membership_removed` | redirect | client | n/a | required |
| GET | `/admin/tenancy/users/:uid/role_assignments/new` | System admin | none | grant-role form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/users/:uid/role_assignments/new` | System admin | `role_assignment_created` | redirect | client | n/a | required |
| GET | `/admin/tenancy/role_assignments/:id/delete` | System admin | none | revoke confirm | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/role_assignments/:id/delete` | System admin | `role_assignment_deleted` | redirect | client | n/a | required |
| GET | `/admin/tenancy/users/:uid/tokens/new` | System admin | none | mint-token form | client | n/a | N/A (GET) |
| POST | `/admin/tenancy/users/:uid/tokens/new` | System admin | `admin_token_minted` | redirect | client | n/a | required |

## Admin — tenant-admin console (`/admin/t/:slug`)

| Method | Path | Actor | Audit kind | View / template | Rendering | Rendering test | CSRF |
|---|---|---|---|---|---|---|---|
| GET | `/admin/t/:slug` | Tenant admin | none | tenant overview | client | n/a | N/A (GET) |
| GET | `/admin/t/:slug.json` | Tenant admin | none | JSON (`tenant`, `counts`) | n/a | n/a | N/A (GET) |
| GET | `/admin/t/:slug/organizations` | Tenant admin | none | org list | client | n/a | N/A (GET) |
| GET | `/admin/t/:slug/organizations.json` | Tenant admin | none | JSON (`tenant`, `organizations`) | n/a | n/a | N/A (GET) |
| GET | `/admin/t/:slug/organizations/:oid` | Tenant admin | none | org detail | client | n/a | N/A (GET) |
| GET | `/admin/t/:slug/organizations/:oid.json` | Tenant admin | none | JSON (`csrf_token`) | n/a | n/a | N/A (GET) |
| GET | `/admin/t/:slug/users` | Tenant admin | none | user list | client | n/a | N/A (GET) |
| GET | `/admin/t/:slug/users.json` | Tenant admin | none | JSON (`tenant`, `users`) | n/a | n/a | N/A (GET) |
| GET | `/admin/t/:slug/users/:uid/role_assignments` | Tenant admin | none | role assignments | client | n/a | N/A (GET) |
| GET | `/admin/t/:slug/users/:uid/role_assignments.json` | Tenant admin | none | JSON (`csrf_token`) | n/a | n/a | N/A (GET) |
| GET | `/admin/t/:slug/subscription` | Tenant admin | none | subscription | client | n/a | N/A (GET) |
| GET | `/admin/t/:slug/subscription.json` | Tenant admin | none | JSON (`tenant`) | n/a | n/a | N/A (GET) |
| GET | `/admin/t/:slug/organizations/new` | Tenant admin | none | new-org form | client | n/a | N/A (GET) |
| GET | `/admin/t/:slug/organizations/new.json` | Tenant admin | none | JSON (`csrf_token`) | n/a | n/a | N/A (GET) |
| POST | `/admin/t/:slug/organizations/new` | Tenant admin | `organization_created` | redirect | client | n/a | required |
| GET | `/admin/t/:slug/organizations/:oid/status` | Tenant admin | none | status form | client | n/a | N/A (GET) |
| POST | `/admin/t/:slug/organizations/:oid/status` | Tenant admin | `organization_status_changed` | redirect | client | n/a | required |
| GET | `/admin/t/:slug/organizations/:oid/groups/new` | Tenant admin | none | new-group form | client | n/a | N/A (GET) |
| GET | `/admin/t/:slug/organizations/:oid/groups/new.json` | Tenant admin | none | JSON (`csrf_token`) | n/a | n/a | N/A (GET) |
| POST | `/admin/t/:slug/organizations/:oid/groups/new` | Tenant admin | `group_created` | redirect | client | n/a | required |
| GET | `/admin/t/:slug/groups/:gid/delete` | Tenant admin | none | delete confirm | client | n/a | N/A (GET) |
| POST | `/admin/t/:slug/groups/:gid/delete` | Tenant admin | `group_deleted` | redirect | client | n/a | required |
| GET | `/admin/t/:slug/users/:uid/role_assignments/new` | Tenant admin | none | grant-role form | client | n/a | N/A (GET) |
| POST | `/admin/t/:slug/users/:uid/role_assignments/new` | Tenant admin | `role_assignment_created` | redirect | client | n/a | required |
| GET | `/admin/t/:slug/role_assignments/:id/delete` | Tenant admin | none | revoke confirm | client | n/a | N/A (GET) |
| POST | `/admin/t/:slug/role_assignments/:id/delete` | Tenant admin | `role_assignment_deleted` | redirect | client | n/a | required |
| GET | `/admin/t/:slug/memberships/new` | Tenant admin | none | add-member form | client | n/a | N/A (GET) |
| GET | `/admin/t/:slug/memberships/new.json` | Tenant admin | none | JSON (`csrf_token`) | n/a | n/a | N/A (GET) |
| POST | `/admin/t/:slug/memberships` | Tenant admin | `membership_added` | redirect | client | n/a | required |
| GET | `/admin/t/:slug/memberships/:uid/delete` | Tenant admin | none | remove confirm | client | n/a | N/A (GET) |
| POST | `/admin/t/:slug/memberships/:uid/delete` | Tenant admin | `membership_removed` | redirect | client | n/a | required |
| GET | `/admin/t/:slug/organizations/:oid/memberships/new` | Tenant admin | none | add-member form | client | n/a | N/A (GET) |
| POST | `/admin/t/:slug/organizations/:oid/memberships` | Tenant admin | `membership_added` | redirect | client | n/a | required |
| GET | `/admin/t/:slug/organizations/:oid/memberships/:uid/delete` | Tenant admin | none | remove confirm | client | n/a | N/A (GET) |
| POST | `/admin/t/:slug/organizations/:oid/memberships/:uid/delete` | Tenant admin | `membership_removed` | redirect | client | n/a | required |
| GET | `/admin/t/:slug/groups/:gid/memberships/new` | Tenant admin | none | add-member form | client | n/a | N/A (GET) |
| POST | `/admin/t/:slug/groups/:gid/memberships` | Tenant admin | `membership_added` | redirect | client | n/a | required |
| GET | `/admin/t/:slug/groups/:gid/memberships/:uid/delete` | Tenant admin | none | remove confirm | client | n/a | N/A (GET) |
| POST | `/admin/t/:slug/groups/:gid/memberships/:uid/delete` | Tenant admin | `membership_removed` | redirect | client | n/a | required |

## REST API v1 (`/api/v1`)

| Method | Path | Actor | Audit kind | View / template | Rendering | Rendering test | CSRF |
|---|---|---|---|---|---|---|---|
| POST | `/api/v1/tenants` | System admin (bearer) | `tenant_created` | JSON | n/a | n/a | N/A (bearer) |
| GET | `/api/v1/tenants` | System admin (bearer) | none | JSON | n/a | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid` | System admin (bearer) | none | JSON | n/a | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/status` | System admin (bearer) | `tenant_status_changed` | JSON | n/a | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/organizations` | System admin (bearer) | `organization_created` | JSON | n/a | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/organizations` | System admin (bearer) | none | JSON | n/a | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/organizations/:oid` | System admin (bearer) | none | JSON | n/a | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/organizations/:oid/status` | System admin (bearer) | `organization_status_changed` | JSON | n/a | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/groups` | System admin (bearer) | `group_created` | JSON | n/a | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/groups` | System admin (bearer) | none | JSON | n/a | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/memberships` | System admin (bearer) | `membership_added` | JSON | n/a | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/memberships` | System admin (bearer) | none | JSON | n/a | n/a | N/A (bearer) |
| POST | `/api/v1/organizations/:oid/memberships` | System admin (bearer) | `membership_added` | JSON | n/a | n/a | N/A (bearer) |
| GET | `/api/v1/organizations/:oid/memberships` | System admin (bearer) | none | JSON | n/a | n/a | N/A (bearer) |
| POST | `/api/v1/groups/:gid/memberships` | System admin (bearer) | `membership_added` | JSON | n/a | n/a | N/A (bearer) |
| GET | `/api/v1/groups/:gid/memberships` | System admin (bearer) | none | JSON | n/a | n/a | N/A (bearer) |
| POST | `/api/v1/role_assignments` | System admin (bearer) | `role_assignment_created` | JSON | n/a | n/a | N/A (bearer) |
| GET | `/api/v1/users/:uid/role_assignments` | System admin (bearer) | none | JSON | n/a | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/subscription` | System admin (bearer) | none | JSON | n/a | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/subscription/plan` | System admin (bearer) | `subscription_plan_changed` | JSON | n/a | n/a | N/A (bearer) |
| POST | `/api/v1/tenants/:tid/subscription/status` | System admin (bearer) | `subscription_status_changed` | JSON | n/a | n/a | N/A (bearer) |
| GET | `/api/v1/tenants/:tid/subscription/history` | System admin (bearer) | none | JSON | n/a | n/a | N/A (bearer) |
| POST | `/api/v1/anonymous/begin` | Anonymous | `anonymous_session_started` | JSON | n/a | n/a | N/A (JSON) |
| POST | `/api/v1/anonymous/promote` | Anonymous user | `anonymous_session_promoted` | JSON | n/a | n/a | N/A (JSON) |
| DELETE | `/api/v1/tenants/:tid/memberships/:uid` | System admin (bearer) | `membership_removed` | JSON | n/a | n/a | N/A (bearer) |
| DELETE | `/api/v1/organizations/:oid/memberships/:uid` | System admin (bearer) | `membership_removed` | JSON | n/a | n/a | N/A (bearer) |
| DELETE | `/api/v1/groups/:gid` | System admin (bearer) | `group_deleted` | JSON | n/a | n/a | N/A (bearer) |
| DELETE | `/api/v1/groups/:gid/memberships/:uid` | System admin (bearer) | `membership_removed` | JSON | n/a | n/a | N/A (bearer) |
| DELETE | `/api/v1/role_assignments/:id` | System admin (bearer) | `role_assignment_deleted` | JSON | n/a | n/a | N/A (bearer) |

## Dev-only routes (`/__dev`)

| Method | Path | Actor | Audit kind | View / template | Rendering | Rendering test | CSRF |
|---|---|---|---|---|---|---|---|
| POST | `/__dev/stage-auth-code/:handle` | Dev only | none | JSON | n/a | n/a | N/A (dev only) |
| GET | `/__dev/audit` | Dev only | none | audit browser | n/a | n/a | N/A (dev only) |

---

## Checklist for adding a new route

When adding a route to `crates/backend/src/lib.rs`, update this table with:

1. **Actor** — who makes this request (anonymous, end user, authenticated user, tenant admin, system admin, RS, RP)
2. **Audit kind** — the `EventKind` emitted on success (or "none" if the route never emits)
3. **View** — the template function or response type
4. **Rendering** — `server` | `client` | `n/a`, per [the view rendering policy](./view-rendering-policy.md). Q4 (machine-facing, renders nothing) is `n/a`; a pre-authentication or unrecoverable surface is `server`; everything else defaults to `client` if it renders through the Leptos shell, `server` if it renders real HTML directly
5. **Rendering test** — a reference to an existing or new test that pins the HTML/JSON shape
6. **CSRF** — "required", "N/A (GET)", "N/A (bearer)", "N/A (JSON)", etc.

The CI check will fail until this table has a row for the new route.
