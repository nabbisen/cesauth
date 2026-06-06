# RFC 095 — Quota enforcement at tenant operations

**Status**: Implemented | **Tier**: Feature | **Target**: v0.65.0

`billing::quota.rs` defines quota checking logic but worker routes that
create users / OIDC clients / organizations do not enforce plan quotas.
Add quota pre-flight to: create user invitation, create OIDC client,
create organization.
