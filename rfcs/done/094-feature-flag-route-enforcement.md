# RFC 094 — Feature flag enforcement at route layer

**Status**: Implemented | **Tier**: Feature | **Target**: v0.65.0

`billing::is_feature_enabled` exists but is not called from worker routes.
Wire feature flag checks into tenant admin routes so Pro-only features
(e.g., advanced OIDC clients) return 402/403 for tenants on Trial plan.
