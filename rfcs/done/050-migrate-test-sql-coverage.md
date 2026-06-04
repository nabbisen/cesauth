# RFC 050 — migrate-test SQL coverage for invitation/deletion

**Status**: Implemented  
**Priority**: P1 (validate D1 adapter queries against real SQLite)  
**Size**: Small

Add migrate-test integration tests that validate the actual SQL used in CloudflareInvitationRepository and CloudflareDeletionRequestRepository against a real SQLite database (same engine as D1). Tests: insert/query/update for each method, conflict detection, partial-index correctness.
