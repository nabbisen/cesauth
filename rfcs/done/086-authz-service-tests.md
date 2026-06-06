# RFC 086 — authz/service.rs coverage

**Status**: Implemented | **Tier**: Quality | **Size**: Small

`check_permission` and `check_permissions_batch` (314 LOC) are the sole authorization
entry point (spec §9.2). Core logic includes scope lattice traversal and expiry checking.
Currently tested only through adapter-test E2E flows; need direct unit tests that
exercise every DenyReason variant independently.
